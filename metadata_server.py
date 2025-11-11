import socket
import threading
import json
import logging
import time
import os
from random import sample

HOST = '0.0.0.0'
PORT = 6000
PERSISTENCE_FILE = 'metadata/metadata.json'
HEARTBEAT_TIMEOUT = 30
REPLICATION_FACTOR = 2

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(threadName)s - %(message)s')

class MetadataServer:
    def __init__(self):
        self.metadata = {
            "nodes": {},
            "users": {}  # email -> {"files": {}, "chunks": {}}
        }
        self.lock = threading.Lock()
        self.port = PORT
        self._load_state()

    # ... _save_state, _load_state, _ensure_user_exists ...
    # (These methods are unchanged from your last version)
    
    def _save_state(self):
        if os.path.isdir(PERSISTENCE_FILE):
            logging.warning(f"'{PERSISTENCE_FILE}' is a directory, removing it.")
            os.rmdir(PERSISTENCE_FILE)
        
        with self.lock:
            os.makedirs(os.path.dirname(PERSISTENCE_FILE), exist_ok=True)
            with open(PERSISTENCE_FILE, 'w') as f:
                json.dump(self.metadata, f, indent=4)
        logging.info("Server state saved.")

    def _load_state(self):
        if os.path.isdir(PERSISTENCE_FILE):
            logging.warning(f"'{PERSISTENCE_FILE}' is a directory, cannot load. Starting fresh.")
            return
        
        try:
            with open(PERSISTENCE_FILE, 'r') as f:
                self.metadata = json.load(f)
                logging.info("Server state loaded from persistence file.")
        except FileNotFoundError:
            logging.info("No persistence file found, starting with a clean state.")
        except json.JSONDecodeError:
            logging.warning("Could not decode persistence file, starting fresh.")

    def _ensure_user_exists(self, user_email):
        """Ensure user namespace exists in metadata"""
        if user_email not in self.metadata["users"]:
            self.metadata["users"][user_email] = {
                "files": {},
                "chunks": {}
            }

    def _prune_dead_nodes(self):
        # ... (Unchanged) ...
        while True:
            time.sleep(HEARTBEAT_TIMEOUT)
            with self.lock:
                now = time.time()
                dead_nodes = [
                    node_id for node_id, info in self.metadata["nodes"].items()
                    if now - info["last_heartbeat"] > HEARTBEAT_TIMEOUT
                ]
                if not dead_nodes: continue
                logging.warning(f"Pruning dead nodes: {dead_nodes}")
                for node_id in dead_nodes:
                    del self.metadata["nodes"][node_id]
                    for user_data in self.metadata["users"].values():
                        for chunk_id, locations in user_data["chunks"].items():
                            if node_id in locations:
                                locations.remove(node_id)
            self._save_state()

    def _send_to_storage_node(self, address, command, payload):
        """Helper to send JSON commands to Storage Nodes."""
        try:
            host, port = address.split(':')
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, int(port)))
                request = json.dumps({"command": command, "payload": payload})
                s.sendall(request.encode('utf-8'))
                response = s.recv(1024)
                return response == b'OK'
        except Exception as e:
            logging.error(f"Failed to send command to node {address}: {e}")
            return False

    def _run_garbage_collection(self, owner_email, chunks_to_check):
        """Deletes orphaned chunks."""
        with self.lock:
            # 1. Find all chunks *still* in use by this user
            all_chunks_in_use = set()
            for file_entry in self.metadata["users"][owner_email]["files"].values():
                if isinstance(file_entry, list): # Check only owned files
                    all_chunks_in_use.update(file_entry)
            
            # 2. Find orphaned chunks
            for chunk_id in chunks_to_check:
                if chunk_id not in all_chunks_in_use:
                    # 3. This chunk is an orphan, delete it
                    logging.info(f"GC: Deleting orphaned chunk {chunk_id} for {owner_email}")
                    if chunk_id in self.metadata["users"][owner_email]["chunks"]:
                        node_ids = self.metadata["users"][owner_email]["chunks"][chunk_id]
                        
                        for node_id in node_ids:
                            if node_id in self.metadata["nodes"]:
                                address = self.metadata["nodes"][node_id]["address"]
                                self._send_to_storage_node(address, "DELETE_CHUNK", {"chunk_id": chunk_id})
                        
                        # 4. Remove from metadata
                        del self.metadata["users"][owner_email]["chunks"][chunk_id]
        
    def _handle_client(self, client_socket):
        try:
            data = client_socket.recv(4096).decode('utf-8')
            request = json.loads(data)
            command = request.get("command")
            payload = request.get("payload", {})

            handler_map = {
                "REGISTER": self._handle_register,
                "HEARTBEAT": self._handle_heartbeat,
                "LIST_FILES": self._handle_list_files,
                "GET_FILE_INFO": self._handle_get_file_info,
                "PUT_FILE_INFO": self._handle_put_file_info,
                "GET_WRITE_NODES": self._handle_get_write_nodes,
                "SHARE_FILE": self._handle_share_file,     # <-- NEW
                "DELETE_FILE": self._handle_delete_file,  # <-- NEW
            }

            handler = handler_map.get(command)
            if handler:
                response = handler(payload)
            else:
                response = {"status": "error", "message": "Unknown command"}
            
            client_socket.sendall(json.dumps(response).encode('utf-8'))
            
        except (json.JSONDecodeError, KeyError) as e:
            error_msg = {"status": "error", "message": f"Invalid request format: {e}"}
            client_socket.sendall(json.dumps(error_msg).encode('utf-8'))
        except Exception as e:
            logging.error(f"An error occurred: {e}", exc_info=True)
        finally:
            client_socket.close()

    # ... _handle_register, _handle_heartbeat ...
    # (Unchanged)
    def _handle_register(self, payload):
        with self.lock:
            node_id, address = payload["node_id"], payload["address"]
            self.metadata["nodes"][node_id] = {
                "address": address,
                "last_heartbeat": time.time()
            }
        logging.info(f"Node '{node_id}' registered at {address}")
        self._save_state()
        return {"status": "ok"}
    
    def _handle_heartbeat(self, payload):
        with self.lock:
            node_id = payload["node_id"]
            if node_id in self.metadata["nodes"]:
                self.metadata["nodes"][node_id]["last_heartbeat"] = time.time()
                logging.info(f"Heartbeat received from '{node_id}'")
                return {"status": "ok"}
        return {"status": "error", "message": "Node not registered"}

    # --- MODIFIED & NEW Handlers ---

    def _handle_list_files(self, payload):
        """MODIFIED: Lists files and their ownership status."""
        user_email = payload.get("user_email")
        if not user_email:
            return {"status": "error", "message": "User email required"}
        
        with self.lock:
            self._ensure_user_exists(user_email)
            files_list = []
            for filename, entry in self.metadata["users"][user_email]["files"].items():
                if isinstance(entry, list):
                    files_list.append({"filename": filename, "owner": "me"})
                elif isinstance(entry, dict) and entry.get("type") == "link":
                    files_list.append({"filename": filename, "owner": entry.get("owner_email")})
            
            return {"status": "ok", "files": files_list}

    def _handle_get_file_info(self, payload):
        """MODIFIED: Follows share links to get file info."""
        user_email = payload.get("user_email")
        filename = payload.get("filename")
        
        if not user_email or not filename:
            return {"status": "error", "message": "User email and filename required"}
        
        with self.lock:
            if user_email not in self.metadata["users"]:
                return {"status": "error", "message": "User not found"}
            
            if filename not in self.metadata["users"][user_email]["files"]:
                return {"status": "error", "message": "File not found"}

            file_entry = self.metadata["users"][user_email]["files"][filename]
            
            owner_email = user_email # Assume current user is owner
            
            # Check if it's a link
            if isinstance(file_entry, dict) and file_entry.get("type") == "link":
                owner_email = file_entry.get("owner_email")
                if owner_email not in self.metadata["users"]:
                    return {"status": "error", "message": "Original owner not found"}
                # Get the *real* file entry from the owner
                file_entry = self.metadata["users"][owner_email]["files"].get(filename)
                if not file_entry:
                     return {"status": "error", "message": "Original file not found"}

            # At this point, file_entry is the chunk list and owner_email is the owner
            chunk_order = file_entry
            locations = {}
            for chunk_id in chunk_order:
                node_ids = self.metadata["users"][owner_email]["chunks"].get(chunk_id, [])
                locations[chunk_id] = [
                    self.metadata["nodes"][node_id]["address"]
                    for node_id in node_ids if node_id in self.metadata["nodes"]
                ]
            return {"status": "ok", "chunks": chunk_order, "locations": locations}

    def _handle_put_file_info(self, payload):
        # ... (Unchanged) ...
        user_email = payload.get("user_email")
        filename = payload.get("filename")
        chunks = payload.get("chunks")
        locations = payload.get("chunk_locations")
        if not user_email or not filename:
            return {"status": "error", "message": "User email and filename required"}
        with self.lock:
            self._ensure_user_exists(user_email)
            user_data = self.metadata["users"][user_email]
            user_data["files"][filename] = chunks
            for chunk_id, node_ids in locations.items():
                user_data["chunks"][chunk_id] = node_ids
        logging.info(f"File '{filename}' committed for user '{user_email}'.")
        self._save_state()
        return {"status": "ok"}


    def _handle_get_write_nodes(self, payload):
        # ... (Unchanged) ...
        with self.lock:
            active_nodes = list(self.metadata["nodes"].keys())
            if len(active_nodes) < REPLICATION_FACTOR:
                return {"status": "error", "message": "Not enough active nodes for replication."}
            k = min(REPLICATION_FACTOR, len(active_nodes))
            chosen_nodes = sample(active_nodes, k)
            node_addresses = [self.metadata["nodes"][nid]["address"] for nid in chosen_nodes]
        return {"status": "ok", "nodes": chosen_nodes, "node_addresses": node_addresses}

    def _handle_share_file(self, payload):
        """NEW: Shares a file with another user."""
        owner_email = payload.get("user_email") # Trusting client
        filename = payload.get("filename")
        share_with_email = payload.get("share_with_email")

        if not owner_email or not filename or not share_with_email:
            return {"status": "error", "message": "Missing required fields"}

        with self.lock:
            # 1. Ensure users exist
            self._ensure_user_exists(owner_email)
            self._ensure_user_exists(share_with_email)
            
            # 2. Check if owner actually has the file
            if filename not in self.metadata["users"][owner_email]["files"]:
                return {"status": "error", "message": "File not found"}
            
            # 3. Check if it's an owned file (not a re-share)
            file_entry = self.metadata["users"][owner_email]["files"][filename]
            if not isinstance(file_entry, list):
                return {"status": "error", "message": "Cannot re-share a shared file"}
            
            # 4. Add the link to the target user
            link = {"type": "link", "owner_email": owner_email}
            self.metadata["users"][share_with_email]["files"][filename] = link
            
            logging.info(f"User '{owner_email}' shared '{filename}' with '{share_with_email}'")
            self._save_state()
            return {"status": "ok"}

    def _handle_delete_file(self, payload):
        """NEW: Deletes a file or a file link."""
        user_email = payload.get("user_email") # Trusting client
        filename = payload.get("filename")

        if not user_email or not filename:
            return {"status": "error", "message": "Missing required fields"}

        with self.lock:
            if user_email not in self.metadata["users"]:
                return {"status": "error", "message": "User not found"}
            
            if filename not in self.metadata["users"][user_email]["files"]:
                return {"status": "error", "message": "File not found"}
            
            file_entry = self.metadata["users"][user_email]["files"][filename]
            
            # Case 1: Deleting a shared file (link)
            if isinstance(file_entry, dict) and file_entry.get("type") == "link":
                del self.metadata["users"][user_email]["files"][filename]
                logging.info(f"User '{user_email}' removed link to '{filename}'")
                self._save_state()
                return {"status": "ok", "message": "Shared file removed"}

            # Case 2: Deleting an owned file
            if isinstance(file_entry, list):
                chunks_to_check = file_entry # Get list of chunks before deleting
                
                # Delete the file entry
                del self.metadata["users"][user_email]["files"][filename]
                
                # Run garbage collection for the chunks
                # This is done in a new thread to avoid blocking the client
                gc_thread = threading.Thread(target=self._run_garbage_collection, 
                                             args=(user_email, chunks_to_check))
                gc_thread.daemon = True
                gc_thread.start()
                
                logging.info(f"User '{user_email}' deleted owned file '{filename}'")
                self._save_state()
                return {"status": "ok", "message": "File deleted"}

        return {"status": "error", "message": "Invalid file type"}

    def start(self):
        # ... (Unchanged) ...
        pruner_thread = threading.Thread(target=self._prune_dead_nodes, daemon=True)
        pruner_thread.name = "NodePruner"
        pruner_thread.start()
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, self.port))
        server_socket.listen(10)
        logging.info(f"Metadata Server listening on {HOST}:{self.port}")
        while True:
            client_socket, addr = server_socket.accept()
            logging.info(f"Accepted connection from {addr}")
            client_thread = threading.Thread(target=self._handle_client, args=(client_socket,))
            client_thread.name = f"Client-{addr[0]}:{addr[1]}"
            client_thread.start()

if __name__ == "__main__":
    server = MetadataServer()
    server.start()