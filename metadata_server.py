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
        while True:
            time.sleep(HEARTBEAT_TIMEOUT)
            with self.lock:
                now = time.time()
                dead_nodes = [
                    node_id for node_id, info in self.metadata["nodes"].items()
                    if now - info["last_heartbeat"] > HEARTBEAT_TIMEOUT
                ]
                
                if not dead_nodes:
                    continue

                logging.warning(f"Pruning dead nodes: {dead_nodes}")
                for node_id in dead_nodes:
                    del self.metadata["nodes"][node_id]
                    # Remove from all users' chunks
                    for user_data in self.metadata["users"].values():
                        for chunk_id, locations in user_data["chunks"].items():
                            if node_id in locations:
                                locations.remove(node_id)
            self._save_state()

    def _handle_client(self, client_socket):
        try:
            data = client_socket.recv(4096).decode('utf-8')
            request = json.loads(data)
            command = request.get("command")
            payload = request.get("payload")

            handler_map = {
                "REGISTER": self._handle_register,
                "HEARTBEAT": self._handle_heartbeat,
                "LIST_FILES": self._handle_list_files,
                "GET_FILE_INFO": self._handle_get_file_info,
                "PUT_FILE_INFO": self._handle_put_file_info,
                "DELETE_FILE": self._handle_delete_file,
                "GET_WRITE_NODES": self._handle_get_write_nodes,
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
            logging.error(f"An error occurred: {e}")
        finally:
            client_socket.close()

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

    def _handle_list_files(self, payload):
        """List files for a specific user"""
        user_email = payload.get("user_email")
        if not user_email:
            return {"status": "error", "message": "User email required"}
        
        with self.lock:
            self._ensure_user_exists(user_email)
            user_files = list(self.metadata["users"][user_email]["files"].keys())
            return {"status": "ok", "files": user_files}

    def _handle_get_file_info(self, payload):
        """Get file info for a specific user"""
        user_email = payload.get("user_email")
        filename = payload.get("filename")
        
        if not user_email or not filename:
            return {"status": "error", "message": "User email and filename required"}
        
        with self.lock:
            if user_email not in self.metadata["users"]:
                return {"status": "error", "message": "User not found"}
            
            user_data = self.metadata["users"][user_email]
            
            if filename not in user_data["files"]:
                return {"status": "error", "message": "File not found"}
            
            chunk_order = user_data["files"][filename]
            locations = {}
            for chunk_id in chunk_order:
                node_ids = user_data["chunks"].get(chunk_id, [])
                locations[chunk_id] = [
                    self.metadata["nodes"][node_id]["address"]
                    for node_id in node_ids if node_id in self.metadata["nodes"]
                ]
            return {"status": "ok", "chunks": chunk_order, "locations": locations}

    def _handle_put_file_info(self, payload):
        """Store file info for a specific user"""
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

    def _handle_delete_file(self, payload):
        """Delete a file's metadata (and prune chunk metadata not referenced by other files)."""
        user_email = payload.get("user_email")
        filename = payload.get("filename")

        if not user_email or not filename:
            return {"status": "error", "message": "User email and filename required"}

        with self.lock:
            if user_email not in self.metadata["users"]:
                return {"status": "error", "message": "User not found"}

            user_data = self.metadata["users"][user_email]
            if filename not in user_data["files"]:
                return {"status": "error", "message": "File not found"}

            # Remove the file entry and collect chunks to check
            chunks_to_check = user_data["files"].pop(filename)

            # For each chunk, determine if any remaining file references it; if not, remove chunk metadata
            for chunk_id in chunks_to_check:
                still_used = False
                for other_chunks in user_data["files"].values():
                    if chunk_id in other_chunks:
                        still_used = True
                        break
                if not still_used:
                    if chunk_id in user_data["chunks"]:
                        del user_data["chunks"][chunk_id]

        logging.info(f"File '{filename}' deleted for user '{user_email}'.")
        self._save_state()
        return {"status": "ok"}

    def _handle_get_write_nodes(self, payload):
        with self.lock:
            active_nodes = list(self.metadata["nodes"].keys())
            if len(active_nodes) < REPLICATION_FACTOR:
                return {"status": "error", "message": "Not enough active nodes for replication."}
            
            chosen_nodes = sample(active_nodes, REPLICATION_FACTOR)
            node_addresses = [self.metadata["nodes"][nid]["address"] for nid in chosen_nodes]
        
        return {"status": "ok", "nodes": chosen_nodes, "node_addresses": node_addresses}

    def start(self):
        pruner_thread = threading.Thread(target=self._prune_dead_nodes, daemon=True)
        pruner_thread.name = "NodePruner"
        pruner_thread.start()

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', self.port))
        server_socket.listen(10)
        logging.info(f"Metadata Server listening on '0.0.0.0':{self.port}")

        while True:
            client_socket, addr = server_socket.accept()
            logging.info(f"Accepted connection from {addr}")
            client_thread = threading.Thread(target=self._handle_client, args=(client_socket,))
            client_thread.name = f"Client-{addr[0]}:{addr[1]}"
            client_thread.start()

if __name__ == "__main__":
    server = MetadataServer()
    server.start()
