import socket
import threading
import os
import json
import time
import logging
import argparse

# ... (Configuration is the same) ...
STORAGE_DIR = 'storage' 
METADATA_SERVER_HOST = os.getenv('METADATA_HOST', '127.0.0.1')
METADATA_SERVER_PORT = 6000
HEARTBEAT_INTERVAL = 10

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(threadName)s - %(message)s')

class StorageNode:
    def __init__(self, node_id, host, port):
        # ... (unchanged) ...
        self.node_id = node_id
        self.host = host
        self.port = port
        self.address = f"{self.node_id}:{self.port}"
        self.storage_path = os.path.join(STORAGE_DIR, self.node_id)
        if not os.path.exists(self.storage_path):
            os.makedirs(self.storage_path)
            logging.info(f"Created storage directory at {self.storage_path}")

    def _send_to_metadata(self, command, payload):
        # ... (unchanged) ...
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((METADATA_SERVER_HOST, METADATA_SERVER_PORT))
                request = json.dumps({"command": command, "payload": payload})
                s.sendall(request.encode('utf-8'))
                response = s.recv(1024)
                return json.loads(response.decode('utf-8'))
        except (ConnectionRefusedError, ConnectionResetError) as e:
            logging.error(f"Could not connect to Metadata Server: {e}")
            return None
        except Exception as e:
            logging.error(f"An error occurred while communicating with Metadata Server: {e}")
            return None

    # --- NEW HELPER METHOD ---
    def _verify_action_with_metadata(self, session_token, action, chunk_id):
        """Asks the metadata server for permission to perform an action."""
        if not session_token:
            return False, "No session token provided"
            
        payload = {
            "session_token": session_token,
            "action": action,
            "chunk_id": chunk_id
        }
        response = self._send_to_metadata("VERIFY_ACTION", payload)
        
        if response and response.get("status") == "ok":
            return True, "Authorized"
        else:
            msg = response.get("message", "Authorization failed") if response else "Connection error"
            return False, msg

    def _start_heartbeat(self):
        # ... (unchanged) ...
        payload = {"node_id": self.node_id, "address": self.address}
        if self._send_to_metadata("REGISTER", payload):
            logging.info(f"Node '{self.node_id}' registered successfully.")
        else:
            logging.error("Failed to register. Will retry with heartbeats.")
        while True:
            time.sleep(HEARTBEAT_INTERVAL)
            payload = {"node_id": self.node_id}
            if self._send_to_metadata("HEARTBEAT", payload):
                logging.info("Sent heartbeat successfully.")
            else:
                logging.warning("Failed to send heartbeat.")

    # --- UPDATED HANDLER ---
    def _handle_client(self, client_socket):
        """Handles a client connection, now with authorization."""
        try:
            logging.info("=== New client request ===")
            
            all_data = bytearray()
            separator = b'\n\n'
            header = None
            
            # 1. Receive the header
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    logging.error("Connection closed before header received")
                    return
                all_data.extend(chunk)
                if separator in all_data:
                    header_bytes, all_data = all_data.split(separator, 1)
                    header = header_bytes.decode('utf-8')
                    break
            
            # 2. Parse the header
            # Protocol: COMMAND\n<chunk_id>\n<session_token>\n[CONTENT_LENGTH]\n\n<data>
            header_lines = header.strip().split('\n')
            if len(header_lines) < 3:
                logging.error(f"Invalid header format: {header_lines}")
                client_socket.sendall(b"ERROR\nInvalid header format")
                return

            command = header_lines[0].strip()
            chunk_id = header_lines[1].strip()
            session_token = header_lines[2].strip()
            
            logging.info(f"Command: {command}, Chunk ID: {chunk_id}")

            # 3. Authorize the action with the Metadata Server
            is_authorized, message = self._verify_action_with_metadata(session_token, command, chunk_id)
            
            if not is_authorized:
                logging.warning(f"Authorization failed for {command} on {chunk_id}: {message}")
                client_socket.sendall(f"ERROR\n{message}".encode('utf-8'))
                return

            # 4. Proceed with action if authorized
            logging.info(f"Authorization successful for {command}")
            chunk_path = os.path.join(self.storage_path, chunk_id)

            if command == "STORE":
                if len(header_lines) < 4:
                    logging.error(f"STORE command missing content length")
                    client_socket.sendall(b"ERROR\nMissing content length")
                    return
                
                content_length = int(header_lines[3].strip())
                logging.info(f"Storing chunk '{chunk_id}' with size {content_length} bytes")
                
                # Receive the rest of the data
                while len(all_data) < content_length:
                    chunk = client_socket.recv(8192)
                    if not chunk:
                        logging.warning(f"Connection closed. Received {len(all_data)}/{content_length} bytes")
                        break
                    all_data.extend(chunk)
                
                # Write to file
                if len(all_data) >= content_length:
                    with open(chunk_path, 'wb') as f:
                        f.write(all_data[:content_length])
                    logging.info(f"✓ Successfully stored chunk '{chunk_id}'")
                    client_socket.sendall(b"OK")
                else:
                    logging.error(f"Incomplete data: received {len(all_data)}, expected {content_length}")
                    client_socket.sendall(b"ERROR\nIncomplete data")

            elif command == "RETRIEVE":
                logging.info(f"RETRIEVE request for chunk '{chunk_id}'")
                if os.path.exists(chunk_path):
                    with open(chunk_path, 'rb') as f:
                        chunk_data = f.read()
                    
                    header_response = f"OK\n{len(chunk_data)}\n\n".encode('utf-8')
                    client_socket.sendall(header_response + chunk_data)
                    logging.info(f"✓ Sent chunk '{chunk_id}' ({len(chunk_data)} bytes)")
                else:
                    client_socket.sendall(b"ERROR\nChunk not found")
                    logging.warning(f"Chunk '{chunk_id}' not found")
            
        except Exception as e:
            logging.error(f"Error handling client: {type(e).__name__}: {e}", exc_info=True)
        finally:
            client_socket.close()
            logging.info("=== Client connection closed ===\n")

    def start(self):
        # ... (unchanged) ...
        heartbeat_thread = threading.Thread(target=self._start_heartbeat, daemon=True)
        heartbeat_thread.name = f"Heartbeat-{self.node_id}"
        heartbeat_thread.start()
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(10)
        logging.info(f"Storage Node '{self.node_id}' listening on {self.host}:{self.port}")
        while True:
            client_socket, addr = server_socket.accept()
            logging.info(f"Accepted connection from client {addr}")
            client_thread = threading.Thread(target=self._handle_client, args=(client_socket,))
            client_thread.setName(f"ClientHandler-{addr[0]}:{addr[1]}")
            client_thread.start()

if __name__ == "__main__":
    # ... (unchanged) ...
    parser = argparse.ArgumentParser(description="Run a distributed storage node.")
    parser.add_argument("node_id", type=str, help="Unique ID and hostname for this node (e.g., 'storage-node-1')")
    parser.add_argument("port", type=int, help="Port for this node to listen on (e.g., 5001)")
    args = parser.parse_args()
    node = StorageNode(node_id=args.node_id, host='0.0.0.0', port=args.port)
    node.start()