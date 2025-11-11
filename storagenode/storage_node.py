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
    # ... __init__, _send_to_metadata, _start_heartbeat ...
    # (These methods are unchanged from your last version)
    
    def __init__(self, node_id, host, port):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.address = f"{self.node_id}:{self.port}"
        self.storage_path = os.path.join(STORAGE_DIR, self.node_id)
        
        if not os.path.exists(self.storage_path):
            os.makedirs(self.storage_path)
            logging.info(f"Created storage directory at {self.storage_path}")

    def _send_to_metadata(self, command, payload):
        """Helper function to send commands to the Metadata Server."""
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
            
    def _start_heartbeat(self):
        """Registers with the metadata server and sends periodic heartbeats."""
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

    def _handle_client(self, client_socket):
        """MODIFIED: Handles raw data (STORE/RETRIEVE) and JSON commands (DELETE_CHUNK)."""
        try:
            logging.info("=== New client request ===")
            
            # Read the first chunk of data to sniff its type
            initial_data_bytes = client_socket.recv(4096)
            if not initial_data_bytes:
                return

            try:
                # Try to parse as JSON (for DELETE_CHUNK command)
                request_str = initial_data_bytes.decode('utf-8')
                request = json.loads(request_str)
                command = request.get("command")
                
                if command == "DELETE_CHUNK":
                    chunk_id = request.get("payload", {}).get("chunk_id")
                    if chunk_id:
                        chunk_path = os.path.join(self.storage_path, chunk_id)
                        if os.path.exists(chunk_path):
                            os.remove(chunk_path)
                            logging.info(f"Deleted chunk '{chunk_id}'")
                            client_socket.sendall(b"OK")
                        else:
                            logging.warning(f"Request to delete non-existent chunk '{chunk_id}'")
                            client_socket.sendall(b"OK") # Still OK, item is gone
                    else:
                        client_socket.sendall(b"ERROR\nMissing chunk_id")
                else:
                    client_socket.sendall(b"ERROR\nUnknown JSON command")

            except (json.JSONDecodeError, UnicodeDecodeError):
                # Failed to parse as JSON, assume raw data protocol (STORE/RETRIEVE)
                self._handle_raw_data(initial_data_bytes, client_socket)

        except Exception as e:
            logging.error(f"Error handling client: {type(e).__name__}: {e}", exc_info=True)
        finally:
            client_socket.close()
            logging.info("=== Client connection closed ===\n")

    def _handle_raw_data(self, initial_data, client_socket):
        """Handles STORE and RETRIEVE commands from the client."""
        try:
            all_data = bytearray(initial_data)
            separator = b'\n\n'
            header = None
            
            # 1. Receive the header
            while separator not in all_data:
                chunk = client_socket.recv(4096)
                if not chunk:
                    logging.error("Connection closed before header received")
                    return
                all_data.extend(chunk)

            header_bytes, all_data = all_data.split(separator, 1)
            header = header_bytes.decode('utf-8')

            # 2. Parse the (INSECURE) header
            # Protocol: COMMAND\n<chunk_id>\n[CONTENT_LENGTH]\n\n<data>
            header_lines = header.strip().split('\n')
            if len(header_lines) < 2:
                logging.error(f"Invalid header format: {header_lines}")
                client_socket.sendall(b"ERROR\nInvalid header format")
                return

            command = header_lines[0].strip()
            chunk_id = header_lines[1].strip()
            chunk_path = os.path.join(self.storage_path, chunk_id)
            
            if command == "STORE":
                if len(header_lines) < 3:
                    client_socket.sendall(b"ERROR\nMissing content length")
                    return
                
                content_length = int(header_lines[2].strip())
                
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
                    client_socket.sendall(b"ERROR\nIncomplete data")

            elif command == "RETRIEVE":
                if os.path.exists(chunk_path):
                    with open(chunk_path, 'rb') as f:
                        chunk_data = f.read()
                    
                    header_response = f"OK\n{len(chunk_data)}\n\n".encode('utf-8')
                    client_socket.sendall(header_response + chunk_data)
                    logging.info(f"✓ Sent chunk '{chunk_id}'")
                else:
                    client_socket.sendall(b"ERROR\nChunk not found")

        except Exception as e:
            logging.error(f"Error in _handle_raw_data: {e}", exc_info=True)


    def start(self):
        # ... (Unchanged) ...
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
    # ... (Unchanged) ...
    parser = argparse.ArgumentParser(description="Run a distributed storage node.")
    parser.add_argument("node_id", type=str, help="Unique ID and hostname for this node (e.g., 'storage-node-1')")
    parser.add_argument("port", type=int, help="Port for this node to listen on (e.g., 5001)")
    args = parser.parse_args()
    node = StorageNode(node_id=args.node_id, host='0.0.0.0', port=args.port)
    node.start()