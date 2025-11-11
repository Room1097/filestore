import socket
import threading
import os
import json
import time
import logging
import argparse

STORAGE_DIR = 'storage' 
METADATA_SERVER_HOST = os.getenv('METADATA_HOST', '127.0.0.1')
METADATA_SERVER_PORT = 6000
HEARTBEAT_INTERVAL = 10 

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(threadName)s - %(message)s')

class StorageNode:
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
        """Handles a client connection for storing or retrieving a chunk."""
        try:
            request_lines = client_socket.recv(1024).decode('utf-8').split('\n', 2)
            command = request_lines[0]
            chunk_id = request_lines[1]
            chunk_path = os.path.join(self.storage_path, chunk_id)

            if command == "STORE":
                content_length_str = request_lines[2].split('\n', 1)[0]
                content_length = int(content_length_str)
                
                initial_data = request_lines[2].split('\n\n', 1)[1].encode('utf-8')

                with open(chunk_path, 'wb') as f:
                    f.write(initial_data)
                    bytes_received = len(initial_data)
                    while bytes_received < content_length:
                        data = client_socket.recv(4096)
                        if not data: break
                        f.write(data)
                        bytes_received += len(data)
                
                logging.info(f"Stored chunk '{chunk_id}' at {chunk_path}")
                client_socket.sendall(b"OK")

            elif command == "RETRIEVE":
                if os.path.exists(chunk_path):
                    with open(chunk_path, 'rb') as f:
                        chunk_data = f.read()
                    
                    header = f"OK\n{len(chunk_data)}\n\n".encode('utf-8')
                    client_socket.sendall(header + chunk_data)
                    logging.info(f"Sent chunk '{chunk_id}' to client.")
                else:
                    client_socket.sendall(b"ERROR\nChunk not found")
                    logging.warning(f"Client requested non-existent chunk '{chunk_id}'")
            
        except Exception as e:
            logging.error(f"Error handling client: {e}")
        finally:
            client_socket.close()

    def start(self):
        """Starts the node's main listening loop and background tasks."""
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
    parser = argparse.ArgumentParser(description="Run a distributed storage node.")
    parser.add_argument("node_id", type=str, help="Unique ID and hostname for this node (e.g., 'storage-node-1')")
    parser.add_argument("port", type=int, help="Port for this node to listen on (e.g., 5001)")
    args = parser.parse_args()

    node = StorageNode(node_id=args.node_id, host='0.0.0.0', port=args.port)
    node.start()