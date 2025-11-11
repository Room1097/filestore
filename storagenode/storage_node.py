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
            logging.info("=== New client request ===")
            
            # Receive data in chunks to build the complete request
            all_data = bytearray()
            separator = b'\n\n'
            separator_found = False
            header = None
            content_length = 0
            
            # First, receive until we find the header separator
            while not separator_found:
                chunk = client_socket.recv(4096)
                if not chunk:
                    logging.error("Connection closed before header received")
                    return
                
                all_data.extend(chunk)
                
                # Check if we have the separator
                separator_index = bytes(all_data).find(separator)
                if separator_index != -1:
                    separator_found = True
                    
                    # Extract header
                    header_bytes = bytes(all_data[:separator_index])
                    try:
                        header = header_bytes.decode('utf-8')
                        logging.info(f"Header received: {header[:100]}")  # Log first 100 chars
                    except UnicodeDecodeError as e:
                        logging.error(f"Failed to decode header: {e}")
                        client_socket.sendall(b"ERROR\nInvalid header encoding")
                        return
                    
                    # Remove header and separator from all_data
                    all_data = all_data[separator_index + len(separator):]
                    break
            
            # Parse header
            header_lines = header.strip().split('\n')
            if len(header_lines) < 2:
                logging.error(f"Invalid header format: {header_lines}")
                client_socket.sendall(b"ERROR\nInvalid header format")
                return
            
            command = header_lines[0].strip()
            chunk_id = header_lines[1].strip()
            
            logging.info(f"Command: {command}, Chunk ID: {chunk_id}")
            
            if command == "STORE":
                if len(header_lines) < 3:
                    logging.error(f"STORE command missing content length")
                    client_socket.sendall(b"ERROR\nMissing content length")
                    return
                
                content_length = int(header_lines[2].strip())
                chunk_path = os.path.join(self.storage_path, chunk_id)
                
                logging.info(f"Storing chunk '{chunk_id}' with size {content_length} bytes")
                logging.info(f"Already received: {len(all_data)} bytes")
                
                # Continue receiving until we have all the data
                while len(all_data) < content_length:
                    remaining = content_length - len(all_data)
                    chunk_size = min(8192, remaining)
                    chunk = client_socket.recv(chunk_size)
                    
                    if not chunk:
                        logging.warning(f"Connection closed. Received {len(all_data)}/{content_length} bytes")
                        break
                    
                    all_data.extend(chunk)
                    
                    if len(all_data) % 50000 == 0:  # Log every 50KB
                        logging.info(f"Progress: {len(all_data)}/{content_length} bytes")
                
                # Write to file
                if len(all_data) == content_length:
                    with open(chunk_path, 'wb') as f:
                        f.write(all_data[:content_length])
                    
                    logging.info(f"✓ Successfully stored chunk '{chunk_id}' ({len(all_data)} bytes)")
                    client_socket.sendall(b"OK")
                else:
                    logging.error(f"Incomplete data: received {len(all_data)}, expected {content_length}")
                    client_socket.sendall(b"ERROR\nIncomplete data")

            elif command == "RETRIEVE":
                chunk_path = os.path.join(self.storage_path, chunk_id)
                
                logging.info(f"RETRIEVE request for chunk '{chunk_id}'")
                
                if os.path.exists(chunk_path):
                    with open(chunk_path, 'rb') as f:
                        chunk_data = f.read()
                    
                    # Send response with proper format
                    header_response = f"OK\n{len(chunk_data)}\n\n".encode('utf-8')
                    
                    # Send header first
                    client_socket.sendall(header_response)
                    
                    # Then send data in chunks to avoid buffer issues
                    bytes_sent = 0
                    chunk_size = 8192
                    while bytes_sent < len(chunk_data):
                        end = min(bytes_sent + chunk_size, len(chunk_data))
                        client_socket.sendall(chunk_data[bytes_sent:end])
                        bytes_sent = end
                    
                    logging.info(f"✓ Sent chunk '{chunk_id}' ({len(chunk_data)} bytes)")
                else:
                    client_socket.sendall(b"ERROR\nChunk not found")
                    logging.warning(f"Chunk '{chunk_id}' not found at {chunk_path}")

                        
            else:
                logging.error(f"Unknown command: {command}")
                client_socket.sendall(b"ERROR\nUnknown command")
            
        except Exception as e:
            logging.error(f"Error handling client: {type(e).__name__}: {e}", exc_info=True)
            try:
                client_socket.sendall(b"ERROR\nServer error")
            except:
                pass
        finally:
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
            except:
                pass
            client_socket.close()
            logging.info("=== Client connection closed ===\n")

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
