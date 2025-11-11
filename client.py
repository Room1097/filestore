import socket
import json
import os
import argparse
import hashlib


METADATA_HOST = '127.0.0.1'
METADATA_PORT = 6000
CHUNK_SIZE = 1024 * 1024 

class Client:
    def _send_to_metadata(self, command, payload):
        """Helper to send JSON commands to the Metadata Server."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((METADATA_HOST, METADATA_PORT))
                request = json.dumps({"command": command, "payload": payload})
                s.sendall(request.encode('utf-8'))
                response = s.recv(4096)
                return json.loads(response.decode('utf-8'))
        except Exception as e:
            print(f"Error communicating with metadata server: {e}")
            return None

    def _send_to_storage_node(self, address, request_data):
        """Helper to send raw data to a Storage Node."""
        try:
            
            host, port = address.split(':')
            host = '127.0.0.1' 
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, int(port)))
                s.sendall(request_data)
                response = s.recv(4096) # Wait for a response
                return response
        except Exception as e:
            print(f"Error communicating with storage node {address}: {e}")
            return None
    
    def list_files(self):
        """Lists all files in the distributed file system."""
        response = self._send_to_metadata("LIST_FILES", {})
        if response and response.get("status") == "ok":
            print("Available files:")
            for filename in response.get("files", []):
                print(f"- {filename}")
        else:
            print("Could not retrieve file list.")

    def upload(self, file_path):
        """Uploads a file to the distributed storage."""
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found.")
            return

        filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        print(f"Starting upload for '{filename}' ({file_size} bytes)")

        chunk_hashes = []
        chunk_locations = {}

        with open(file_path, 'rb') as f:
            chunk_index = 0
            while True:
                chunk_data = f.read(CHUNK_SIZE)
                if not chunk_data:
                    break

                chunk_hash = hashlib.sha256(chunk_data).hexdigest()
                chunk_hashes.append(chunk_hash)
                
                
                response = self._send_to_metadata("GET_WRITE_NODES", {})
                if not response or response.get("status") != "ok":
                    print(f"Error: Could not get write locations for chunk {chunk_index}.")
                    return

                nodes = response.get("nodes")
                node_addresses = response.get("node_addresses")
                chunk_locations[chunk_hash] = nodes

                
                print(f"  Uploading chunk {chunk_index+1} ({len(chunk_data)} bytes) to {nodes}...")
                header = f"STORE\n{chunk_hash}\n{len(chunk_data)}\n\n".encode('utf-8')
                
                success = False
                for address in node_addresses:
                    if self._send_to_storage_node(address, header + chunk_data) == b'OK':
                        success = True
                
                if not success:
                    print(f"Error: Failed to upload chunk {chunk_index} to any node.")
                    return
                chunk_index += 1
        
        
        payload = {
            "filename": filename,
            "chunks": chunk_hashes,
            "chunk_locations": chunk_locations
        }
        response = self._send_to_metadata("PUT_FILE_INFO", payload)
        if response and response.get("status") == "ok":
            print(f"Upload of '{filename}' complete!")
        else:
            print(f"Error: Failed to commit file metadata for '{filename}'.")

    def download(self, filename, output_path):
        """Downloads a file from the distributed storage."""
        print(f"Starting download for '{filename}'...")
        
        
        response = self._send_to_metadata("GET_FILE_INFO", {"filename": filename})
        if not response or response.get("status") != "ok":
            print(f"Error: Could not get file info for '{filename}'. Message: {response.get('message')}")
            return

        chunk_order = response.get("chunks")
        locations = response.get("locations")
        
        with open(output_path, 'wb') as f:
            for i, chunk_hash in enumerate(chunk_order):
                print(f"  Downloading chunk {i+1}/{len(chunk_order)}...")
                chunk_addresses = locations.get(chunk_hash, [])
                if not chunk_addresses:
                    print(f"Error: No locations found for chunk {chunk_hash}. File is corrupt or nodes are down.")
                    return
                
                chunk_data = None
                for address in chunk_addresses:
                    header = f"RETRIEVE\n{chunk_hash}\n".encode('utf-8')
                    raw_response = self._send_to_storage_node(address, header)
                    
                    if raw_response and raw_response.startswith(b'OK'):
                        parts = raw_response.split(b'\n\n', 1)
                        chunk_data = parts[1]
                        break 
                
                if chunk_data:
                    f.write(chunk_data)
                else:
                    print(f"Error: Failed to download chunk {chunk_hash} from any replica.")
                    os.remove(output_path) 
                    return
        
        print(f"Download complete! File saved to '{output_path}'.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Client for the Distributed File System.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    upload_parser = subparsers.add_parser("upload", help="Upload a file.")
    upload_parser.add_argument("filepath", type=str, help="The local path to the file to upload.")

    download_parser = subparsers.add_parser("download", help="Download a file.")
    download_parser.add_argument("filename", type=str, help="The name of the file on the DFS.")
    download_parser.add_argument("output", type=str, help="The local path to save the downloaded file.")

    list_parser = subparsers.add_parser("list", help="List all files.")

    args = parser.parse_args()
    client = Client()

    if args.command == "upload":
        client.upload(args.filepath)
    elif args.command == "download":
        client.download(args.filename, args.output)
    elif args.command == "list":
        client.list_files()