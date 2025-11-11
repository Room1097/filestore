import streamlit as st
import socket
import json
import os
import hashlib
import time

# Configuration - connect to Docker containers via localhost
METADATA_HOST = '127.0.0.1'
METADATA_PORT = 6000
CHUNK_SIZE = 1024 * 1024

# Initialize session state for file list
if 'file_list' not in st.session_state:
    st.session_state.file_list = []

class DFSClient:
    """Refactored client with all socket operations"""
    
    def _send_to_metadata(self, command, payload):
        """Helper to send JSON commands to the Metadata Server."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect((METADATA_HOST, METADATA_PORT))
                request = json.dumps({"command": command, "payload": payload})
                s.sendall(request.encode('utf-8'))
                response = s.recv(4096)
                return json.loads(response.decode('utf-8'))
        except ConnectionRefusedError:
            st.error(f"Cannot connect to metadata server at {METADATA_HOST}:{METADATA_PORT}. Is Docker running?")
            return None
        except socket.timeout:
            st.error("Metadata server connection timed out")
            return None
        except Exception as e:
            st.error(f"Error communicating with metadata server: {e}")
            return None

    def _send_to_storage_node(self, address, request_data):
        """Helper to send raw data to a Storage Node."""
        host = None
        port = None
        try:
            host, port = address.split(':')
            # Always use localhost when running outside Docker
            host = '127.0.0.1'
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(30)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                
                s.connect((host, int(port)))
                s.sendall(request_data)
                
                # Small delay to let server process
                time.sleep(0.05)
                
                response = s.recv(4096)
                
                # Properly shutdown
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                
                return response
                
        except ConnectionRefusedError:
            st.error(f"Storage node {host}:{port} refused connection. Is the container running?")
            return None
        except ConnectionResetError:
            st.error(f"Storage node {host}:{port} reset the connection")
            return None
        except socket.timeout:
            st.error(f"Storage node {host}:{port} timed out")
            return None
        except Exception as e:
            st.error(f"Error with storage node {host}:{port} - {type(e).__name__}: {e}")
            return None
    
    def list_files(self):
        """Lists all files in the distributed file system."""
        response = self._send_to_metadata("LIST_FILES", {})
        if response and response.get("status") == "ok":
            return response.get("files", [])
        return []

    def upload(self, file_data, filename):
        """Uploads a file to the distributed storage."""
        file_size = len(file_data)
        
        chunk_hashes = []
        chunk_locations = {}
        
        # Progress tracking
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        offset = 0
        chunk_index = 0
        total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
        
        try:
            while offset < file_size:
                chunk_data = file_data[offset:offset + CHUNK_SIZE]
                
                chunk_hash = hashlib.sha256(chunk_data).hexdigest()
                chunk_hashes.append(chunk_hash)
                
                # Get write nodes
                response = self._send_to_metadata("GET_WRITE_NODES", {})
                if not response or response.get("status") != "ok":
                    st.error(f"Could not get write locations for chunk {chunk_index}.")
                    progress_bar.empty()
                    status_text.empty()
                    return False

                nodes = response.get("nodes")
                node_addresses = response.get("node_addresses")
                chunk_locations[chunk_hash] = nodes

                # Upload chunk to storage nodes
                status_text.text(f"Uploading chunk {chunk_index + 1}/{total_chunks} ({len(chunk_data)} bytes)...")
                header = f"STORE\n{chunk_hash}\n{len(chunk_data)}\n\n".encode('utf-8')
                
                success = False
                for address in node_addresses:
                    response_data = self._send_to_storage_node(address, header + chunk_data)
                    if response_data and response_data.startswith(b'OK'):
                        success = True
                        st.success(f"✓ Chunk {chunk_index + 1} uploaded to {address}")
                        break  # Successfully uploaded to one node
                
                if not success:
                    st.error(f"Failed to upload chunk {chunk_index} to any node.")
                    progress_bar.empty()
                    status_text.empty()
                    return False
                
                chunk_index += 1
                offset += CHUNK_SIZE
                progress_bar.progress(chunk_index / total_chunks)
            
            # Commit file metadata
            status_text.text("Committing file metadata...")
            payload = {
                "filename": filename,
                "chunks": chunk_hashes,
                "chunk_locations": chunk_locations
            }
            response = self._send_to_metadata("PUT_FILE_INFO", payload)
            
            progress_bar.empty()
            status_text.empty()
            
            if response and response.get("status") == "ok":
                return True
            else:
                st.error(f"Failed to commit metadata: {response.get('message', 'Unknown error')}")
                return False
                
        except Exception as e:
            st.error(f"Upload error: {type(e).__name__}: {e}")
            progress_bar.empty()
            status_text.empty()
            return False

    def download(self, filename):
        """Downloads a file from the distributed storage."""
        try:
            response = self._send_to_metadata("GET_FILE_INFO", {"filename": filename})
            if not response or response.get("status") != "ok":
                st.error(f"Could not get file info for '{filename}'. {response.get('message', '')}")
                return None

            chunk_order = response.get("chunks")
            locations = response.get("locations")
            
            file_data = bytearray()
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            for i, chunk_hash in enumerate(chunk_order):
                status_text.text(f"Downloading chunk {i + 1}/{len(chunk_order)}...")
                chunk_addresses = locations.get(chunk_hash, [])
                
                if not chunk_addresses:
                    st.error(f"No locations found for chunk {chunk_hash}.")
                    progress_bar.empty()
                    status_text.empty()
                    return None
                
                chunk_data = None
                for address in chunk_addresses:
                    try:
                        host, port = address.split(':')
                        host = '127.0.0.1'  # Use localhost when running outside Docker
                        
                        # Create RETRIEVE request
                        header = f"RETRIEVE\n{chunk_hash}\n\n".encode('utf-8')
                        
                        # Connect and send request
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(10)
                        s.connect((host, int(port)))
                        
                        # Send the RETRIEVE request
                        s.sendall(header)
                        
                        # Small delay to let server process
                        time.sleep(0.05)
                        
                        # Receive response
                        response_data = bytearray()
                        separator_found = False
                        
                        # Read until we find header separator
                        while not separator_found:
                            chunk = s.recv(4096)
                            if not chunk:
                                break
                            response_data.extend(chunk)
                            if b'\n\n' in response_data:
                                separator_found = True
                                break
                        
                        # Parse response
                        if response_data.startswith(b'OK'):
                            separator_index = bytes(response_data).find(b'\n\n')
                            header_bytes = response_data[:separator_index]
                            body_bytes = response_data[separator_index + 2:]
                            
                            # Parse header to get content length
                            header_text = header_bytes.decode('utf-8')
                            header_lines = header_text.split('\n')
                            
                            if len(header_lines) >= 2:
                                content_length = int(header_lines[1])
                                
                                # Collect remaining data
                                while len(body_bytes) < content_length:
                                    remaining = content_length - len(body_bytes)
                                    chunk = s.recv(min(8192, remaining))
                                    if not chunk:
                                        break
                                    body_bytes.extend(chunk)
                                
                                if len(body_bytes) == content_length:
                                    chunk_data = bytes(body_bytes)
                                    st.success(f"✓ Downloaded chunk {i + 1} from {address}")
                        
                        s.close()
                        
                        if chunk_data:
                            break  # Successfully got the chunk
                            
                    except socket.timeout:
                        st.warning(f"⏱ Timeout downloading from {address}, trying next replica...")
                        try:
                            s.close()
                        except:
                            pass
                        continue
                    except Exception as e:
                        st.warning(f"⚠ Error with {address}: {type(e).__name__}: {e}")
                        try:
                            s.close()
                        except:
                            pass
                        continue
                
                if chunk_data:
                    file_data.extend(chunk_data)
                else:
                    st.error(f"Failed to download chunk {chunk_hash} from any replica.")
                    progress_bar.empty()
                    status_text.empty()
                    return None
                
                progress_bar.progress((i + 1) / len(chunk_order))
            
            progress_bar.empty()
            status_text.empty()
            
            return bytes(file_data)
            
        except Exception as e:
            st.error(f"Download error: {type(e).__name__}: {e}")
            import traceback
            st.error(traceback.format_exc())
            return None


# Streamlit UI
st.set_page_config(page_title="Distributed File System", page_icon="📁", layout="wide")

st.title("📁 Distributed File System")
st.markdown("---")

# Initialize client
client = DFSClient()

# Create tabs for different operations
tab1, tab2, tab3 = st.tabs(["📤 Upload", "📥 Download", "📋 List Files"])

# Upload Tab
with tab1:
    st.header("Upload File")
    
    uploaded_file = st.file_uploader("Choose a file to upload", type=None)
    
    if uploaded_file is not None:
        col1, col2 = st.columns(2)
        with col1:
            st.write(f"**Filename:** {uploaded_file.name}")
        with col2:
            st.write(f"**Size:** {uploaded_file.size:,} bytes")
        
        st.write(f"**Chunks:** {(uploaded_file.size + CHUNK_SIZE - 1) // CHUNK_SIZE}")
        
        if st.button("Upload to DFS", type="primary", key="upload_btn"):
            with st.spinner("Uploading..."):
                file_data = uploaded_file.read()
                success = client.upload(file_data, uploaded_file.name)
                
                if success:
                    st.success(f"✅ '{uploaded_file.name}' uploaded successfully!")
                    st.balloons()
                    # Refresh file list
                    st.session_state.file_list = client.list_files()
                else:
                    st.error("❌ Upload failed. Check the error messages above.")

# Download Tab
with tab2:
    st.header("Download File")
    
    col1, col2 = st.columns([3, 1])
    
    with col2:
        if st.button("🔄 Refresh List", key="refresh_download"):
            st.session_state.file_list = client.list_files()
            st.rerun()
    
    if not st.session_state.file_list:
        st.session_state.file_list = client.list_files()
    
    if st.session_state.file_list:
        with col1:
            selected_file = st.selectbox(
                "Select a file to download", 
                st.session_state.file_list,
                key="file_selector"
            )
        
        if st.button("Download File", type="primary", key="download_btn"):
            with st.spinner(f"Downloading {selected_file}..."):
                file_data = client.download(selected_file)
                
                if file_data:
                    st.success(f"✅ '{selected_file}' downloaded successfully! ({len(file_data):,} bytes)")
                    st.download_button(
                        label="💾 Save File to Computer",
                        data=file_data,
                        file_name=selected_file,
                        mime="application/octet-stream",
                        key="save_btn"
                    )
    else:
        st.info("📭 No files available in the DFS. Upload a file first!")

# List Files Tab
with tab3:
    st.header("Available Files")
    
    col1, col2 = st.columns([3, 1])
    
    with col2:
        if st.button("🔄 Refresh", key="refresh_list"):
            st.session_state.file_list = client.list_files()
            st.rerun()
    
    files = client.list_files()
    
    if files:
        st.write(f"**Total files:** {len(files)}")
        st.markdown("---")
        
        # Create a nice table view
        for idx, filename in enumerate(files, 1):
            col_a, col_b = st.columns([1, 10])
            with col_a:
                st.write(f"**{idx}.**")
            with col_b:
                st.write(f"`{filename}`")
    else:
        st.info("📭 No files stored in the DFS yet.")

# Sidebar with system info
with st.sidebar:
    st.header("⚙️ System Info")
    
    # Connection status indicator
    st.markdown("### 🔌 Connection Status")
    
    # Check metadata server
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((METADATA_HOST, METADATA_PORT))
            st.success("✅ Metadata Server: Connected")
    except:
        st.error("❌ Metadata Server: Disconnected")
    
    # Check storage nodes
    storage_nodes = [
        ("Storage Node 1", 5001),
        ("Storage Node 2", 5002),
        ("Storage Node 3", 5003)
    ]
    
    for name, port in storage_nodes:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((METADATA_HOST, port))
                st.success(f"✅ {name}: Connected")
        except:
            st.error(f"❌ {name}: Disconnected")
    
    st.markdown("---")
    st.markdown("### ⚙️ Configuration")
    st.write(f"**Metadata Server:** `{METADATA_HOST}:{METADATA_PORT}`")
    st.write(f"**Chunk Size:** `{CHUNK_SIZE / (1024*1024):.1f} MB`")
    
    st.markdown("---")
    st.markdown("### 📖 Instructions")
    st.markdown("""
    1. **Upload**: Select a file and click upload
    2. **Download**: Choose from available files
    3. **List**: View all stored files
    
    **Note:** Make sure Docker containers are running:
    ```
    docker-compose up -d
    ```
    """)
    
    st.markdown("---")
    st.markdown("### 🐛 Debug")
    if st.button("Clear File List Cache"):
        st.session_state.file_list = []
        st.success("Cache cleared!")
        st.rerun()
