import streamlit as st
import socket
import json
import os
import hashlib
import time

# Configuration - connect to Docker containers via localhost
# Configuration - connect to Docker containers via localhost
AUTH_HOST = '127.0.0.1'
AUTH_PORT = 8000  # Changed from 7000
METADATA_HOST = '127.0.0.1'
METADATA_PORT = 6000
CHUNK_SIZE = 1024 * 1024


# Initialize session state
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'session_token' not in st.session_state:
    st.session_state.session_token = None
if 'user_email' not in st.session_state:
    st.session_state.user_email = None
if 'user_name' not in st.session_state:
    st.session_state.user_name = None
if 'file_list' not in st.session_state:
    st.session_state.file_list = []

class AuthClient:
    """Client for authentication operations"""
    
    def _send_to_auth(self, command, payload):
        """Send request to auth server"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect((AUTH_HOST, AUTH_PORT))
                request = json.dumps({"command": command, "payload": payload})
                s.sendall(request.encode('utf-8'))
                response = s.recv(4096)
                return json.loads(response.decode('utf-8'))
        except ConnectionRefusedError:
            st.error(f"Cannot connect to auth server at {AUTH_HOST}:{AUTH_PORT}. Is Docker running?")
            return None
        except Exception as e:
            st.error(f"Auth error: {e}")
            return None
    
    def register(self, email, password, name):
        """Register new user"""
        response = self._send_to_auth("REGISTER", {
            "email": email,
            "password": password,
            "name": name
        })
        return response
    
    def login(self, email, password):
        """Login user"""
        response = self._send_to_auth("LOGIN", {
            "email": email,
            "password": password
        })
        return response
    
    def verify(self, session_token):
        """Verify session token"""
        response = self._send_to_auth("VERIFY", {
            "session_token": session_token
        })
        return response
    
    def logout(self, session_token):
        """Logout user"""
        response = self._send_to_auth("LOGOUT", {
            "session_token": session_token
        })
        return response

class DFSClient:
    """Client for distributed file system operations"""
    
    def __init__(self, user_email):

        self.session_token = st.session_state.get("session_token")
    
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
            host = '127.0.0.1'
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(30)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                
                s.connect((host, int(port)))
                s.sendall(request_data)
                
                time.sleep(0.05)
                
                response = s.recv(4096)
                
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
        """Lists all files for the current user"""
        response = self._send_to_metadata("LIST_FILES", {"session_token": self.session_token})
        if response and response.get("status") == "ok":
            return response.get("files", [])
        return []

    def upload(self, file_data, filename):
        """Uploads a file to the distributed storage."""
        file_size = len(file_data)
        
        chunk_hashes = []
        chunk_locations = {}
        
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
                
                response = self._send_to_metadata("GET_WRITE_NODES", {"session_token": self.session_token})
                if not response or response.get("status") != "ok":
                    st.error(f"Could not get write locations for chunk {chunk_index}.")
                    progress_bar.empty()
                    status_text.empty()
                    return False

                nodes = response.get("nodes")
                node_addresses = response.get("node_addresses")
                chunk_locations[chunk_hash] = nodes

                status_text.text(f"Uploading chunk {chunk_index + 1}/{total_chunks} ({len(chunk_data)} bytes)...")
          # Add the session token as the 3rd line
                header = f"STORE\n{chunk_hash}\n{self.session_token}\n{len(chunk_data)}\n\n".encode('utf-8')
                
                success = False
                for address in node_addresses:
                    response_data = self._send_to_storage_node(address, header + chunk_data)
                    if response_data and response_data.startswith(b'OK'):
                        success = True
                        st.success(f"✓ Chunk {chunk_index + 1} uploaded to {address}")
                        break
                
                if not success:
                    st.error(f"Failed to upload chunk {chunk_index} to any node.")
                    progress_bar.empty()
                    status_text.empty()
                    return False
                
                chunk_index += 1
                offset += CHUNK_SIZE
                progress_bar.progress(chunk_index / total_chunks)
            
            status_text.text("Committing file metadata...")
            payload = {
                "filename": filename,
                "chunks": chunk_hashes,
                "chunk_locations": chunk_locations,
                "session_token": self.session_token
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
            response = self._send_to_metadata("GET_FILE_INFO", {
                "filename": filename,
                "session_token": st.session_state.session_token
            })
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
                        host = '127.0.0.1'
                        
                        session_token = st.session_state["session_token"]
                        header = f"RETRIEVE\n{chunk_hash}\n{session_token}\n\n".encode('utf-8')
                        
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(10)
                        s.connect((host, int(port)))
                        
                        s.sendall(header)
                        
                        time.sleep(0.05)
                        
                        response_data = bytearray()
                        separator_found = False
                        
                        while not separator_found:
                            chunk = s.recv(4096)
                            if not chunk:
                                break
                            response_data.extend(chunk)
                            if b'\n\n' in response_data:
                                separator_found = True
                                break
                        
                        if response_data.startswith(b'OK'):
                            separator_index = bytes(response_data).find(b'\n\n')
                            header_bytes = response_data[:separator_index]
                            body_bytes = response_data[separator_index + 2:]
                            
                            header_text = header_bytes.decode('utf-8')
                            header_lines = header_text.split('\n')
                            
                            if len(header_lines) >= 2:
                                content_length = int(header_lines[1])
                                
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
                            break
                            
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
            return None


# Streamlit UI
st.set_page_config(page_title="Distributed File System", page_icon="📁", layout="wide")

# Authentication check
if not st.session_state.logged_in:
    st.title("📁 Distributed File System - Login")
    
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    auth_client = AuthClient()
    
    with tab1:
        st.header("Login")
        
        with st.form("login_form"):
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Login", type="primary")
            
            if submit:
                if not email or not password:
                    st.error("Please enter both email and password")
                else:
                    response = auth_client.login(email, password)
                    if response and response.get("status") == "ok":
                        st.session_state.logged_in = True
                        st.session_state.session_token = response.get("session_token")
                        st.session_state.user_email = response.get("email")
                        st.session_state.user_name = response.get("name")
                        st.success(f"Welcome back, {response.get('name')}!")
                        st.rerun()
                    else:
                        st.error(response.get("message", "Login failed"))
    
    with tab2:
        st.header("Register")
        
        with st.form("register_form"):
            reg_name = st.text_input("Name")
            reg_email = st.text_input("Email")
            reg_password = st.text_input("Password", type="password")
            reg_password_confirm = st.text_input("Confirm Password", type="password")
            submit = st.form_submit_button("Register", type="primary")
            
            if submit:
                if not reg_name or not reg_email or not reg_password:
                    st.error("Please fill all fields")
                elif reg_password != reg_password_confirm:
                    st.error("Passwords do not match")
                elif len(reg_password) < 6:
                    st.error("Password must be at least 6 characters")
                else:
                    response = auth_client.register(reg_email, reg_password, reg_name)
                    if response and response.get("status") == "ok":
                        st.success("Registration successful! Please login.")
                    else:
                        st.error(response.get("message", "Registration failed"))

else:
    # User is logged in
    st.title("📁 Distributed File System")
    
    # Logout button in sidebar
    with st.sidebar:
        st.header(f"👤 {st.session_state.user_name}")
        st.write(f"**Email:** {st.session_state.user_email}")
        
        if st.button("🚪 Logout", type="primary"):
            auth_client = AuthClient()
            auth_client.logout(st.session_state.session_token)
            st.session_state.logged_in = False
            st.session_state.session_token = None
            st.session_state.user_email = None
            st.session_state.user_name = None
            st.session_state.file_list = []
            st.rerun()
        
        st.markdown("---")
        
        # Connection status
        st.markdown("### 🔌 System Status")
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((AUTH_HOST, AUTH_PORT))
                st.success("✅ Auth Server")
        except:
            st.error("❌ Auth Server")
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((METADATA_HOST, METADATA_PORT))
                st.success("✅ Metadata Server")
        except:
            st.error("❌ Metadata Server")
        
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
                    st.success(f"✅ {name}")
            except:
                st.error(f"❌ {name}")
        
        st.markdown("---")
        st.markdown("### ⚙️ Configuration")
        st.write(f"**Auth Server:** `{AUTH_HOST}:{AUTH_PORT}`")
        st.write(f"**Metadata Server:** `{METADATA_HOST}:{METADATA_PORT}`")
        st.write(f"**Chunk Size:** `{CHUNK_SIZE / (1024*1024):.1f} MB`")
    
    st.markdown("---")
    
    # Initialize DFS client with user email
    client = DFSClient(st.session_state.user_email)
    
    # Create tabs
    tab1, tab2, tab3 = st.tabs(["📤 Upload", "📥 Download", "📋 My Files"])
    
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
            st.info("📭 No files uploaded yet. Upload a file first!")
    
    # List Files Tab
    with tab3:
        st.header("My Files")
        
        col1, col2 = st.columns([3, 1])
        
        with col2:
            if st.button("🔄 Refresh", key="refresh_list"):
                st.session_state.file_list = client.list_files()
                st.rerun()
        
        files = client.list_files()
        
        if files:
            st.write(f"**Total files:** {len(files)}")
            st.markdown("---")
            
            for idx, filename in enumerate(files, 1):
                col_a, col_b = st.columns([1, 10])
                with col_a:
                    st.write(f"**{idx}.**")
                with col_b:
                    st.write(f"`{filename}`")
        else:
            st.info("📭 No files stored yet.")
