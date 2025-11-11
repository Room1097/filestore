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
CHUNK_SIZE = 1024 * 2048

# -----------------------------
# Streamlit Page Setup & Styling
# -----------------------------
st.set_page_config(page_title="Distributed File System", layout="wide")

# Custom dark theme and UI polish
st.markdown("""
    <style>
        /* Global styling */
        body, .stApp {
            background-color: #111418;
            color: #e0e0e0;
        }
        .block-container {
            padding-top: 2rem;
            padding-bottom: 2rem;
            max-width: 1200px;
        }
        h1, h2, h3, h4, h5 {
            font-family: "Inter", sans-serif;
            font-weight: 600;
        }

        /* Gradient header */
        .header-container {
            background: linear-gradient(90deg, #0d1b2a 0%, #1b263b 50%, #2E8BC0 100%);
            padding: 1.2rem 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            color: #f1f1f1;
        }

        /* Card container */
        .card {
            background-color: #1a1d23;
            padding: 1.2rem 1.5rem;
            border-radius: 10px;
            box-shadow: 0 0 8px rgba(0,0,0,0.4);
            margin-bottom: 1rem;
        }

        /* Buttons */
        .stButton>button {
            background: #2E8BC0;
            color: white;
            border: none;
            border-radius: 6px;
            padding: 0.6rem 1.2rem;
            font-weight: 500;
        }
        .stButton>button:hover {
            background: #1b6390;
        }

        /* Tabs styling */
        .stTabs [data-baseweb="tab-list"] {
            gap: 10px;
        }
        .stTabs [data-baseweb="tab"] {
            background-color: #1a1d23;
            border-radius: 6px 6px 0 0;
            padding: 0.6em 1em;
            color: #bdbdbd;
        }
        .stTabs [aria-selected="true"] {
            background-color: #2E8BC0 !important;
            color: white !important;
            border-bottom: 2px solid #2E8BC0 !important;
        }

        /* Sidebar */
        section[data-testid="stSidebar"] {
            background-color: #0d1b2a !important;
            color: #e0e0e0;
        }

        /* Success / Error simplification */
        .stAlert {
            border-radius: 6px;
        }
    </style>
""", unsafe_allow_html=True)




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
        self.user_email = user_email
    
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
        response = self._send_to_metadata("LIST_FILES", {"user_email": self.user_email})
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
                
                response = self._send_to_metadata("GET_WRITE_NODES", {})
                if not response or response.get("status") != "ok":
                    st.error(f"Could not get write locations for chunk {chunk_index}.")
                    progress_bar.empty()
                    status_text.empty()
                    return False

                nodes = response.get("nodes")
                node_addresses = response.get("node_addresses")
                chunk_locations[chunk_hash] = nodes

                status_text.text(f"Uploading chunk {chunk_index + 1}/{total_chunks} ({len(chunk_data)} bytes)...")
                header = f"STORE\n{chunk_hash}\n{len(chunk_data)}\n\n".encode('utf-8')
                
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
                "user_email": self.user_email,
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
            response = self._send_to_metadata("GET_FILE_INFO", {
                "user_email": self.user_email,
                "filename": filename
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
                        
                        header = f"RETRIEVE\n{chunk_hash}\n\n".encode('utf-8')
                        
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


# -----------------------------
# Login / Register UI
# -----------------------------
if not st.session_state.logged_in:
    st.markdown('<div class="header-container"><h2>Distributed File System</h2><p>Secure, scalable, and fault-tolerant file management</p></div>', unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["Login", "Register"])
    auth_client = AuthClient()

    with tab1:
        with st.container():
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.subheader("Sign In")
            with st.form("login_form"):
                email = st.text_input("Email Address")
                password = st.text_input("Password", type="password")
                submit = st.form_submit_button("Login")

                if submit:
                    if not email or not password:
                        st.warning("Please fill in all fields.")
                    else:
                        res = auth_client.login(email, password)
                        if res and res["status"] == "ok":
                            st.session_state.logged_in = True
                            st.session_state.session_token = res["session_token"]
                            st.session_state.user_email = res["email"]
                            st.session_state.user_name = res["name"]
                            st.rerun()
                        else:
                            st.error("Invalid credentials")
            st.markdown('</div>', unsafe_allow_html=True)

    with tab2:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.subheader("Create an Account")
        with st.form("register_form"):
            name = st.text_input("Full Name")
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            confirm = st.text_input("Confirm Password", type="password")
            submit = st.form_submit_button("Register")

            if submit:
                if not all([name, email, password, confirm]):
                    st.warning("All fields are required.")
                elif password != confirm:
                    st.warning("Passwords do not match.")
                else:
                    res = auth_client.register(email, password, name)
                    if res["status"] == "ok":
                        st.success("Account created successfully. You may now log in.")
                    else:
                        st.error("Registration failed.")
        st.markdown('</div>', unsafe_allow_html=True)

# -----------------------------
# Main Dashboard UI
# -----------------------------
else:
    st.markdown(f"""
        <div class="header-container">
            <h2>Distributed File System Dashboard</h2>
            <p>Welcome, {st.session_state.user_name}</p>
        </div>
    """, unsafe_allow_html=True)

    # Sidebar layout
    with st.sidebar:
        st.markdown("#### Account")
        st.write(st.session_state.user_email)
        if st.button("Logout"):
            AuthClient().logout(st.session_state.session_token)
            for k in list(st.session_state.keys()):
                del st.session_state[k]
            st.rerun()

        st.divider()
        st.markdown("#### Server Status")

        servers = [
            ("Auth Server", AUTH_PORT),
            ("Metadata Server", METADATA_PORT),
            ("Storage Node 1", 5001),
            ("Storage Node 2", 5002),
            ("Storage Node 3", 5003),
        ]
        for name, port in servers:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    s.connect((AUTH_HOST, port))
                    st.success(name)
            except:
                st.error(name)

        st.divider()
        st.markdown("#### Configuration")
        st.write(f"Auth: `{AUTH_HOST}:{AUTH_PORT}`")
        st.write(f"Metadata: `{METADATA_HOST}:{METADATA_PORT}`")
        st.write(f"Chunk Size: `{CHUNK_SIZE/(1024*1024):.1f} MB`")

    # Main tabs
    dfs = DFSClient(st.session_state.user_email)
    tab1, tab2, tab3 = st.tabs(["Upload", "Download", "My Files"])

    # --- Upload Tab ---
    with tab1:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.subheader("Upload File")

        uploaded = st.file_uploader("Select a file to upload")

        if uploaded:
            # Compute stats
            size_mb = uploaded.size / (1024 * 1024)
            chunks = (uploaded.size + CHUNK_SIZE - 1) // CHUNK_SIZE

            # Combined summary in a clean table-like box
            st.markdown("""
                <div style="
                    background-color: #1D262E;
                    border: 1px solid #dfe3e6;
                    border-radius: 8px;
                    padding: 12px 18px;
                    margin-top: 10px;
                    margin-bottom: 15px;
                ">
                    <div style="display: flex; justify-content: space-between;">
                        <div><b>Filename:</b></div><div>{name}</div>
                    </div>
                    <div style="display: flex; justify-content: space-between;">
                        <div><b>File Size:</b></div><div>{size:.2f} MB</div>
                    </div>
                    <div style="display: flex; justify-content: space-between;">
                        <div><b>Chunks:</b></div><div>{chunks}</div>
                    </div>
                </div>
            """.format(name=uploaded.name, size=size_mb, chunks=chunks),
            unsafe_allow_html=True)

            # Centered upload button
            col1, col2, col3 = st.columns([1, 2, 1])
            with col2:
                if st.button("Upload File", use_container_width=True):
                    with st.spinner("Uploading..."):
                        success = dfs.upload(uploaded.read(), uploaded.name)
                        if success:
                            st.success("File uploaded successfully.")
                            st.session_state.file_list = dfs.list_files()
                        else:
                            st.error("Upload failed.")
        else:
            st.info("Select a file to see summary and upload options.")
        
        st.markdown('</div>', unsafe_allow_html=True)


    # --- Download Tab ---
    with tab2:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.subheader("Download File")
        if st.button("Refresh List"):
            st.session_state.file_list = dfs.list_files()

        file_list = st.session_state.file_list or dfs.list_files()
        if file_list:
            selected = st.selectbox("Select a file", file_list)
            if st.button("Download Selected"):
                with st.spinner(f"Downloading {selected}..."):
                    data = dfs.download(selected)
                    st.download_button("Save File", data, file_name=selected)
                    st.success("Download complete.")
        else:
            st.info("No files available for download.")
        st.markdown('</div>', unsafe_allow_html=True)

    # --- Files Tab ---
    with tab3:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.subheader("Stored Files")
        files = dfs.list_files()
        if files:
            for i, f in enumerate(files, start=1):
                st.markdown(f"<p style='margin-bottom: 0.3rem;'> <b>{i}.</b> {f}</p>", unsafe_allow_html=True)
        else:
            st.info("No files stored yet.")
        st.markdown('</div>', unsafe_allow_html=True)