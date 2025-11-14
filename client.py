import streamlit as st
import socket
import json
import os
import hashlib
import time

# Config
AUTH_HOST = '127.0.0.1'
AUTH_PORT = 8000
METADATA_HOST = '127.0.0.1'
METADATA_PORT = 6000
CHUNK_SIZE = 1024 * 2048

# -----------------------------
# Streamlit Styling (subtle, minimal, primarily for buttons and color/text polish)
# -----------------------------
st.set_page_config(page_title="Distributed File System", layout="wide")
st.markdown("""
    <style>
        body, .stApp {
            background: linear-gradient(135deg, #162039 0%, #24415b 100%);
            color: #e1e6ec;
        }
        .block-container {
            padding-top: 2rem;
            padding-bottom: 2rem;
            max-width: 1160px;
            background: none;
            box-shadow: none;
        }
        h1, h2, h3, h4, h5 {
            font-family: "Inter", sans-serif;
            font-weight: 600;
            color: #fff;
        }
        .st-emotion-cache-10trblm, .st-emotion-cache-1d391kg {
            background: linear-gradient(97deg, #305e9c 24%, #173d6b 95%);
            padding: 12px 22px !important;
            border-radius: 5px;
            color: #f5fbff !important;
            margin-bottom: 18px;
            box-shadow: none;
        }
        /* Remove excessive card/box feel */
        .card, .st-emotion-cache-1nm2qww, .stContainer {
            background: none !important;
            box-shadow: none !important;
            padding: 0;
            margin-bottom: 0.3rem;
            border-radius: 0 !important;
        }
        /* Subtle button styling, gentle rounding */
        .stButton>button {
            background: linear-gradient(93deg, #466fa5 78%, #164f7c 100%);
            color: #f5fbff;
            border: none;
            border-radius: 6px;
            font-weight: 600;
            padding: 0.48rem 1.15rem;
            margin-bottom: 3px;
            font-size: 16px;
            box-shadow: none;
            transition: background 0.19s;
        }
        .stButton>button:hover, .stDownloadButton>button:hover {
            background: linear-gradient(93deg, #2b3a59 80%, #214269 120%) !important;
            color: #b6d6f7 !important;
        }
        /* Save file/download button */
        .stDownloadButton>button {
            background: linear-gradient(92deg, #498ccc 64%, #215882 91%);
            color: #f6f9fc;
            border-radius: 6px;
            font-weight: 600;
            margin-top: 4px;
        }
        /* File uploader - more subtle */
        section[data-testid="stFileUploaderDropzone"] {
            background: #20334d;
            border: 1px solid #1d3046;
            border-radius: 0px;
        }
        /* Pop out the actual upload input area with a thin white border */
        section[data-testid="stFileUploaderDropzone"] div[role="button"] {
            border: 1.5px solid #fff;
            border-radius: 6px !important;
            box-shadow: 0 0 0 2px #fff3 inset;
            background: rgba(32, 51, 77, 0.95);
            transition: box-shadow 0.2s, border-color 0.2s;
        }
        section[data-testid="stFileUploaderDropzone"] div[role="button"]:hover {
            border-color: #b6d6f7;
            box-shadow: 0 0 0 3px #eaf2ff88 inset;
        }
        /* Tabs - gentle accent, no containing box */
        .stTabs [data-baseweb="tab-list"] {
            gap: 12px;
            background: none;
            border-bottom: 1px solid #2c4880;
        }
        .stTabs [data-baseweb="tab"] {
            border-radius: 0px;
            background: none !important;
            color: #c6e2ff;
            font-weight: 500;
        }
        .stTabs [aria-selected="true"] {
            background: none;
            color: #fff !important;
            border-bottom: 2.5px solid #2e8bc0 !important;
        }
        /* Sidebar: minimal accent color only, no box */
        section[data-testid="stSidebar"] {
            background: #18263a !important;
            color: #dde7f2;
            border-radius: 0px;
            box-shadow: none;
        }
        /* Success/Error: keep it minimal */
        .stAlert {
            border-radius: 3px;
            border-width: 1px;
            background: #19284033;
        }
        /* Misc text */
        .css-1qaijid, .st-emotion-cache-1v0mbdj, .st-emotion-cache-1v0mbdj p {
            color: #d2e8ff;
        }
        /* Tables/file list: no round */
        .stDataFrame, .stTable {
            border-radius: 0px;
            overflow: hidden;
            background: #202b3b;
        }
        /* Input widgets - minimal underline style, no round */
        .stTextInput>div>div>input, .stPasswordInput>div>div>input {
            background: none;
            color: #e4f1ff;
            border: none;
            border-bottom: 2px solid #3b5774;
            border-radius: 0px;
            font-weight: 500;
        }
        .stTextInput>div>div>input:focus, .stPasswordInput>div>div>input:focus {
            border-bottom: 2px solid #4689bf;
        }
        /* Hide Streamlit "Deploy" button and 3-dot menu */
        header[data-testid="stHeader"] div[data-testid="stDecoration"] { display: none !important; }
        header[data-testid="stHeader"] span[data-testid="stDeployButton"] { display: none !important; }
        header[data-testid="stHeader"] { visibility: hidden !important; height: 0px !important; min-height: 0px !important; }
        /* Hide Press Enter to Submit Form */
        .stForm .stFormSubmitInstructions {
            display: none !important;
            visibility: hidden !important;
            height: 0 !important;
            margin: 0 !important;
            padding: 0 !important;
        }
    </style>
""", unsafe_allow_html=True)

# Session state
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
    def _send_to_auth(self, command, payload):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect((AUTH_HOST, AUTH_PORT))
                req = json.dumps({"command": command, "payload": payload})
                s.sendall(req.encode('utf-8'))
                response = s.recv(4096)
                return json.loads(response.decode('utf-8'))
        except ConnectionRefusedError:
            st.error(f"Cannot connect to auth server at {AUTH_HOST}:{AUTH_PORT}. Is Docker running?")
            return None
        except Exception as e:
            st.error(f"Auth error: {e}")
            return None

    def register(self, email, password, name):
        return self._send_to_auth("REGISTER", {
            "email": email, "password": password, "name": name
        })

    def login(self, email, password):
        return self._send_to_auth("LOGIN", {
            "email": email, "password": password
        })

    def verify(self, session_token):
        return self._send_to_auth("VERIFY", {"session_token": session_token})

    def logout(self, session_token):
        return self._send_to_auth("LOGOUT", {"session_token": session_token})

class DFSClient:
    def __init__(self, user_email):
        self.user_email = user_email

    def _send_to_metadata(self, command, payload):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect((METADATA_HOST, METADATA_PORT))
                req = json.dumps({"command": command, "payload": payload})
                s.sendall(req.encode('utf-8'))
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
        response = self._send_to_metadata("LIST_FILES", {"user_email": self.user_email})
        if response and response.get("status") == "ok":
            return response.get("files", [])
        return []

    def upload(self, file_data, filename):
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

    def delete(self, filename):
        response = self._send_to_metadata("GET_FILE_INFO", {
            "user_email": self.user_email,
            "filename": filename
        })
        if not response or response.get("status") != "ok":
            st.error(f"Could not get file info for '{filename}': {response.get('message', '') if response else 'No response'}")
            return False

        chunk_order = response.get("chunks", [])
        locations = response.get("locations", {})

        for chunk_hash in chunk_order:
            chunk_addresses = locations.get(chunk_hash, [])
            for address in chunk_addresses:
                header = f"DELETE\n{chunk_hash}\n\n".encode('utf-8')
                try:
                    resp = self._send_to_storage_node(address, header)
                    if resp and resp.startswith(b'OK'):
                        st.info(f"Deleted chunk {chunk_hash} on {address}")
                    else:
                        st.warning(f"Delete failed on {address} for chunk {chunk_hash}")
                except Exception as e:
                    st.warning(f"Error deleting chunk {chunk_hash} on {address}: {e}")

        md_resp = self._send_to_metadata("DELETE_FILE", {
            "user_email": self.user_email,
            "filename": filename
        })
        if md_resp and md_resp.get("status") == "ok":
            return True
        else:
            st.error(f"Failed to delete metadata for '{filename}': {md_resp.get('message', '') if md_resp else 'No response'}")
            return False

# -----------------------------
# Login / Register UI
# -----------------------------
if not st.session_state.logged_in:
    st.title("📁 Distributed File System - Login")

    tab1, tab2 = st.tabs(["Login", "Register"])

    auth_client = AuthClient()

    with tab1:
        st.header("Login")
        with st.form("login_form", clear_on_submit=True):
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
        with st.form("register_form", clear_on_submit=True):
            reg_name = st.text_input("Name")
            reg_email = st.text_input("Email")
            reg_password = st.text_input("Password", type="password")
            reg_password_confirm = st.text_input("Confirm Password", type="password")
            submit = st.form_submit_button("Register", type="primary")
            if submit:
                if not all([reg_name, reg_email, reg_password, reg_password_confirm]):
                    st.warning("All fields are required.")
                elif reg_password != reg_password_confirm:
                    st.warning("Passwords do not match.")
                else:
                    res = auth_client.register(reg_email, reg_password, reg_name)
                    if res and res.get("status") == "ok":
                        st.success("Account created successfully. You may now log in.")
                    else:
                        st.error("Registration failed.")

# -----------------------------
# Main Dashboard UI
# -----------------------------
else:
    st.title("📁 Distributed File System")

    # Sidebar
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
            ("Storage Node 3", 5003),
        ]
        for name, port in storage_nodes:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    s.connect((AUTH_HOST, port))
                    st.success(name)
            except:
                st.error(f"❌ {name}")

        st.markdown("---")
        st.markdown("### ⚙️ Configuration")
        st.write(f"**Auth Server:** `{AUTH_HOST}:{AUTH_PORT}`")
        st.write(f"**Metadata Server:** `{METADATA_HOST}:{METADATA_PORT}`")
        st.write(f"**Chunk Size:** `{CHUNK_SIZE / (1024*1024):.1f} MB`")

    st.markdown("---")
    client = DFSClient(st.session_state.user_email)

    st.header("Upload File")
    if 'upload_reset_counter' not in st.session_state:
        st.session_state.upload_reset_counter = 0
    def reset_upload():
        st.session_state.upload_reset_counter += 1

    uploaded_file = st.file_uploader(
        "Choose a file to upload",
        type=None,
        key=f"file_uploader_{st.session_state.upload_reset_counter}"
    )

    if uploaded_file is not None:
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**Filename:** `{uploaded_file.name}`")
        with col2:
            st.markdown(f"**Size:** `{uploaded_file.size:,} bytes`")
        st.markdown(f"**Chunks:** `{(uploaded_file.size + CHUNK_SIZE - 1) // CHUNK_SIZE}`")

        if st.button("Upload to DFS", type="primary", key="upload_btn"):
            with st.spinner("Uploading..."):
                file_data = uploaded_file.read()
                success = client.upload(file_data, uploaded_file.name)
                if success:
                    st.success(f"✅ '{uploaded_file.name}' uploaded successfully!")
                    st.balloons()
                    st.session_state.file_list = client.list_files()
                    reset_upload()
                    st.rerun()
                else:
                    st.error("❌ Upload failed. Check the error messages above.")

    st.markdown("---")
    st.header("My Files")

    col_list_left, col_list_right = st.columns([3, 1])
    with col_list_right:
        if st.button("🔄 Refresh List", key="refresh_list"):
            st.session_state.file_list = client.list_files()
            st.rerun()

    if not st.session_state.file_list:
        st.session_state.file_list = client.list_files()
    files = st.session_state.file_list

    if files:
        st.write(f"**Total files:** {len(files)}")
        st.markdown("---")
        for idx, filename in enumerate(files, 1):
            row_col1, row_col2, row_col3 = st.columns([4, 1, 1])
            with row_col1:
                st.markdown(f"`{filename}`")
            with row_col2:
                download_clicked = st.button("⬇️ Download", key=f"download_{filename}")
            with row_col3:
                delete_clicked = st.button("🗑️ Delete", key=f"delete_{filename}")

            if download_clicked:
                with st.spinner(f"Downloading {filename}..."):
                    file_data = client.download(filename)
                    if file_data:
                        st.success(f"✅ '{filename}' downloaded successfully! ({len(file_data):,} bytes)")
                        st.download_button(
                            label="💾 Save File to Computer",
                            data=file_data,
                            file_name=filename,
                            mime="application/octet-stream",
                            key=f"save_{filename}"
                        )
            if delete_clicked:
                with st.spinner(f"Deleting {filename}..."):
                    ok = client.delete(filename)
                    if ok:
                        st.success(f"Deleted '{filename}'")
                        st.session_state.file_list = client.list_files()
                        st.rerun()
                    else:
                        st.error(f"Failed to delete '{filename}'")
    else:
        st.info("📭 No files stored yet.")