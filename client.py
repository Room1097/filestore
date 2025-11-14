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
# Streamlit Styling
# -----------------------------
st.set_page_config(page_title="Distributed File System", layout="wide")
st.markdown("""
<style>

    /* -------- GLOBAL -------- */
    body, .stApp {
        background: linear-gradient(145deg, #09152a 0%, #0c233d 100%);
        color: #e8eef5;
        font-family: "Inter", sans-serif;
    }

    .block-container {
        padding-top: 2rem !important;
        max-width: 1100px;
    }

    /* -------- TITLES -------- */
    h1, h2, h3 {
        font-weight: 700;
        letter-spacing: -0.5px;
    }

    /* Soft glowing underline header */
    h1::after {
        content: "";
        display: block;
        width: 60px;
        margin-top: 8px;
        height: 3px;
        background: linear-gradient(90deg, #46a0ff, #1e5fa9);
        border-radius: 6px;
    }

    /* -------- GLASS CARD (NOW APPLIED TO ST-ELEMENTS) -------- */
    
    /* This now styles the Login/Register Tab Group */
    .stTabs {
        background: rgba(255,255,255,0.04);
        backdrop-filter: blur(14px);
        padding: 1rem 1.4rem;
        border-radius: 12px;
        border: 1px solid rgba(255,255,255,0.08);
        margin-bottom: 1.2rem;
        box-shadow: 0 0 18px rgba(0,0,0,0.35);
    }

    /* This new rule styles the File Uploader */
    [data-testid="stFileUploader"] {
        background: rgba(255,255,255,0.04);
        backdrop-filter: blur(14px);
        padding: 1.2rem 1.4rem 1.4rem 1.4rem; /* A little more padding */
        border-radius: 12px;
        border: 1px solid rgba(255,255,255,0.08);
        margin-bottom: 1.2rem;
        box-shadow: 0 0 18px rgba(0,0,0,0.35);
    }


    /* -------- FILE CARDS (NOW APPLIED TO st.container(border=True)) -------- */
    
    /* We target the .st-border class from st.container(border=True) */
    .st-border {
        padding: 14px 18px !important; /* Use !important to override defaults */
        border-radius: 8px !important;
        margin-bottom: 10px;
        background: rgba(255,255,255,0.05);
        border: 1px solid rgba(255,255,255,0.08) !important; /* Override default border */
        border-left: 3px solid #1b79d1 !important; /* Keep your accent */
        transition: background .2s;
    }

    .st-border:hover {
        background: rgba(255,255,255,0.09);
    }
    
    /* # NEW: Style for the st.metric upload summary */
    [data-testid="stMetric"] {
        border: 1px solid rgba(255,255,255,0.1);
        background: rgba(255,255,255,0.03);
        padding: 10px 15px;
        border-radius: 8px;
    }
    [data-testid="stMetricLabel"] {
        color: #bcd7f7; /* Lighter label color */
        font-size: 0.9rem;
    }
    [data-testid="stMetricValue"] {
        color: #ffffff; /* White value color */
    }
    /* # END NEW */

    /* -------- BUTTONS -------- */
    .stButton>button, .stDownloadButton>button {
        background: linear-gradient(90deg, #2188d8, #1762a3);
        padding: 0.55rem 1.3rem;
        border-radius: 8px;
        font-weight: 600;
        border: none;
        transition: 0.22s ease;
        color: #eaf3ff;
    }

    .stButton>button:hover, .stDownloadButton>button:hover {
        background: linear-gradient(90deg, #3aa4ff, #1e7bd0);
        transform: translateY(-1px);
        box-shadow: 0 4px 14px rgba(0,0,0,0.25);
    }

    /* -------- INPUTS -------- */
    input[type="text"], input[type="password"] {
        background: rgba(255,255,255,0.06) !important;
        border: 1px solid rgba(255,255,255,0.15) !important;
        border-radius: 6px !important;
        color: #eaf3ff !important;
    }

    /* -------- TABS -------- */
    .stTabs [data-baseweb="tab"] {
        background: none !important;
        padding: 9px 18px !important;
        font-weight: 500;
        color: #bcd7f7;
        border: 1px solid transparent;
    }

    .stTabs [aria-selected="true"] {
        border-bottom: 2px solid #1d7ed6 !important;
        color: white !important;
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
# MAIN UI (Login + Dashboard)
# -----------------------------

# -----------------------------------
# LOGIN / REGISTER
# -----------------------------------
if not st.session_state.logged_in:

    st.title("Distributed File System")

    tab_login, tab_register = st.tabs(["Login", "Register"])
    auth_client = AuthClient()

    # ------------ LOGIN ------------
    with tab_login:
        st.subheader("Sign In")

        with st.form("login_form", clear_on_submit=True):
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Login")

            if submit:
                if not email or not password:
                    st.error("Please enter both email and password.")
                else:
                    response = auth_client.login(email, password)
                    if response and response.get("status") == "ok":
                        st.session_state.logged_in = True
                        st.session_state.session_token = response.get("session_token")
                        st.session_state.user_email = response.get("email")
                        st.session_state.user_name = response.get("name")
                        st.success(f"Welcome back, {response.get('name')}")
                        st.rerun()
                    else:
                        st.error(response.get("message", "Login failed"))

    # ------------ REGISTER ------------
    with tab_register:
        st.subheader("Create Account")

        with st.form("register_form", clear_on_submit=True):
            reg_name = st.text_input("Name")
            reg_email = st.text_input("Email")
            reg_password = st.text_input("Password", type="password")
            reg_password_confirm = st.text_input("Confirm Password", type="password")
            submit = st.form_submit_button("Register")

            if submit:
                if not all([reg_name, reg_email, reg_password, reg_password_confirm]):
                    st.warning("All fields are required.")
                elif reg_password != reg_password_confirm:
                    st.warning("Passwords do not match.")
                else:
                    res = auth_client.register(reg_email, reg_password, reg_name)
                    if res and res.get("status") == "ok":
                        st.success("Account created successfully.")
                    else:
                        st.error("Registration failed.")
    


# -----------------------------------
# DASHBOARD
# -----------------------------------
else:
    
    # # NEW: Added a title for the logged-in dashboard
    st.title(f"Welcome, {st.session_state.user_name}")

    # ===============================
    # SIDEBAR — USER DETAILS + LOGOUT
    # ===============================
    with st.sidebar:

        st.markdown(f"### {st.session_state.user_name}")
        st.markdown(f"<p style='opacity:0.7'>{st.session_state.user_email}</p>", unsafe_allow_html=True)

        if st.button("Logout",icon=":material/logout:"):
            auth_client = AuthClient()
            auth_client.logout(st.session_state.session_token)
            st.session_state.logged_in = False
            st.session_state.session_token = None
            st.session_state.user_email = None
            st.session_state.user_name = None
            st.session_state.file_list = []
            st.rerun()

        st.markdown("---")
        st.subheader("System Status")

        # Added CSS for status chips here for completeness
        st.markdown("""
        <style>
        .status-chip {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85rem;
            font-weight: 500;
            margin-bottom: 6px;
        }
        .status-online {
            background-color: #1e462e;
            color: #70e19a;
            border: 1px solid #2a5c3e;
        }
        .status-offline {
            background-color: #442026;
            color: #f78b9c;
            border: 1px solid #5e2e38;
        }
        </style>
        """, unsafe_allow_html=True)

        def check_port(name, port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    s.connect(("127.0.0.1", port))
                    st.markdown(f"<div class='status-chip status-online'>{name}: Online</div>", unsafe_allow_html=True)
            except:
                st.markdown(f"<div class='status-chip status-offline'>{name}: Offline</div>", unsafe_allow_html=True)

        check_port("Auth Server", AUTH_PORT)
        check_port("Metadata Server", METADATA_PORT)

        for label, port in [
            ("Storage Node 1", 5001),
            ("Storage Node 2", 5002),
            ("Storage Node 3", 5003)
        ]:
            check_port(label, port)

        st.markdown("---")
        st.subheader("Configuration")
        st.text(f"Auth Server: {AUTH_HOST}:{AUTH_PORT}")
        st.text(f"Metadata: {METADATA_HOST}:{METADATA_PORT}")
        st.text(f"Chunk Size: {CHUNK_SIZE/(1024*1024):.1f} MB")



    # ===============================
    # UPLOAD AREA
    # ===============================
    st.subheader("Upload File")
    client = DFSClient(st.session_state.user_email)

    if 'upload_reset_counter' not in st.session_state:
        st.session_state.upload_reset_counter = 0

    def reset_upload():
        st.session_state.upload_reset_counter += 1

    uploaded_file = st.file_uploader(
        "Select a file",
        type=None,
        key=f"file_uploader_{st.session_state.upload_reset_counter}"
    )

    if uploaded_file:
        # # CHANGED: Replaced 3x st.info with a single summary block
        # st.markdown(f"**File to Upload:** `{uploaded_file.name}`")
        
        col1, col2 = st.columns(2)
        col1.metric("Total Size", f"{uploaded_file.size / (1024*1024):.2f} MB" if uploaded_file.size > 1024*1024 else f"{uploaded_file.size / 1024:.2f} KB")
        col2.metric("Total Chunks", f"{(uploaded_file.size + CHUNK_SIZE - 1) // CHUNK_SIZE}")
        # # END CHANGED
        
        if st.button("Upload",icon=":material/upload:"):
            with st.spinner("Uploading..."):
                ok = client.upload(uploaded_file.read(), uploaded_file.name)
                if ok:
                    st.success("File uploaded.")
                    st.session_state.file_list = client.list_files()
                    reset_upload()
                    st.rerun()
                else:
                    st.error("Upload failed.")

    st.markdown("---")



    # ===============================
    # FILE LIST AREA
    # ===============================
    st.subheader("My Files")

    if st.button("Refresh",icon=":material/sync:"):
        st.session_state.file_list = client.list_files()
        st.rerun()

    if not st.session_state.file_list:
        st.session_state.file_list = client.list_files()

    files = st.session_state.file_list

    if not files:
        st.info("No files available.")
    else:
        for filename in files:
            with st.container(border=True):
                col1, col2, col3 = st.columns([6, 2, 2])
                col1.markdown(f"**{filename}**")

                if col2.button("Download", key=f"dl_{filename}",icon=":material/download:"):
                    file_data = client.download(filename)
                    if file_data:
                        st.download_button(
                            "Save",
                            file_data,
                            filename,
                            "application/octet-stream",
                            key=f"save_{filename}"
                        )

                if col3.button("Delete", key=f"del_{filename}",icon=":material/delete:"):
                    ok = client.delete(filename)
                    if ok:
                        st.success("Deleted.")
                        st.session_state.file_list = client.list_files()
                        st.rerun()
                    else:
                        st.error("Delete failed.")