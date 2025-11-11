import streamlit as st
import socket
import json
import os
import hashlib
import time

# ---------- Page setup (place early in Streamlit apps) ----------
st.set_page_config(page_title="Distributed File System", page_icon="📁", layout="wide")

# ---------- Configuration ----------
# Connect to Docker containers via localhost
AUTH_HOST = '127.0.0.1'
AUTH_PORT = 8000
METADATA_HOST = '127.0.0.1'
METADATA_PORT = 6000
CHUNK_SIZE = 1024 * 1024  # 1 MiB

# ---------- Session State ----------
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

# ---------- Auth Client ----------
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
        return self._send_to_auth("REGISTER", {"email": email, "password": password, "name": name})

    def login(self, email, password):
        """Login user"""
        return self._send_to_auth("LOGIN", {"email": email, "password": password})

    def verify(self, session_token):
        """Verify session token"""
        return self._send_to_auth("VERIFY", {"session_token": session_token})

    def logout(self, session_token):
        """Logout user"""
        return self._send_to_auth("LOGOUT", {"session_token": session_token})

# ---------- DFS Client ----------
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
        s = None
        try:
            host, port = address.split(':')
            host = '127.0.0.1'  # Connect to localhost

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(30)  # 30-second timeout
            s.connect((host, int(port)))

            # Send all data
            s.sendall(request_data)

            # Signal that we are DONE writing.
            s.shutdown(socket.SHUT_WR)

            # Read the full response from the server.
            response_data = bytearray()
            while True:
                chunk = s.recv(1024)
                if not chunk:
                    break
                response_data.extend(chunk)

            return bytes(response_data)

        except ConnectionRefusedError:
            st.error(f"Storage node {host}:{port} refused connection. Is the container running?")
            return None
        except (socket.timeout, TimeoutError):
            st.error(f"Storage node {host}:{port} timed out")
            return None
        except Exception as e:
            st.error(f"Error with storage node {host}:{port} - {type(e).__name__}: {e}")
            return None
        finally:
            if s:
                s.close()

    # ---------- Normalized list_files ----------
    def list_files(self):
        """
        Lists all files for the current user.
        Always returns: [{"filename": "...", "owner": "..."}]
        """
        response = self._send_to_metadata("LIST_FILES", {"user_email": self.user_email})
        if not (response and response.get("status") == "ok"):
            return []

        raw = response.get("files", [])
        norm = []

        # If server returns a mapping like {"fileA.txt": {...}, "fileB.txt": {...}}
        if isinstance(raw, dict):
            for name, meta in raw.items():
                owner = "me"
                if isinstance(meta, dict):
                    owner = meta.get("owner") or meta.get("owner_email") or ("me" if meta.get("is_owner", True) else "shared")
                norm.append({"filename": str(name), "owner": str(owner)})
            return norm

        # If server returns a list
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict):
                    name = item.get("filename") or item.get("file_name") or item.get("name") or item.get("key")
                    if not isinstance(name, str):
                        continue
                    owner = item.get("owner") or item.get("owner_email")
                    if not owner:
                        owner = "me" if item.get("is_owner", True) else "shared"
                    norm.append({"filename": name, "owner": str(owner)})
                elif isinstance(item, (list, tuple)) and item and isinstance(item[0], str):
                    name = item[0]
                    owner = item[1] if len(item) > 1 and isinstance(item[1], str) else "me"
                    norm.append({"filename": name, "owner": owner})
                elif isinstance(item, str):
                    norm.append({"filename": item, "owner": "me"})
            return norm

        # Single string
        if isinstance(raw, str):
            return [{"filename": raw, "owner": "me"}]

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

                # GET_WRITE_NODES doesn't need user_email
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
                # Insecure header (by design for this assignment)
                header = f"STORE\n{chunk_hash}\n{len(chunk_data)}\n\n".encode('utf-8')

                success = False
                for address in node_addresses:
                    response_data = self._send_to_storage_node(address, header + chunk_data)
                    if response_data and response_data.startswith(b'OK'):
                        success = True
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
                st.error(f"Failed to commit metadata: {response.get('message', 'Unknown error') if response else 'No response'}")
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
                st.error(f"Could not get file info for '{filename}'. {response.get('message', '') if response else ''}")
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
                        s.shutdown(socket.SHUT_WR)  # Signal end of request

                        response_data = bytearray()
                        separator_found = False

                        # Read until header is found
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

                                # Read remaining body
                                while len(body_bytes) < content_length:
                                    remaining = content_length - len(body_bytes)
                                    chunk = s.recv(min(8192, remaining))
                                    if not chunk:
                                        break
                                    body_bytes.extend(chunk)

                                if len(body_bytes) == content_length:
                                    chunk_data = bytes(body_bytes)

                        s.close()

                        if chunk_data:
                            break  # Success, move to next chunk

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

    def share_file(self, filename, share_with_email):
        """Shares a file with another user."""
        payload = {
            "user_email": self.user_email,
            "filename": filename,
            "share_with_email": share_with_email
        }
        return self._send_to_metadata("SHARE_FILE", payload)

    def delete_file(self, filename):
        """Deletes a file or file link."""
        payload = {"user_email": self.user_email, "filename": filename}
        return self._send_to_metadata("DELETE_FILE", payload)

# ---------- UI ----------
if not st.session_state.logged_in:
    # ---------- Auth UI ----------
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
                        # Clear any stale data; tabs will fetch fresh normalized list
                        st.session_state.file_list = []
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
    # ---------- Main App ----------
    st.title("📁 Distributed File System")

    # Sidebar
    with st.sidebar:
        st.header(f"👤 {st.session_state.user_name}")
        st.write(f"**Email:** {st.session_state.user_email}")

        if st.button("🚪 Logout", type="primary"):
            auth_client = AuthClient()
            try:
                auth_client.logout(st.session_state.session_token)
            except Exception:
                pass
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

    # DFS client
    client = DFSClient(st.session_state.user_email)

    # Tabs
    tab1, tab2, tab3 = st.tabs(["📤 Upload", "📥 Download", "📋 My Files"])

    # ---------- Upload Tab ----------
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
                        st.session_state.file_list = client.list_files()  # Refresh file list (normalized)
                    else:
                        st.error("❌ Upload failed. Check the error messages above.")

    # ---------- Download Tab (uses normalized list) ----------
    with tab2:
        st.header("Download File")

        col1, col2 = st.columns([3, 1])

        with col2:
            if st.button("🔄 Refresh List", key="refresh_download"):
                st.session_state.file_list = client.list_files()
                st.rerun()

        # Ensure the file list is fresh (normalized)
        if not st.session_state.file_list:
            st.session_state.file_list = client.list_files()

        files = st.session_state.file_list  # normalized list of dicts

        if files:
            with col1:
                filenames = [f["filename"] for f in files if isinstance(f, dict) and "filename" in f]

                selected_file = st.selectbox(
                    "Select a file to download",
                    filenames,
                    key="file_selector"
                )

            if st.button("Download File", type="primary", key="download_btn"):
                if not selected_file:
                    st.warning("Please select a file.")
                else:
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
                            st.error("❌ Download failed. See errors above.")
        else:
            st.info("📭 No files uploaded yet. Upload a file first!")

    # ---------- My Files Tab (uses normalized list) ----------
    with tab3:
        st.header("My Files")

        col1, col2 = st.columns([3, 1])

        with col2:
            if st.button("🔄 Refresh", key="refresh_list"):
                st.session_state.file_list = client.list_files()
                st.rerun()

        files = st.session_state.file_list
        if not files:
            files = client.list_files()
            st.session_state.file_list = files

        if files:
            st.write(f"**Total files:** {len(files)}")
            st.markdown("---")

            # Header row
            cols = st.columns([4, 3, 1, 1])
            cols[0].markdown("**Filename**")
            cols[1].markdown("**Owner**")
            cols[2].markdown("**Share**")
            cols[3].markdown("**Delete**")

            for fi in files:
                if not isinstance(fi, dict):
                    continue
                filename = fi.get("filename")
                owner = fi.get("owner", "me")
                if not filename:
                    continue

                cols = st.columns([4, 3, 1, 1])

                # Column 1: Filename
                cols[0].write(f"`{filename}`")

                # Column 2: Owner
                cols[1].markdown("*(You)*" if owner == "me" else f"*{owner}*")

                # Column 3: Share
                if owner == "me":
                    with cols[2].popover("Share"):
                        st.markdown(f"**Share `{filename}`**")
                        share_email = st.text_input("Enter user's email:", key=f"email_{filename}")
                        if st.button("Confirm Share", key=f"share_{filename}"):
                            if share_email:
                                response = client.share_file(filename, share_email)
                                if response and response.get("status") == "ok":
                                    st.success("File shared!")
                                else:
                                    msg = response.get('message') if response else 'Unknown error'
                                    st.error(f"Failed: {msg}")
                            else:
                                st.warning("Please enter an email.")
                else:
                    cols[2].markdown("—")

                # Column 4: Delete
                with cols[3].popover("Delete"):
                    st.warning(f"Are you sure you want to delete `{filename}`?")
                    if st.button("Confirm Delete", type="primary", key=f"del_{filename}"):
                        response = client.delete_file(filename)
                        if response and response.get("status") == "ok":
                            st.success(f"'{filename}' deleted.")
                            st.session_state.file_list = client.list_files()
                            st.rerun()
                        else:
                            msg = response.get('message') if response else 'Unknown error'
                            st.error(f"Failed: {msg}")
        else:
            st.info("📭 No files stored yet.")
