# 🚀 Filestore: Simple Distributed File System (DFS)

![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python)
![Docker](https://img.shields.io/badge/Docker-blue?logo=docker)
![Streamlit](https://img.shields.io/badge/Streamlit-red?logo=streamlit)

A minimal **Distributed File System (DFS)** built in Python — demonstrating real-world **distributed systems** concepts like service discovery, replication, fault tolerance, and persistence.

It includes:
- 🔐 An **authentication server** for user security.  
- 🧠 A **metadata server** for coordination.  
- 🗄️ Multiple **storage nodes** for distributed file chunks.  
- 💻 A **Streamlit web client** for file upload/download.

All backend components are **containerized using Docker & Docker Compose** for easy deployment and scaling.

---

## 📘 Table of Contents

1. [💡 Concepts Demonstrated](#-concepts-demonstrated)  
2. [✨ Key Features](#-key-features)  
3. [🏗️ System Architecture](#%EF%B8%8F-system-architecture)  
   - [Authentication Server](#1-%EF%B8%8F-authentication-server-auth_serverpy)  
   - [Metadata Server](#2-%EF%B8%8F-metadata-server-metadata_serverpy)  
   - [Storage Node](#3-%EF%B8%8F-storage-node-storage_nodepy)  
   - [Client](#4-%EF%B8%8F-client-clientpy)  
4. [🌊 Example Flow](#-example-flow)  
5. [🏁 How to Run](#-how-to-run)  
6. [📚 References](#-references)

---

## 💡 Concepts Demonstrated

This project is a practical exploration of **distributed system design** concepts from courses like *CS401: Distributed and Parallel Computing*:

- 🔐 **Authentication & Security:** Centralized user identity and access control.  
- 🌐 **Service Discovery:** Storage nodes dynamically register with the metadata server.  
- 🧩 **Data Chunking:** Files are split into 1 MB chunks before being stored.  
- 🔄 **Data Replication:** Each chunk is replicated (`REPLICATION_FACTOR = 2`) for durability.  
- ❤️ **Fault Tolerance:** Metadata server monitors node heartbeats (every 10 s) and prunes dead nodes after 30 s.  
- 📒 **Centralized Metadata:** One server manages all file–chunk mappings.  
- 💾 **Persistence:** Metadata and user data survive restarts via JSON storage.  
- 🧠 **Layered Architecture:** Clear separation of **auth**, **control**, and **data** planes.

---

## ✨ Key Features

- 🔐 **User Authentication:** Secure login, registration, and token-based sessions.  
- 📤 **File Uploading & Downloading:** Streamlit UI for user operations.  
- 🧩 **Chunking:** Files split into 1 MB parts (`CHUNK_SIZE` in `client.py`).  
- 🔄 **Replication:** Redundant copies ensure data durability.  
- ❤️ **Fault Detection:** Active heartbeat-based monitoring of storage nodes.  
- 📒 **Persistent Metadata:** All system state stored in `metadata/`.  
- 🖥️ **Web UI:** Simple Streamlit-based frontend for DFS interaction.  
- 🐳 **Dockerized Deployment:** All components managed with Docker Compose.

---

## 🏗️ System Architecture

The DFS consists of four main components:

---

### 1. 🔐 Authentication Server (`auth_server.py`)

**Role:** The *security plane* — the system’s gatekeeper.

**Responsibilities:**
- Handles user registration (`REGISTER`) and login (`LOGIN`).  
- Hashes and verifies passwords using `bcrypt`.  
- Issues, validates, and expires session tokens.  
- Persists user info (`metadata/users.json`) and active sessions (`metadata/sessions.json`).  
- **Default Port:** `8000`

---

### 2. 🧠 Metadata Server (`metadata_server.py`)

**Role:** The *control plane* — the “brain” of the DFS.

**Responsibilities:**
- Manages the file namespace and chunk mappings.  
- Selects storage nodes for replication.  
- Handles node registration and heartbeats.  
- Responds to client read/write requests.  
- **Default Port:** `6000`

---

### 3. 🗄️ Storage Node (`storage_node.py`)

**Role:** The *data plane* — handles actual storage and retrieval.

**Responsibilities:**
- Registers with the metadata server.  
- Sends periodic heartbeats (every 10 s).  
- Stores incoming file chunks on disk.  
- Serves `STORE` and `RETRIEVE` commands.  
- **Example Ports:** `5001`, `5002`, `5003`

---

### 4. 💻 Client (`client.py`)

**Role:** The *user interface* — built with Streamlit.

**Responsibilities:**
- Provides a web-based UI for login, upload, and download.  
- Communicates with the **Auth Server** for login/registration.  
- Interacts with the **Metadata Server** for control operations.  
- Directly connects to **Storage Nodes** for data transfer.

---

## 🌊 Example Flow

*(Assumes the user is authenticated)*

### 🔼 Uploading a File

1. **Client:** User selects `my_file.txt` in Streamlit UI.  
2. **Client:** Splits file into chunks (e.g., `chunk-A`, `chunk-B`).  
3. **Client → Metadata Server:** Requests write locations (`GET_WRITE_NODES`).  
4. **Metadata Server:** Returns replication plan (e.g., nodes 1 & 3).  
5. **Client → Storage Nodes:** Sends `STORE` commands with chunk data.  
6. **Client → Metadata Server:** Commits file info (`PUT_FILE_INFO`).  

### 🔽 Downloading a File

1. **Client:** User selects `my_file.txt`.  
2. **Client → Metadata Server:** Requests chunk mapping (`GET_FILE_INFO`).  
3. **Metadata Server:** Responds with node locations for each chunk.  
4. **Client → Storage Nodes:** Retrieves chunks (`RETRIEVE`).  
5. **Nodes → Client:** Returns chunk data.  
6. **Client:** Reassembles the chunks and serves the download.

---

## 🏁 How to Run

### 1. 🧰 Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/)  
- [Docker Compose](https://docs.docker.com/compose/)  
- [Python 3.9+](https://www.python.org/)  
- `pip` (Python package manager)

---

### 2. ▶️ Run the Application

Ensure that your `docker-compose.yml` and all necessary `Dockerfile`s are ready.

#### Step 1: Start Backend Services

Build and start all containers (Auth, Metadata, Storage) in detached mode:

```bash
docker-compose up -d --build
````

Check running services:

```bash
docker-compose ps
```

Expected:

```
auth-server
metadata-server
storage-node-1
storage-node-2
storage-node-3
```

#### Step 2: Install Client Dependencies

In a separate terminal:

```bash
pip install -r requirements.txt
```

#### Step 3: Run the Streamlit Client

```bash
streamlit run client.py
```

The app will open automatically at **[http://localhost:8501](http://localhost:8501)**.

---

### 3. ⏹️ Stopping the System

To stop all services:

```bash
# Stop Streamlit
Ctrl + C

# Stop and remove containers
docker-compose down
```

Persistent data remains in `metadata/` and `storage/` directories.

---

## 📚 References

| ID  | Concept                                | Source                                    |
| --- | -------------------------------------- | ----------------------------------------- |
| [1] | Distributed Metadata & Replication     | Google File System (GFS)                  |
| [2] | Client–Server Data Flow                | Hadoop Distributed File System (HDFS)     |
| [3] | Authentication & Security              | bcrypt / token-based authentication model |
| [4] | Fault Tolerance & Heartbeat Monitoring | Common Distributed System design patterns |

---

> 🧠 **Educational Purpose:**
> Filestore DFS is designed for learning and experimentation — a simplified, modular system to explore authentication, metadata management, replication, and fault-tolerant file storage.
