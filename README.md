# 🚀 Filestore: Simple Distributed File System (DFS)

![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python)
![Docker](https://img.shields.io/badge/Docker-blue?logo=docker)
![Streamlit](https://img.shields.io/badge/Streamlit-red?logo=streamlit)

A minimal **Distributed File System (DFS)** built in Python — designed to demonstrate real-world **distributed systems** concepts like service discovery, replication, fault tolerance, and persistence.

It uses:
- A **metadata server** for coordination  
- Multiple **storage nodes** for distributed file chunks  
- A **Streamlit web client** for easy file upload/download  

All backend components are **containerized with Docker & Docker Compose** for fast deployment and scaling.

---

## 📘 Table of Contents

1. [💡 Concepts Demonstrated](#-concepts-demonstrated)  
2. [✨ Key Features](#-key-features)  
3. [🏗️ System Architecture](#%EF%B8%8F-system-architecture)  
   - [Metadata Server](#1-%EF%B8%8F-metadata-server-metadataserverpy)  
   - [Storage Node](#2-%EF%B8%8F-storage-node-storagenodepy)  
   - [Client](#3-%EF%B8%8F-client-clientpy)  
4. [🌊 Example Flow](#-example-flow)  
5. [🏁 How to Run](#-how-to-run)  
6. [📚 References](#-references)

---

## 💡 Concepts Demonstrated

This project provides a hands-on implementation of ideas from **CS401: Distributed and Parallel Computing**, including:

- **Service Discovery:** Storage nodes register dynamically with the metadata server.  
- **Data Chunking:** Files are split into **1 MB chunks** before being stored.  
- **Data Replication:** Each chunk is replicated for durability (`REPLICATION_FACTOR = 2`).  
- **Fault Tolerance:** The metadata server monitors node heartbeats (every 10 s) and removes dead nodes after 30 s.  
- **Centralized Metadata:** A single server manages file-chunk mappings.  
- **Persistence:** Metadata is stored in `metadata.json` to survive restarts.  
- **Client–Server Architecture:** Separation between the **control plane** (metadata) and **data plane** (storage).

---

## ✨ Key Features

- 📤 **File Uploading & Downloading** — Upload and retrieve files via Streamlit UI  
- 🧩 **Chunking** — Files split into 1 MB pieces (`CHUNK_SIZE` in `client.py`)  
- 🔄 **Replication** — Redundant copies ensure durability  
- ❤️ **Fault Detection** — Metadata server tracks heartbeats from nodes  
- 📒 **Persistent Metadata** — State stored in `metadata/metadata.json`  
- 🖥️ **Web-based UI** — Intuitive Streamlit frontend  
- 🐳 **Containerized Deployment** — Managed through Docker Compose  

---

## 🏗️ System Architecture

The DFS consists of three core components:

### 1. 🧠 Metadata Server (`metadata_server.py`)

**Role:** The *control plane* (the “brain”).  
**Responsibilities:**
- Manages the file namespace  
- Tracks which chunks make up each file  
- Assigns storage nodes for replication  
- Handles node registration and heartbeats  
- Responds to client write and read requests  
- **Default Port:** `6000`

---

### 2. 🗄️ Storage Node (`storage_node.py`)

**Role:** The *data plane* (the “worker”).  
**Responsibilities:**
- Registers with the metadata server  
- Sends periodic heartbeats (every 10 s)  
- Stores incoming file chunks on disk  
- Serves `STORE` and `RETRIEVE` requests  
- **Example Ports:** `5001`, `5002`, `5003`

---

### 3. 💻 Client (`client.py`)

**Role:** The *user interface*.  
**Responsibilities:**
- Provides a Streamlit web UI  
- Communicates with the metadata server for file metadata  
- Connects directly to storage nodes for file transfer  

---

## 🌊 Example Flow

### 🔼 Uploading a File

1. **Client:** User selects `my_file.txt` in the Streamlit UI.  
2. **Client:** Splits file into chunks (e.g., `chunk-A`, `chunk-B`).  
3. **Client → Metadata Server:** Requests write locations (`GET_WRITE_NODES`).  
4. **Metadata Server:** Responds with replication plan (e.g., nodes 1 & 3).  
5. **Client → Nodes:** Sends `STORE` commands with chunk data.  
6. **Client:** Notifies metadata server once upload completes (`PUT_FILE_INFO`).  

### 🔽 Downloading a File

1. **Client:** User selects `my_file.txt`.  
2. **Client → Metadata Server:** Requests chunk mapping (`GET_FILE_INFO`).  
3. **Metadata Server:** Returns chunk locations.  
4. **Client → Nodes:** Retrieves chunks (`RETRIEVE`).  
5. **Nodes → Client:** Sends chunk data.  
6. **Client:** Reassembles chunks into the original file and serves download.

---

## 🏁 How to Run

### 1. 🧰 Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- [Docker Compose](https://docs.docker.com/compose/)
- [Python 3.9+](https://www.python.org/)
- `pip` (Python package manager)

---

### 2. ⚙️ One-Time Setup

#### A. Create `storagenode` Directory
```bash
mkdir storagenode
````

#### B. Create `storagenode/Dockerfile`

```dockerfile
# storagenode/Dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY storage_node.py .
ENTRYPOINT ["python"]
```

#### C. Create `requirements.txt`

```bash
echo "streamlit" > requirements.txt
```

---

### 3. ▶️ Run the Application

#### Project Structure

```
.
├── client.py
├── docker-compose.yml
├── Dockerfile           # Metadata server
├── metadata_server.py
├── requirements.txt     # Contains "streamlit"
├── storage_node.py
└── storagenode/
    └── Dockerfile       # Storage node image
```

#### Step 1: Start Backend Services

```bash
docker-compose up -d --build
```

Check running containers:

```bash
docker-compose ps
```

Expected output:

```
metadata-server
storage-node-1
storage-node-2
storage-node-3
```

#### Step 2: Install Client Dependencies

```bash
pip install -r requirements.txt
```

#### Step 3: Run the Streamlit Client

```bash
streamlit run client.py
```

Visit: [http://localhost:8501](http://localhost:8501)

---

### 4. ⏹️ Stopping the System

To stop everything safely:

```bash
# Stop Streamlit (Ctrl + C)
docker-compose down
```

This removes the containers and the Docker network
(but preserves persistent data in `metadata/` and `storage/`).

---

## 📚 References

| ID  | Concept                            | Source / Origin                                                     |
| --- | ---------------------------------- | ------------------------------------------------------------------- |
| [1] | Metadata & Fault Tolerance         | Inspired by **GFS (Google File System)** principles                 |
| [2] | Client–Server Data Flow & Chunking | Adapted from **HDFS (Hadoop Distributed File System)** concepts     |
| [3] | Node Discovery & Heartbeats        | Modeled after standard **Service Discovery** in distributed systems |

---

> 🧠 **Educational Purpose:**
> Filestore DFS is designed as a lightweight learning project to explore distributed systems principles like consistency, replication, and fault tolerance — similar to how large-scale systems like GFS or HDFS work internally.


