# SOC Case Management System

A **Dockerized SOC (Security Operations Center) Case Management System** designed to manage security events, alerts, and investigations efficiently.  

This system ingests Suricata logs, organizes them into a MongoDB database, tracks cases in MySQL, and provides a GUI for SOC analysts to triage and manage cases.

---

## Project Overview

This project allows SOC analysts to:

- Store and manage security alerts from Suricata in **MongoDB**.
- Track cases, assignments, and history in **MySQL**.
- Triage alerts and promote them to cases using a **Python GUI**.
- Run the full stack **Dockerized**, with all dependencies pre-configured.
- Easily clone and run on any system with Docker installed.

---

## Architecture Overview

| Component | Purpose |
|-----------|---------|
| **Backend (Python)** | GUI application + ingestion logic |
| **MySQL** | Stores cases, users, assignments, and history |
| **MongoDB** | Stores Suricata events with schema validation |
| **Docker Compose** | Orchestrates all services and ensures reproducible setup |

---

## Prerequisites

Ensure you have the following installed:

- [Docker](https://docs.docker.com/get-docker/) (v20+)
- [Docker Compose](https://docs.docker.com/compose/install/) (v2+)
- [Git](https://git-scm.com/downloads)
- Python 3.10+ (for running GUI, optional if using Docker)

Check installation:

```bash
docker --version
docker compose version
git --version
python3 --version
```
## Installation & Setup
Follow these steps to get the system running from scratch.

### Step 1: Clone the Repository:

Open your terminal and clone the project to your local machine:
```bash
git clone https://github.com/MuhammadAbdullahSalahuddin/SOC_CaseManagment
cd SOC_CaseManagment
```

### Step 2: Start the Database Infrastructure

We use Docker to spin up MySQL and MongoDB. This ensures you don't need to manually install SQL servers on your machine.

```bash
docker compose up -d
```

### Step 3: Set Up the Python Environment

The GUI requires specific Python libraries to run (specifically PyQt6 for the interface and database connectors). You can install them using one of the following methods:

#### Option A: Using requirements.txt (Recommended)

The requirements.txt file is already in the folder, simply run:

```bash
pip install -r requirements.txt
```

#### Option B: Manual Installation

If you prefer to install the packages manually, run the following command:

```bash
pip install PyQt6 mysql-connector-python pymongo
```
