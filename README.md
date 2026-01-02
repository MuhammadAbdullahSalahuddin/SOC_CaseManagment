# SOC Case Management System

A Dockerized SOC (Security Operations Center) Case Management System using:

- Python (backend + GUI)
- MySQL (case management database)
- MongoDB (Suricata log storage)
- Docker & Docker Compose for reproducible setup

This project is designed so that it can be cloned and run on any system with Docker installed, without manual database configuration.

---

## Architecture Overview

- **Backend**: Python application (GUI + ingestion logic)
- **MySQL**: Stores cases, users, assignments, and history
- **MongoDB**: Stores Suricata events with schema validation
- **Docker Compose**: Orchestrates all services

---

## Prerequisites

You must have the following installed:

- Docker (v20+)
- Docker Compose (v2+)
- Git

Check installation:

```bash
docker --version
docker compose version
git --version
