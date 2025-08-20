# 🛠️ System Utility Monitoring Project

A cross-platform project that monitors basic system security and configuration, stores the reports in a backend (JSON Server), and displays them in a ReactJS Admin Dashboard.

---

## 📂 Project Structure

solsphere/
│── myproject/ # React Frontend (Admin Dashboard)
│── json/ # Backend (JSON Server + db.json storage)
│── system-utility/ # Client (system check script)

---

## ⚙️ Features

### 1. ✅ System Utility (Client)
- Cross-platform (Windows / Linux / macOS)  
- Checks:
  - Disk encryption status
  - OS update status
  - Antivirus presence
  - Inactivity sleep settings (≤ 10 mins)
- Runs as a background daemon:
  - Periodically (every 15–60 mins) checks system state
  - Sends updates only if there are changes
  - Uses minimal system resources
- Reports results to backend API

### 2. 🔁 Backend (JSON Server API)
- Accepts and stores system data  
- Provides REST API endpoints:
  - List all machines and their latest status  
  - Filter by OS, issues, etc.  
  - Export CSV (optional)  

### 3. 🖥️ Admin Dashboard (ReactJS Frontend)
- Displays all reporting machines  
- Shows latest values from each machine  
- Flags configuration issues:
  - Disk not encrypted
  - Outdated OS
  - Missing antivirus
  - Sleep timeout > 10 mins
- Displays last check-in time  
- Provides filtering and sorting options  

---

## 🚀 Installation

### 1️⃣ Clone Repository
```bash
git clone https://github.com/<your-username>/<your-repo-name>.git
cd solsphere


### 2️⃣ Backend Setup (JSON Server)

```bash
cd json
npm init -y
npm install -g json-server
