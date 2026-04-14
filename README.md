# 🛡️ Cryptexora IDS — Intrusion Detection System

A beginner-friendly, web-based Intrusion Detection System built with
**Python Flask** (backend) and **HTML/CSS/JavaScript** (frontend).

---

## 📁 Project Folder Structure

```
cryptexora/
│
├── app.py                  ← Flask backend (main server)
├── requirements.txt        ← Python packages needed
├── README.md               ← This file
│
├── templates/              ← HTML pages
│   ├── base.html           ← Shared sidebar layout
│   ├── login.html          ← Login page
│   ├── welcome.html        ← Introduction/overview page
│   ├── dashboard.html      ← Stats dashboard
│   ├── detection.html      ← IDS analysis tool
│   └── logs.html           ← Traffic log history
│
└── static/
    └── css/
        └── style.css       ← All styles (light glassmorphism theme)
```

---

## 🚀 How to Run (Step-by-Step)

### Step 1 — Make sure Python is installed
Open a terminal and type:
```
python --version
```
You should see Python 3.8 or higher. If not, download it from https://python.org

---

### Step 2 — Open the project in VS Code
1. Open VS Code
2. Go to **File → Open Folder**
3. Select the `cryptexora` folder

---

### Step 3 — Open the integrated terminal
In VS Code: **Terminal → New Terminal**
(or press `Ctrl + backtick`)

---

### Step 4 — Install Flask
In the terminal, run:
```
pip install flask
```
or if that doesn't work:
```
pip3 install flask
```

---

### Step 5 — Start the server
```
python app.py
```
You should see:
```
✅  Cryptexora IDS is running!
🌐  Open your browser → http://127.0.0.1:5000
```

---

### Step 6 — Open in browser
Open your web browser and go to:
```
http://127.0.0.1:5000
```

---

## 🔑 Login Credentials

| Username | Password  |
|----------|-----------|
| admin    | admin123  |
| user     | user123   |

---

## 🔍 How to Use the IDS

1. **Login** with admin / admin123
2. Click **IDS Detection** in the sidebar
3. Enter:
   - An IP address (e.g. 192.168.1.1)
   - Packet size in bytes (e.g. 1024)
   - Request type (GET, POST, DELETE, etc.)
4. Click **Analyze Traffic**
5. See the NORMAL or ATTACK result instantly
6. Go to **Traffic Logs** to see all past scans

---

## 🧠 Detection Rules Explained

| Rule | Condition | Result |
|------|-----------|--------|
| Suspicious IP | Starts with 192.168.100. or 10.0.0. | ATTACK (MEDIUM) |
| DDoS Pattern | Packet size > 9000 bytes | ATTACK (HIGH) |
| Large Packet | Packet size > 5000 bytes | ATTACK (MEDIUM) |
| Dangerous Method | DELETE or PATCH | ATTACK (MEDIUM) |
| Unknown Method | Not a standard HTTP method | ATTACK (HIGH) |
| Zero-byte Probe | Packet size = 0 | ATTACK (MEDIUM) |
| Everything else | Normal conditions | NORMAL (LOW) |

---

## 🛑 To Stop the Server
Press `Ctrl + C` in the terminal.

---

## 💡 Tips for Beginners

- All data is stored **in memory** — it resets when you restart the server
- You can add more rules in `app.py` inside the `analyze()` function
- The frontend is in the `templates/` folder — just edit the HTML
- All styles are in `static/css/style.css`

---

*Built for educational purposes · Cryptexora IDS v1.0*
