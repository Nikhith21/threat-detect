# Threat Detect CLI

A lightweight, installable SIEM-style CLI tool engineered for real-time security analytics. It parses unstructured server authentication logs, applies custom heuristic thresholds, and detects anomalous behavior including distributed brute-force campaigns and network reconnaissance.

---

## 🚀 Features

* **Brute-force attack detection** via failed authentication heuristics
* **Invalid user enumeration detection** * **SSH scanning & protocol anomaly detection**
* **MITRE ATT&CK mapping** (T1110, T1087, T1046)
* **Severity classification** (LOW, MEDIUM, HIGH, CRITICAL)
* **Real-time log monitoring** (`--watch` mode) with memory-safe IP tracking
* **Colored terminal output** for rapid SOC triage
* **JSON alert export** for seamless SIEM integration

---

## ⚠️ Requirements

* Python 3.8 or higher
* pip (comes with Python)

---

## 📦 Installation

### 1. Clone the repository

```bash
git clone [https://github.com/your-username/threat-detect.git](https://github.com/your-username/threat-detect.git)
cd threat-detect
```

---

### 2. (Optional but recommended) Create virtual environment

```bash
python -m venv .venv
```

Activate it:

**Windows**

```bash
.venv\Scripts\activate
```

**Mac/Linux**

```bash
source .venv/bin/activate
```

---

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

### 4. Install the tool

```bash
pip install .
```

---

## ⚡ Usage

### Analyze a historical log file

```bash
threat-detect --file auth.log
```

---

### Real-time monitoring (SOC-style)

```bash
threat-detect --file auth.log --watch
```

---

## 🧪 Example Output

```text
[BRUTE FORCE][HIGH][T1110] 1.2.3.4 → 6
[USER SCAN][MEDIUM][T1087] 5.5.5.5 → 3
[SCAN][LOW][T1046] Suspicious connection attempt
```

---

## ⚙️ Configuration

Modify detection thresholds dynamically in `config.json` to reduce false positives:

```json
{
  "brute_force_threshold": 5,
  "invalid_user_threshold": 3,
  "top_attackers_limit": 5
}
```

---

## 📁 Output

After execution, the tool generates:

* Console alerts (real-time or batch)
* `alerts.json` file with structured threat data

Example:

```json
[
  {
    "ip": "1.2.3.4",
    "type": "Brute Force",
    "count": 6,
    "severity": "HIGH",
    "mitre": "T1110"
  }
]
```

---

## 🧠 Detection Logic

The tool identifies threats by evaluating log patterns against configurable thresholds:

* Repeated failed login attempts exceeding standard user error → **Brute Force (T1110)**
* Multiple invalid usernames attempting access → **User Enumeration (T1087)**
* Protocol anomalies / malformed connections → **Network Scanning (T1046)**

---

## 🛠️ Troubleshooting

### ❌ `threat-detect` command not found

Run:

```bash
pip install .
```

Restart terminal if needed.

---

### ❌ Missing dependencies

```bash
pip install -r requirements.txt
```

---

### ❌ Python not recognized

Install Python:
https://www.python.org/downloads/

---

### ❌ No alerts showing

Your log file may not contain enough attack activity to trigger the thresholds.
Try adding test entries to your `auth.log`:

```text
Failed password for root from 1.2.3.4
Failed password for root from 1.2.3.4
Failed password for root from 1.2.3.4
Failed password for root from 1.2.3.4
Failed password for root from 1.2.3.4
```

---

## 💡 Notes

* Designed specifically for Linux SSH logs (`auth.log`)
* Extensible architecture allows for integration with other log sources
* Engineered to handle massive log ingestion without memory degradation

---

## 📜 License

MIT License