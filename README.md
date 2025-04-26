
# 🚀 Network Anomaly Detection System  
**Author: Sathinsha Semasinghe**

A real-time network traffic monitoring and anomaly detection system featuring an advanced GUI, built using Python and deep learning.

---

## ✨ Features

### 🛰️ Real-time Network Monitoring
- Live packet capture and analysis
- Protocol-based traffic classification (TCP, UDP, Other)
- Real-time packet rate monitoring
- Dynamic traffic visualization

### 🛡️ Advanced Anomaly Detection
- Transformer-based deep learning model
- Real-time anomaly scoring
- Adaptive threshold adjustment
- Early warning alerts for potential threats

### 🖥️ Interactive GUI
- **Live Traffic Display**
  - Real-time packet rate graphs
  - Protocol distribution visualized with progress bars
  - Color-coded anomaly score visualization
- **Anomaly Detection Log**
  - Severity-based color gradients
  - Timestamp, IP, Protocol, and Score tracking
  - Warning indicators for critical anomalies
  - Auto-scrolling with 100-entry history
- **Protocol Analysis**
  - Real-time protocol distribution
  - Visual traffic composition bars
  - Packet rate statistics
- **Model Evaluation**
  - Performance metrics display
  - Threshold configuration
  - Live model training updates

### 🛠️ Model Training Capabilities
- In-app model training interface
- Real-time training progress monitoring
- Automatic model evaluation and metrics reporting

---

## 📦 Requirements

```bash
Python >= 3.8
customtkinter >= 5.2.0
tkinter
matplotlib >= 3.7.1
scapy >= 2.5.0
torch >= 2.0.1
numpy >= 1.24.3
```

---

## 🛠️ Installation Guide

### Prerequisites

**1. Install Wireshark**

- **Windows**:  
  Download from [Wireshark.org](https://www.wireshark.org/download.html) and ensure "Install Npcap" is selected. Add Wireshark to PATH.

- **Linux**:
  ```bash
  sudo apt-get update
  sudo apt-get install wireshark libpcap-dev
  ```

- **Mac**:
  ```bash
  brew install wireshark
  ```

**2. Install VS Code Extensions**
- Install "Python" and "Pylance" extensions.
- Reload VS Code.

---

### Python Environment Setup

1. Install Python 3.8 or newer: [python.org](https://python.org)
2. Create and activate a virtual environment:

   **Windows:**
   ```bash
   python -m venv venv
   .\venv\Scripts\activate
   ```

   **Linux/Mac:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Upgrade pip:
   ```bash
   python -m pip install --upgrade pip
   ```

4. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/network-anomaly-detection.git
   cd network-anomaly-detection
   ```

5. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

### System-specific Notes

- **Tkinter**:
  - Windows: Included with Python
  - Linux:
    ```bash
    sudo apt-get install python3-tk
    ```
  - Mac:
    ```bash
    brew install python-tk@3.9
    ```

---

## 🧪 Verifying Installation

```bash
python --version
python -c "import customtkinter; import matplotlib; import scapy.all; import torch; import numpy"
```

Check Wireshark configuration:
```bash
python -c "import scapy.all as scapy; print(scapy.conf.prog.wireshark)"
```

---

## 🚀 Running the Application

**Windows**:
```bash
python network_ids.py
```
(Ensure you run the terminal as Administrator.)

**Linux/Mac**:
```bash
sudo python network_ids.py
```

> **Note:** Root/Admin privileges are necessary for packet capturing.

---

## 📖 Usage Guide

- **Start Monitoring**: Launch the app and click "Start Monitoring."
- **Traffic Visualization**: Observe real-time packet rates, protocol distribution, and anomaly scores.
- **Anomaly Detection**:
  - White → Yellow: Normal
  - Orange: Suspicious
  - Red: Anomalous
  - ⚠️ Warning: Above-threshold anomalies
- **Threshold Adjustment**: Tune sensitivity with the provided slider.
- **Model Training**: Capture ≥100 packets → Train → Evaluate.

---

## 🛠️ Technical Details

| Component       | Technology            |
|-----------------|------------------------|
| GUI             | CustomTkinter, Tkinter |
| Packet Capture  | Scapy                  |
| ML Model        | Transformer-based      |
| Visualization   | Matplotlib             |

---

## 🛡️ Security Features

- Real-time threat alerts
- Configurable thresholds
- Detailed packet analysis
- Historical tracking of anomalies

---

## 🛠️ Troubleshooting

- **Permission Errors**: Run with Administrator rights.
- **High CPU Usage**: Reduce update rates.
- **Display Glitches**: Update drivers, verify Tkinter.

Common errors:
| Error                             | Solution                                       |
|-----------------------------------|------------------------------------------------|
| "Administrator privileges required" | Run as Admin/root.                          |
| "Error capturing packet"          | Verify network interface and Scapy install.  |

---

## 👥 Contributing

1. Fork the repo
2. Create a feature branch
3. Commit & push changes
4. Open a Pull Request 🚀

---

## 📝 License

This project is licensed under the **MIT License**.  
See the [LICENSE](LICENSE) file for more details.

---

## 🙏 Acknowledgments

- CustomTkinter for UI enhancements
- Scapy for packet capture
- PyTorch for model training
- Matplotlib for dynamic graphs

---

## 📈 Version History

- **v1.0.0**: Initial Release - Basic monitoring and detection
- **v2.0.0**: Major Upgrade - Advanced GUI, improved detection, model training feature

---

## 🌟 Future Plans

- Deep packet inspection
- Custom visual themes
- Statistical reporting
- Automated threat responses

---

## 📬 Contact

For queries or support, feel free to open an issue in the repository.

---

### ✍️ Developed by **Sathinsha Semasinghe**

