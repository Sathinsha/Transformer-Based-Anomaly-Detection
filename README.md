

# 🚀 Network Anomaly Detection System  
[![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)  
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)  
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20Mac-informational)]()  
**Developed by: Sathinsha Semasinghe**

---

A real-time network traffic monitoring and anomaly detection system using a Transformer-based deep learning model.  
The system provides a modern GUI interface for monitoring network traffic, detecting anomalies, and visualizing network statistics.

---

## ✨ Features

- Real-time network packet capture and analysis
- Transformer-based anomaly detection
- Interactive GUI with dark/light theme support
- Live traffic visualization and statistics
- Protocol-specific monitoring (TCP, UDP, Others)
- Adjustable anomaly detection threshold
- Real-time packet rate monitoring
- Anomaly event logging with detailed information
- Model retraining capability with live data
- Thread-safe packet processing
- Automatic periodic updates
- Color-coded anomaly scoring system

---

## 🖥️ Interface Overview

### Main Window
- **Resolution**: 1200×800 pixels
- **Theme**: Light mode with blue accent colors
- **Design**: Clean white background with contrasting elements

### Control Panel
- **Monitoring Controls**:
  - Start/Stop Monitoring (Royal Blue `#2B60DE`)
  - "Start Capture for Training" button
  - Packet counter and "Stop & Train" button (Red `#FF4444`)
- **Threshold Control**:
  - Adjustable slider (0–1 range, 100 steps)
  - Current threshold display
- **Statistics Panel**:
  - Protocol counters (TCP, UDP, Other)
  - Real-time packet rate display
- **Visualization Area**:
  - Dark-themed Matplotlib graphs
  - Real-time traffic and protocol charts
  - Anomaly score timeline
- **Anomaly Table**:
  - Custom-styled Treeview with color-coded entries
  - Auto-updating with sortable columns

---

## 🛠️ Technical Architecture

| Component              | Details                                                                 |
|-------------------------|-------------------------------------------------------------------------|
| **Transformer Model**   | Custom architecture for anomaly detection (8-dimensional input)         |
| **Model Training**      | Live packet capture, early stopping, learning rate scheduling           |
| **GUI Application**     | Built with CustomTkinter, real-time Matplotlib visualization            |
| **Thread Management**   | Thread-safe packet processing and periodic updates                     |

---

## 📦 Requirements

```bash
customtkinter==5.2.0
matplotlib==3.7.1
scapy==2.5.0
torch==2.0.1
numpy==1.24.3
```

---

## ⚙️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/network-anomaly-detection.git
   cd network-anomaly-detection
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Usage

1. Start the application:
   ```bash
   python network_ids.py
   ```

2. Key Features:
   - Monitor real-time network traffic
   - Adjust anomaly detection sensitivity
   - View live statistics and anomaly scores
   - Capture and retrain models using real traffic

3. Model Retraining:
   - "Start Capture for Training" to collect new data
   - "Stop & Train" to retrain the model
   - The model is automatically updated and loaded

---

## 🔍 Feature Details

### Packet Features Analyzed
- Packet length
- Protocol type (TCP/UDP)
- Time-to-Live (TTL)
- Source port
- Destination port
- Window size (TCP)
- TCP flags
- UDP packet length

### Anomaly Detection
- Based on reconstruction error
- Adjustable classification threshold
- Real-time scoring and anomaly visualization
- Severity color indicators:
  - Normal: White → Yellow
  - Suspicious: Orange
  - Anomalous: Red

### Real-Time Visualization
- Live packet rate graph
- Protocol distribution bar charts
- Anomaly score timeline
- Real-time updates every second
- Dark-themed plots for enhanced clarity

---

## 🔒 Security Considerations

- Passive monitoring (no packet alteration)
- Local-only operation (no data transmission)
- Secure, thread-safe data handling
- Graceful shutdown and recovery features

---

## 🧩 Development Structure

- `network_ids.py`: Main application and GUI management
- `model.py`: Transformer model design and packet feature extraction
- `model_trainer.py`: Live data training and model optimization

---

## 🛡️ Error Handling

- Smooth shutdown on closing the app
- Thread-safe operation
- Popup error messages via messagebox
- Automatic recovery from training errors
- Preservation of model training state

---

## 📝 License

This project is licensed under the **MIT License**.

---

## 🙏 Acknowledgments

- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) – GUI framework
- [Scapy](https://scapy.net/) – Network packet manipulation
- [PyTorch](https://pytorch.org/) – Deep learning framework
- [Matplotlib](https://matplotlib.org/) – Visualization library

---

## ✍️ Developed with passion by **Sathinsha Semasinghe**


