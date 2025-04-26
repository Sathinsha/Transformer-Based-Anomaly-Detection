import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
import queue
from scapy.all import sniff
import torch
import numpy as np
from datetime import datetime
import os
from model import TransformerAnomalyDetector, PacketFeatureExtractor

# Set appearance mode and default color theme
ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

# Configure matplotlib for dark theme
plt.style.use('dark_background')

class NetworkAnomalyDetectorGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Network Anomaly Detector")
        self.geometry("1200x800")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Set window background color to white
        self.configure(fg_color="white")

        # Initialize status variable
        self.status_var = tk.StringVar(value="Initializing...")

        # Initialize components
        self.packet_queue = queue.Queue()
        self.feature_extractor = PacketFeatureExtractor()
        self.model = TransformerAnomalyDetector()
        
        # Data for plots
        self.traffic_data = []
        self.anomaly_scores = []
        self.timestamps = []
        
        # Add training state variables
        self.training_capture = False
        self.captured_packets = []
        self.capture_count = tk.StringVar(value="Captured Packets: 0")
        
        # Initialize protocol statistics with thread-safe counters
        self.protocol_stats = {
            'TCP': 0,
            'UDP': 0,
            'Other': 0
        }
        
        # Initialize protocol counts with StringVar
        self.protocol_counts = {
            'TCP': tk.StringVar(value="TCP: 0"),
            'UDP': tk.StringVar(value="UDP: 0"),
            'Other': tk.StringVar(value="Other: 0")
        }
        
        # Initialize packet rate variable
        self.packet_rate_var = tk.StringVar(value="Packet Rate: 0/s")
        
        # Create GUI
        self.create_gui_elements()
        self.setup_plots()
        
        # Initialize update timer
        self.after(1000, self.periodic_update)  # Update every second
        
        # Configure style for table with light theme
        style = ttk.Style()
        style.configure("Treeview", 
                       background="white",
                       foreground="black",
                       fieldbackground="white")
        style.configure("Treeview.Heading",
                       background="#f0f0f0",
                       foreground="black")

        # Initialize counters and state
        self.packet_count = 0
        self.anomaly_count = 0
        self.threshold = 0.5
        self.monitoring = False

        # Load model after GUI is created
        self.load_model()
        
    def create_gui_elements(self):
        # Create main container
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Create main frame with white background
        main_frame = ctk.CTkFrame(self, fg_color="white")
        main_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        # Control Panel with light gray background
        control_frame = ctk.CTkFrame(main_frame, fg_color="#f0f0f0")
        control_frame.pack(fill="x", padx=5, pady=5)
        
        # Left side controls with light background
        left_controls = ctk.CTkFrame(control_frame, fg_color="#f0f0f0")
        left_controls.pack(side="left", fill="x", expand=True)
        
        # Buttons frame with light background
        button_frame = ctk.CTkFrame(left_controls, fg_color="#f0f0f0")
        button_frame.pack(side="left", padx=5)
        
        # Update button colors for better contrast
        self.start_button = ctk.CTkButton(
            button_frame, 
            text="Start Monitoring", 
            command=self.toggle_monitoring,
            width=150,
            fg_color="#2B60DE",  # Royal Blue
            hover_color="#1E90FF"  # Dodger Blue
        )
        self.start_button.pack(side="left", padx=5)
        
        # Create training control frame
        self.training_frame = ctk.CTkFrame(button_frame, fg_color="#f0f0f0")
        self.training_frame.pack(side="left", padx=5)
        
        self.retrain_button = ctk.CTkButton(
            self.training_frame, 
            text="Start Capture for Training", 
            command=self.retrain_model,
            width=150,
            fg_color="#2B60DE",
            hover_color="#1E90FF"
        )
        self.retrain_button.pack(side="left", padx=5)
        
        # Create capture counter label (hidden by default)
        self.capture_label = ctk.CTkLabel(
            self.training_frame,
            textvariable=self.capture_count,
            text_color="#1E1E1E",
            width=150
        )
        self.capture_label.pack(side="left", padx=5)
        self.capture_label.pack_forget()  # Hide initially
        
        # Create stop button (hidden by default)
        self.stop_capture_button = ctk.CTkButton(
            self.training_frame,
            text="Stop & Train",
            command=self.stop_capture_and_train,
            width=150,
            fg_color="#FF4444",
            hover_color="#FF6666"
        )
        self.stop_capture_button.pack(side="left", padx=5)
        self.stop_capture_button.pack_forget()  # Hide initially
        
        # Right side controls with light background
        right_controls = ctk.CTkFrame(control_frame, fg_color="#f0f0f0")
        right_controls.pack(side="right", fill="x", padx=5)
        
        # Threshold frame with light background
        threshold_frame = ctk.CTkFrame(right_controls, fg_color="#f0f0f0")
        threshold_frame.pack(side="right", padx=5)
        
        threshold_label = ctk.CTkLabel(
            threshold_frame,
            text="Anomaly Threshold:",
            width=120,
            text_color="#1E1E1E"  # Dark text for contrast
        )
        threshold_label.pack(side="left")
        
        self.threshold_slider = ctk.CTkSlider(
            threshold_frame,
            from_=0,
            to=1,
            number_of_steps=100,
            command=self.update_threshold,
            width=200
        )
        self.threshold_slider.set(0.5)
        self.threshold_slider.pack(side="left", padx=5)
        
        self.threshold_value_label = ctk.CTkLabel(
            threshold_frame,
            text="0.50",
            width=50
        )
        self.threshold_value_label.pack(side="left", padx=5)
        
        # Stats Frame with light gray background
        stats_frame = ctk.CTkFrame(main_frame, fg_color="#f0f0f0")
        stats_frame.pack(fill="x", padx=5, pady=5)
        
        # Update stats labels with dark text
        self.packet_count_var = tk.StringVar(value="Total Packets: 0")
        packet_count_label = ctk.CTkLabel(
            stats_frame, 
            textvariable=self.packet_count_var,
            width=150,
            text_color="#1E1E1E"  # Dark text for contrast
        )
        packet_count_label.pack(side="left", padx=20)
        
        self.anomaly_count_var = tk.StringVar(value="Anomalies: 0")
        anomaly_count_label = ctk.CTkLabel(
            stats_frame, 
            textvariable=self.anomaly_count_var,
            width=150,
            text_color="#1E1E1E"  # Dark text for contrast
        )
        anomaly_count_label.pack(side="left", padx=20)
        
        # Plots frame with dark background for charts
        plots_frame = ctk.CTkFrame(main_frame, fg_color="#1E1E1E")
        plots_frame.pack(fill="x", padx=5, pady=5)
        
        # Create horizontal layout for charts
        charts_container = ctk.CTkFrame(plots_frame, fg_color="#1E1E1E")
        charts_container.pack(fill="x", expand=True)
        
        # Left chart (Traffic)
        self.traffic_canvas_widget = tk.Frame(charts_container)
        self.traffic_canvas_widget.pack(side="left", fill="both", expand=True, padx=2)
        
        # Right chart (Anomaly)
        self.anomaly_canvas_widget = tk.Frame(charts_container)
        self.anomaly_canvas_widget.pack(side="right", fill="both", expand=True, padx=2)
        
        # Create bottom container for table and evaluation
        bottom_container = ctk.CTkFrame(main_frame, fg_color="white")
        bottom_container.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Left side - Anomaly Table (reduced size)
        table_container = ctk.CTkFrame(bottom_container, fg_color="white")
        table_container.pack(side="left", fill="both", expand=True, padx=(0,2.5))
        self.create_anomaly_table(table_container)
        
        # Right side - Model Evaluation Results and Protocol Analysis
        self.eval_container = ctk.CTkFrame(bottom_container, fg_color="white")
        self.eval_container.pack(side="right", fill="both", expand=True, padx=(2.5,0))
        
        # Model Evaluation Box (top part)
        eval_box = ctk.CTkFrame(self.eval_container, fg_color="white")
        eval_box.pack(fill="x", pady=(0, 5))
        
        eval_label = ctk.CTkLabel(
            eval_box,
            text="Model Evaluation Results",
            font=("Helvetica", 14, "bold"),
            text_color="#1E1E1E"
        )
        eval_label.pack(pady=(5, 0))
        
        # Create text widget for evaluation results (reduced height)
        self.eval_text = ctk.CTkTextbox(
            eval_box,
            height=120,  # Reduced height
            font=("Courier", 12),
            text_color="#1E1E1E",
            fg_color="#f5f5f5"
        )
        self.eval_text.pack(fill="x", padx=5, pady=5)
        
        # Protocol Analysis Section (bottom part)
        protocol_frame = ctk.CTkFrame(self.eval_container, fg_color="white")
        protocol_frame.pack(fill="both", expand=True, pady=(5, 0))
        
        protocol_label = ctk.CTkLabel(
            protocol_frame,
            text="Real-time Protocol Analysis",
            font=("Helvetica", 14, "bold"),
            text_color="#1E1E1E"
        )
        protocol_label.pack(pady=(5, 0))
        
        # Protocol statistics frame
        stats_container = ctk.CTkFrame(protocol_frame, fg_color="#f5f5f5")
        stats_container.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Create protocol count labels with custom styling
        for protocol, var in self.protocol_counts.items():
            protocol_stat = ctk.CTkFrame(stats_container, fg_color="#f5f5f5")
            protocol_stat.pack(fill="x", padx=5, pady=2)
            
            count_label = ctk.CTkLabel(
                protocol_stat,
                textvariable=var,
                font=("Helvetica", 12),
                text_color="#1E1E1E"
            )
            count_label.pack(side="left", padx=5)
            
            # Add progress bar for each protocol
            setattr(self, f"{protocol.lower()}_progress", ctk.CTkProgressBar(
                protocol_stat,
                width=200,
                height=15,
                border_width=0,
                fg_color="#e0e0e0",
                progress_color=self.get_protocol_color(protocol)
            ))
            getattr(self, f"{protocol.lower()}_progress").pack(side="right", padx=5)
            getattr(self, f"{protocol.lower()}_progress").set(0)
        
        # Add rate statistics
        rate_frame = ctk.CTkFrame(protocol_frame, fg_color="#f5f5f5")
        rate_frame.pack(fill="x", padx=5, pady=(5, 5))
        
        rate_label = ctk.CTkLabel(
            rate_frame,
            textvariable=self.packet_rate_var,
            font=("Helvetica", 12),
            text_color="#1E1E1E"
        )
        rate_label.pack(pady=5)
        
        # Status bar with light theme
        self.status_bar = ctk.CTkLabel(
            main_frame,
            textvariable=self.status_var,
            anchor="w",
            fg_color="#f0f0f0",
            text_color="#1E1E1E"
        )
        self.status_bar.pack(fill="x", padx=5, pady=2)
        
    def create_anomaly_table(self, parent):
        # Create table frame with white background
        table_frame = ctk.CTkFrame(parent, fg_color="white")
        table_frame.pack(fill="both", expand=True)
        
        # Create table label with larger font
        table_label = ctk.CTkLabel(
            table_frame,
            text="Anomaly Detection Log",
            font=("Helvetica", 18, "bold"),
            text_color="#1E1E1E"
        )
        table_label.pack(pady=(5, 0))
        
        # Configure style for larger fonts and colors
        style = ttk.Style()
        
        # Configure main treeview style
        style.configure(
            "Custom.Treeview",
            font=('Helvetica', 14),
            rowheight=40,
            background="white",
            fieldbackground="white",
            foreground="#1E1E1E",
            borderwidth=0
        )
        
        # Configure header style
        style.configure(
            "Custom.Treeview.Heading",
            font=('Helvetica', 15, 'bold'),
            background="#f0f0f0",
            foreground="#1E1E1E",
            borderwidth=1,
            relief="solid"
        )
        
        # Remove borders
        style.layout("Custom.Treeview", [
            ('Custom.Treeview.treearea', {'sticky': 'nswe'})
        ])
        
        # Create Treeview with custom style
        self.anomaly_table = ttk.Treeview(
            table_frame,
            columns=("timestamp", "ip", "protocol", "score"),
            show="headings",
            height=8,
            style="Custom.Treeview",
            selectmode="none"  # Disable selection highlighting
        )
        
        # Define columns with centered alignment and increased width
        self.anomaly_table.heading("timestamp", text="TIMESTAMP", anchor="center")
        self.anomaly_table.heading("ip", text="IP ADDRESS", anchor="center")
        self.anomaly_table.heading("protocol", text="PROTOCOL", anchor="center")
        self.anomaly_table.heading("score", text="SCORE", anchor="center")
        
        # Configure column widths and alignment
        self.anomaly_table.column("timestamp", width=200, anchor="center")
        self.anomaly_table.column("ip", width=200, anchor="center")
        self.anomaly_table.column("protocol", width=150, anchor="center")
        self.anomaly_table.column("score", width=150, anchor="center")
        
        # Add scrollbar with custom style
        style.configure(
            "Custom.Vertical.TScrollbar",
            background="#f0f0f0",
            bordercolor="#f0f0f0",
            arrowcolor="#1E1E1E",
            troughcolor="#e0e0e0"
        )
        
        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.anomaly_table.yview,
            style="Custom.Vertical.TScrollbar"
        )
        self.anomaly_table.configure(yscrollcommand=scrollbar.set)
        
        # Pack elements
        self.anomaly_table.pack(side="left", fill="both", expand=True, padx=(5,0), pady=5)
        scrollbar.pack(side="right", fill="y", pady=5)
        
        # Initialize tag counter
        self.tag_counter = 0

    def get_score_color(self, score):
        """Generate color gradient based on anomaly score"""
        try:
            # Ensure score is a valid float
            score = float(score)
            
            # Normalize score for color calculation
            if score <= self.threshold:
                # Below threshold: White to Yellow to Orange
                ratio = min(score / self.threshold, 1.0)
                if ratio < 0.5:
                    # White to Yellow
                    intensity = ratio * 2
                    red = 255
                    green = 255
                    blue = int(255 * (1 - intensity))
                else:
                    # Yellow to Orange
                    intensity = (ratio - 0.5) * 2
                    red = 255
                    green = int(255 * (1 - intensity * 0.5))
                    blue = 0
            else:
                # Above threshold: Orange to Red
                excess = score - self.threshold
                max_excess = self.threshold  # Assuming symmetric range
                ratio = min(excess / max_excess, 1.0)
                
                red = 255
                green = int(128 * (1 - ratio))
                blue = 0
            
            # Ensure color values are valid
            red = max(0, min(255, red))
            green = max(0, min(255, green))
            blue = max(0, min(255, blue))
            
            return f'#{red:02x}{green:02x}{blue:02x}'
            
        except Exception as e:
            print(f"Error generating color: {e}")
            return '#FFFFFF'  # Default to white on error
        
    def update_threshold(self, value):
        self.threshold = value
        self.threshold_value_label.configure(text=f"{value:.2f}")
        
    def toggle_monitoring(self):
        if not self.monitoring:
            try:
                self.monitoring = True
                self.start_button.configure(text="Stop Monitoring")
                self.capture_thread = threading.Thread(target=self.capture_packets)
                self.capture_thread.daemon = True
                self.capture_thread.start()
                self.status_var.set("Monitoring network traffic...")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to start monitoring: {str(e)}")
                self.monitoring = False
                self.start_button.configure(text="Start Monitoring")
        else:
            self.monitoring = False
            self.start_button.configure(text="Start Monitoring")
            self.status_var.set("Monitoring stopped")
            
    def capture_packets(self):
        def handle_error(error_msg):
            self.after(0, lambda: self.status_var.set(error_msg))
            self.after(0, lambda: self.start_button.configure(text="Start Monitoring"))
            self.monitoring = False

        while self.monitoring:
            try:
                # Try to start packet capture
                sniff(count=1, prn=self.process_packet, store=0)
            except PermissionError:
                error_msg = "Error: Administrator privileges required for packet capture"
                print(error_msg)
                handle_error(error_msg)
                messagebox.showerror("Permission Error", 
                    "This application requires administrator privileges to capture network packets.\n"
                    "Please restart the application as administrator.")
                break
            except Exception as e:
                error_msg = f"Error capturing packet: {str(e)}"
                print(error_msg)
                handle_error(error_msg)
                break
                
    def process_packet(self, packet):
        if not packet.haslayer('IP'):
            return
            
        try:
            # Extract features
            features = self.feature_extractor.extract_features(packet)
            normalized_features = self.feature_extractor.normalize_features(features)
            
            # Add to queue for processing
            self.packet_queue.put((packet, normalized_features))
            self.packet_count += 1
            
            # Update protocol statistics immediately
            protocol = 'Other'
            if packet.haslayer('TCP'):
                protocol = 'TCP'
            elif packet.haslayer('UDP'):
                protocol = 'UDP'
            
            # Thread-safe protocol stats update using after method
            self.after(0, lambda p=protocol: self.update_protocol_count(p))
            
            # Update packet rate calculation
            current_time = datetime.now()
            self.timestamps.append(current_time)
            
            # Remove timestamps older than 1 second
            while len(self.timestamps) > 0 and (current_time - self.timestamps[0]).total_seconds() > 1:
                self.timestamps.pop(0)
            
            # Calculate packets per second
            packets_per_second = len(self.timestamps)
            
            # Update packet rate display immediately
            self.after(0, lambda: self.packet_rate_var.set(f"Packet Rate: {packets_per_second}/s"))
            
            # Schedule GUI updates
            self.after(10, lambda: self.update_gui(packets_per_second))
            
        except Exception as e:
            print(f"Error processing packet: {e}")
            self.after(0, lambda: self.status_var.set(f"Error processing packet: {str(e)}"))
        
    def update_gui(self, packets_per_second=0):
        try:
            # Process packets in queue
            while not self.packet_queue.empty():
                packet, features = self.packet_queue.get()
                
                # Get model prediction
                with torch.no_grad():
                    features_tensor = torch.FloatTensor(features).unsqueeze(0)
                    reconstruction = self.model(features_tensor)
                    mse = torch.mean((features_tensor - reconstruction) ** 2).item()
                    
                # Update plots
                self.update_plots(mse, packets_per_second)
                
                # Update counts
                self.packet_count_var.set(f"Total Packets: {self.packet_count} (Rate: {packets_per_second}/s)")
                
                if mse > self.threshold:
                    self.anomaly_count += 1
                    self.anomaly_count_var.set(f"Anomalies: {self.anomaly_count}")
                    self.add_anomaly_to_table(packet, mse)
                    
                    # Flash status bar for anomalies
                    self.status_var.set(f"⚠️ Anomaly detected! Score: {mse:.4f}")
                    self.after(2000, lambda: self.status_var.set("Monitoring network traffic..."))
                    
        except Exception as e:
            print(f"Error updating GUI: {e}")
            self.status_var.set(f"Error updating GUI: {str(e)}")
                
    def update_plots(self, anomaly_score, packets_per_second):
        try:
            timestamp = datetime.now()
            
            # Update anomaly score data
            self.anomaly_scores.append(anomaly_score)
            if len(self.anomaly_scores) > 100:
                self.anomaly_scores.pop(0)
            
            # Update traffic plot
            self.traffic_ax.clear()
            self.traffic_ax.plot(range(len(self.timestamps)), 
                               [packets_per_second] * len(self.timestamps), 
                               'b-', label='Packets/s')
            self.traffic_ax.set_title("Network Traffic Rate")
            self.traffic_ax.set_ylabel("Packets/s")
            self.traffic_ax.grid(True, alpha=0.3)
            self.traffic_canvas.draw()
            
            # Update anomaly plot
            self.anomaly_ax.clear()
            self.anomaly_ax.plot(range(len(self.anomaly_scores)), 
                               self.anomaly_scores, 
                               'r-', label='Anomaly Score')
            self.anomaly_ax.axhline(y=self.threshold, 
                                   color='g', 
                                   linestyle='--',
                                   label='Threshold')
            self.anomaly_ax.set_title("Anomaly Scores")
            self.anomaly_ax.set_ylabel("Score")
            self.anomaly_ax.grid(True, alpha=0.3)
            self.anomaly_ax.legend()
            self.anomaly_canvas.draw()
        except Exception as e:
            print(f"Error updating plots: {e}")
            self.status_var.set(f"Error updating plots: {str(e)}")
        
    def add_anomaly_to_table(self, packet, score):
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ip = packet['IP'].src if packet.haslayer('IP') else "Unknown"
            protocol = "TCP" if packet.haslayer('TCP') else "UDP" if packet.haslayer('UDP') else "Other"
            
            # Format score with appropriate color and symbol
            score_str = f"{score:.4f}"
            if score > self.threshold:
                score_str = f"⚠️ {score:.4f}"
            
            # Generate unique tag
            tag_name = f"score_{self.tag_counter}"
            self.tag_counter += 1
            
            # Configure tag with background color before inserting
            try:
                color = self.get_score_color(score)
                self.anomaly_table.tag_configure(
                    tag_name,
                    background=color,
                    foreground="#000000" if score <= self.threshold else "#FFFFFF"
                )
            except Exception as e:
                print(f"Error configuring tag: {e}")
                tag_name = ""  # Use no tag if configuration fails
            
            # Insert new row with tag
            item_id = self.anomaly_table.insert(
                "", 0,
                values=(timestamp, ip, protocol, score_str),
                tags=(tag_name,)
            )
            
            # Keep only last 100 entries
            all_items = self.anomaly_table.get_children()
            if len(all_items) > 100:
                old_item = all_items[-1]
                # Clean up old tags
                old_tags = self.anomaly_table.item(old_item, "tags")
                self.anomaly_table.delete(old_item)
                for tag in old_tags:
                    try:
                        self.anomaly_table.tag_delete(tag)
                    except:
                        pass
                
        except Exception as e:
            print(f"Error adding anomaly to table: {e}")
            self.status_var.set(f"Error adding anomaly to table: {str(e)}")
            
    def load_model(self):
        try:
            if os.path.exists("anomaly_detector.pth"):
                # Load the checkpoint that contains model state and metrics
                checkpoint = torch.load("anomaly_detector.pth")
                
                # Load model state
                self.model.load_state_dict(checkpoint['model_state_dict'])
                self.model.eval()
                
                # Set threshold from saved model
                if 'threshold' in checkpoint:
                    self.threshold = checkpoint['threshold']
                    self.threshold_slider.set(self.threshold)
                    self.threshold_value_label.configure(text=f"{self.threshold:.2f}")
                
                # Display evaluation results if available
                if 'eval_results' in checkpoint and hasattr(self, 'eval_text'):
                    eval_results = checkpoint['eval_results']
                    eval_summary = (
                        "=== Loaded Model Evaluation Results ===\n"
                        f"Precision: {eval_results['precision']:.4f}\n"
                        f"Recall: {eval_results['recall']:.4f}\n"
                        f"F1 Score: {eval_results['f1']:.4f}\n"
                        f"Anomaly Threshold: {eval_results['threshold']:.6f}\n"
                        f"Normal Traffic Stats:\n"
                        f"  Mean: {eval_results['normal_mean']:.6f}\n"
                        f"  Std: {eval_results['normal_std']:.6f}\n"
                    )
                    self.eval_text.delete('1.0', 'end')
                    self.eval_text.insert('end', eval_summary)
                
                self.status_var.set("Model loaded successfully")
            else:
                self.status_var.set("No pre-trained model found. Using initial model.")
                
        except Exception as e:
            print(f"Error loading model: {e}")
            self.status_var.set(f"Error loading model: {str(e)}")
            # Initialize a fresh model if loading fails
            self.model = TransformerAnomalyDetector()
            self.model.eval()
        
    def retrain_model(self):
        try:
            if not self.training_capture:
                # Start capturing packets for training
                self.training_capture = True
                self.captured_packets = []
                self.capture_count.set("Captured Packets: 0")
                
                # Update UI
                self.retrain_button.configure(state="disabled")
                self.start_button.configure(state="disabled")
                self.capture_label.pack(side="left", padx=5)  # Show counter
                self.stop_capture_button.pack(side="left", padx=5)  # Show stop button
                
                # Start capture thread
                self.training_thread = threading.Thread(target=self.capture_training_packets)
                self.training_thread.daemon = True
                self.training_thread.start()
                
                self.status_var.set("Capturing packets for training...")
                
        except Exception as e:
            print(f"Error starting training capture: {e}")
            self.status_var.set(f"Error starting training capture: {str(e)}")

    def capture_training_packets(self):
        def handle_packet(packet):
            if not packet.haslayer('IP'):
                return
            
            try:
                features = self.feature_extractor.extract_features(packet)
                normalized_features = self.feature_extractor.normalize_features(features)
                self.captured_packets.append((packet, normalized_features))
                
                # Update counter
                self.after(0, lambda: self.capture_count.set(f"Captured Packets: {len(self.captured_packets)}"))
                
            except Exception as e:
                print(f"Error processing training packet: {e}")

        while self.training_capture:
            try:
                sniff(count=1, prn=handle_packet, store=0)
            except Exception as e:
                print(f"Error in training capture: {e}")
                self.after(0, lambda: self.status_var.set(f"Error in training capture: {str(e)}"))
                break

    def stop_capture_and_train(self):
        try:
            self.training_capture = False
            self.stop_capture_button.configure(state="disabled")
            
            if len(self.captured_packets) < 100:  # Minimum packets threshold
                messagebox.showwarning("Warning", 
                    "Not enough packets captured (minimum 100 required).\nPlease capture more packets.")
                self.reset_training_ui()
                return
            
            self.status_var.set(f"Starting training on {len(self.captured_packets)} packets...")
            
            # Start actual training in a separate thread
            training_thread = threading.Thread(target=self.train_on_captured)
            training_thread.daemon = True
            training_thread.start()
            
        except Exception as e:
            print(f"Error stopping capture: {e}")
            self.status_var.set(f"Error stopping capture: {str(e)}")
            self.reset_training_ui()

    def train_on_captured(self):
        try:
            from model_trainer import ModelTrainer
            
            # Create feature dataset from captured packets
            features_data = [features for _, features in self.captured_packets]
            
            self.after(0, lambda: self.status_var.set("Training model on captured packets..."))
            self.after(0, lambda: self.eval_text.delete('1.0', 'end'))
            self.after(0, lambda: self.eval_text.insert('end', "Starting training...\n"))
            
            def update_training_status(status):
                self.after(0, lambda: self.eval_text.insert('end', status))
                self.after(0, lambda: self.eval_text.see('end'))
            
            # Initialize and train model
            trainer = ModelTrainer()
            eval_results = trainer.train_on_data(features_data, callback=update_training_status)
            
            # Display evaluation results
            eval_summary = (
                "\n=== Model Evaluation Results ===\n"
                f"Precision: {eval_results['precision']:.4f}\n"
                f"Recall: {eval_results['recall']:.4f}\n"
                f"F1 Score: {eval_results['f1']:.4f}\n"
                f"Anomaly Threshold: {eval_results['threshold']:.6f}\n"
                f"Normal Traffic Stats:\n"
                f"  Mean: {eval_results['normal_mean']:.6f}\n"
                f"  Std: {eval_results['normal_std']:.6f}\n"
            )
            
            self.after(0, lambda: self.eval_text.insert('end', eval_summary))
            self.after(0, lambda: self.eval_text.see('end'))
            
            # Load the newly trained model
            checkpoint = torch.load("anomaly_detector.pth")
            self.model.load_state_dict(checkpoint['model_state_dict'])
            self.model.eval()
            
            # Update threshold
            self.threshold = checkpoint['threshold']
            self.threshold_slider.set(self.threshold)
            self.threshold_value_label.configure(text=f"{self.threshold:.2f}")
            
            self.after(0, lambda: self.status_var.set("Model training completed successfully"))
            
        except Exception as e:
            print(f"Error during training: {e}")
            self.after(0, lambda: self.status_var.set(f"Error during training: {str(e)}"))
        finally:
            self.after(0, self.reset_training_ui)

    def reset_training_ui(self):
        """Reset UI elements after training"""
        self.training_capture = False
        self.captured_packets = []
        self.capture_count.set("Captured Packets: 0")
        
        # Reset buttons and labels
        self.retrain_button.configure(state="normal")
        self.start_button.configure(state="normal")
        self.stop_capture_button.pack_forget()
        self.capture_label.pack_forget()
        
    def on_closing(self):
        """Clean up resources before closing"""
        try:
            self.monitoring = False
            plt.close('all')  # Close all matplotlib figures
            self.quit()
        except Exception as e:
            print(f"Error during cleanup: {e}")
            self.quit()
        
    def run(self):
        try:
            self.mainloop()
        except Exception as e:
            print(f"Error in main loop: {e}")
            self.quit()

    def setup_plots(self):
        try:
            # Traffic plot with adjusted size
            self.traffic_fig, self.traffic_ax = plt.subplots(figsize=(8, 3))
            self.traffic_canvas = FigureCanvasTkAgg(
                self.traffic_fig, 
                self.traffic_canvas_widget
            )
            self.traffic_canvas.get_tk_widget().pack(fill="both", expand=True)
            
            # Anomaly score plot with adjusted size
            self.anomaly_fig, self.anomaly_ax = plt.subplots(figsize=(8, 3))
            self.anomaly_canvas = FigureCanvasTkAgg(
                self.anomaly_fig, 
                self.anomaly_canvas_widget
            )
            self.anomaly_canvas.get_tk_widget().pack(fill="both", expand=True)
            
            # Configure plots
            self.traffic_ax.set_facecolor('#2a2d2e')
            self.traffic_fig.patch.set_facecolor('#2a2d2e')
            self.anomaly_ax.set_facecolor('#2a2d2e')
            self.anomaly_fig.patch.set_facecolor('#2a2d2e')
            
            # Add more padding to plots
            self.traffic_fig.tight_layout(pad=2.0)
            self.anomaly_fig.tight_layout(pad=2.0)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to setup plots: {str(e)}")

    def get_protocol_color(self, protocol):
        """Return color for different protocols"""
        colors = {
            'TCP': "#2B60DE",  # Royal Blue
            'UDP': "#50C878",  # Emerald Green
            'Other': "#FF8C00"  # Dark Orange
        }
        return colors.get(protocol, "#808080")  # Default gray

    def update_protocol_count(self, protocol):
        """Thread-safe update of protocol statistics"""
        try:
            # Update the counter
            self.protocol_stats[protocol] += 1
            
            # Update the display immediately
            count = self.protocol_stats[protocol]
            self.protocol_counts[protocol].set(f"{protocol}: {count}")
            
            # Calculate and update progress bar
            total = sum(self.protocol_stats.values())
            if total > 0:
                percentage = count / total
                progress_bar = getattr(self, f"{protocol.lower()}_progress")
                if progress_bar:
                    progress_bar.set(percentage)
                    
        except Exception as e:
            print(f"Error updating protocol count: {e}")

    def update_protocol_stats(self):
        """Update protocol statistics display"""
        try:
            total_packets = sum(self.protocol_stats.values())
            if total_packets > 0:
                for protocol in self.protocol_stats:
                    count = self.protocol_stats[protocol]
                    percentage = count / total_packets
                    
                    # Update count display
                    self.protocol_counts[protocol].set(f"{protocol}: {count}")
                    
                    # Update progress bar
                    progress_bar = getattr(self, f"{protocol.lower()}_progress")
                    if progress_bar:
                        progress_bar.set(percentage)
                        
        except Exception as e:
            print(f"Error updating protocol stats: {e}")

    def periodic_update(self):
        """Periodic update of GUI elements"""
        try:
            # Update protocol statistics
            self.update_protocol_stats()
            
            # Schedule next update
            self.after(1000, self.periodic_update)
        except Exception as e:
            print(f"Error in periodic update: {e}")
            # Ensure the timer continues even if there's an error
            self.after(1000, self.periodic_update)

if __name__ == "__main__":
    try:
        app = NetworkAnomalyDetectorGUI()
        app.run()
    except Exception as e:
        print(f"Failed to start application: {e}")
        messagebox.showerror("Error", f"Failed to start application: {str(e)}") 