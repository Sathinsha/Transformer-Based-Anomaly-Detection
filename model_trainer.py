import torch
import torch.nn as nn
import torch.optim as optim
from scapy.all import sniff
import numpy as np
from model import TransformerAnomalyDetector, PacketFeatureExtractor
import threading
import queue
import time
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score

class ModelTrainer:
    def __init__(self, input_dim=8, training_duration=300):
        self.model = TransformerAnomalyDetector(input_dim=input_dim)
        self.feature_extractor = PacketFeatureExtractor()
        self.training_duration = training_duration
        self.packet_queue = queue.Queue()
        self.training_data = []
        self.optimizer = torch.optim.Adam(self.model.parameters(), lr=0.001)
        self.criterion = nn.MSELoss()
        self.scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            self.optimizer, 
            mode='min', 
            factor=0.5, 
            patience=5, 
            verbose=True
        )
        
    def collect_training_data(self):
        """Collect network traffic data for training"""
        start_time = time.time()
        
        def packet_callback(packet):
            if packet.haslayer('IP'):
                features = self.feature_extractor.extract_features(packet)
                self.packet_queue.put(features)
                
        # Start packet capture in a separate thread
        capture_thread = threading.Thread(
            target=lambda: sniff(
                timeout=self.training_duration,
                prn=packet_callback,
                store=0
            )
        )
        capture_thread.start()
        
        # Process packets from queue
        while time.time() - start_time < self.training_duration:
            while not self.packet_queue.empty():
                features = self.packet_queue.get()
                self.training_data.append(features)
            time.sleep(0.1)
            
        capture_thread.join()
        
        # Convert to numpy array
        self.training_data = np.array(self.training_data)
        
    def train_model(self, batch_size=32, epochs=10, learning_rate=0.001):
        """Train the transformer model on collected data"""
        if len(self.training_data) == 0:
            raise ValueError("No training data available")
            
        # Normalize data
        normalized_data = np.array([
            self.feature_extractor.normalize_features(features)
            for features in self.training_data
        ])
        
        # Convert to PyTorch tensor
        train_tensor = torch.FloatTensor(normalized_data)
        
        # Create data loader
        train_dataset = torch.utils.data.TensorDataset(train_tensor)
        train_loader = torch.utils.data.DataLoader(
            train_dataset,
            batch_size=batch_size,
            shuffle=True
        )
        
        # Training loop
        self.model.train()
        for epoch in range(epochs):
            total_loss = 0
            for batch in train_loader:
                features = batch[0]
                
                # Forward pass
                reconstructed = self.model(features)
                loss = self.criterion(reconstructed, features)
                
                # Backward pass
                self.optimizer.zero_grad()
                loss.backward()
                self.optimizer.step()
                
                total_loss += loss.item()
                
            avg_loss = total_loss / len(train_loader)
            print(f"Epoch {epoch+1}/{epochs}, Loss: {avg_loss:.6f}")
            
        # Save the trained model
        torch.save(self.model.state_dict(), "anomaly_detector.pth")
        print("Model saved to anomaly_detector.pth")
        
    def train(self):
        """Train model by capturing live packets"""
        training_data = []
        
        def packet_callback(packet):
            if packet.haslayer('IP'):
                features = self.feature_extractor.extract_features(packet)
                normalized_features = self.feature_extractor.normalize_features(features)
                training_data.append(normalized_features)
        
        # Capture packets for training
        print("Capturing packets for training...")
        sniff(prn=packet_callback, timeout=self.training_duration)
        
        if len(training_data) == 0:
            raise Exception("No packets captured for training")
            
        # Convert to tensor and train
        self.train_on_data(training_data)
        
    def train_on_data(self, features_data, callback=None):
        """Train model on pre-captured packet features with evaluation"""
        if len(features_data) == 0:
            raise Exception("No training data provided")
            
        print(f"Training on {len(features_data)} packets...")
        
        # Split data into train and validation sets
        train_data, val_data = train_test_split(features_data, test_size=0.2, random_state=42)
        
        # Convert to tensors
        train_tensor = torch.FloatTensor(train_data)
        val_tensor = torch.FloatTensor(val_data)
        
        # Create data loaders
        train_loader = torch.utils.data.DataLoader(
            train_tensor, 
            batch_size=32, 
            shuffle=True
        )
        val_loader = torch.utils.data.DataLoader(
            val_tensor,
            batch_size=32,
            shuffle=False
        )
        
        # Training loop
        best_val_loss = float('inf')
        best_model = None
        early_stop_counter = 0
        max_early_stop = 10
        
        num_epochs = 50
        train_losses = []
        val_losses = []
        
        for epoch in range(num_epochs):
            # Training phase
            self.model.train()
            train_loss = 0
            num_train_batches = 0
            
            for batch in train_loader:
                self.optimizer.zero_grad()
                output = self.model(batch)
                loss = self.criterion(output, batch)
                loss.backward()
                self.optimizer.step()
                
                train_loss += loss.item()
                num_train_batches += 1
            
            avg_train_loss = train_loss / num_train_batches
            train_losses.append(avg_train_loss)
            
            # Validation phase
            self.model.eval()
            val_loss = 0
            num_val_batches = 0
            
            with torch.no_grad():
                for batch in val_loader:
                    output = self.model(batch)
                    loss = self.criterion(output, batch)
                    val_loss += loss.item()
                    num_val_batches += 1
            
            avg_val_loss = val_loss / num_val_batches
            val_losses.append(avg_val_loss)
            
            # Learning rate scheduling
            self.scheduler.step(avg_val_loss)
            
            # Early stopping check
            if avg_val_loss < best_val_loss:
                best_val_loss = avg_val_loss
                best_model = self.model.state_dict()
                early_stop_counter = 0
            else:
                early_stop_counter += 1
            
            # Progress report
            status = (f"Epoch {epoch+1}/{num_epochs}, "
                     f"Train Loss: {avg_train_loss:.6f}, "
                     f"Val Loss: {avg_val_loss:.6f}")
            print(status)
            
            if callback:
                callback(status + "\n")
            
            if early_stop_counter >= max_early_stop:
                print("Early stopping triggered")
                if callback:
                    callback("Early stopping triggered - model converged\n")
                break
        
        # Load best model
        self.model.load_state_dict(best_model)
        
        # Final evaluation
        self.model.eval()
        anomaly_threshold = self.calculate_threshold(val_loader)
        eval_results = self.evaluate_model(val_loader, anomaly_threshold)
        
        # Save the model
        torch.save({
            'model_state_dict': self.model.state_dict(),
            'threshold': anomaly_threshold,
            'train_losses': train_losses,
            'val_losses': val_losses,
            'eval_results': eval_results
        }, "anomaly_detector.pth")
        
        return eval_results
        
    def calculate_threshold(self, loader):
        """Calculate anomaly threshold based on validation set"""
        reconstruction_errors = []
        
        with torch.no_grad():
            for batch in loader:
                output = self.model(batch)
                errors = torch.mean((batch - output) ** 2, dim=1)
                reconstruction_errors.extend(errors.numpy())
        
        # Set threshold as mean + 2 * std (covers ~95% of normal data)
        threshold = np.mean(reconstruction_errors) + 2 * np.std(reconstruction_errors)
        return threshold
        
    def evaluate_model(self, loader, threshold):
        """Evaluate model performance"""
        all_errors = []
        with torch.no_grad():
            for batch in loader:
                output = self.model(batch)
                errors = torch.mean((batch - output) ** 2, dim=1)
                all_errors.extend(errors.numpy())
        
        # Generate synthetic anomalies by adding noise
        normal_data = np.array(all_errors)
        anomaly_data = normal_data * np.random.uniform(2, 3, size=len(normal_data))
        
        # Combine data and create labels
        all_data = np.concatenate([normal_data, anomaly_data])
        true_labels = np.concatenate([
            np.zeros(len(normal_data)),
            np.ones(len(anomaly_data))
        ])
        
        # Predict anomalies
        pred_labels = (all_data > threshold).astype(int)
        
        # Calculate metrics
        results = {
            'precision': precision_score(true_labels, pred_labels),
            'recall': recall_score(true_labels, pred_labels),
            'f1': f1_score(true_labels, pred_labels),
            'threshold': threshold,
            'normal_mean': np.mean(normal_data),
            'normal_std': np.std(normal_data)
        }
        
        return results 