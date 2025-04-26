import torch
import torch.nn as nn
import numpy as np

class TransformerAnomalyDetector(nn.Module):
    def __init__(self, input_dim=8, nhead=4, num_layers=2, dim_feedforward=128):
        super().__init__()
        
        self.embedding = nn.Linear(input_dim, dim_feedforward)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=dim_feedforward,
            nhead=nhead,
            dim_feedforward=dim_feedforward,
            batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.decoder = nn.Sequential(
            nn.Linear(dim_feedforward, dim_feedforward // 2),
            nn.ReLU(),
            nn.Linear(dim_feedforward // 2, input_dim)
        )
        
    def forward(self, x):
        x = self.embedding(x)
        x = self.transformer(x)
        x = self.decoder(x)
        return x

class PacketFeatureExtractor:
    def __init__(self):
        self.feature_names = [
            'packet_length', 'protocol', 'ttl', 'src_port', 
            'dst_port', 'window_size', 'tcp_flags', 'udp_length'
        ]
        
    def extract_features(self, packet):
        features = []
        
        # Packet length
        features.append(len(packet))
        
        # Protocol
        if packet.haslayer('TCP'):
            features.append(6)  # TCP protocol number
        elif packet.haslayer('UDP'):
            features.append(17)  # UDP protocol number
        else:
            features.append(0)
            
        # TTL
        if 'IP' in packet:
            features.append(packet['IP'].ttl)
        else:
            features.append(0)
            
        # Source port
        if packet.haslayer('TCP') or packet.haslayer('UDP'):
            features.append(packet.sport)
        else:
            features.append(0)
            
        # Destination port
        if packet.haslayer('TCP') or packet.haslayer('UDP'):
            features.append(packet.dport)
        else:
            features.append(0)
            
        # Window size (TCP)
        if packet.haslayer('TCP'):
            features.append(packet['TCP'].window)
        else:
            features.append(0)
            
        # TCP flags
        if packet.haslayer('TCP'):
            features.append(int(packet['TCP'].flags))
        else:
            features.append(0)
            
        # UDP length
        if packet.haslayer('UDP'):
            features.append(packet['UDP'].len)
        else:
            features.append(0)
            
        return np.array(features, dtype=np.float32)

    def normalize_features(self, features):
        # Simple min-max normalization
        return (features - np.min(features)) / (np.max(features) - np.min(features) + 1e-10) 