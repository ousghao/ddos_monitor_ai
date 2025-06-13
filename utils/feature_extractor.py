import numpy as np
from scapy.all import *
from collections import defaultdict
import time
from typing import Dict, List, Tuple

class FeatureExtractor:
    def __init__(self, window_size: int = 10):
        """
        Initialize the feature extractor with a sliding window for packet analysis.
        
        Args:
            window_size (int): Number of seconds to consider for feature extraction
        """
        self.window_size = window_size
        self.packet_buffer = defaultdict(list)
        self.last_cleanup = time.time()
        
    def _cleanup_old_packets(self, current_time: float):
        """Remove packets older than window_size from the buffer"""
        if current_time - self.last_cleanup > 1:  # Cleanup every second
            cutoff_time = current_time - self.window_size
            for ip in list(self.packet_buffer.keys()):
                self.packet_buffer[ip] = [p for p in self.packet_buffer[ip] 
                                        if p['timestamp'] > cutoff_time]
                if not self.packet_buffer[ip]:
                    del self.packet_buffer[ip]
            self.last_cleanup = current_time

    def extract_features(self, packet: Packet) -> Dict[str, float]:
        """
        Extract features from a network packet.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Dictionary of extracted features
        """
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return None
            
        current_time = time.time()
        self._cleanup_old_packets(current_time)
        
        # Extract basic packet information
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        tcp_flags = packet[TCP].flags
        
        # Store packet info in buffer
        packet_info = {
            'timestamp': current_time,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'tcp_flags': tcp_flags,
            'length': len(packet)
        }
        
        self.packet_buffer[src_ip].append(packet_info)
        
        # Calculate features for the source IP
        features = self._calculate_features(src_ip)
        return features

    def _calculate_features(self, ip: str) -> Dict[str, float]:
        """Calculate statistical features for a given IP address"""
        packets = self.packet_buffer[ip]
        if not packets:
            return None
            
        # Basic packet statistics
        packet_lengths = [p['length'] for p in packets]
        packet_times = [p['timestamp'] for p in packets]
        
        # TCP flag counts
        syn_count = sum(1 for p in packets if p['tcp_flags'] & 0x02)  # SYN flag
        ack_count = sum(1 for p in packets if p['tcp_flags'] & 0x10)  # ACK flag
        
        # Calculate time-based features
        time_diffs = np.diff(packet_times) if len(packet_times) > 1 else [0]
        
        features = {
            'packet_count': len(packets),
            'avg_packet_length': np.mean(packet_lengths),
            'std_packet_length': np.std(packet_lengths),
            'min_packet_length': np.min(packet_lengths),
            'max_packet_length': np.max(packet_lengths),
            'avg_time_diff': np.mean(time_diffs),
            'std_time_diff': np.std(time_diffs),
            'syn_ratio': syn_count / len(packets),
            'ack_ratio': ack_count / len(packets),
            'packet_rate': len(packets) / self.window_size
        }
        
        return features

    def get_feature_names(self) -> List[str]:
        """Return the list of feature names in the order they are extracted"""
        return [
            'packet_count',
            'avg_packet_length',
            'std_packet_length',
            'min_packet_length',
            'max_packet_length',
            'avg_time_diff',
            'std_time_diff',
            'syn_ratio',
            'ack_ratio',
            'packet_rate'
        ] 