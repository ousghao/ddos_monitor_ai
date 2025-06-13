#!/usr/bin/env python3
import os
import sys
import time
import logging
import threading
import subprocess
from datetime import datetime
from typing import Dict, Optional
import joblib
import numpy as np
from scapy.all import sniff, IP, TCP
import pandas as pd

from utils.feature_extractor import FeatureExtractor
from utils.visualizer import TrafficVisualizer
from utils.state_manager import StateManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'ddos_detection_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class DDoSDetector:
    def __init__(self, model_path: str, interface: str, threshold: float = 0.8):
        """
        Initialize the DDoS detector.
        
        Args:
            model_path (str): Path to the trained model file
            interface (str): Network interface to monitor
            threshold (float): Probability threshold for attack detection
        """
        self.interface = interface
        self.threshold = threshold
        self.feature_extractor = FeatureExtractor()
        self.visualizer = TrafficVisualizer()
        self.state_manager = StateManager()
        
        # Load the trained model
        try:
            self.model = joblib.load(model_path)
            logger.info(f"Successfully loaded model from {model_path}")
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            raise
            
        # Initialize attack tracking
        self.attack_counts: Dict[str, int] = {}
        self.blocked_ips: set = set()
        
        # Start visualization in a separate thread
        self.viz_thread = threading.Thread(target=self.visualizer.start)
        self.viz_thread.daemon = True
        self.viz_thread.start()
        
    def block_ip(self, ip: str):
        """Block an IP address using iptables"""
        if ip in self.blocked_ips:
            return
            
        try:
            # Add iptables rule to block the IP
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            self.blocked_ips.add(ip)
            self.state_manager.add_block(ip, datetime.now())
            logger.warning(f"Blocked IP address: {ip}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error blocking IP {ip}: {str(e)}")
            
    def process_packet(self, packet):
        """Process a network packet and detect potential attacks"""
        try:
            # Extract features from the packet
            features = self.feature_extractor.extract_features(packet)
            if features is None:
                return
                
            # Convert features to model input format
            feature_names = self.feature_extractor.get_feature_names()
            feature_vector = np.array([features[f] for f in feature_names]).reshape(1, -1)
            
            # Make prediction
            attack_probability = self.model.predict_proba(feature_vector)[0][1]
            
            # Update visualization
            self.visualizer.update_data(
                packet_rate=features['packet_rate'],
                attack_probability=attack_probability
            )
            
            # Update state manager with metrics
            self.state_manager.update_metrics(
                syn_counts={packet[IP].src: features['syn_ratio'] * features['packet_count']},
                traffic_rates={packet[IP].src: features['packet_rate']},
                alert_rates={packet[IP].src: attack_probability}
            )
            
            # Check for attack
            if attack_probability > self.threshold:
                src_ip = packet[IP].src
                self.attack_counts[src_ip] = self.attack_counts.get(src_ip, 0) + 1
                
                # Log potential attack
                logger.warning(
                    f"Potential DDoS attack detected from {src_ip} "
                    f"(probability: {attack_probability:.2f})"
                )
                
                # Add alert to state manager
                self.state_manager.add_alert(src_ip, attack_probability, datetime.now())
                
                # Block IP if auto-blocking is enabled and threshold reached
                if (self.state_manager.auto_blocking and 
                    self.attack_counts[src_ip] >= 3):
                    self.block_ip(src_ip)
                    
        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")
            
    def start(self):
        """Start the DDoS detection system"""
        logger.info(f"Starting DDoS detection on interface {self.interface}")
        try:
            # Start packet capture
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                store=0
            )
        except KeyboardInterrupt:
            logger.info("Stopping DDoS detection")
            self.visualizer.stop()
        except Exception as e:
            logger.error(f"Error in packet capture: {str(e)}")
            self.visualizer.stop()
            raise

def main():
    """Main entry point"""
    if os.geteuid() != 0:
        logger.error("This script must be run as root")
        sys.exit(1)
        
    # Configuration
    MODEL_PATH = "model2001/random_forest_model.joblib"  # Update with your model path
    INTERFACE = "eth0"  # Update with your interface
    THRESHOLD = 0.8
    
    try:
        detector = DDoSDetector(MODEL_PATH, INTERFACE, THRESHOLD)
        detector.start()
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 