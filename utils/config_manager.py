import json
import os
from datetime import datetime
from typing import Dict, List, Optional
import threading

class ConfigManager:
    def __init__(self, config_file: str = "config.json"):
        """
        Initialize the configuration manager.
        
        Args:
            config_file (str): Path to the configuration file
        """
        self.config_file = config_file
        self.lock = threading.Lock()
        self.config = self._load_config()
        
    def _load_config(self) -> Dict:
        """Load configuration from file or create default"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except Exception:
                return self._create_default_config()
        return self._create_default_config()
        
    def _create_default_config(self) -> Dict:
        """Create default configuration"""
        return {
            "blocked_ips": {},
            "detection_threshold": 0.8,
            "feature_window": 10,
            "current_model": "random_forest_model.joblib",
            "ip_tags": {}
        }
        
    def _save_config(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)
            
    def get_blocked_ips(self) -> Dict[str, Dict]:
        """Get all blocked IPs with their metadata"""
        with self.lock:
            return self.config["blocked_ips"]
            
    def add_blocked_ip(self, ip: str, reason: str = "", tag: str = ""):
        """Add an IP to the blocked list with metadata"""
        with self.lock:
            self.config["blocked_ips"][ip] = {
                "timestamp": datetime.now().isoformat(),
                "reason": reason,
                "tag": tag
            }
            self._save_config()
            
    def remove_blocked_ip(self, ip: str):
        """Remove an IP from the blocked list"""
        with self.lock:
            if ip in self.config["blocked_ips"]:
                del self.config["blocked_ips"][ip]
                self._save_config()
                
    def update_detection_threshold(self, threshold: float):
        """Update the detection threshold"""
        with self.lock:
            self.config["detection_threshold"] = threshold
            self._save_config()
            
    def update_feature_window(self, window: int):
        """Update the feature extraction window"""
        with self.lock:
            self.config["feature_window"] = window
            self._save_config()
            
    def update_current_model(self, model_name: str):
        """Update the current model"""
        with self.lock:
            self.config["current_model"] = model_name
            self._save_config()
            
    def add_ip_tag(self, ip: str, tag: str):
        """Add a tag to an IP"""
        with self.lock:
            self.config["ip_tags"][ip] = tag
            self._save_config()
            
    def get_ip_tag(self, ip: str) -> Optional[str]:
        """Get the tag for an IP"""
        with self.lock:
            return self.config["ip_tags"].get(ip)
            
    def get_all_settings(self) -> Dict:
        """Get all current settings"""
        with self.lock:
            return self.config.copy() 