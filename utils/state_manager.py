from collections import deque
from datetime import datetime
import threading
from typing import Dict, List, Deque, Optional
import queue

class StateManager:
    def __init__(self, max_history: int = 1000):
        """
        Initialize the state manager for sharing data between detector and Streamlit.
        
        Args:
            max_history (int): Maximum number of historical records to keep
        """
        self.max_history = max_history
        
        # Thread-safe queues for real-time updates
        self.alert_queue = queue.Queue()
        self.block_queue = queue.Queue()
        
        # Historical data storage
        self.syn_counts: Deque[Dict[str, int]] = deque(maxlen=max_history)
        self.traffic_rates: Deque[Dict[str, float]] = deque(maxlen=max_history)
        self.alert_rates: Deque[Dict[str, float]] = deque(maxlen=max_history)
        
        # Current state
        self.blocked_ips: set = set()
        self.auto_blocking: bool = True
        self.last_update: datetime = datetime.now()
        
        # Thread safety
        self.lock = threading.Lock()
        
    def add_alert(self, ip: str, probability: float, timestamp: datetime):
        """Add a new alert to the queue"""
        self.alert_queue.put({
            'ip': ip,
            'probability': probability,
            'timestamp': timestamp
        })
        
    def add_block(self, ip: str, timestamp: datetime):
        """Add a new blocked IP to the queue"""
        self.block_queue.put({
            'ip': ip,
            'timestamp': timestamp
        })
        with self.lock:
            self.blocked_ips.add(ip)
            
    def remove_block(self, ip: str):
        """Remove an IP from the blocked list"""
        with self.lock:
            self.blocked_ips.discard(ip)
            
    def update_metrics(self, 
                      syn_counts: Dict[str, int],
                      traffic_rates: Dict[str, float],
                      alert_rates: Dict[str, float]):
        """Update historical metrics"""
        with self.lock:
            self.syn_counts.append(syn_counts)
            self.traffic_rates.append(traffic_rates)
            self.alert_rates.append(alert_rates)
            self.last_update = datetime.now()
            
    def get_metrics(self) -> Dict:
        """Get current metrics for Streamlit display"""
        with self.lock:
            return {
                'syn_counts': list(self.syn_counts),
                'traffic_rates': list(self.traffic_rates),
                'alert_rates': list(self.alert_rates),
                'blocked_ips': list(self.blocked_ips),
                'last_update': self.last_update,
                'auto_blocking': self.auto_blocking
            }
            
    def toggle_auto_blocking(self):
        """Toggle automatic IP blocking"""
        with self.lock:
            self.auto_blocking = not self.auto_blocking
            return self.auto_blocking
            
    def get_new_alerts(self) -> List[Dict]:
        """Get new alerts from the queue"""
        alerts = []
        while not self.alert_queue.empty():
            try:
                alerts.append(self.alert_queue.get_nowait())
            except queue.Empty:
                break
        return alerts
        
    def get_new_blocks(self) -> List[Dict]:
        """Get new blocked IPs from the queue"""
        blocks = []
        while not self.block_queue.empty():
            try:
                blocks.append(self.block_queue.get_nowait())
            except queue.Empty:
                break
        return blocks 