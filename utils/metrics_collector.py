import psutil
import time
from datetime import datetime
from typing import Dict, List, Deque
from collections import deque
import threading

class MetricsCollector:
    def __init__(self, max_history: int = 1000):
        """
        Initialize the metrics collector.
        
        Args:
            max_history (int): Maximum number of historical records to keep
        """
        self.max_history = max_history
        
        # System metrics
        self.cpu_usage: Deque[float] = deque(maxlen=max_history)
        self.memory_usage: Deque[float] = deque(maxlen=max_history)
        self.timestamps: Deque[datetime] = deque(maxlen=max_history)
        
        # Network metrics
        self.packet_rates: Deque[float] = deque(maxlen=max_history)
        self.byte_rates: Deque[float] = deque(maxlen=max_history)
        self.drop_rates: Deque[float] = deque(maxlen=max_history)
        
        # Thread safety
        self.lock = threading.Lock()
        
        # Initialize network counters
        self.last_net_io = psutil.net_io_counters()
        self.last_time = time.time()
        
    def collect_metrics(self):
        """Collect current system metrics"""
        with self.lock:
            current_time = datetime.now()
            
            # CPU and Memory
            self.cpu_usage.append(psutil.cpu_percent())
            self.memory_usage.append(psutil.virtual_memory().percent)
            self.timestamps.append(current_time)
            
            # Network metrics
            current_net_io = psutil.net_io_counters()
            current_time = time.time()
            
            # Calculate rates
            time_diff = current_time - self.last_time
            if time_diff > 0:
                bytes_sent_rate = (current_net_io.bytes_sent - self.last_net_io.bytes_sent) / time_diff
                bytes_recv_rate = (current_net_io.bytes_recv - self.last_net_io.bytes_recv) / time_diff
                packets_sent_rate = (current_net_io.packets_sent - self.last_net_io.packets_sent) / time_diff
                packets_recv_rate = (current_net_io.packets_recv - self.last_net_io.packets_recv) / time_diff
                drop_rate = (current_net_io.dropin - self.last_net_io.dropin + 
                           current_net_io.dropout - self.last_net_io.dropout) / time_diff
                
                self.byte_rates.append(bytes_sent_rate + bytes_recv_rate)
                self.packet_rates.append(packets_sent_rate + packets_recv_rate)
                self.drop_rates.append(drop_rate)
            
            # Update last values
            self.last_net_io = current_net_io
            self.last_time = current_time
            
    def get_current_metrics(self) -> Dict:
        """Get current system metrics"""
        with self.lock:
            return {
                'cpu_usage': self.cpu_usage[-1] if self.cpu_usage else 0,
                'memory_usage': self.memory_usage[-1] if self.memory_usage else 0,
                'packet_rate': self.packet_rates[-1] if self.packet_rates else 0,
                'byte_rate': self.byte_rates[-1] if self.byte_rates else 0,
                'drop_rate': self.drop_rates[-1] if self.drop_rates else 0,
                'timestamp': self.timestamps[-1] if self.timestamps else datetime.now()
            }
            
    def get_historical_metrics(self) -> Dict:
        """Get historical metrics for plotting"""
        with self.lock:
            return {
                'timestamps': list(self.timestamps),
                'cpu_usage': list(self.cpu_usage),
                'memory_usage': list(self.memory_usage),
                'packet_rates': list(self.packet_rates),
                'byte_rates': list(self.byte_rates),
                'drop_rates': list(self.drop_rates)
            }
            
    def start_collection(self, interval: float = 1.0):
        """Start collecting metrics in a background thread"""
        def collection_loop():
            while True:
                self.collect_metrics()
                time.sleep(interval)
                
        thread = threading.Thread(target=collection_loop, daemon=True)
        thread.start()
        return thread 