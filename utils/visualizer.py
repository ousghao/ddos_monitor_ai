import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import numpy as np
from collections import deque
from datetime import datetime
import threading
from typing import Dict, List, Deque

class TrafficVisualizer:
    def __init__(self, max_points: int = 100):
        """
        Initialize the traffic visualizer.
        
        Args:
            max_points (int): Maximum number of points to display in the graph
        """
        self.max_points = max_points
        self.times: Deque[float] = deque(maxlen=max_points)
        self.packet_rates: Deque[float] = deque(maxlen=max_points)
        self.attack_flags: Deque[bool] = deque(maxlen=max_points)
        
        self.fig, (self.ax1, self.ax2) = plt.subplots(2, 1, figsize=(10, 8))
        self.fig.suptitle('Real-time Network Traffic Monitoring')
        
        # Packet rate plot
        self.line1, = self.ax1.plot([], [], 'b-', label='Packet Rate')
        self.ax1.set_ylabel('Packets/second')
        self.ax1.set_title('Network Traffic Rate')
        self.ax1.grid(True)
        self.ax1.legend()
        
        # Attack detection plot
        self.line2, = self.ax2.plot([], [], 'r-', label='Attack Probability')
        self.ax2.set_xlabel('Time')
        self.ax2.set_ylabel('Attack Probability')
        self.ax2.set_title('Attack Detection')
        self.ax2.grid(True)
        self.ax2.legend()
        
        self.lock = threading.Lock()
        self.animation = None
        
    def update_data(self, packet_rate: float, attack_probability: float):
        """
        Update the visualization data.
        
        Args:
            packet_rate (float): Current packet rate
            attack_probability (float): Probability of an attack
        """
        current_time = datetime.now().timestamp()
        with self.lock:
            self.times.append(current_time)
            self.packet_rates.append(packet_rate)
            self.attack_flags.append(attack_probability)
    
    def _update_plot(self, frame):
        """Update the plot with new data"""
        with self.lock:
            times = list(self.times)
            packet_rates = list(self.packet_rates)
            attack_flags = list(self.attack_flags)
            
            if not times:
                return self.line1, self.line2
                
            # Update packet rate plot
            self.line1.set_data(times, packet_rates)
            self.ax1.set_xlim(min(times), max(times))
            self.ax1.set_ylim(0, max(packet_rates) * 1.1 if packet_rates else 1)
            
            # Update attack detection plot
            self.line2.set_data(times, attack_flags)
            self.ax2.set_xlim(min(times), max(times))
            self.ax2.set_ylim(0, 1)
            
            return self.line1, self.line2
    
    def start(self):
        """Start the visualization"""
        self.animation = FuncAnimation(
            self.fig, self._update_plot, interval=1000,
            blit=True
        )
        plt.show()
        
    def stop(self):
        """Stop the visualization"""
        if self.animation:
            self.animation.event_source.stop()
            plt.close(self.fig) 