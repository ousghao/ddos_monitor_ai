import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import pandas as pd
import time
import threading
import subprocess
import json
from utils.state_manager import StateManager
from utils.config_manager import ConfigManager
from utils.metrics_collector import MetricsCollector

# Initialize session state
if 'state_manager' not in st.session_state:
    st.session_state.state_manager = StateManager()
if 'config_manager' not in st.session_state:
    st.session_state.config_manager = ConfigManager()
if 'metrics_collector' not in st.session_state:
    st.session_state.metrics_collector = MetricsCollector()
    st.session_state.metrics_collector.start_collection()

def get_iptables_rules():
    """Get current iptables rules"""
    try:
        result = subprocess.run(['iptables', '-L', 'INPUT', '-n'], 
                              capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error getting iptables rules: {str(e)}"

def unblock_ip(ip: str):
    """Remove iptables rule for an IP"""
    try:
        subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], 
                      check=True)
        st.session_state.config_manager.remove_blocked_ip(ip)
        st.success(f"Successfully unblocked {ip}")
    except subprocess.CalledProcessError as e:
        st.error(f"Error unblocking {ip}: {str(e)}")

def block_ip(ip: str, reason: str = "", tag: str = ""):
    """Add iptables rule to block an IP"""
    try:
        subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], 
                      check=True)
        st.session_state.config_manager.add_blocked_ip(ip, reason, tag)
        st.success(f"Successfully blocked {ip}")
    except subprocess.CalledProcessError as e:
        st.error(f"Error blocking {ip}: {str(e)}")

def create_traffic_chart(metrics, title):
    """Create a line chart for traffic metrics"""
    if not metrics:
        return None
        
    # Convert metrics to DataFrame
    df = pd.DataFrame(metrics)
    
    # Create line chart
    fig = go.Figure()
    for column in df.columns:
        fig.add_trace(go.Scatter(
            y=df[column],
            name=column,
            mode='lines'
        ))
    
    fig.update_layout(
        title=title,
        xaxis_title="Time",
        yaxis_title="Count/Rate",
        height=300
    )
    
    return fig

def create_heatmap(alerts, title):
    """Create a heatmap of alerts over time"""
    if not alerts:
        return None
        
    # Convert alerts to DataFrame
    df = pd.DataFrame(alerts)
    df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
    df['day'] = pd.to_datetime(df['timestamp']).dt.day_name()
    
    # Create pivot table
    pivot = df.pivot_table(
        values='probability',
        index='day',
        columns='hour',
        aggfunc='count'
    )
    
    # Create heatmap
    fig = px.imshow(
        pivot,
        title=title,
        labels=dict(x="Hour", y="Day", color="Alert Count"),
        aspect="auto"
    )
    
    return fig

def main():
    st.set_page_config(
        page_title="DDoS Detection Monitor",
        page_icon="🛡️",
        layout="wide"
    )
    
    st.title("DDoS Detection Monitor")
    
    # Sidebar controls
    st.sidebar.title("Controls")
    
    # Configuration controls
    st.sidebar.subheader("Configuration")
    threshold = st.sidebar.slider(
        "Detection Threshold",
        min_value=0.5,
        max_value=1.0,
        value=st.session_state.config_manager.get_all_settings()["detection_threshold"],
        step=0.05
    )
    st.session_state.config_manager.update_detection_threshold(threshold)
    
    window = st.sidebar.slider(
        "Feature Window (seconds)",
        min_value=5,
        max_value=60,
        value=st.session_state.config_manager.get_all_settings()["feature_window"],
        step=5
    )
    st.session_state.config_manager.update_feature_window(window)
    
    auto_blocking = st.sidebar.toggle(
        "Auto Blocking",
        value=st.session_state.state_manager.auto_blocking,
        on_change=st.session_state.state_manager.toggle_auto_blocking
    )
    
    # Manual IP management
    st.sidebar.subheader("Manual IP Management")
    ip = st.sidebar.text_input("IP Address")
    reason = st.sidebar.text_input("Reason (optional)")
    tag = st.sidebar.text_input("Tag (optional)")
    
    col1, col2 = st.sidebar.columns(2)
    with col1:
        if st.button("Block IP"):
            if ip:
                block_ip(ip, reason, tag)
            else:
                st.error("Please enter an IP address")
    with col2:
        if st.button("Unblock IP"):
            if ip:
                unblock_ip(ip)
            else:
                st.error("Please enter an IP address")
    
    # Main content
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("Live Traffic Metrics")
        
        # Get current metrics
        metrics = st.session_state.state_manager.get_metrics()
        system_metrics = st.session_state.metrics_collector.get_current_metrics()
        
        # System metrics
        st.metric("CPU Usage", f"{system_metrics['cpu_usage']:.1f}%")
        st.metric("Memory Usage", f"{system_metrics['memory_usage']:.1f}%")
        st.metric("Packet Rate", f"{system_metrics['packet_rate']:.1f} packets/s")
        st.metric("Drop Rate", f"{system_metrics['drop_rate']:.1f} packets/s")
        
        # Create charts
        if metrics['syn_counts']:
            st.plotly_chart(
                create_traffic_chart(metrics['syn_counts'], "SYN Packet Counts"),
                use_container_width=True
            )
            
        if metrics['traffic_rates']:
            st.plotly_chart(
                create_traffic_chart(metrics['traffic_rates'], "Traffic Rates"),
                use_container_width=True
            )
            
        if metrics['alert_rates']:
            st.plotly_chart(
                create_traffic_chart(metrics['alert_rates'], "Alert Rates"),
                use_container_width=True
            )
            
        # Top IPs by traffic
        if metrics['traffic_rates']:
            df = pd.DataFrame(metrics['traffic_rates'])
            top_ips = df.sum().sort_values(ascending=False).head(10)
            st.subheader("Top 10 IPs by Traffic")
            st.bar_chart(top_ips)
    
    with col2:
        st.subheader("Recent Alerts")
        
        # Display new alerts
        alerts = st.session_state.state_manager.get_new_alerts()
        if alerts:
            for alert in alerts:
                st.warning(
                    f"Alert: {alert['ip']} "
                    f"(Probability: {alert['probability']:.2f}) "
                    f"at {alert['timestamp'].strftime('%H:%M:%S')}"
                )
        
        st.subheader("Blocked IPs")
        
        # Display and manage blocked IPs
        blocked_ips = st.session_state.config_manager.get_blocked_ips()
        if blocked_ips:
            for ip, data in blocked_ips.items():
                with st.expander(f"{ip} ({data['tag'] if data['tag'] else 'No tag'})"):
                    st.text(f"Blocked at: {data['timestamp']}")
                    st.text(f"Reason: {data['reason']}")
                    if st.button("Unblock", key=f"unblock_{ip}"):
                        unblock_ip(ip)
        else:
            st.info("No IPs currently blocked")
        
        st.subheader("System Status")
        st.text(f"Last Update: {system_metrics['timestamp'].strftime('%H:%M:%S')}")
        st.text(f"Auto Blocking: {'Enabled' if auto_blocking else 'Disabled'}")
        
        # Display iptables rules
        st.subheader("Current iptables Rules")
        st.code(get_iptables_rules(), language="bash")
    
    # Auto-refresh
    time.sleep(1)
    st.experimental_rerun()

if __name__ == "__main__":
    main() 