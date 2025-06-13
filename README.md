# Real-time DDoS Detection System

A comprehensive DDoS detection system with real-time monitoring, machine learning-based detection, and a web-based dashboard.

## Project Structure

```
.
├── detect_ddos.py           # ML model training script
├── live_detector.py         # Main real-time detection script
├── streamlit_monitor.py     # Web-based monitoring dashboard
├── requirements.txt         # Python dependencies
├── config.json             # Persistent configuration storage
├── utils/
│   ├── feature_extractor.py # Network packet feature extraction
│   ├── visualizer.py        # Real-time traffic visualization
│   ├── state_manager.py     # Shared state management
│   ├── config_manager.py    # Configuration management
│   └── metrics_collector.py # System metrics collection
└── model2001/              # Directory containing trained models
    └── random_forest_model.joblib
```

## File Descriptions

### Core Components

1. **detect_ddos.py**
   - Trains multiple ML models on SYN flood dataset
   - Implements data preprocessing and feature selection
   - Evaluates model performance with various metrics
   - Saves trained models for real-time detection

2. **live_detector.py**
   - Captures live network traffic using Scapy
   - Processes packets and extracts features
   - Uses trained ML model for attack detection
   - Manages IP blocking via iptables
   - Integrates with state manager for web interface

3. **streamlit_monitor.py**
   - Web-based monitoring dashboard
   - Real-time traffic visualization
   - IP management interface
   - System metrics display
   - Configuration controls

### Utility Modules

1. **utils/feature_extractor.py**
   - Extracts features from network packets
   - Implements sliding window analysis
   - Calculates statistical metrics
   - Maintains packet history

2. **utils/visualizer.py**
   - Real-time traffic visualization
   - Attack probability plotting
   - Historical data display
   - Thread-safe updates

3. **utils/state_manager.py**
   - Manages shared state between components
   - Handles real-time data updates
   - Maintains alert and block queues
   - Thread-safe operations

4. **utils/config_manager.py**
   - Manages persistent configuration
   - Handles IP blocking rules
   - Stores IP tags and reasons
   - Maintains detection settings

5. **utils/metrics_collector.py**
   - Collects system performance metrics
   - Monitors CPU and memory usage
   - Tracks network statistics
   - Provides historical data

## Features

### Real-time Detection
- Continuous network traffic monitoring
- Instant DDoS attack detection
- Automatic IP blocking
- Configurable detection thresholds

### Web Interface
- Real-time traffic visualization
- System metrics dashboard
- IP management controls
- Configuration settings

### Advanced Visualizations
- Per-IP traffic timelines
- Top 10 IPs by traffic volume
- System resource usage
- Alert heatmaps
- Packet rate analysis

### IP Management
- Manual IP blocking/unblocking
- IP tagging and categorization
- Block reason tracking
- Persistent blocked IP list

### System Monitoring
- CPU and Memory usage
- Network packet rates
- Drop rate tracking
- Interface statistics

### Configuration
- Detection threshold adjustment
- Feature window settings
- Auto-blocking toggle
- Model selection

## Model Training and Components

The system uses a Random Forest classifier for attack detection. The training process includes:

1. **Data Preprocessing**:
   - Label encoding
   - Feature standardization
   - Top 30 feature selection

2. **Model Components** (saved in `model2001/` directory):
   - `random_forest_model.joblib`: Trained Random Forest model
   - `scaler.joblib`: StandardScaler for feature normalization
   - `feature_selector.joblib`: Feature selection component
   - `selected_features.joblib`: List of selected features
   - `confusion_matrix_*.png`: Model evaluation visualizations

3. **Training Process**:
   ```bash
   python detect_ddos.py
   ```
   This will:
   - Load and preprocess the dataset
   - Train multiple models (Random Forest, SVM, KNN, etc.)
   - Evaluate model performance
   - Save the best model (Random Forest) and its components
   - Generate confusion matrix visualizations

## Installation

1. **Install Dependencies**
   ```bash
   # Create virtual environment
   python -m venv venv
   
   # Activate environment
   # On Linux/Mac:
   source venv/bin/activate
   # On Windows:
   .\venv\Scripts\activate
   
   # Install requirements
   pip install -r requirements.txt
   ```

2. **Train Models** (if needed)
   ```bash
   python detect_ddos.py
   ```

## Usage

### Starting the System

1. **Start the Detector**
   ```bash
   # Run with root privileges
   sudo python3 live_detector.py
   ```

2. **Launch Web Interface**
   ```bash
   # In a separate terminal
   streamlit run streamlit_monitor.py
   ```

### Web Interface Features

1. **Dashboard**
   - Real-time traffic metrics
   - System performance indicators
   - Attack alerts
   - Blocked IPs

2. **Controls**
   - Detection threshold adjustment
   - Feature window configuration
   - Auto-blocking toggle
   - Manual IP management

3. **IP Management**
   - View blocked IPs
   - Add/remove blocks
   - Tag IPs
   - Track block reasons

4. **Monitoring**
   - CPU/Memory usage
   - Network statistics
   - Alert history
   - System status

## Configuration

The system can be configured through:

1. **Web Interface**
   - Detection threshold
   - Feature window size
   - Auto-blocking settings

2. **config.json**
   - Persistent settings
   - IP blocking rules
   - System preferences

## Troubleshooting

1. **Permission Issues**
   ```bash
   # Ensure root privileges
   sudo python3 live_detector.py
   ```

2. **Interface Problems**
   ```bash
   # Check available interfaces
   ifconfig
   # or
   ip addr
   ```

3. **Model Loading**
   - Verify model file exists
   - Check model format
   - Ensure correct path

4. **Web Interface**
   - Check Streamlit installation
   - Verify port availability
   - Check browser compatibility

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## License

[Add your license information here]

## Acknowledgments

- Scapy for packet capture
- Scikit-learn for machine learning
- Streamlit for web interface
- Plotly for visualizations

## Dataset Management

### Large File Handling
The project uses Git Large File Storage (Git LFS) to handle large datasets. The training dataset (`dos_ddos_dataset.csv`) exceeds GitHub's file size limit and must be managed using Git LFS.

### Setting up Git LFS

1. **Install Git LFS**
   ```bash
   # On Ubuntu/Debian
   sudo apt install git-lfs

   # On macOS with Homebrew
   brew install git-lfs

   # On Windows with Chocolatey
   choco install git-lfs
   ```

2. **Initialize Git LFS**
   ```bash
   git lfs install
   ```

3. **Track Large Files**
   ```bash
   git lfs track "*.csv"
   git add .gitattributes
   ```

4. **Commit and Push**
   ```bash
   git add .
   git commit -m "Add dataset with Git LFS"
   git push
   ```

### Alternative Dataset Storage
If you prefer not to use Git LFS, you can:
1. Store the dataset in a cloud storage service (e.g., Google Drive, AWS S3)
2. Add the dataset to `.gitignore`
3. Document the dataset location in this README

### Dataset Requirements
- Format: CSV
- Required columns: [list your required columns]
- Minimum size: [specify minimum dataset size]
- Recommended size: [specify recommended dataset size]
