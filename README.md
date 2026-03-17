# AI NET GUARDIAN

<img width="1710" height="994" alt="AINETGUARDIAN" src="https://github.com/user-attachments/assets/286a8e8c-8261-4950-b662-ea8df6929d25" />


> **Advanced AI-Powered Network Security Dashboard for Real-time Threat Detection and Traffic Classification**
> **ACKNOWLEDGEMENT**: *This project was conducted as a requirement of the Department of Computer Science and Engineering at the GITAM School of Technology. We would like to express our gratitude to the department for the invaluable resources and infrastructure that facilitated our research. We are especially thankful to Mr. Mohan Krishna Samantula, Assistant Professor in the CSE Department, for his valuable support and encouragement. His expertise has been crucial to the successful completion of this work. We also extend our sincere thanks to Dr. Venkata Ramana Murthy Oruganti, Associate Professor from GITAM University, for his constant support, insightful guidance, and motivation throughout this endeavour.*

## 🌟 Live Demo

 **[Try the Live Application](https://ainetguardian.streamlit.app)** 

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Usage](#-usage)
- [API Reference](#-api-reference)
- [Model Performance](#-model-performance)

## 🎯 Overview

AI Network Security Dashboard is a cutting-edge machine learning application designed to detect malicious URLs, classify network traffic, and provide comprehensive security analytics in real-time. Built with advanced Random Forest algorithms and featuring an intuitive Streamlit interface, this tool serves as your first line of defense against web-based threats.

### 🎥 Quick Demo






https://github.com/user-attachments/assets/fbe2f55d-73f3-434b-8b89-151618740b62







## ✨ Key Features

### 🔍 **Real-time URL Analysis**
- **Instant Threat Detection**: Analyze URLs in real-time for malicious content
- **XSS & SQL Injection Detection**: Advanced pattern recognition for common attack vectors
- **Confidence Scoring**: ML-powered confidence levels for each prediction
- **Bulk Processing**: Analyze multiple URLs simultaneously

### 📊 **Comprehensive Analytics**
- **Interactive Visualizations**: Beautiful charts and graphs using Plotly
- **Traffic Classification**: Automatic categorization of network traffic types
- **Performance Metrics**: Detailed model accuracy, precision, and recall statistics
- **Temporal Analysis**: Time-based threat pattern identification

### 🚀 **Advanced ML Pipeline**
- **Random Forest Classifier**: Optimized with hyperparameter tuning
- **Feature Engineering**: 30+ sophisticated features including:
  - URL structure analysis
  - Entropy calculations
  - SQL injection patterns
  - XSS detection patterns
  - Character encoding analysis
- **Real-time Processing**: Sub-second prediction times

### 🎨 **Modern UI/UX**
- **Responsive Design**: Works perfectly on desktop and mobile
- **Dark/Light Mode**: Automatic theme adaptation
- **Animated Components**: Smooth transitions and loading animations
- **Professional Styling**: Modern gradients and styling

## 🏗️ Architecture

![arch_diag drawio (1)](https://github.com/user-attachments/assets/c2d8346d-2cf0-417a-a38e-6471d11470c9)


## ⚙️ Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Git (for cloning)

### Quick Start

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/ai-network-security-dashboard.git
   cd ai-network-security-dashboard
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Train the Model** (Optional - Pre-trained model included)
   ```bash
   python train_enhanced.py
   ```

5. **Run the Application**
   ```bash
   streamlit run app.py
   ```

6. **Access the Dashboard**
   Open your browser and navigate to `http://localhost:8501`

## 🚀 Usage

### Real-time URL Analysis

1. **Navigate to Real-time Analysis**: Select "Real-time URL Analysis" from the sidebar
2. **Input URLs**: Enter one or more URLs in the text area (one per line)
3. **Analyze**: Click "🔍 Analyze URLs" to get instant results
4. **Review Results**: View threat status, confidence scores, and traffic classification

```python
# Example URLs to test
http://example.com/search?q=test
http://malicious.com?q=<script>alert('xss')</script>
http://bank.com/transfer?to='; DROP TABLE users;--
```

### Batch File Analysis

1. **Upload CSV File**: Use the file uploader (supports up to 200MB)
2. **CSV Format**: Ensure your CSV contains a 'url' column
3. **Process**: Click "🚀 Start Analysis" for bulk processing
4. **Download Results**: Export analyzed data with threat classifications

### Model Performance Review

- View comprehensive metrics including accuracy, precision, recall
- Analyze confusion matrices and ROC curves
- Examine feature importance rankings
- Review cross-validation results

## 📊 Model Performance

The enhanced Random Forest model achieves impressive performance metrics:

| Metric | Score |
|--------|-------|
| **Accuracy** | 94.1% |
| **Precision** | 90.9% |
| **Recall** | 100% |
| **F1-Score** | 95.2% |

### Key Features Used

- **URL Structure Analysis**: Token count, length statistics, encoding patterns
- **Security Pattern Detection**: SQL injection, XSS, command injection patterns  
- **Entropy Calculations**: Information theory-based randomness analysis
- **Character Analysis**: Special characters, numeric patterns, suspicious sequences
- **Parameter Analysis**: Query parameter structure and content analysis

## 🔧 API Reference

### Core Functions

#### `extract_features(url)`
Extracts comprehensive features from a URL for ML analysis.

```python
from utils.feature_extraction import extract_features

features = extract_features("http://example.com?q=test")
# Returns: array of 30+ numerical features
```

#### `TrafficAnalyzer.classify_traffic(url)`
Classifies network traffic type based on URL patterns.

```python
from utils.traffic_analyzer import TrafficAnalyzer

analyzer = TrafficAnalyzer()
traffic_type = analyzer.classify_traffic("http://cdn.example.com/image.jpg")
# Returns: "CDN", "API", "Web", "Email", etc.
```

### Configuration Options

Create a `config.py` file for custom settings:

```python
# Model Configuration
MODEL_PATH = "model/rf_model.pkl"
CONFIDENCE_THRESHOLD = 0.5
MAX_FILE_SIZE_MB = 200

# UI Configuration
THEME_COLOR = "#667eea"
ENABLE_ANIMATIONS = True
SHOW_DEBUG_INFO = False
```

## 🛠️ Development

### Project Structure

```
ai-network-security-dashboard/
├── app.py                      # Main Streamlit application
├── requirements.txt            # Python dependencies
├── train_enhanced.py          # Model training script
├── sample_http.csv           # Sample training data
├── model/                    # Trained models directory
│   ├── rf_model.pkl         # Random Forest model
│   └── training_metadata.json
├── utils/                    # Utility modules
│   ├── feature_extraction.py # Feature engineering
│   ├── traffic_analyzer.py  # Traffic classification
│   └── dummy_data.py        # Data generation
└── README.md                # This file
```


### Testing

```bash
# Run basic functionality tests
python -c "from utils.feature_extraction import extract_features; print('✅ Feature extraction works')"

# Test model loading
python -c "import joblib; model = joblib.load('model/rf_model.pkl'); print('✅ Model loads successfully')"
```

## 🔒 Security Considerations

- **Data Privacy**: No URLs are stored permanently; all processing is ephemeral
- **Model Security**: Pre-trained models are included to prevent training data exposure
- **Input Validation**: All user inputs are sanitized and validated
- **Rate Limiting**: Built-in protections against abuse

## 🚀 Deployment

### Streamlit Cloud (Recommended)

1. Fork this repository
2. Connect to Streamlit Cloud
3. Deploy with one click
4. Access your live dashboard

## 📈 Performance Optimization

- **Caching**: Streamlit caching for model loading and feature extraction
- **Batch Processing**: Efficient handling of large CSV files
- **Memory Management**: Optimized for processing 200MB+ files
- **Parallel Processing**: Multi-threaded feature extraction

## 🔄 Changelog

### v2.1.0 (Latest)
- ✨ Enhanced UI with modern animations
- 🚀 Improved model performance (95.8% accuracy)
- 📊 Advanced traffic classification
- 🎨 Dark/Light mode support
- 📁 Large file processing (200MB+)


