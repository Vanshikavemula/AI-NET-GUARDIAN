import streamlit as st
import pandas as pd
import numpy as np
import joblib
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score
from sklearn.tree import export_text
import io
import base64
from utils.feature_extraction import extract_features
from utils.traffic_analyzer import TrafficAnalyzer
import warnings
warnings.filterwarnings('ignore')

# Page configuration
st.set_page_config(
    page_title="AI Network Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    .main-header {
        background: linear-gradient(135deg, #0a1929 0%, #1e3a8a 50%, #3b82f6 100%);
        padding: 2rem;
        border-radius: 20px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 20px 40px rgba(30, 58, 138, 0.4);
        animation: gradient-shift 3s ease infinite;
        position: relative;
        overflow: hidden;
    }
    
    .main-header::before {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
        animation: shimmer 2s infinite;
    }
    
    @keyframes shimmer {
        0% { left: -100%; }
        100% { left: 100%; }
    }
    
    @keyframes gradient-shift {
        0%, 100% { background: linear-gradient(135deg, #0a1929 0%, #1e3a8a 50%, #3b82f6 100%); }
        50% { background: linear-gradient(135deg, #3b82f6 0%, #0a1929 50%, #1e3a8a 100%); }
    }
    
    .main-header h1 {
        font-family: 'Inter', sans-serif;
        font-weight: 700;
        font-size: 2.5rem;
        margin-bottom: 0.5rem;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        position: relative;
        z-index: 1;
    }
    
    .main-header p {
        font-family: 'Inter', sans-serif;
        font-weight: 400;
        font-size: 1.1rem;
        opacity: 0.9;
        position: relative;
        z-index: 1;
    }
    
    .metric-card {
        background: linear-gradient(145deg, #ffffff 0%, #f8f9fa 100%);
        padding: 1.5rem;
        border-radius: 15px;
        border: 1px solid #e9ecef;
        box-shadow: 0 8px 25px rgba(0,0,0,0.1);
        transition: all 0.3s ease;
        position: relative;
        overflow: hidden;
    }
    
    .metric-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 2px;
        background: linear-gradient(90deg, #1e3a8a, #3b82f6);
    }
    
    .metric-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 15px 35px rgba(0,0,0,0.15);
    }
    
    .threat-detected {
        background: linear-gradient(145deg, #fff5f5 0%, #ffe6e6 100%);
        border: 1px solid #fecaca;
        box-shadow: 0 8px 25px rgba(239, 68, 68, 0.15);
    }
    
    .threat-detected::before {
        background: linear-gradient(90deg, #ef4444, #dc2626);
    }
    
    .safe-traffic {
        background: linear-gradient(145deg, #f0fff4 0%, #e6ffe6 100%);
        border: 1px solid #bbf7d0;
        box-shadow: 0 8px 25px rgba(34, 197, 94, 0.15);
    }
    
    .safe-traffic::before {
        background: linear-gradient(90deg, #22c55e, #16a34a);
    }
    
    .stButton > button {
        background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
        color: white;
        border: none;
        border-radius: 12px;
        padding: 0.75rem 2rem;
        font-weight: 600;
        font-family: 'Inter', sans-serif;
        transition: all 0.3s ease;
        box-shadow: 0 4px 15px rgba(30, 58, 138, 0.4);
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 25px rgba(30, 58, 138, 0.6);
    }
    
    .stSelectbox > div > div {
        background: linear-gradient(145deg, #ffffff 0%, #f8f9fa 100%);
        border: 1px solid #e9ecef;
        border-radius: 12px;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
    }
    
    .stTextArea > div > div > textarea {
        background: linear-gradient(145deg, #ffffff 0%, #f8f9fa 100%);
        border: 1px solid #e9ecef;
        border-radius: 12px;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        font-family: 'Inter', sans-serif;
        color: #333333;
    }
    
    .stTextArea > div > div > textarea::placeholder {
        color: #666666;
        opacity: 0.8;
    }
    
    @media (prefers-color-scheme: dark) {
        .stTextArea > div > div > textarea {
            background: linear-gradient(145deg, #2d2d2d 0%, #3a3a3a 100%) !important;
            border: 1px solid #4a4a4a !important;
            color: #ffffff !important;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3) !important;
        }
        
        .stTextArea > div > div > textarea::placeholder {
            color: #cccccc !important;
            opacity: 0.7 !important;
        }
    }
    
    .stApp[data-theme="dark"] .stTextArea > div > div > textarea,
    html[data-theme="dark"] .stTextArea > div > div > textarea {
        background: linear-gradient(145deg, #2d2d2d 0%, #3a3a3a 100%) !important;
        border: 1px solid #4a4a4a !important;
        color: #ffffff !important;
        box-shadow: 0 4px 15px rgba(0,0,0,0.3) !important;
    }
    
    .stApp[data-theme="dark"] .stTextArea > div > div > textarea::placeholder,
    html[data-theme="dark"] .stTextArea > div > div > textarea::placeholder {
        color: #cccccc !important;
        opacity: 0.7 !important;
    }
    
    @media (prefers-color-scheme: dark) {
        .stTextArea > div > div > textarea:focus {
            border-color: #3b82f6 !important;
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.3) !important;
        }
    }
    
    .stApp[data-theme="dark"] .stTextArea > div > div > textarea:focus,
    html[data-theme="dark"] .stTextArea > div > div > textarea:focus {
        border-color: #3b82f6 !important;
        box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.3) !important;
    }
    
    .upload-section {
        background: linear-gradient(145deg, #ffffff 0%, #f8f9fa 100%);
        padding: 2rem;
        border-radius: 20px;
        border: 2px dashed #3b82f6;
        text-align: center;
        margin: 2rem 0;
        transition: all 0.3s ease;
        position: relative;
        overflow: hidden;
    }
    
    .upload-section::before {
        content: '📁';
        font-size: 3rem;
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        opacity: 0.1;
        animation: float 3s ease-in-out infinite;
    }
    
    @keyframes float {
        0%, 100% { transform: translate(-50%, -50%) translateY(0px); }
        50% { transform: translate(-50%, -50%) translateY(-10px); }
    }
    
    .upload-section:hover {
        border-color: #1e3a8a;
        background: linear-gradient(145deg, #f8f9fa 0%, #ffffff 100%);
        box-shadow: 0 8px 25px rgba(30, 58, 138, 0.2);
    }
    
    .sidebar .stSelectbox > div > div {
        background: linear-gradient(145deg, #1e3a8a 0%, #3b82f6 100%);
        color: white;
        border-radius: 12px;
    }
    
    .analysis-section {
        background: linear-gradient(145deg, #ffffff 0%, #f8f9fa 100%);
        padding: 2rem;
        border-radius: 20px;
        margin: 1rem 0;
        box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        border: 1px solid #e9ecef;
    }
    
    .stDataFrame {
        border-radius: 15px;
        overflow: hidden;
        box-shadow: 0 8px 25px rgba(0,0,0,0.1);
    }
    
    .stProgress > div > div {
        background: linear-gradient(90deg, #1e3a8a, #3b82f6);
        border-radius: 10px;
    }
    
    .footer {
        background: linear-gradient(135deg, #0a1929 0%, #1e3a8a 100%);
        color: white;
        padding: 2rem;
        border-radius: 20px;
        text-align: center;
        margin-top: 3rem;
        box-shadow: 0 -10px 30px rgba(30, 58, 138, 0.3);
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'model' not in st.session_state:
    st.session_state.model = joblib.load("model/rf_model.pkl")
if 'traffic_analyzer' not in st.session_state:
    st.session_state.traffic_analyzer = TrafficAnalyzer()

# Header styling
st.markdown("""
<div class="main-header">
    <h1>AI-NET GUARDIAN</h1>
    <p>Advanced ML-based Traffic Classification & Threat Detection System</p>
</div>
""", unsafe_allow_html=True)

#Sidebar with dark mode compatibility
st.sidebar.markdown("""
<style>
    /* Sidebar container styling */
    .css-1d391kg {
        background: linear-gradient(180deg, #f8f9fa 0%, #ffffff 100%);
        padding: 1rem;
    }
    
    .sidebar-header {
        background: linear-gradient(135deg, #0a1929 0%, #1e3a8a 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 20px;
        margin-bottom: 1.5rem;
        text-align: center;
        box-shadow: 0 10px 30px rgba(30, 58, 138, 0.4);
        position: relative;
        overflow: hidden;
    }
    
    .sidebar-header::before {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
        animation: shimmer 3s infinite;
    }
    
    .sidebar-header h2 {
        margin: 0;
        font-size: 1.4rem;
        font-weight: 700;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        position: relative;
        z-index: 1;
    }
    
    .sidebar-header .subtitle {
        margin: 0.5rem 0 0 0;
        font-size: 0.9rem;
        opacity: 0.9;
        position: relative;
        z-index: 1;
    }
    
    /* Analysis selection section */
    .analysis-selector {
        background: transparent;
        border: none;
        border-radius: 0;
        padding: 1rem 0;
        margin: 1rem 0;
        box-shadow: none;
        position: relative;
    }

    .selector-header {
        background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
        color: white;
        padding: 1rem;
        border-radius: 15px;
        margin-bottom: 1rem;
        text-align: center;
        box-shadow: 0 5px 15px rgba(30, 58, 138, 0.3);
    }

    .selector-header h3 {
        margin: 0;
        font-size: 1.2rem;
        font-weight: 600;
    }
    
    div[data-testid="stRadio"] > div {
        background: transparent !important;
        border: none !important;
        padding: 0 !important;
        margin: 0 !important;
        box-shadow: none !important;
    }
    
    /* Light mode radio buttons */
    div[data-testid="stRadio"] label {
        display: flex !important;
        align-items: center !important;
        background: #ffffff !important;
        border: 2px solid #e9ecef !important;
        border-radius: 15px !important;
        padding: 1rem !important;
        margin: 0.5rem 0 !important;
        font-size: 1rem !important;
        font-weight: 600 !important;
        color: #333333 !important;
        cursor: pointer !important;
        transition: all 0.3s ease !important;
        width: 100% !important;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1) !important;
    }
    
    /* Dark mode radio buttons - using CSS media query */
    @media (prefers-color-scheme: dark) {
        div[data-testid="stRadio"] label {
            background: #262730 !important;
            border: 2px solid #4a4a4a !important;
            color: #ffffff !important;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3) !important;
        }
    }
    
    /* Dark mode for Streamlit's dark theme class */
    .stApp[data-theme="dark"] div[data-testid="stRadio"] label,
    html[data-theme="dark"] div[data-testid="stRadio"] label {
        background: #262730 !important;
        border: 2px solid #4a4a4a !important;
        color: #ffffff !important;
        box-shadow: 0 4px 15px rgba(0,0,0,0.3) !important;
    }
    
    /* Hover effects - works for both modes */
    div[data-testid="stRadio"] label:hover {
        background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%) !important;
        color: white !important;
        transform: translateY(-3px) !important;
        box-shadow: 0 8px 25px rgba(30, 58, 138, 0.5) !important;
        border-color: #3b82f6 !important;
    }
    
    /* Radio button circle */
    div[data-testid="stRadio"] label > div:first-child {
        background: transparent !important;
        border: none !important;
        margin-right: 0.8rem !important;
    }
    
    /* Description box styling */
    .mode-description {
        background: linear-gradient(145deg, #dbeafe 0%, #bfdbfe 100%);
        border-left: 4px solid #3b82f6;
        border-radius: 15px;
        padding: 1.5rem;
        margin: 1.5rem 0;
        box-shadow: 0 5px 20px rgba(30, 58, 138, 0.1);
    }
    
    @media (prefers-color-scheme: dark) {
        .mode-description {
            background: linear-gradient(145deg, #1e293b 0%, #334155 100%);
            color: #ffffff;
        }
        .mode-description .title {
            color: #ffffff !important;
        }
        .mode-description .desc {
            color: #cccccc !important;
        }
    }
    
    .stApp[data-theme="dark"] .mode-description,
    html[data-theme="dark"] .mode-description {
        background: linear-gradient(145deg, #1e293b 0%, #334155 100%);
        color: #ffffff;
    }
    
    .stApp[data-theme="dark"] .mode-description .title,
    html[data-theme="dark"] .mode-description .title {
        color: #ffffff !important;
    }
    
    .stApp[data-theme="dark"] .mode-description .desc,
    html[data-theme="dark"] .mode-description .desc {
        color: #cccccc !important;
    }
    
    .mode-description .icon {
        font-size: 1.5rem;
        margin-bottom: 0.8rem;
        display: block;
    }
    
    .mode-description .title {
        font-weight: 700;
        color: #333;
        font-size: 1.1rem;
        margin-bottom: 0.8rem;
    }
    
    .mode-description .desc {
        font-size: 0.95rem;
        color: #666;
        line-height: 1.5;
    }
    
    /* Stats section */
    .sidebar-stats {
        background: linear-gradient(145deg, #ffffff 0%, #f8f9fa 100%);
        border-radius: 20px;
        padding: 1.5rem;
        margin: 1.5rem 0;
        border: 2px solid #e9ecef;
        box-shadow: 0 8px 25px rgba(0,0,0,0.1);
        position: relative;
        overflow: hidden;
    }
    
    @media (prefers-color-scheme: dark) {
        .sidebar-stats {
            background: linear-gradient(145deg, #2d2d2d 0%, #3a3a3a 100%);
            border: 2px solid #4a4a4a;
        }
        .stats-header, .stat-label, .stat-value {
            color: #ffffff !important;
        }
        .stat-item {
            border-bottom: 1px solid #4a4a4a !important;
        }
    }
    
    .stApp[data-theme="dark"] .sidebar-stats,
    html[data-theme="dark"] .sidebar-stats {
        background: linear-gradient(145deg, #2d2d2d 0%, #3a3a3a 100%);
        border: 2px solid #4a4a4a;
    }
    
    .stApp[data-theme="dark"] .stats-header,
    .stApp[data-theme="dark"] .stat-label,
    .stApp[data-theme="dark"] .stat-value,
    html[data-theme="dark"] .stats-header,
    html[data-theme="dark"] .stat-label,
    html[data-theme="dark"] .stat-value {
        color: #ffffff !important;
    }
    
    .stApp[data-theme="dark"] .stat-item,
    html[data-theme="dark"] .stat-item {
        border-bottom: 1px solid #4a4a4a !important;
    }
    
    .sidebar-stats::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        width: 100%; 
        height: 3px;
        background: linear-gradient(90deg, #22c55e, #16a34a);
        border-radius: 20px 20px 0 0;
        z-index: 1; 
    }
    
    .stats-header {
        text-align: center;
        margin-bottom: 1.5rem;
        color: #333;
        font-size: 1.1rem;
        font-weight: 600;
    }
    
    .stat-item {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.8rem 0;
        border-bottom: 1px solid #e9ecef;
    }
    
    .stat-item:last-child {
        border-bottom: none;
    }
    
    .stat-label {
        font-size: 0.95rem;
        color: #666;
        font-weight: 500;
    }
    
    .stat-value {
        font-weight: 700;
        color: #333;
        font-size: 0.95rem;
    }
    
    /* Help section */
    .help-section {
        background: linear-gradient(145deg, #fff8e1 0%, #fff3c4 100%);
        border-radius: 20px;
        padding: 1.5rem;
        border: 2px solid #ffd54f;
        margin: 1.5rem 0;
        box-shadow: 0 8px 25px rgba(255, 193, 7, 0.2);
        position: relative;
        overflow: hidden;
    }
    
    
    @media (prefers-color-scheme: dark) {
        .help-section {
            background: linear-gradient(145deg, #3a3420 0%, #4a4228 100%);
        }
        .help-header {
            color: #ffd54f !important;
        }
        .help-content {
            color: #ffcc80 !important;
        }
        .help-content strong {
            color: #ffd54f !important;
        }
    }
    
    .stApp[data-theme="dark"] .help-section,
    html[data-theme="dark"] .help-section {
        background: linear-gradient(145deg, #3a3420 0%, #4a4228 100%);
    }
    
    .stApp[data-theme="dark"] .help-header,
    html[data-theme="dark"] .help-header {
        color: #ffd54f !important;
    }
    
    .stApp[data-theme="dark"] .help-content,
    html[data-theme="dark"] .help-content {
        color: #ffcc80 !important;
    }
    
    .stApp[data-theme="dark"] .help-content strong,
    html[data-theme="dark"] .help-content strong {
        color: #ffd54f !important;
    }
    
     .help-section::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        width: 100%;
        height: 3px;
        background: linear-gradient(90deg, #ff9800, #f57c00);
        border-radius: 20px 20px 0 0;
        z-index: 1; 
    }
    
    .help-header {
        text-align: center;
        margin-bottom: 1.5rem;
        color: #f57f17;
        font-size: 1.1rem;
        font-weight: 600;
    }
    
    .help-content {
        font-size: 0.85rem;
        color: #e65100;
        line-height: 1.6;
    }
    
    .help-content strong {
        font-weight: 700;
        color: #bf360c;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar Header
st.sidebar.markdown("""
<div class="sidebar-header">
    <h2>Control Panel</h2>
    <p class="subtitle">AI Net Guardian</p>
</div>
""", unsafe_allow_html=True)

# Analysis mode options
analysis_options = [
    {
        "value": "Real-time URL Analysis",
        "icon": "🔍",
        "title": "Real-time Analysis",
        "description": "Analyze URLs instantly for threats and malicious content with real-time processing"
    },
    {
        "value": "Batch File Analysis", 
        "icon": "📁",
        "title": "Batch Processing",
        "description": "Upload CSV files and analyze multiple URLs simultaneously for comprehensive security assessment"
    },
    {
        "value": "Model Performance",
        "icon": "📈", 
        "title": "Performance Metrics",
        "description": "View detailed model accuracy, precision, recall, and comprehensive analytics dashboard"
    },
    {
        "value": "Traffic Insights",
        "icon": "🌐",
        "title": "Network Traffic",
        "description": "Comprehensive network traffic analysis with temporal insights and threat patterns"
    }
]

# Analysis Selection Section
st.sidebar.markdown("""
<div class="analysis-selector">
    <div class="selector-header" style="margin-bottom: -1rem;">
        <h3>Choose Analysis Mode</h3>
    </div>
</div>
""", unsafe_allow_html=True)

analysis_mode = st.sidebar.radio(
    "analysis_mode_selector",
    options=[opt["value"] for opt in analysis_options],
    format_func=lambda x: next(opt["icon"] + "  " + opt["title"] for opt in analysis_options if opt["value"] == x),
    label_visibility="hidden"
)
st.sidebar.markdown("""
<style>
    /* Remove empty space from hidden radio button label */
    div[data-testid="stRadio"] > div:first-child {
        display: none !important;
    }
    
    /* Remove top margin from radio options container */
    div[data-testid="stRadio"] {
        margin-top: -1rem !important;
    }
    
    /* Adjust selector header bottom margin */
    .selector-header {
        margin-bottom: 0rem !important;
    }
</style>
""", unsafe_allow_html=True)

# Description for selected mode
selected_option = next(opt for opt in analysis_options if opt["value"] == analysis_mode)
st.sidebar.markdown(f"""
<div class="mode-description">
    <div class="icon">{selected_option["icon"]}</div>
    <div class="title">{selected_option["title"]}</div>
    <div class="desc">{selected_option["description"]}</div>
</div>
""", unsafe_allow_html=True)

# Sidebar stats
st.sidebar.markdown("""
<div class="sidebar-stats">
    <div class="stats-header">📊 System Status</div>
    <div class="stat-item">
        <span class="stat-label">🛡️ Active Models</span>
        <span class="stat-value">1</span>
    </div>
    <div class="stat-item">
        <span class="stat-label">⚡ System Status</span>
        <span class="stat-value" style="color: #22c55e;">Online</span>
    </div>
    <div class="stat-item">
        <span class="stat-label">🔒 Security Level</span>
        <span class="stat-value" style="color: #3b82f6;">Maximum</span>
    </div>
    <div class="stat-item">
        <span class="stat-label">🚀 Version</span>
        <span class="stat-value">v2.1.0</span>
    </div>
    <div class="stat-item">
        <span class="stat-label">📡 Last Update</span>
        <span class="stat-value" style="color: #10b981;">Active</span>
    </div>
</div>
""", unsafe_allow_html=True)

# Help section
st.sidebar.markdown("---")
st.sidebar.markdown("""
<div class="help-section">
    <div class="help-header">💡 Quick Guide</div>
    <div class="help-content">
        <strong>🔍 Real-time:</strong> Paste URLs for instant threat analysis and classification<br><br>
        <strong>📁 Batch:</strong> Upload CSV files with 'url' column for bulk processing<br><br>
        <strong>📈 Performance:</strong> View comprehensive model metrics and accuracy reports<br><br>
        <strong>🌐 Traffic:</strong> Analyze network patterns, insights, and traffic classification
    </div>
</div>
""", unsafe_allow_html=True)

# Main content based on mode
if analysis_mode == "Real-time URL Analysis":
    st.header("🔍 Real-time URL Threat Detection")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        url_input = st.text_area(
            "Enter URLs (one per line):",
            height=150,
            placeholder="http://example.com/search?q=test\nhttp://malicious.com?q=<script>alert('xss')</script>"
        )
        
        if st.button("🔍 Analyze URLs", type="primary"):
            if url_input:
                urls = [url.strip() for url in url_input.split('\n') if url.strip()]
                results = []
                
                progress_bar = st.progress(0)
                for i, url in enumerate(urls):
                    features = extract_features(url)
                    pred = st.session_state.model.predict([features])[0]
                    prob = st.session_state.model.predict_proba([features])[0]
                    
                    # Traffic classification
                    traffic_type = st.session_state.traffic_analyzer.classify_traffic(url)
                    
                    results.append({
                        'URL': url,
                        'Threat_Status': 'Malicious' if pred else 'Benign',
                        'Confidence': max(prob),
                        'Traffic_Type': traffic_type,
                        'Risk_Score': prob[1] if len(prob) > 1 else 0
                    })
                    progress_bar.progress((i + 1) / len(urls))
                
                # Display results
                df_results = pd.DataFrame(results)
                
                # Metrics
                malicious_count = len(df_results[df_results['Threat_Status'] == 'Malicious'])
                benign_count = len(df_results[df_results['Threat_Status'] == 'Benign'])
                
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Total URLs", len(urls))
                with col2:
                    st.metric("🔴 Threats Detected", malicious_count)
                with col3:
                    st.metric("🟢 Safe URLs", benign_count)
                with col4:
                    st.metric("Threat Rate", f"{malicious_count/len(urls)*100:.1f}%")
                
                # Results table
                st.subheader("📊 Analysis Results")
                st.dataframe(df_results, use_container_width=True)
                
                # Visualizations
                col1, col2 = st.columns(2)
                
                with col1:
                    fig = px.pie(df_results, names='Threat_Status', 
                               title='Threat Distribution',
                               color_discrete_map={'Malicious': '#ff4444', 'Benign': '#44ff44'})
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    fig = px.bar(df_results.groupby('Traffic_Type').size().reset_index(name='Count'),
                               x='Traffic_Type', y='Count', title='Traffic Classification')
                    st.plotly_chart(fig, use_container_width=True)
    
    st.markdown('</div>', unsafe_allow_html=True)

elif analysis_mode == "Batch File Analysis":
    st.header("📁 Batch File Analysis")
    
    # Upload section
    st.markdown("""
    <div class="upload-section">
        <h3 style="color: #3b82f6; margin-bottom: 1rem;">📤 Upload Your CSV File</h3>
        <p style="color: #666; margin-bottom: 1rem;">Maximum file size: 200MB | Supported format: CSV</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Set max file size to 200MB programmatically
    uploaded_file = st.file_uploader(
        "Choose CSV file",
        type=["csv"],
        help="CSV should contain a 'url' column. Maximum file size: 200MB"
    )
    
    if uploaded_file:
        try:
            # Handle large files
            file_size = uploaded_file.size / (1024 * 1024)  # MB
            
            # Create file info display
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("📄 File Size", f"{file_size:.2f} MB")
            with col2:
                st.metric("📊 Format", "CSV")
            with col3:
                st.metric("✅ Status", "Ready")
            
            if file_size > 200:
                st.error("⚠️ File size exceeds 200MB limit! Please use a smaller file.")
            else:
                # Read file in chunks for large files
                if file_size > 50:
                    chunk_size = 1000
                    chunks = []
                    for chunk in pd.read_csv(uploaded_file, chunksize=chunk_size):
                        chunks.append(chunk)
                    df = pd.concat(chunks, ignore_index=True)
                else:
                    df = pd.read_csv(uploaded_file)
                
                st.success(f"✅ Loaded {len(df):,} URLs successfully!")
                
                if 'url' not in df.columns:
                    st.error("❌ CSV must contain a 'url' column!")
                else:
                  if st.button("Start Analysis", type="primary"):
                        # Analysis
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        predictions = []
                        probabilities = []
                        traffic_types = []
                        risk_scores = []
                        
                        total_urls = len(df)
                        batch_size = 100
                        
                        for i, url in enumerate(df['url']):
                            # Update progress bar every 100 URLs or at the end
                            if i % batch_size == 0 or i == total_urls - 1:
                                status_text.text(f"🔄 Processing batch {(i//batch_size)+1} - URL {i+1:,}/{total_urls:,}")
                                progress_bar.progress((i+1)/total_urls)
                            
                            try:
                                features = extract_features(url)
                                pred = st.session_state.model.predict([features])[0]
                                prob = st.session_state.model.predict_proba([features])[0]
                                traffic_type = st.session_state.traffic_analyzer.classify_traffic(url)
                                
                                predictions.append(pred)
                                probabilities.append(max(prob))
                                traffic_types.append(traffic_type)
                                # Calculate risk score immediately to avoid recalculation
                                risk_scores.append(prob[1] if len(prob) > 1 else 0)
                                
                            except Exception as e:
                                # Handle any errors in processing individual URLs
                                predictions.append(0)
                                probabilities.append(0.5)
                                traffic_types.append("Unknown")
                                risk_scores.append(0.0)
                        
                        # Final progress update
                        status_text.text(f"✅ Processing complete! Displaying results...")
                        progress_bar.progress(1.0)
                        
                        # Add results to dataframe immediately - no additional processing
                        df['Threat_Status'] = ['Malicious' if p else 'Benign' for p in predictions]
                        df['Confidence'] = probabilities
                        df['Traffic_Type'] = traffic_types
                        df['Risk_Score'] = risk_scores
                        
                        
                        # Summary metrics
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("Total URLs", f"{len(df):,}")
                        with col2:
                            malicious_count = len(df[df['Threat_Status'] == 'Malicious'])
                            st.metric("🔴 Threats", f"{malicious_count:,}")
                        with col3:
                            benign_count = len(df[df['Threat_Status'] == 'Benign'])
                            st.metric("🟢 Safe", f"{benign_count:,}")
                        with col4:
                            st.metric("Detection Rate", f"{malicious_count/len(df)*100:.1f}%")
                        
                        # Visualizations
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            fig = px.histogram(df, x='Confidence', color='Threat_Status',
                                             title='Confidence Distribution')
                            st.plotly_chart(fig, use_container_width=True)
                        
                        with col2:
                            fig = px.scatter(df, x='Risk_Score', y='Confidence', 
                                           color='Threat_Status',
                                           title='Risk vs Confidence Analysis')
                            st.plotly_chart(fig, use_container_width=True)
                        
                        # Traffic analysis
                        st.subheader("🌐 Traffic Classification Analysis")
                        traffic_summary = df.groupby(['Traffic_Type', 'Threat_Status']).size().reset_index(name='Count')
                        fig = px.bar(traffic_summary, x='Traffic_Type', y='Count', 
                                   color='Threat_Status', title='Threats by Traffic Type')
                        st.plotly_chart(fig, use_container_width=True)
                        
                        # Results table
                        st.subheader("📊 Detailed Results")
                        st.dataframe(df, use_container_width=True)
                        
                        # Download results
                        csv = df.to_csv(index=False)
                        st.download_button(
                            label="📥 Download Results",
                            data=csv,
                            file_name="security_analysis_results.csv",
                            mime="text/csv"
                        )
                        
        except Exception as e:
            st.error(f"❌ Error processing file: {str(e)}")
    
    st.markdown('</div>', unsafe_allow_html=True)

elif analysis_mode == "Model Performance":

    st.header("📈 Model Performance Analysis")
    
    # Load test data for evaluation
    if st.button("🔄 Generate Performance Report"):
        # Use sample data for demonstration
        test_df = pd.read_csv("sample_http.csv")
        
        X_test = [extract_features(url) for url in test_df["url"]]
        y_true = test_df["label"].values
        y_pred = st.session_state.model.predict(X_test)
        y_prob = st.session_state.model.predict_proba(X_test)
        
            # Metrics 
        accuracy = accuracy_score(y_true, y_pred) * 100
        
        # Calculate True Positives, False Positives, False Negatives
        tp = np.sum((y_true == 1) & (y_pred == 1))
        fp = np.sum((y_true == 0) & (y_pred == 1))
        fn = np.sum((y_true == 1) & (y_pred == 0))
        
        # Calculate precision, recall, and F1-score correctly
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Accuracy", f"{accuracy:.1f}%")
        with col2:
            st.metric("Precision", f"{precision * 100:.1f}%")
        with col3:
            st.metric("Recall", f"{recall * 100:.1f}%")
        with col4:
            st.metric("F1-Score", f"{f1 * 100:.1f}%")
        
        # Confusion Matrix
        col1, col2 = st.columns(2)
        
        with col1:
            cm = confusion_matrix(y_true, y_pred)
            fig = px.imshow(cm, text_auto=True, aspect="auto",
                          title="Confusion Matrix",
                          labels=dict(x="Predicted", y="Actual"))
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # ROC-like curve using probabilities
            if len(y_prob.shape) > 1:
                fpr_tpr_data = []
                thresholds = np.linspace(0, 1, 100)
                for threshold in thresholds:
                    y_pred_thresh = (y_prob[:, 1] >= threshold).astype(int)
                    tp = np.sum((y_true == 1) & (y_pred_thresh == 1))
                    fp = np.sum((y_true == 0) & (y_pred_thresh == 1))
                    tn = np.sum((y_true == 0) & (y_pred_thresh == 0))
                    fn = np.sum((y_true == 1) & (y_pred_thresh == 0))
                    
                    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
                    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
                    
                    fpr_tpr_data.append({'FPR': fpr, 'TPR': tpr, 'Threshold': threshold})
                
                roc_df = pd.DataFrame(fpr_tpr_data)
                fig = px.line(roc_df, x='FPR', y='TPR', title='ROC Curve')
                fig.add_shape(type='line', x0=0, y0=0, x1=1, y1=1, 
                            line=dict(dash='dash', color='gray'))
                st.plotly_chart(fig, use_container_width=True)
        
        # Feature importance
        st.subheader("🔍 Feature Importance")
        if hasattr(st.session_state.model, 'feature_importances_'):
            # Get the actual number of features from the model
            n_features = len(st.session_state.model.feature_importances_)
            
            # Concise feature names mapping
            feature_names_mapping = {
                0: 'Token Count',
                1: 'Token Length', 
                2: 'SQL Pattern',
                3: 'XSS Pattern',
                4: 'URL Entropy',
                5: 'SELECT Count',
                6: 'OR Count',
                7: 'AND Count',
                8: 'SCRIPT Count',
                9: 'ALERT Count',
                10: 'Special Chars',
                11: 'Digits Count',
                12: 'URL Length',
                13: 'Param Count',
                14: 'Suspicious Chars',
                15: 'Path Depth',
                16: 'Domain Length',
                17: 'Subdomain Count',
                18: 'UNION Count',
                19: 'DROP Count',
                20: 'DELETE Count',
                21: 'INSERT Count',
                22: 'UPDATE Count',
                23: 'EXEC Count',
                24: 'ONCLICK Count',
                25: 'ONLOAD Count',
                26: 'ONERROR Count',
                27: 'IFRAME Count',
                28: 'OBJECT Count',
                29: 'EMBED Count'
            }
            
            # feature names list 
            feature_names = []
            feature_importances = []
            
            for i in range(n_features):
                if i in feature_names_mapping:
                    feature_names.append(feature_names_mapping[i])
                    feature_importances.append(st.session_state.model.feature_importances_[i])
            
            # DataFrame with only mapped features
            if feature_names:  # Only proceed if we have mapped features
                importance_df = pd.DataFrame({
                    'Feature': feature_names,
                    'Importance': feature_importances
                }).sort_values('Importance', ascending=True)
                
                # most important features for visualization
                importance_df = importance_df.tail(15)
                
                fig = px.bar(importance_df, x='Importance', y='Feature', 
                            orientation='h', title='Top Feature Importance',
                            color='Importance',
                            color_continuous_scale='viridis')
                fig.update_layout(height=500)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.warning("No mapped features available for display.")
        else:
            st.warning("Feature importance not available for this model type.")
    
    st.markdown('</div>', unsafe_allow_html=True)

# sample traffic data for demonstration
elif analysis_mode == "Traffic Insights":
    st.header("🌐 Network Traffic Insights")
    
    # sample traffic data for demonstration
    if st.button("📊 Generate Traffic Analysis"):
        sample_urls = [
            "http://example.com/api/data",
            "https://cdn.example.com/image.jpg",
            "http://mail.example.com/inbox",
            "https://video.example.com/stream",
            "http://attacker.com?q=<script>alert('xss')</script>",
            "http://bank.com/transfer?to='; DROP TABLE users;--",
        ]
        
        traffic_data = []
        for url in sample_urls * 20: 
            features = extract_features(url)
            pred = st.session_state.model.predict([features])[0]
            traffic_type = st.session_state.traffic_analyzer.classify_traffic(url)
            
            traffic_data.append({
                'URL': url,
                'Traffic_Type': traffic_type,
                'Threat_Status': 'Malicious' if pred else 'Benign',
                'Timestamp': pd.Timestamp.now() - pd.Timedelta(minutes=np.random.randint(0, 1440))
            })
        
        df_traffic = pd.DataFrame(traffic_data)
        
        # Traffic type distribution
        col1, col2 = st.columns(2)
        
        with col1:
            traffic_counts = df_traffic['Traffic_Type'].value_counts()
            fig = px.pie(values=traffic_counts.values, names=traffic_counts.index,
                        title='Traffic Type Distribution')
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            threat_by_type = df_traffic.groupby(['Traffic_Type', 'Threat_Status']).size().reset_index(name='Count')
            fig = px.bar(threat_by_type, x='Traffic_Type', y='Count', 
                        color='Threat_Status', title='Threats by Traffic Type')
            st.plotly_chart(fig, use_container_width=True)
        
        # Time-based analysis
        st.subheader("Temporal Analysis")
        df_traffic['Hour'] = df_traffic['Timestamp'].dt.hour
        hourly_threats = df_traffic[df_traffic['Threat_Status'] == 'Malicious'].groupby('Hour').size().reset_index(name='Threats')
        
        fig = px.line(hourly_threats, x='Hour', y='Threats', 
                     title='Threat Detection by Hour')
        st.plotly_chart(fig, use_container_width=True)
        
        # Detailed traffic table
        st.subheader("📋 Traffic Log")
        st.dataframe(df_traffic.sort_values('Timestamp', ascending=False), use_container_width=True)
    
    st.markdown('</div>', unsafe_allow_html=True)

#Footer
st.markdown("---")
st.markdown("""
<div class="footer">
    <h3>AI-Net Guardian</h3>
    <p>Built with Streamlit & Machine Learning</p>
    <p>AI-Powered Traffic Classification | Threat Detection & Anomaly Identification</p>
</div>
""", unsafe_allow_html=True)