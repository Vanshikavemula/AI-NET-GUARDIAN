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

# Custom CSS
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #667eea;
    }
    .threat-detected {
        background: #ffe6e6;
        border-left: 4px solid #ff4444;
    }
    .safe-traffic {
        background: #e6ffe6;
        border-left: 4px solid #44ff44;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'model' not in st.session_state:
    st.session_state.model = joblib.load("model/rf_model.pkl")
if 'traffic_analyzer' not in st.session_state:
    st.session_state.traffic_analyzer = TrafficAnalyzer()

# Header
st.markdown("""
<div class="main-header">
    <h1>🛡️ AI-Powered Network Security Dashboard</h1>
    <p>Advanced ML-based Traffic Classification & Threat Detection System</p>
</div>
""", unsafe_allow_html=True)

# Sidebar
st.sidebar.title("🔧 Control Panel")
analysis_mode = st.sidebar.selectbox(
    "Select Analysis Mode",
    ["Real-time URL Analysis", "Batch File Analysis", "Model Performance", "Traffic Insights"]
)

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

elif analysis_mode == "Batch File Analysis":
    st.header("📁 Batch File Analysis")
    
    uploaded_file = st.file_uploader(
        "Upload CSV file (Max 500MB)",
        type=["csv"],
        help="CSV should contain a 'url' column"
    )
    
    if uploaded_file:
        try:
            # Handle large files
            file_size = uploaded_file.size / (1024 * 1024)  # MB
            st.info(f"File size: {file_size:.2f} MB")
            
            if file_size > 500:
                st.error("File size exceeds 500MB limit!")
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
                
                st.success(f"Loaded {len(df)} URLs successfully!")
                
                if 'url' not in df.columns:
                    st.error("CSV must contain a 'url' column!")
                else:
                    if st.button("🚀 Start Analysis", type="primary"):
                        # Analysis
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        features_list = []
                        predictions = []
                        probabilities = []
                        traffic_types = []
                        
                        for i, url in enumerate(df['url']):
                            if i % 100 == 0:
                                status_text.text(f"Processing URL {i+1}/{len(df)}")
                                progress_bar.progress((i+1)/len(df))
                            
                            features = extract_features(url)
                            pred = st.session_state.model.predict([features])[0]
                            prob = st.session_state.model.predict_proba([features])[0]
                            traffic_type = st.session_state.traffic_analyzer.classify_traffic(url)
                            
                            features_list.append(features)
                            predictions.append(pred)
                            probabilities.append(max(prob))
                            traffic_types.append(traffic_type)
                        
                        # Add results to dataframe
                        df['Threat_Status'] = ['Malicious' if p else 'Benign' for p in predictions]
                        df['Confidence'] = probabilities
                        df['Traffic_Type'] = traffic_types
                        df['Risk_Score'] = [prob[1] if len(prob) > 1 else 0 for prob in 
                                          [st.session_state.model.predict_proba([f])[0] for f in features_list]]
                        
                        # Summary metrics
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("Total URLs", len(df))
                        with col2:
                            malicious_count = len(df[df['Threat_Status'] == 'Malicious'])
                            st.metric("🔴 Threats", malicious_count)
                        with col3:
                            benign_count = len(df[df['Threat_Status'] == 'Benign'])
                            st.metric("🟢 Safe", benign_count)
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
            st.error(f"Error processing file: {str(e)}")

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
        accuracy = accuracy_score(y_true, y_pred)
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Accuracy", f"{accuracy:.3f}")
        with col2:
            precision = np.mean([1 if y_true[i] == y_pred[i] and y_pred[i] == 1 else 0 for i in range(len(y_true))]) if any(y_pred) else 0
            st.metric("Precision", f"{precision:.3f}")
        with col3:
            recall = np.mean([1 if y_true[i] == y_pred[i] and y_true[i] == 1 else 0 for i in range(len(y_true))]) if any(y_true) else 0
            st.metric("Recall", f"{recall:.3f}")
        with col4:
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            st.metric("F1-Score", f"{f1:.3f}")
        
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
            
            # Default feature names - adjust based on your actual features
            default_feature_names = ['Token Count', 'Token Length Sum', 'SQL Pattern', 
                                   'XSS Pattern', 'Entropy', 'Select Count', 'OR Count', 
                                   'AND Count', 'Script Count', 'Alert Count']
            
            # Handle different numbers of features
            if n_features <= len(default_feature_names):
                feature_names = default_feature_names[:n_features]
            else:
                # If model has more features than our default names, add generic names
                feature_names = default_feature_names + [f'Feature_{i}' for i in range(len(default_feature_names), n_features)]
            
            # Create DataFrame with matching lengths
            importance_df = pd.DataFrame({
                'Feature': feature_names,
                'Importance': st.session_state.model.feature_importances_
            }).sort_values('Importance', ascending=True)
            
            fig = px.bar(importance_df, x='Importance', y='Feature', 
                        orientation='h', title='Feature Importance')
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.warning("Feature importance not available for this model type.")
    
    # Generate sample traffic data for demonstration
elif analysis_mode == "Traffic Insights":
    st.header("🌐 Network Traffic Insights")
    
    # Generate sample traffic data for demonstration
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
        for url in sample_urls * 20:  # Simulate more data
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
        st.subheader("⏰ Temporal Analysis")
        df_traffic['Hour'] = df_traffic['Timestamp'].dt.hour
        hourly_threats = df_traffic[df_traffic['Threat_Status'] == 'Malicious'].groupby('Hour').size().reset_index(name='Threats')
        
        fig = px.line(hourly_threats, x='Hour', y='Threats', 
                     title='Threat Detection by Hour')
        st.plotly_chart(fig, use_container_width=True)
        
        # Detailed traffic table
        st.subheader("📋 Traffic Log")
        st.dataframe(df_traffic.sort_values('Timestamp', ascending=False), use_container_width=True)

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666;'>
    <p>🛡️ AI-Powered Network Security Dashboard | Built with Streamlit & Machine Learning</p>
    <p>Deliverable 1: AI-Powered Traffic Classification ✓ | Deliverable 2: Threat Detection & Anomaly Identification ✓</p>
</div>
""", unsafe_allow_html=True)