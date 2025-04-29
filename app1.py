import os
import pandas as pd
import numpy as np
import joblib
import streamlit as st
from scapy.all import IP, TCP, UDP, rdpcap
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
import tempfile
import matplotlib.pyplot as plt
import seaborn as sns
import time
import base64
from PIL import Image
from io import BytesIO

# Set page config
st.set_page_config(
    page_title="Network.NIRVANA",
    page_icon="🛡️",
    layout="wide"
)


# Function to create a centered container
def centered_container(width=None):
    if width:
        _, container, _ = st.columns([1, width, 1])
        return container
    else:
        _, container, _ = st.columns([1, 3, 1])
        return container


# Function to show animated text
def st_text_animator(text, delay=0.03):
    placeholder = st.empty()
    animated_text = ""
    for char in text:
        animated_text += char
        placeholder.markdown(f"<p style='font-size: 20px; text-align: center;'>{animated_text}</p>",
                             unsafe_allow_html=True)
        time.sleep(delay)
    return placeholder


# Function to apply custom CSS
def apply_custom_css():
    st.markdown("""
    <style>
        .main .block-container {
            padding-top: 2rem;
            padding-bottom: 2rem;
        }
        .stApp {
            background-color: #f5f7fa;
        }
        .stSidebar {
            background-color: #e8eef9;
        }
        .css-1d391kg {
            padding-top: 1rem;
        }
        .st-bw {
            background-color: #ffffff;
        }
        .stButton>button {
            background-color: #4169e1;
            color: white;
            border-radius: 5px;
            padding: 0.5rem 1rem;
            font-weight: bold;
            width: 100%;
            transition: all 0.3s;
        }
        .stButton>button:hover {
            background-color: #2a4cbb;
            transform: translateY(-2px);
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        div[data-testid="stMetric"] {
            background-color: white;
            padding: 15px 10px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            text-align: center;
        }
        h1, h2, h3 {
            text-align: center;
        }
        .footer {
            position: fixed;
            left: 0;
            bottom: 0;
            width: 100%;
            background-color: #333;
            color: white;
            text-align: center;
            padding: 10px;
        }
        .info-box {
            background-color: #f8f9fa;
            border-left: 5px solid #4169e1;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }
        .highlight {
            background-color: #f0f7ff;
            padding: 20px;
            border-radius: 10px;
            margin: 10px 0;
            border: 1px solid #d0e1ff;
            text-align: center;
        }
    </style>
    """, unsafe_allow_html=True)


# Function to generate a base64 encoded image from a BytesIO object
def get_image_base64(image_bytes):
    return base64.b64encode(image_bytes.getvalue()).decode()


# Function to create a logo placeholder
def create_logo():
    # Create a simple logo with a network icon
    buffer = BytesIO()
    fig, ax = plt.subplots(figsize=(4, 4))

    # Creating a network-like pattern for the logo
    np.random.seed(42)
    G = np.random.rand(10, 10)  # Connection matrix
    pos = np.random.rand(10, 2)  # Position of nodes

    # Plot nodes
    ax.scatter(pos[:, 0], pos[:, 1], s=200, c='#4169e1', zorder=2)

    # Plot connections
    for i in range(10):
        for j in range(i + 1, 10):
            if G[i, j] > 0.7:  # Only draw some connections
                ax.plot([pos[i, 0], pos[j, 0]], [pos[i, 1], pos[j, 1]], 'k-', alpha=0.6, zorder=1)

    # Add text "NIRVANA"
    ax.text(0.5, 0.5, "NIRVANA", fontsize=24, fontweight='bold',
            ha='center', va='center', color='white', zorder=3,
            bbox=dict(facecolor='#4169e1', alpha=0.8, boxstyle='round,pad=0.5'))

    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis('off')
    plt.tight_layout()

    # Save figure to BytesIO object
    plt.savefig(buffer, format='png', dpi=100)
    plt.close()

    return buffer


# Read PCAP file and convert to CSV using Scapy
@st.cache_data
def pcap_to_csv_scapy(uploaded_file):
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_pcap:
        tmp_pcap.write(uploaded_file.getvalue())
        pcap_path = tmp_pcap.name

    try:
        with st.spinner("Processing PCAP file..."):
            packets = rdpcap(pcap_path)
            data = []

            for pkt in packets:
                packet_info = {
                    'timestamp': pkt.time,
                    'length': len(pkt),
                    'protocol': 'Unknown',
                    'src_ip': None,
                    'dst_ip': None,
                    'src_port': None,
                    'dst_port': None,
                    'is_tcp': 0,
                    'is_udp': 0
                }

                if pkt.haslayer(IP):
                    packet_info['src_ip'] = str(pkt[IP].src)
                    packet_info['dst_ip'] = str(pkt[IP].dst)

                if pkt.haslayer(TCP):
                    packet_info['protocol'] = 'TCP'
                    packet_info['src_port'] = int(pkt[TCP].sport)
                    packet_info['dst_port'] = int(pkt[TCP].dport)
                    packet_info['is_tcp'] = 1

                if pkt.haslayer(UDP):
                    packet_info['protocol'] = 'UDP'
                    packet_info['src_port'] = int(pkt[UDP].sport)
                    packet_info['dst_port'] = int(pkt[UDP].dport)
                    packet_info['is_udp'] = 1

                data.append(packet_info)

            df = pd.DataFrame(data)

            # Save to a temporary CSV file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.csv') as tmp_csv:
                csv_path = tmp_csv.name
                df.to_csv(csv_path, index=False)

            return df, csv_path
    except Exception as e:
        st.error(f"Error processing PCAP file: {e}")
        return None, None
    finally:
        # Clean up the temporary PCAP file
        if os.path.exists(pcap_path):
            os.unlink(pcap_path)


# Preprocess Data
def preprocess_data(df, fit=False):
    try:
        with st.spinner("Preprocessing data..."):
            df = df.fillna(0)

            categorical_features = ['protocol', 'src_ip', 'dst_ip']
            for col in categorical_features:
                df[col] = df[col].astype(str)

            numerical_features = ['timestamp', 'length', 'src_port', 'dst_port']

            column_transformer = ColumnTransformer([
                ('encoder', OneHotEncoder(handle_unknown='ignore', sparse_output=False), categorical_features),
                ('scaler', StandardScaler(), numerical_features)
            ], remainder='passthrough')

            if fit:
                X_transformed = column_transformer.fit_transform(df)
                # Save transformer to a temporary file
                with tempfile.NamedTemporaryFile(delete=False, suffix='.pkl') as tmp_file:
                    transformer_path = tmp_file.name
                    joblib.dump(column_transformer, transformer_path)
                st.session_state.transformer_path = transformer_path
            else:
                if 'transformer_path' in st.session_state:
                    encoder = joblib.load(st.session_state.transformer_path)
                    X_transformed = encoder.transform(df)
                else:
                    st.error("No transformer found. Please train the model first.")
                    return None, None

            # For demo, we're generating random labels (0 or 1) for each packet
            # In a real scenario, you would use actual labeled data
            y = np.random.randint(0, 2, size=len(df))
            return X_transformed, y

    except Exception as e:
        st.error(f"Error in preprocessing data: {e}")
        return None, None


# Train Model
def train_model(X, y):
    try:
        with st.spinner("Training model..."):
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

            # Get user-selected parameters
            n_estimators = st.session_state.n_estimators
            max_depth = st.session_state.max_depth if st.session_state.use_max_depth else None

            model = RandomForestClassifier(
                n_estimators=n_estimators,
                max_depth=max_depth,
                random_state=42
            )

            model.fit(X_train, y_train)
            predictions = model.predict(X_test)

            accuracy = accuracy_score(y_test, predictions)
            conf_matrix = confusion_matrix(y_test, predictions)
            class_report = classification_report(y_test, predictions, output_dict=True)

            # Save model to a temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pkl') as tmp_file:
                model_path = tmp_file.name
                joblib.dump(model, model_path)

            st.session_state.model_path = model_path

            return accuracy, conf_matrix, class_report

    except Exception as e:
        st.error(f"Error in training model: {e}")
        return None, None, None


# Detect Threats
def detect_threats(df):
    try:
        with st.spinner("Detecting threats..."):
            if 'model_path' not in st.session_state:
                st.error("No trained model found. Please train a model first.")
                return None

            model = joblib.load(st.session_state.model_path)

            X_transformed, _ = preprocess_data(df, fit=False)
            if X_transformed is None:
                return None

            predictions = model.predict(X_transformed)
            threat_probability = model.predict_proba(X_transformed)[:, 1]

            threat_summary = {
                'total_packets': len(df),
                'threat_packets': int(np.sum(predictions)),
                'safe_packets': int(len(predictions) - np.sum(predictions)),
                'threat_percentage': float(np.mean(predictions) * 100),
                'predictions': predictions,
                'threat_probability': threat_probability
            }

            return threat_summary

    except Exception as e:
        st.error(f"Error in detecting threats: {e}")
        return None


# Visualization functions
def plot_packet_distribution(df):
    st.subheader("📊 Packet Analysis")

    st.markdown("""
    <div class="info-box">
        <h4>What am I looking at?</h4>
        <p>These visualizations show the distribution of network protocols and packet sizes in your data.
        The graphs help identify which protocols are most common and how packet sizes are distributed,
        which can be useful for detecting unusual traffic patterns.</p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        # Protocol distribution
        protocol_counts = df['protocol'].value_counts()
        fig, ax = plt.subplots(figsize=(6, 4))
        bars = protocol_counts.plot(kind='bar', ax=ax, color='#4169e1')
        ax.set_title('Protocol Distribution')
        ax.set_ylabel('Count')

        # Add value annotations
        for i, v in enumerate(protocol_counts):
            ax.text(i, v + 0.1, str(v), ha='center')

        plt.tight_layout()
        st.pyplot(fig)

    with col2:
        # Packet length distribution
        fig, ax = plt.subplots(figsize=(6, 4))
        sns.histplot(df['length'], bins=20, kde=True, ax=ax, color='#4169e1')
        ax.set_title('Packet Length Distribution')
        ax.set_xlabel('Packet Length')
        ax.set_ylabel('Count')
        plt.tight_layout()
        st.pyplot(fig)

    # Top source and destination IPs
    st.markdown("### 🔍 Top Network Addresses")

    st.markdown("""
    <div class="info-box">
        <p>These tables show the most frequent source and destination IP addresses in your network traffic.
        High frequency of certain IPs might indicate normal servers or potential attack sources.</p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Top Source IPs")
        top_src = df['src_ip'].value_counts().head(10)
        st.dataframe(top_src, use_container_width=True)

    with col2:
        st.markdown("#### Top Destination IPs")
        top_dst = df['dst_ip'].value_counts().head(10)
        st.dataframe(top_dst, use_container_width=True)


def plot_threat_results(threat_summary, df):
    st.subheader("🛡️ Threat Detection Results")

    st.markdown("""
    <div class="info-box">
        <h4>Understanding the Results</h4>
        <p>This analysis shows packets classified as safe or potentially threatening based on their characteristics.
        The pie chart visualizes the proportion of threat vs. safe packets, while the metrics show exact counts.
        Remember that this is a machine learning prediction and may require further investigation.</p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Total Packets", threat_summary['total_packets'])

    with col2:
        st.metric("Threat Packets", threat_summary['threat_packets'])

    with col3:
        st.metric("Threat Percentage", f"{threat_summary['threat_percentage']:.2f}%")

    # Plot threat vs safe packets
    col1, col2 = st.columns([2, 3])

    with col1:
        fig, ax = plt.subplots(figsize=(6, 6))
        labels = ['Safe', 'Threat']
        sizes = [threat_summary['safe_packets'], threat_summary['threat_packets']]
        colors = ['#4CAF50', '#F44336']

        # Create pie chart with shadow and custom styling
        patches, texts, autotexts = ax.pie(
            sizes, labels=labels, autopct='%1.1f%%',
            startangle=90, colors=colors,
            shadow=True, explode=(0, 0.1)
        )

        # Enhance text visibility
        for text in texts:
            text.set_fontsize(12)
            text.set_fontweight('bold')

        for autotext in autotexts:
            autotext.set_fontsize(10)
            autotext.set_fontweight('bold')
            autotext.set_color('white')

        ax.axis('equal')
        plt.tight_layout()
        st.pyplot(fig)

    with col2:
        st.markdown("### 📝 Threat Analysis Summary")

        # Calculate and display additional metrics
        if threat_summary['threat_percentage'] > 20:
            risk_level = "High"
            risk_color = "#F44336"
        elif threat_summary['threat_percentage'] > 5:
            risk_level = "Medium"
            risk_color = "#FFA726"
        else:
            risk_level = "Low"
            risk_color = "#4CAF50"

        st.markdown(f"""
        <div style="background-color: {risk_color}; padding: 15px; border-radius: 10px; color: white;">
            <h4 style="margin: 0; text-align: center;">Risk Level: {risk_level}</h4>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div style="margin-top: 20px; background-color: #f8f9fa; padding: 15px; border-radius: 10px;">
            <h4>What does this mean?</h4>
            <ul>
                <li>Safe packets represent normal network traffic</li>
                <li>Threat packets may indicate suspicious activity</li>
                <li>Higher threat percentages suggest more investigation is needed</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    # Display top threat sources
    df_with_prediction = df.copy()
    df_with_prediction['threat_prediction'] = threat_summary['predictions']
    df_with_prediction['threat_probability'] = threat_summary['threat_probability']

    threat_df = df_with_prediction[df_with_prediction['threat_prediction'] == 1]

    if len(threat_df) > 0:
        st.markdown("### 🔍 Top Threat Sources")

        st.markdown("""
        <div class="info-box">
            <p>These are the IP addresses most frequently associated with potentially malicious activity in your network.
            Focus your investigation on these sources first.</p>
        </div>
        """, unsafe_allow_html=True)

        threat_sources = threat_df['src_ip'].value_counts().head(10)

        col1, col2 = st.columns(2)

        with col1:
            st.dataframe(threat_sources, use_container_width=True)

        with col2:
            fig, ax = plt.subplots(figsize=(6, 4))
            bars = threat_sources.plot(kind='bar', ax=ax, color='#F44336')
            ax.set_title('Top Threat Sources')
            ax.set_ylabel('Count')

            # Add value annotations
            for i, v in enumerate(threat_sources):
                ax.text(i, v + 0.1, str(v), ha='center')

            plt.tight_layout()
            st.pyplot(fig)

        # Show the most suspicious packets
        st.markdown("### ⚠️ Most Suspicious Packets")

        st.markdown("""
        <div class="info-box">
            <p>These individual packets have the highest probability of being threats according to our model.
            Examine these specific connections more closely.</p>
        </div>
        """, unsafe_allow_html=True)

        suspicious_packets = df_with_prediction.sort_values(by='threat_probability', ascending=False).head(10)
        st.dataframe(suspicious_packets, use_container_width=True)

        # Add some recommended actions
        st.markdown("### 🛠️ Recommended Actions")

        st.markdown("""
        <div class="highlight">
            <h4>Based on the analysis, consider these actions:</h4>
            <ol>
                <li>Investigate the top threat source IPs</li>
                <li>Check for unusual port usage in suspicious packets</li>
                <li>Compare threat detection results with your network security logs</li>
                <li>Consider implementing traffic filtering for high-risk sources</li>
                <li>Schedule regular monitoring of these network segments</li>
            </ol>
        </div>
        """, unsafe_allow_html=True)


# Main app layout
# Main app layout
def main():
    # Apply custom CSS
    apply_custom_css()

    # Initialize session state variables
    if 'uploaded_data' not in st.session_state:
        st.session_state.uploaded_data = None
    if 'n_estimators' not in st.session_state:
        st.session_state.n_estimators = 100
    if 'max_depth' not in st.session_state:
        st.session_state.max_depth = 10
    if 'use_max_depth' not in st.session_state:
        st.session_state.use_max_depth = True
    if 'model_trained' not in st.session_state:
         st.session_state.model_trained = False
    if 'model_accuracy' not in st.session_state:
         st.session_state.model_accuracy = 0.0
    if 'conf_matrix' not in st.session_state:
         st.session_state.conf_matrix = np.zeros((2,2)) # Default empty matrix
    if 'class_report' not in st.session_state:
         st.session_state.class_report = {} # Default empty report
    if 'threat_summary' not in st.session_state:
         st.session_state.threat_summary = None
    if 'threat_level' not in st.session_state:
         st.session_state.threat_level = "ANALYSIS PENDING"
    if 'alert_color' not in st.session_state:
         st.session_state.alert_color = "#FFA500" # Default orange

    # Create logo and display in header
    logo_bytes = create_logo()
    logo_base64 = get_image_base64(logo_bytes)

    # Display app title and logo
    header_col1, header_col2 = st.columns([3, 1])

    with header_col1:
        st.markdown("""
        <h1 style="text-align: center; font-size: 3em; margin-bottom: 0;">Network.NIRVANA</h1>
        <h3 style="text-align: center; margin-top: 0; color: #4169e1;">Advanced Network Threat Detection</h3>
        """, unsafe_allow_html=True)

    with header_col2:
        st.markdown(f"""
        <div style="display: flex; justify-content: center;">
            <img src="data:image/png;base64,{logo_base64}" width="100">
        </div>
        """, unsafe_allow_html=True)

    # Display developer info
    st.markdown("""
    <div style="text-align: center; margin-bottom: 20px;">
        <p style="color: #666; font-style: italic;">
            Developed by Lakshmeesha Suvarna | Advanced Network Security Solutions
        </p>
    </div>
    """, unsafe_allow_html=True)

    # --- Sidebar ---
    st.sidebar.markdown("""
    <div style="text-align: center; padding: 10px 0;">
        <h2>🛠️ Control Panel</h2>
    </div>
    """, unsafe_allow_html=True)

    # File Upload Section
    st.sidebar.header("1. Upload Data")
    uploaded_file = st.sidebar.file_uploader("Upload a PCAP file", type=["pcap", "pcapng"])

    if uploaded_file is not None:
        if st.sidebar.button("🔍 Process PCAP File"):
            with st.spinner("Processing PCAP file... This may take a moment"):
                df,csv_path= pcap_to_csv_scapy(uploaded_file)
                if df is not None:
                    st.session_state.uploaded_data = df
                    st.session_state.csv_path = csv_path
                    # Reset previous results when new data is processed
                    st.session_state.model_trained = False
                    st.session_state.threat_summary = None
                    st.session_state.threat_level = "ANALYSIS PENDING"
                    st.session_state.alert_color = "#FFA500"
                    st.success(f"✅ Successfully processed {len(df)} packets from {uploaded_file.name}")
                    st.markdown("""
                    <style>
                    @keyframes pulse { 0% { transform: scale(1); } 50% { transform: scale(1.05); } 100% { transform: scale(1); } }
                    .pulse { animation: pulse 2s infinite; display: block; margin: 10px auto; text-align: center; padding: 10px; background-color: #e8f0fe; border-radius: 10px; width: 80%; }
                    </style>
                    <div class="pulse"> <h4>Step 1 Complete! Now train your model in step 2.</h4> </div>
                    """, unsafe_allow_html=True)
                    st.rerun() # Rerun to update the main panel immediately

    # Model Training Section
    st.sidebar.header("2. Train Model")
    st.sidebar.markdown("Model Parameters:")

    st.session_state.n_estimators = st.sidebar.slider("Number of trees", 10, 500, 100, key="n_estimators_slider")
    st.session_state.use_max_depth = st.sidebar.checkbox("Limit tree depth", True, key="use_max_depth_check")
    if st.session_state.use_max_depth:
        st.session_state.max_depth = st.sidebar.slider("Maximum tree depth", 1, 30, 10, key="max_depth_slider")

    if st.session_state.uploaded_data is not None:
        if st.sidebar.button("🧠 Train Model"):
            with st.spinner("Training model... Please wait"):
                X, y = preprocess_data(st.session_state.uploaded_data, fit=True)
                if X is not None and y is not None:
                    accuracy, conf_matrix, class_report = train_model(X, y)
                    if accuracy is not None:
                        st.session_state.model_trained = True
                        st.session_state.model_accuracy = accuracy
                        st.session_state.conf_matrix = conf_matrix
                        st.session_state.class_report = class_report
                        # Reset threat detection results if model is retrained
                        st.session_state.threat_summary = None
                        st.session_state.threat_level = "ANALYSIS PENDING"
                        st.session_state.alert_color = "#FFA500"
                        st.success(f"✅ Model trained successfully with accuracy: {accuracy:.2f}")
                        st.markdown("""
                        <div class="pulse"> <h4>Step 2 Complete! Now detect threats in step 3.</h4> </div>
                        """, unsafe_allow_html=True)
                        st.rerun() # Rerun to update the main panel

    # Threat Detection Section
    st.sidebar.header("3. Detect Threats")
    if st.session_state.uploaded_data is not None:
        if st.session_state.model_trained:
            if st.sidebar.button("🔍 Detect Threats"):
                with st.spinner("Analyzing network traffic for threats..."):
                    threat_summary = detect_threats(st.session_state.uploaded_data)
                    if threat_summary is not None:
                        st.session_state.threat_summary = threat_summary
                        threat_percentage = threat_summary['threat_percentage']
                        if threat_percentage > 50:
                            threat_level = "⚠️ HIGH THREAT DETECTED"
                            alert_color = "#F44336"
                        elif threat_percentage > 20:
                            threat_level = "⚠️ MEDIUM THREAT DETECTED"
                            alert_color = "#FF9800"
                        elif threat_percentage > 5:
                            threat_level = "⚠️ LOW THREAT DETECTED"
                            alert_color = "#FFC107"
                        else:
                            threat_level = "✅ NETWORK APPEARS SAFE"
                            alert_color = "#4CAF50"
                        st.session_state.threat_level = threat_level
                        st.session_state.alert_color = alert_color
                        st.markdown("""
                        <div class="pulse"> <h4>Analysis Complete! View your results below.</h4> </div>
                        """, unsafe_allow_html=True)
                        st.rerun() # Rerun to update main panel
        else:
             st.sidebar.warning("Train the model first (Step 2).")
    else:
        st.sidebar.info("Upload and process data first (Step 1).")


    # Help and About section in sidebar
    with st.sidebar.expander("ℹ️ About & Help"):
        st.markdown("""
        **Network.NIRVANA** is an advanced network security analysis tool that helps detect potential threats in network traffic.

        **How to use:**
        1. Upload a PCAP file containing network traffic
        2. Process the file to extract packet information
        3. Train the machine learning model with your preferred settings
        4. Run threat detection to identify suspicious activity

        **For questions or support:**
        Contact: your.email@example.com
        """)

    # Footer with credits
    st.sidebar.markdown("""
    <div style="text-align: center; font-size: 0.8em; margin-top: 20px; color: #6c757d;">
        <p>© 2025 Lakshmeesha Suvarna | Network.NIRVANA</p>
    </div>
    """, unsafe_allow_html=True)


    # --- Main content area ---
    if st.session_state.uploaded_data is not None:
        # --- Display Data Analysis and Model Info ---
        st.header("📊 Dataset Information")
        st.markdown(f"""
            <div class="highlight">
                <h4>Dataset Overview</h4>
                <p><strong>File:</strong> {uploaded_file.name if uploaded_file else 'Unknown'}</p>
                <p><strong>Packets:</strong> {len(st.session_state.uploaded_data)}</p>
                <p><strong>Status:</strong> Processed and ready for analysis</p>
            </div>
            """, unsafe_allow_html=True)

        # Display sample data
        with st.expander("Preview Network Data"):
            st.dataframe(st.session_state.uploaded_data.head(10), use_container_width=True)
            st.markdown("""
                <div class="info-box">
                    <p>This preview shows the first 10 packets extracted from your PCAP file.
                    Each row represents a network packet with information about source, destination, protocol, and more.</p>
                </div>
                """, unsafe_allow_html=True)

        # Display packet distribution
        plot_packet_distribution(st.session_state.uploaded_data)

        # Display model info if trained
        if st.session_state.model_trained:
            st.header("🧠 Machine Learning Model Performance")
            st.markdown(f"""
                <div class="highlight">
                    <h4>Model Configuration & Accuracy</h4>
                    <p><strong>Algorithm:</strong> Random Forest Classifier</p>
                    <p><strong>Accuracy:</strong> {st.session_state.model_accuracy:.2f}</p>
                    <p><strong>Trees:</strong> {st.session_state.n_estimators}</p>
                    <p><strong>Max Depth:</strong> {"Unlimited" if not st.session_state.use_max_depth else st.session_state.max_depth}</p>
                </div>
                """, unsafe_allow_html=True)

            with st.expander("View Model Details (Confusion Matrix & Classification Report)"):
                model_col1, model_col2 = st.columns(2)
                with model_col1:
                    st.subheader("Confusion Matrix")
                    conf_matrix = st.session_state.conf_matrix
                    fig, ax = plt.subplots(figsize=(5, 4)) # Adjusted size
                    sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues',
                                xticklabels=['Safe', 'Threat'],
                                yticklabels=['Safe', 'Threat'],
                                ax=ax, cbar=False) # Removed color bar for space
                    ax.set_xlabel('Predicted Label')
                    ax.set_ylabel('True Label')
                    plt.tight_layout()
                    st.pyplot(fig)
                    st.markdown("""
                        <div class="info-box">
                            <p><strong>Matrix Legend:</strong><br>
                            Top-Left: True Negatives (Safe)<br>
                            Bottom-Right: True Positives (Threat)<br>
                            Top-Right: False Positives (Safe as Threat)<br>
                            Bottom-Left: False Negatives (Threat as Safe)</p>
                        </div>
                        """, unsafe_allow_html=True)

                with model_col2:
                    st.subheader("Classification Report")
                    if st.session_state.class_report: # Check if report exists
                        # Convert classification report to a nicer format
                        report_data = {
                            'Precision': [st.session_state.class_report['0']['precision'], st.session_state.class_report['1']['precision'], st.session_state.class_report['weighted avg']['precision']],
                            'Recall': [st.session_state.class_report['0']['recall'], st.session_state.class_report['1']['recall'], st.session_state.class_report['weighted avg']['recall']],
                            'F1-Score': [st.session_state.class_report['0']['f1-score'], st.session_state.class_report['1']['f1-score'], st.session_state.class_report['weighted avg']['f1-score']],
                            'Support': [st.session_state.class_report['0']['support'], st.session_state.class_report['1']['support'], st.session_state.class_report['weighted avg']['support']]
                        }
                        metrics_df = pd.DataFrame(report_data, index=['Safe (0)', 'Threat (1)', 'Weighted Avg'])
                        st.dataframe(metrics_df.style.format("{:.2f}"), use_container_width=True) # Format floats
                    else:
                        st.warning("Classification report not available.")

                    st.markdown("""
                        <div class="info-box" style="margin-top: 10px;">
                            <h4>Understanding Model Metrics</h4>
                            <ul>
                                <li><strong>Accuracy:</strong> Overall correctness</li>
                                <li><strong>Precision:</strong> Correct positive predictions</li>
                                <li><strong>Recall:</strong> Actual positives correctly identified</li>
                                <li><strong>F1-Score:</strong> Balance of Precision & Recall</li>
                            </ul>
                        </div>
                        """, unsafe_allow_html=True)
        else:
             st.info("Model not trained yet. Please train the model using the sidebar (Step 2).")

        # --- Display Threat Analysis ---
        if st.session_state.threat_summary is not None:
            # Show alert banner
            st.markdown(f"""
                <div style="background-color: {st.session_state.alert_color}; color: white; padding: 15px; border-radius: 10px; text-align: center; margin: 20px 0;">
                    <h2 style="margin:0; color: white;">{st.session_state.threat_level}</h2>
                </div>
                """, unsafe_allow_html=True)

            # Show threat analysis results
            plot_threat_results(st.session_state.threat_summary, st.session_state.uploaded_data)

            # --- Add export options ---
            st.header("📤 Export Results")
            st.markdown("""
                <div class="info-box">
                    <p>Export your analysis results for documentation or further investigation.</p>
                </div>
                """, unsafe_allow_html=True)

            exp_col1, exp_col2, exp_col3 = st.columns(3)

            with exp_col1:
                # Create threat report dataframe in memory
                df_with_prediction = st.session_state.uploaded_data.copy()
                df_with_prediction['threat_prediction'] = st.session_state.threat_summary['predictions']
                df_with_prediction['threat_probability'] = st.session_state.threat_summary['threat_probability']
                csv_export = df_with_prediction.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="Export Threat Report (CSV)",
                    data=csv_export,
                    file_name="threat_report.csv",
                    mime="text/csv",
                    key='download-csv'
                )


            with exp_col2:
                 # Create a summary in markdown format
                summary_md = f"""
# Network Threat Analysis Report

## Summary
- **Date**: {time.strftime("%Y-%m-%d %H:%M:%S")}
- **File Analyzed**: {uploaded_file.name if uploaded_file else 'Unknown'}
- **Total Packets**: {st.session_state.threat_summary['total_packets']}
- **Threat Level**: {st.session_state.threat_level.replace('⚠️', '').replace('✅', '').strip()}

## Threat Statistics
- **Threat Packets**: {st.session_state.threat_summary['threat_packets']}
- **Safe Packets**: {st.session_state.threat_summary['safe_packets']}
- **Threat Percentage**: {st.session_state.threat_summary['threat_percentage']:.2f}%

## Model Information
- **Algorithm**: Random Forest Classifier
- **Accuracy**: {st.session_state.model_accuracy:.2f}
- **Trees**: {st.session_state.n_estimators}
- **Max Depth**: {"Unlimited" if not st.session_state.use_max_depth else st.session_state.max_depth}

## Recommendations
1. Investigate the top threat source IPs
2. Check for unusual port usage in suspicious packets
3. Compare threat detection results with your network security logs
4. Consider implementing traffic filtering for high-risk sources
5. Schedule regular monitoring of these network segments

## Notes
This report was generated automatically by Network.NIRVANA. The threat detection is based on
machine learning predictions and may require further investigation by security professionals.
"""
                st.download_button(
                    label="Export Summary Report (MD)",
                    data=summary_md.encode('utf-8'),
                    file_name="threat_analysis_report.md",
                    mime="text/markdown",
                    key='download-md'
                 )

            with exp_col3:
                 # Create a figure with threat visualizations
                fig_export = plt.figure(figsize=(12, 8))
                fig_export.suptitle("Network Threat Analysis Summary", fontsize=16, fontweight='bold')

                # Add threat pie chart
                ax1 = fig_export.add_subplot(221)
                labels = ['Safe', 'Threat']
                sizes = [st.session_state.threat_summary['safe_packets'], st.session_state.threat_summary['threat_packets']]
                colors = ['#4CAF50', '#F44336']
                ax1.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors, shadow=True, explode=(0, 0.1))
                ax1.set_title('Threat vs Safe Distribution')

                # Add protocol bar chart
                ax2 = fig_export.add_subplot(222)
                protocol_counts = st.session_state.uploaded_data['protocol'].value_counts().head() # Top 5
                protocol_counts.plot(kind='bar', ax=ax2, color='#4169e1')
                ax2.set_title('Top Protocol Distribution')
                ax2.tick_params(axis='x', rotation=45)

                # Add length histogram
                ax3 = fig_export.add_subplot(223)
                sns.histplot(st.session_state.uploaded_data['length'], bins=30, kde=True, ax=ax3, color='#4169e1')
                ax3.set_title('Packet Length Distribution')
                ax3.set_xlabel('Packet Length')

                # Add confusion matrix if available
                ax4 = fig_export.add_subplot(224)
                if st.session_state.model_trained:
                    conf_matrix = st.session_state.conf_matrix
                    sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues', xticklabels=['Safe', 'Threat'], yticklabels=['Safe', 'Threat'], ax=ax4, cbar=False)
                    ax4.set_title('Model Confusion Matrix')
                    ax4.set_xlabel('Predicted')
                    ax4.set_ylabel('Actual')
                else:
                     ax4.text(0.5, 0.5, 'Model not trained', ha='center', va='center', fontsize=12)
                     ax4.axis('off')


                plt.tight_layout(rect=[0, 0.03, 1, 0.95]) # Adjust layout

                # Save figure to a BytesIO object
                img_bytes = BytesIO()
                plt.savefig(img_bytes, format='png', dpi=150)
                plt.close(fig_export) # Close the figure to free memory
                img_bytes.seek(0)

                st.download_button(
                    label="Export Visualization (PNG)",
                    data=img_bytes,
                    file_name="threat_visualization.png",
                    mime="image/png",
                    key='download-png'
                )
        else:
             st.info("Threat detection not run yet. Please run detection using the sidebar (Step 3).")

    else:
        # --- Display Welcome Screen when no data is loaded ---
        st.markdown("""
            <div style="text-align: center; padding: 30px 20px; background-color: #f8f9fa; border-radius: 10px; margin: 20px 0;">
                <h2>👋 Welcome to Network.NIRVANA</h2>
                <p style="font-size: 1.2em; margin: 15px 0;">
                    Your advanced network threat detector powered by machine learning
                </p>
                <div style="padding: 15px; background-color: #e8eef9; border-radius: 10px; max-width: 600px; margin: 20px auto;">
                    <h3>🚀 Getting Started</h3>
                    <ol style="text-align: left; padding-left: 30px; margin-top: 10px;">
                        <li>Upload a PCAP file containing network traffic using the sidebar</li>
                        <li>Process the file to extract packet information</li>
                        <li>Train a machine learning model with your preferred settings</li>
                        <li>Run threat detection to identify suspicious network activity</li>
                    </ol>
                </div>
                 <p style="font-style: italic; margin-top: 20px; color: #6c757d;">
                    Use the sidebar panel on the left to begin your analysis.
                </p>
            </div>
            """, unsafe_allow_html=True)

        # Intro Columns (was originally causing the error)
        intro_col1, intro_col2 = st.columns([2, 1]) # Adjusted ratio

        with intro_col1:
            st.markdown("""
            ## 🌟 About Network.NIRVANA

            An advanced solution for network traffic analysis and threat detection.

            ### 🔍 What can you do?

            - **Analyze network traffic** captured in PCAP files
            - **Visualize network patterns** with intuitive graphs
            - **Train machine learning models** to detect anomalies
            - **Identify potential threats** in your network
            - **Get actionable insights** to improve security

            ### 🚀 Getting Started Steps

            1. **Upload PCAP** (Sidebar Step 1)
            2. **Process File** (Button in Step 1)
            3. **Train Model** (Sidebar Step 2)
            4. **Detect Threats** (Sidebar Step 3)

            Let's secure your network together!
            """)

        with intro_col2:
            st.markdown("""
            <div style="background-color: #f0f7ff; padding: 20px; border-radius: 10px; text-align: center; height: 100%;">
                <h3 style="color: #4169e1;">Why Network Monitoring Matters</h3>
                <p style="font-size:0.9em;">Cyber threats are constantly evolving. Proactive network analysis helps identify vulnerabilities and suspicious activities before they cause significant damage.</p>
                <h4 style="color: #4169e1; margin-top: 20px;">Average Stats:</h4>
                <p style="font-size:0.9em;">🕒 ~280 days to identify a data breach</p>
                <p style="font-size:0.9em;">💰 ~$4M average cost of a breach</p>
                <p style="margin-top: 15px; font-weight: bold;">Stay vigilant!</p>
            </div>
            """, unsafe_allow_html=True)

        # Features section
        st.markdown("<h2 style='text-align: center; margin-top: 40px;'>🛡️ Key Features</h2>", unsafe_allow_html=True)
        feat_col1, feat_col2, feat_col3 = st.columns(3)
        feature_card_style = "background-color: white; padding: 20px; border-radius: 10px; height: 200px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); display: flex; flex-direction: column; justify-content: center;"

        with feat_col1:
            st.markdown(f"""
            <div style="{feature_card_style}">
                <h3 style="text-align: center; color: #4169e1; margin-bottom:10px;">🔍 Deep Packet Analysis</h3>
                <p style="text-align: center; font-size:0.9em;">Examine network packets in detail, including protocols, sources, destinations.</p>
            </div>
            """, unsafe_allow_html=True)

        with feat_col2:
            st.markdown(f"""
            <div style="{feature_card_style}">
                <h3 style="text-align: center; color: #4169e1; margin-bottom:10px;">🧠 ML-Powered Detection</h3>
                <p style="text-align: center; font-size:0.9em;">Leverage machine learning to identify anomalies and potential security threats.</p>
            </div>
            """, unsafe_allow_html=True)

        with feat_col3:
            st.markdown(f"""
            <div style="{feature_card_style}">
                <h3 style="text-align: center; color: #4169e1; margin-bottom:10px;">📊 Interactive Visualization</h3>
                <p style="text-align: center; font-size:0.9em;">View intuitive graphs to understand traffic patterns and security status.</p>
            </div>
            """, unsafe_allow_html=True)


        # How it works section
        st.markdown("<h2 style='text-align: center; margin-top: 40px;'>⚙️ How It Works</h2>", unsafe_allow_html=True)
        st.markdown("""
        <div style="background-color: white; padding: 20px; border-radius: 10px; margin-top: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <ol style="padding-left: 20px;">
                <li style="margin-bottom: 10px;"><strong>Upload Network Data:</strong> Import your PCAP files using the sidebar.</li>
                <li style="margin-bottom: 10px;"><strong>Process & Analyze:</strong> Extract features from packets and analyze traffic patterns.</li>
                <li style="margin-bottom: 10px;"><strong>Train AI Model:</strong> Build and train machine learning models on your data.</li>
                <li><strong>Detect & Report:</strong> Identify threats and generate comprehensive security reports.</li>
            </ol>
        </div>
        """, unsafe_allow_html=True)

        # Final call to action
        st.markdown("""
        <div style="background-color: #4169e1; color: white; padding: 25px; border-radius: 10px; text-align: center; margin-top: 40px;">
            <h2>Ready to Secure Your Network?</h2>
            <p style="font-size: 1.1em;">Upload your PCAP file using the sidebar to start detecting threats!</p>
        </div>
        """, unsafe_allow_html=True)

        # Footer for the main page (when no data is loaded)
        st.markdown("""
        <div style="text-align: center; margin-top: 50px; padding: 20px; color: #666;">
            <p>© 2025 Laksmeesha Suvarna | Network.NIRVANA | Advanced Network Security Solutions</p>
            <p style="font-size: 0.8em;">Powered by Streamlit, Scapy, and Scikit-learn</p>
        </div>
        """, unsafe_allow_html=True)

# --- Run the app ---
if __name__ == "__main__":
    main()