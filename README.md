# NETWORKNIRVANA

# Network.NIRVANA - Advanced Network Threat Detection

**Network.NIRVANA** is a powerful application designed to analyze network traffic and detect potential security threats. It leverages machine learning techniques to identify anomalies within network data captured in PCAP files, providing users with valuable insights into their network's security posture.

## Features

* **PCAP File Analysis:** Upload and process PCAP files to extract detailed information about network traffic.
* **Data Visualization:** Visualize network traffic patterns, protocol distributions, and packet sizes through interactive charts and graphs.
* **Machine Learning Model Training:** Train a Random Forest Classifier model to identify malicious network activity. Users can adjust parameters like the number of trees and maximum tree depth.
* **Threat Detection:** Analyze network traffic using the trained model to detect potential threats and generate comprehensive threat reports.
* **Detailed Reporting:** View threat summaries, including threat percentages, top threat sources, and lists of suspicious packets.
* **Data Export:** Export analysis results in CSV and Markdown formats for further analysis and reporting.

## Getting Started

1.  **Upload Data:** In the sidebar, upload a PCAP file containing the network traffic you want to analyze.
2.  **Process PCAP File:** Click the "Process PCAP File" button to extract relevant information from the uploaded file.
3.  **Train Model:** Adjust the model parameters (number of trees, maximum tree depth) in the sidebar and click "Train Model" to train the machine learning model.
4.  **Detect Threats:** Click "Detect Threats" to analyze the processed network traffic and identify potential security threats.
5.  **View Results:** Review the analysis results, including visualizations and threat summaries, in the main panel.
6.  **Export Results:** Export the analysis results in CSV or Markdown format for further use.

## Technologies Used

* Streamlit:  For building the interactive web application.
* Scapy:  For reading and parsing PCAP files.
* scikit-learn:  For machine learning (Random Forest Classifier).
* pandas:  For data manipulation and analysis.
* numpy:  For numerical operations.
* matplotlib and seaborn:  For data visualization.

## Installation

To run this application, you'll need to install the required Python packages. You can do this using pip:

```bash
pip install streamlit scapy pandas numpy scikit-learn matplotlib seaborn joblib
