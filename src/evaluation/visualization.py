"""
Visualization Module
Create plots and charts for network traffic analysis
"""

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from pathlib import Path
from loguru import logger
from typing import Optional, List
import yaml


class NetworkVisualizer:
    """Visualize network traffic analysis results"""
    
    def __init__(self, config_path: str = "config/default.yaml"):
        """Initialize visualizer"""
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        viz_config = config['visualization']
        self.figsize = tuple(viz_config['figsize'])
        self.style = viz_config['style']
        self.dpi = viz_config['dpi']
        self.palette = viz_config['color_palette']
        
        # Set style
        sns.set_style(self.style)
        sns.set_palette(self.palette)
    
    def plot_protocol_distribution(self, df: pd.DataFrame, save_path: Optional[str] = None):
        """Plot protocol distribution"""
        logger.info("Plotting protocol distribution")
        
        if 'protocol' not in df.columns:
            logger.warning("Protocol column not found")
            return
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=self.figsize)
        
        # Count plot
        protocol_counts = df['protocol'].value_counts().head(10)
        protocol_counts.plot(kind='bar', ax=ax1, color=sns.color_palette(self.palette, len(protocol_counts)))
        ax1.set_title('Top 10 Protocols by Packet Count', fontsize=14, fontweight='bold')
        ax1.set_xlabel('Protocol')
        ax1.set_ylabel('Packet Count')
        ax1.tick_params(axis='x', rotation=45)
        
        # Pie chart
        protocol_pct = df['protocol'].value_counts().head(5)
        ax2.pie(protocol_pct, labels=protocol_pct.index, autopct='%1.1f%%', startangle=90)
        ax2.set_title('Top 5 Protocols Distribution', fontsize=14, fontweight='bold')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=self.dpi, bbox_inches='tight')
            logger.info(f"Plot saved to {save_path}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_traffic_timeline(self, df: pd.DataFrame, save_path: Optional[str] = None):
        """Plot traffic over time"""
        logger.info("Plotting traffic timeline")
        
        if 'timestamp' not in df.columns:
            logger.warning("Timestamp column not found")
            return
        
        fig, ax = plt.subplots(figsize=self.figsize)
        
        # Convert timestamp to datetime
        df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
        
        # Resample to 1-second intervals
        traffic_rate = df.set_index('datetime').resample('1S').size()
        
        traffic_rate.plot(ax=ax, linewidth=2)
        ax.set_title('Network Traffic Rate Over Time', fontsize=14, fontweight='bold')
        ax.set_xlabel('Time')
        ax.set_ylabel('Packets per Second')
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=self.dpi, bbox_inches='tight')
            logger.info(f"Plot saved to {save_path}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_anomaly_scores(self, scores: np.ndarray, predictions: np.ndarray, 
                           save_path: Optional[str] = None):
        """Plot anomaly score distribution"""
        logger.info("Plotting anomaly scores")
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=self.figsize)
        
        # Score distribution
        ax1.hist(scores[predictions == 1], bins=50, alpha=0.7, label='Normal', color='green')
        ax1.hist(scores[predictions == -1], bins=50, alpha=0.7, label='Anomaly', color='red')
        ax1.set_title('Anomaly Score Distribution', fontsize=14, fontweight='bold')
        ax1.set_xlabel('Anomaly Score')
        ax1.set_ylabel('Frequency')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Box plot
        data = pd.DataFrame({
            'Score': scores,
            'Class': np.where(predictions == -1, 'Anomaly', 'Normal')
        })
        sns.boxplot(data=data, x='Class', y='Score', ax=ax2)
        ax2.set_title('Anomaly Scores by Class', fontsize=14, fontweight='bold')
        ax2.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=self.dpi, bbox_inches='tight')
            logger.info(f"Plot saved to {save_path}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_confusion_matrix(self, cm: np.ndarray, labels: List[str],
                             save_path: Optional[str] = None):
        """Plot confusion matrix"""
        logger.info("Plotting confusion matrix")
        
        fig, ax = plt.subplots(figsize=(8, 6))
        
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=labels, yticklabels=labels, ax=ax)
        ax.set_title('Confusion Matrix', fontsize=14, fontweight='bold')
        ax.set_xlabel('Predicted Label')
        ax.set_ylabel('True Label')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=self.dpi, bbox_inches='tight')
            logger.info(f"Plot saved to {save_path}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_port_distribution(self, df: pd.DataFrame, save_path: Optional[str] = None):
        """Plot destination port distribution"""
        logger.info("Plotting port distribution")
        
        if 'dst_port' not in df.columns:
            logger.warning("Destination port column not found")
            return
        
        fig, ax = plt.subplots(figsize=self.figsize)
        
        top_ports = df['dst_port'].value_counts().head(20)
        top_ports.plot(kind='barh', ax=ax, color=sns.color_palette(self.palette, len(top_ports)))
        ax.set_title('Top 20 Destination Ports', fontsize=14, fontweight='bold')
        ax.set_xlabel('Packet Count')
        ax.set_ylabel('Port')
        ax.grid(True, alpha=0.3, axis='x')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=self.dpi, bbox_inches='tight')
            logger.info(f"Plot saved to {save_path}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_packet_size_distribution(self, df: pd.DataFrame, save_path: Optional[str] = None):
        """Plot packet size distribution"""
        logger.info("Plotting packet size distribution")
        
        if 'length' not in df.columns:
            logger.warning("Length column not found")
            return
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=self.figsize)
        
        # Histogram
        ax1.hist(df['length'], bins=50, edgecolor='black', alpha=0.7)
        ax1.set_title('Packet Size Distribution', fontsize=14, fontweight='bold')
        ax1.set_xlabel('Packet Size (bytes)')
        ax1.set_ylabel('Frequency')
        ax1.grid(True, alpha=0.3)
        
        # Box plot
        ax2.boxplot(df['length'], vert=True)
        ax2.set_title('Packet Size Box Plot', fontsize=14, fontweight='bold')
        ax2.set_ylabel('Packet Size (bytes)')
        ax2.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=self.dpi, bbox_inches='tight')
            logger.info(f"Plot saved to {save_path}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_ip_traffic(self, df: pd.DataFrame, top_n: int = 10, 
                       save_path: Optional[str] = None):
        """Plot top IP addresses by traffic volume"""
        logger.info("Plotting IP traffic")
        
        if 'src_ip' not in df.columns or 'length' not in df.columns:
            logger.warning("Required columns not found")
            return
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=self.figsize)
        
        # Top source IPs
        top_src = df.groupby('src_ip')['length'].sum().sort_values(ascending=False).head(top_n)
        top_src.plot(kind='barh', ax=ax1, color='skyblue')
        ax1.set_title(f'Top {top_n} Source IPs by Traffic Volume', fontsize=12, fontweight='bold')
        ax1.set_xlabel('Total Bytes')
        ax1.set_ylabel('Source IP')
        
        # Top destination IPs
        if 'dst_ip' in df.columns:
            top_dst = df.groupby('dst_ip')['length'].sum().sort_values(ascending=False).head(top_n)
            top_dst.plot(kind='barh', ax=ax2, color='lightcoral')
            ax2.set_title(f'Top {top_n} Destination IPs by Traffic Volume', fontsize=12, fontweight='bold')
            ax2.set_xlabel('Total Bytes')
            ax2.set_ylabel('Destination IP')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=self.dpi, bbox_inches='tight')
            logger.info(f"Plot saved to {save_path}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_feature_importance(self, importance_df: pd.DataFrame, top_n: int = 20,
                               save_path: Optional[str] = None):
        """Plot feature importance"""
        logger.info("Plotting feature importance")
        
        fig, ax = plt.subplots(figsize=(10, 8))
        
        top_features = importance_df.head(top_n)
        top_features.plot(x='feature', y='importance', kind='barh', ax=ax, legend=False,
                         color=sns.color_palette(self.palette, len(top_features)))
        ax.set_title(f'Top {top_n} Feature Importance', fontsize=14, fontweight='bold')
        ax.set_xlabel('Importance Score')
        ax.set_ylabel('Feature')
        ax.grid(True, alpha=0.3, axis='x')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=self.dpi, bbox_inches='tight')
            logger.info(f"Plot saved to {save_path}")
        else:
            plt.show()
        
        plt.close()
    
    def create_analysis_report(self, df: pd.DataFrame, output_dir: str):
        """Create a complete analysis report with multiple plots"""
        logger.info(f"Creating analysis report in {output_dir}")
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Generate all plots
        self.plot_protocol_distribution(df, str(output_path / 'protocol_distribution.png'))
        self.plot_traffic_timeline(df, str(output_path / 'traffic_timeline.png'))
        self.plot_port_distribution(df, str(output_path / 'port_distribution.png'))
        self.plot_packet_size_distribution(df, str(output_path / 'packet_size_distribution.png'))
        self.plot_ip_traffic(df, save_path=str(output_path / 'ip_traffic.png'))
        
        logger.info("Analysis report created successfully")
