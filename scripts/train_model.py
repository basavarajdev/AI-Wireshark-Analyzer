"""
Model Training Script
Train ML models on network traffic data
"""

import argparse
import pandas as pd
import numpy as np
from pathlib import Path
from loguru import logger
import yaml

import sys
sys.path.append(str(Path(__file__).parent.parent))

from src.parsers.packet_parser import PacketParser
from src.preprocessing.cleaning import DataCleaner
from src.preprocessing.feature_engineering import FeatureEngineer
from src.core.model import IsolationForestModel, AutoencoderModel, AttackClassifier


def train_isolation_forest(data_path: str, output_path: str):
    """Train Isolation Forest model"""
    logger.info(f"Training Isolation Forest on {data_path}")
    
    # Load data
    if data_path.endswith('.csv'):
        df = pd.read_csv(data_path)
    elif data_path.endswith(('.pcap', '.pcapng')):
        parser = PacketParser()
        df = parser.parse_pcap(data_path)
        
        cleaner = DataCleaner()
        df = cleaner.clean(df)
        
        engineer = FeatureEngineer()
        df = engineer.engineer_features(df)
        df = engineer.get_ml_features(df)
    else:
        raise ValueError(f"Unsupported file format: {data_path}")
    
    logger.info(f"Training data shape: {df.shape}")
    
    # Train model
    model = IsolationForestModel()
    model.train(df)
    
    # Save model
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    model.save(output_path)
    
    logger.info(f"Model saved to {output_path}")


def train_autoencoder(data_path: str, output_path: str, epochs: int = 100):
    """Train Autoencoder model"""
    logger.info(f"Training Autoencoder on {data_path}")
    
    # Load data
    if data_path.endswith('.csv'):
        df = pd.read_csv(data_path)
    elif data_path.endswith(('.pcap', '.pcapng')):
        parser = PacketParser()
        df = parser.parse_pcap(data_path)
        
        cleaner = DataCleaner()
        df = cleaner.clean(df)
        
        engineer = FeatureEngineer()
        df = engineer.engineer_features(df)
        df = engineer.get_ml_features(df)
    else:
        raise ValueError(f"Unsupported file format: {data_path}")
    
    logger.info(f"Training data shape: {df.shape}")
    
    # Update config for custom epochs
    if epochs != 100:
        config = yaml.safe_load(open("config/default.yaml"))
        config['models']['autoencoder']['epochs'] = epochs
        with open("config/temp.yaml", 'w') as f:
            yaml.dump(config, f)
        config_path = "config/temp.yaml"
    else:
        config_path = "config/default.yaml"
    
    # Train model
    model = AutoencoderModel(config_path=config_path)
    model.train(df)
    
    # Save model
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    model.save(output_path)
    
    logger.info(f"Model saved to {output_path}")
    
    # Clean up temp config
    if Path("config/temp.yaml").exists():
        Path("config/temp.yaml").unlink()


def train_classifier(data_path: str, label_path: str, output_path: str):
    """Train attack classifier"""
    logger.info(f"Training classifier on {data_path}")
    
    # Load data
    df = pd.read_csv(data_path)
    labels = pd.read_csv(label_path)
    
    logger.info(f"Training data shape: {df.shape}")
    logger.info(f"Label distribution:\n{labels.value_counts()}")
    
    # Train model
    model = AttackClassifier()
    model.train(df, labels.values.ravel())
    
    # Save model
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    model.save(output_path)
    
    # Save feature importance
    importance = model.get_feature_importance()
    importance_path = output_path.replace('.pkl', '_importance.csv')
    importance.to_csv(importance_path, index=False)
    
    logger.info(f"Model saved to {output_path}")
    logger.info(f"Feature importance saved to {importance_path}")


def main():
    """Main training script"""
    parser = argparse.ArgumentParser(description='Train ML models for network traffic analysis')
    parser.add_argument('--data', '-d', required=True, help='Training data path (CSV or PCAP)')
    parser.add_argument('--labels', '-l', help='Labels CSV (for classifier)')
    parser.add_argument('--model-type', '-m', required=True,
                       choices=['isolation_forest', 'autoencoder', 'classifier'],
                       help='Model type to train')
    parser.add_argument('--output', '-o', required=True, help='Output model path')
    parser.add_argument('--epochs', type=int, default=100, help='Training epochs (autoencoder)')
    
    args = parser.parse_args()
    
    logger.info(f"Starting model training: {args.model_type}")
    
    try:
        if args.model_type == 'isolation_forest':
            train_isolation_forest(args.data, args.output)
        
        elif args.model_type == 'autoencoder':
            train_autoencoder(args.data, args.output, args.epochs)
        
        elif args.model_type == 'classifier':
            if not args.labels:
                raise ValueError("Labels path required for classifier training")
            train_classifier(args.data, args.labels, args.output)
        
        logger.info("Training completed successfully!")
    
    except Exception as e:
        logger.error(f"Training failed: {e}")
        raise


if __name__ == '__main__':
    main()
