"""
Model Evaluation Script
Evaluate trained ML models
"""

import argparse
import pandas as pd
import numpy as np
from pathlib import Path
from loguru import logger
import json

import sys
sys.path.append(str(Path(__file__).parent.parent))

from src.core.model import IsolationForestModel, AutoencoderModel, AttackClassifier
from src.evaluation.metrics import calculate_anomaly_metrics, calculate_classification_metrics
from src.evaluation.visualization import NetworkVisualizer
from src.preprocessing.cleaning import DataCleaner
from src.preprocessing.feature_engineering import FeatureEngineer
from src.parsers.packet_parser import PacketParser


def evaluate_anomaly_model(model_path: str, data_path: str, labels_path: str = None, 
                           output_dir: str = "results/evaluation"):
    """Evaluate anomaly detection model"""
    logger.info(f"Evaluating anomaly model: {model_path}")
    
    # Load test data
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
    
    logger.info(f"Test data shape: {df.shape}")
    
    # Load model
    if model_path.endswith('.pkl'):
        model = IsolationForestModel()
        model.load(model_path)
    elif model_path.endswith('.h5'):
        model = AutoencoderModel()
        model.load(model_path)
    else:
        raise ValueError(f"Unsupported model format: {model_path}")
    
    # Predict
    predictions = model.predict(df)
    scores = model.score_samples(df)
    
    # Load labels if available
    if labels_path:
        labels = pd.read_csv(labels_path).values.ravel()
        
        # Calculate metrics
        metrics = calculate_anomaly_metrics(labels, predictions, scores)
        
        logger.info("Evaluation Metrics:")
        logger.info(f"  Accuracy: {metrics['accuracy']:.4f}")
        logger.info(f"  Precision: {metrics['precision']:.4f}")
        logger.info(f"  Recall: {metrics['recall']:.4f}")
        logger.info(f"  F1 Score: {metrics['f1_score']:.4f}")
        
        # Save metrics
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        with open(output_path / 'metrics.json', 'w') as f:
            json.dump(metrics, f, indent=2)
        
        # Visualizations
        viz = NetworkVisualizer()
        viz.plot_anomaly_scores(
            scores, predictions,
            save_path=str(output_path / 'anomaly_scores.png')
        )
        
        if 'confusion_matrix' in metrics:
            cm = np.array([
                [metrics['confusion_matrix']['true_negatives'], 
                 metrics['confusion_matrix']['false_positives']],
                [metrics['confusion_matrix']['false_negatives'],
                 metrics['confusion_matrix']['true_positives']]
            ])
            viz.plot_confusion_matrix(
                cm, ['Normal', 'Anomaly'],
                save_path=str(output_path / 'confusion_matrix.png')
            )
        
        logger.info(f"Evaluation results saved to {output_path}")
    
    else:
        # No labels - just statistics
        anomaly_count = (predictions == -1).sum()
        stats = {
            "total_samples": len(predictions),
            "anomalies_detected": int(anomaly_count),
            "anomaly_rate": float(anomaly_count / len(predictions)),
            "score_stats": {
                "min": float(scores.min()),
                "max": float(scores.max()),
                "mean": float(scores.mean()),
                "std": float(scores.std())
            }
        }
        
        logger.info("Detection Statistics:")
        logger.info(f"  Total Samples: {stats['total_samples']}")
        logger.info(f"  Anomalies: {stats['anomalies_detected']}")
        logger.info(f"  Anomaly Rate: {stats['anomaly_rate']:.2%}")
        
        # Save stats
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        with open(output_path / 'statistics.json', 'w') as f:
            json.dump(stats, f, indent=2)
        
        logger.info(f"Statistics saved to {output_path}")


def evaluate_classifier(model_path: str, data_path: str, labels_path: str,
                       output_dir: str = "results/evaluation"):
    """Evaluate classification model"""
    logger.info(f"Evaluating classifier: {model_path}")
    
    # Load test data
    df = pd.read_csv(data_path)
    labels = pd.read_csv(labels_path).values.ravel()
    
    logger.info(f"Test data shape: {df.shape}")
    
    # Load model
    model = AttackClassifier()
    model.load(model_path)
    
    # Predict
    predictions = model.predict(df)
    probabilities = model.predict_proba(df)
    
    # Calculate metrics
    unique_labels = np.unique(labels)
    label_names = [f"Class_{i}" for i in unique_labels]
    
    metrics = calculate_classification_metrics(labels, predictions, label_names)
    
    logger.info("Classification Metrics:")
    logger.info(f"  Accuracy: {metrics['accuracy']:.4f}")
    logger.info(f"  Precision (macro): {metrics['precision_macro']:.4f}")
    logger.info(f"  Recall (macro): {metrics['recall_macro']:.4f}")
    logger.info(f"  F1 Score (macro): {metrics['f1_macro']:.4f}")
    
    # Save metrics
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    with open(output_path / 'metrics.json', 'w') as f:
        json.dump(metrics, f, indent=2)
    
    # Visualizations
    viz = NetworkVisualizer()
    
    cm = np.array(metrics['confusion_matrix'])
    viz.plot_confusion_matrix(
        cm, label_names,
        save_path=str(output_path / 'confusion_matrix.png')
    )
    
    # Feature importance
    importance = model.get_feature_importance()
    viz.plot_feature_importance(
        importance,
        save_path=str(output_path / 'feature_importance.png')
    )
    
    logger.info(f"Evaluation results saved to {output_path}")


def main():
    """Main evaluation script"""
    parser = argparse.ArgumentParser(description='Evaluate trained ML models')
    parser.add_argument('--model', '-m', required=True, help='Model path')
    parser.add_argument('--data', '-d', required=True, help='Test data path')
    parser.add_argument('--labels', '-l', help='True labels path (optional for anomaly detection)')
    parser.add_argument('--model-type', '-t', required=True,
                       choices=['anomaly', 'classifier'],
                       help='Model type')
    parser.add_argument('--output-dir', '-o', default='results/evaluation',
                       help='Output directory')
    
    args = parser.parse_args()
    
    logger.info(f"Starting model evaluation: {args.model_type}")
    
    try:
        if args.model_type == 'anomaly':
            evaluate_anomaly_model(args.model, args.data, args.labels, args.output_dir)
        
        elif args.model_type == 'classifier':
            if not args.labels:
                raise ValueError("Labels path required for classifier evaluation")
            evaluate_classifier(args.model, args.data, args.labels, args.output_dir)
        
        logger.info("Evaluation completed successfully!")
    
    except Exception as e:
        logger.error(f"Evaluation failed: {e}")
        raise


if __name__ == '__main__':
    main()
