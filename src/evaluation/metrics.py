"""
Evaluation Metrics Module
Calculate performance metrics for ML models
"""

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score, roc_curve
)
from loguru import logger
from typing import Dict, Tuple, Optional


def calculate_anomaly_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_scores: Optional[np.ndarray] = None) -> Dict:
    """
    Calculate metrics for anomaly detection
    
    Args:
        y_true: True labels (1 = normal, -1 = anomaly)
        y_pred: Predicted labels (1 = normal, -1 = anomaly)
        y_scores: Anomaly scores (optional)
        
    Returns:
        Dictionary of metrics
    """
    logger.info("Calculating anomaly detection metrics")
    
    # Convert to binary (0 = normal, 1 = anomaly)
    y_true_binary = (y_true == -1).astype(int)
    y_pred_binary = (y_pred == -1).astype(int)
    
    metrics = {}
    
    # Basic metrics
    metrics['accuracy'] = float(accuracy_score(y_true_binary, y_pred_binary))
    metrics['precision'] = float(precision_score(y_true_binary, y_pred_binary, zero_division=0))
    metrics['recall'] = float(recall_score(y_true_binary, y_pred_binary, zero_division=0))
    metrics['f1_score'] = float(f1_score(y_true_binary, y_pred_binary, zero_division=0))
    
    # Confusion matrix
    cm = confusion_matrix(y_true_binary, y_pred_binary)
    metrics['confusion_matrix'] = {
        'true_negatives': int(cm[0, 0]),
        'false_positives': int(cm[0, 1]),
        'false_negatives': int(cm[1, 0]),
        'true_positives': int(cm[1, 1])
    }
    
    # False positive/negative rates
    tn, fp, fn, tp = cm.ravel()
    metrics['false_positive_rate'] = float(fp / (fp + tn)) if (fp + tn) > 0 else 0
    metrics['false_negative_rate'] = float(fn / (fn + tp)) if (fn + tp) > 0 else 0
    
    # AUC-ROC if scores provided
    if y_scores is not None:
        try:
            metrics['auc_roc'] = float(roc_auc_score(y_true_binary, y_scores))
        except:
            logger.warning("Could not calculate AUC-ROC")
    
    logger.info(f"Metrics calculated - Accuracy: {metrics['accuracy']:.4f}, F1: {metrics['f1_score']:.4f}")
    
    return metrics


def calculate_classification_metrics(y_true: np.ndarray, y_pred: np.ndarray, 
                                     labels: Optional[list] = None) -> Dict:
    """
    Calculate metrics for multi-class classification
    
    Args:
        y_true: True labels
        y_pred: Predicted labels
        labels: List of label names
        
    Returns:
        Dictionary of metrics
    """
    logger.info("Calculating classification metrics")
    
    metrics = {}
    
    # Overall metrics
    metrics['accuracy'] = float(accuracy_score(y_true, y_pred))
    metrics['precision_macro'] = float(precision_score(y_true, y_pred, average='macro', zero_division=0))
    metrics['recall_macro'] = float(recall_score(y_true, y_pred, average='macro', zero_division=0))
    metrics['f1_macro'] = float(f1_score(y_true, y_pred, average='macro', zero_division=0))
    
    # Per-class metrics
    if labels is not None:
        report = classification_report(y_true, y_pred, target_names=labels, output_dict=True, zero_division=0)
        metrics['per_class'] = report
    
    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred)
    metrics['confusion_matrix'] = cm.tolist()
    
    logger.info(f"Classification metrics - Accuracy: {metrics['accuracy']:.4f}")
    
    return metrics


def calculate_detection_stats(df: pd.DataFrame, predictions: np.ndarray) -> Dict:
    """
    Calculate statistics about detections
    
    Args:
        df: DataFrame with packet data
        predictions: Anomaly predictions (1 = normal, -1 = anomaly)
        
    Returns:
        Dictionary of statistics
    """
    stats = {}
    
    total = len(predictions)
    anomalies = (predictions == -1).sum()
    normal = (predictions == 1).sum()
    
    stats['total_samples'] = int(total)
    stats['anomalies_detected'] = int(anomalies)
    stats['normal_samples'] = int(normal)
    stats['anomaly_rate'] = float(anomalies / total) if total > 0 else 0
    
    # Per-protocol breakdown
    if 'protocol' in df.columns:
        df_with_pred = df.copy()
        df_with_pred['prediction'] = predictions
        
        protocol_stats = df_with_pred.groupby('protocol')['prediction'].agg([
            ('total', 'count'),
            ('anomalies', lambda x: (x == -1).sum())
        ]).to_dict('index')
        
        stats['per_protocol'] = protocol_stats
    
    return stats


def calculate_threshold_metrics(y_true: np.ndarray, y_scores: np.ndarray, 
                                thresholds: np.ndarray) -> pd.DataFrame:
    """
    Calculate metrics at different thresholds
    
    Args:
        y_true: True labels (1 = normal, -1 = anomaly)
        y_scores: Anomaly scores
        thresholds: Array of threshold values to test
        
    Returns:
        DataFrame with metrics at each threshold
    """
    y_true_binary = (y_true == -1).astype(int)
    
    results = []
    
    for threshold in thresholds:
        y_pred_binary = (y_scores > threshold).astype(int)
        
        precision = precision_score(y_true_binary, y_pred_binary, zero_division=0)
        recall = recall_score(y_true_binary, y_pred_binary, zero_division=0)
        f1 = f1_score(y_true_binary, y_pred_binary, zero_division=0)
        
        results.append({
            'threshold': threshold,
            'precision': precision,
            'recall': recall,
            'f1_score': f1
        })
    
    return pd.DataFrame(results)


def find_optimal_threshold(y_true: np.ndarray, y_scores: np.ndarray, 
                           metric: str = 'f1') -> Tuple[float, Dict]:
    """
    Find optimal threshold for anomaly detection
    
    Args:
        y_true: True labels
        y_scores: Anomaly scores
        metric: Metric to optimize ('f1', 'precision', 'recall')
        
    Returns:
        Tuple of (optimal_threshold, metrics_at_threshold)
    """
    y_true_binary = (y_true == -1).astype(int)
    
    # Test range of thresholds
    thresholds = np.linspace(y_scores.min(), y_scores.max(), 100)
    
    best_threshold = thresholds[0]
    best_score = 0
    best_metrics = {}
    
    for threshold in thresholds:
        y_pred_binary = (y_scores > threshold).astype(int)
        
        if metric == 'f1':
            score = f1_score(y_true_binary, y_pred_binary, zero_division=0)
        elif metric == 'precision':
            score = precision_score(y_true_binary, y_pred_binary, zero_division=0)
        elif metric == 'recall':
            score = recall_score(y_true_binary, y_pred_binary, zero_division=0)
        else:
            raise ValueError(f"Unknown metric: {metric}")
        
        if score > best_score:
            best_score = score
            best_threshold = threshold
            best_metrics = calculate_anomaly_metrics(
                y_true,
                np.where(y_scores > threshold, -1, 1),
                y_scores
            )
    
    logger.info(f"Optimal threshold: {best_threshold:.4f} ({metric}={best_score:.4f})")
    
    return best_threshold, best_metrics
