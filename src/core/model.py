"""
ML Model Definitions
Anomaly detection and classification models
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
from typing import Optional, Tuple
from loguru import logger
import yaml

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    logger.warning("TensorFlow not available, autoencoder models disabled")


class IsolationForestModel:
    """Isolation Forest for anomaly detection"""
    
    def __init__(self, config_path: str = "config/default.yaml"):
        """
        Initialize Isolation Forest model
        
        Args:
            config_path: Path to configuration file
        """
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        model_config = config['models']['isolation_forest']
        
        self.model = IsolationForest(
            n_estimators=model_config['n_estimators'],
            contamination=model_config['contamination'],
            random_state=model_config['random_state'],
            n_jobs=-1
        )
        
        self.scaler = StandardScaler()
        self.is_fitted = False
    
    def train(self, X: pd.DataFrame) -> 'IsolationForestModel':
        """
        Train the model
        
        Args:
            X: Training features
            
        Returns:
            Self
        """
        logger.info(f"Training Isolation Forest on {len(X)} samples")
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        self.model.fit(X_scaled)
        self.is_fitted = True
        
        logger.info("Isolation Forest training complete")
        return self
    
    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """
        Predict anomalies
        
        Args:
            X: Features to predict
            
        Returns:
            Predictions (1 = normal, -1 = anomaly)
        """
        if not self.is_fitted:
            raise ValueError("Model not fitted. Call train() first.")
        
        X_scaled = self.scaler.transform(X)
        predictions = self.model.predict(X_scaled)
        
        return predictions
    
    def score_samples(self, X: pd.DataFrame) -> np.ndarray:
        """
        Get anomaly scores
        
        Args:
            X: Features to score
            
        Returns:
            Anomaly scores (lower = more anomalous)
        """
        if not self.is_fitted:
            raise ValueError("Model not fitted. Call train() first.")
        
        X_scaled = self.scaler.transform(X)
        scores = self.model.score_samples(X_scaled)
        
        return scores
    
    def save(self, filepath: str):
        """Save model to disk"""
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'is_fitted': self.is_fitted
        }, filepath)
        logger.info(f"Model saved to {filepath}")
    
    def load(self, filepath: str):
        """Load model from disk"""
        data = joblib.load(filepath)
        self.model = data['model']
        self.scaler = data['scaler']
        self.is_fitted = data['is_fitted']
        logger.info(f"Model loaded from {filepath}")


class AutoencoderModel:
    """Autoencoder for anomaly detection"""
    
    def __init__(self, config_path: str = "config/default.yaml"):
        """
        Initialize Autoencoder model
        
        Args:
            config_path: Path to configuration file
        """
        if not TENSORFLOW_AVAILABLE:
            raise ImportError("TensorFlow is required for Autoencoder models")
        
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        self.model_config = config['models']['autoencoder']
        self.encoding_dim = self.model_config['encoding_dim']
        
        self.model = None
        self.scaler = StandardScaler()
        self.threshold = None
        self.is_fitted = False
    
    def _build_model(self, input_dim: int):
        """Build autoencoder architecture"""
        
        # Encoder
        encoder_input = layers.Input(shape=(input_dim,))
        encoded = layers.Dense(128, activation='relu')(encoder_input)
        encoded = layers.Dropout(0.2)(encoded)
        encoded = layers.Dense(64, activation='relu')(encoded)
        encoded = layers.Dense(self.encoding_dim, activation='relu')(encoded)
        
        # Decoder
        decoded = layers.Dense(64, activation='relu')(encoded)
        decoded = layers.Dense(128, activation='relu')(decoded)
        decoded = layers.Dropout(0.2)(decoded)
        decoded = layers.Dense(input_dim, activation='sigmoid')(decoded)
        
        # Autoencoder
        autoencoder = keras.Model(encoder_input, decoded)
        
        autoencoder.compile(
            optimizer=keras.optimizers.Adam(learning_rate=self.model_config['learning_rate']),
            loss='mse',
            metrics=['mae']
        )
        
        return autoencoder
    
    def train(self, X: pd.DataFrame) -> 'AutoencoderModel':
        """
        Train the autoencoder
        
        Args:
            X: Training features
            
        Returns:
            Self
        """
        logger.info(f"Training Autoencoder on {len(X)} samples")
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Build model
        input_dim = X_scaled.shape[1]
        self.model = self._build_model(input_dim)
        
        # Train
        history = self.model.fit(
            X_scaled, X_scaled,
            epochs=self.model_config['epochs'],
            batch_size=self.model_config['batch_size'],
            validation_split=self.model_config['validation_split'],
            verbose=1,
            callbacks=[
                keras.callbacks.EarlyStopping(
                    monitor='val_loss',
                    patience=10,
                    restore_best_weights=True
                )
            ]
        )
        
        # Calculate threshold from training data
        reconstruction_errors = self._calculate_reconstruction_error(X_scaled)
        self.threshold = np.percentile(reconstruction_errors, 95)
        
        self.is_fitted = True
        logger.info("Autoencoder training complete")
        
        return self
    
    def _calculate_reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        """Calculate reconstruction error"""
        predictions = self.model.predict(X, verbose=0)
        mse = np.mean(np.power(X - predictions, 2), axis=1)
        return mse
    
    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """
        Predict anomalies
        
        Args:
            X: Features to predict
            
        Returns:
            Predictions (1 = normal, -1 = anomaly)
        """
        if not self.is_fitted:
            raise ValueError("Model not fitted. Call train() first.")
        
        X_scaled = self.scaler.transform(X)
        errors = self._calculate_reconstruction_error(X_scaled)
        
        # Anomaly if reconstruction error > threshold
        predictions = np.where(errors > self.threshold, -1, 1)
        
        return predictions
    
    def score_samples(self, X: pd.DataFrame) -> np.ndarray:
        """
        Get anomaly scores (reconstruction errors)
        
        Args:
            X: Features to score
            
        Returns:
            Anomaly scores (higher = more anomalous)
        """
        if not self.is_fitted:
            raise ValueError("Model not fitted. Call train() first.")
        
        X_scaled = self.scaler.transform(X)
        scores = self._calculate_reconstruction_error(X_scaled)
        
        return scores
    
    def save(self, filepath: str):
        """Save model to disk"""
        # Save Keras model
        self.model.save(filepath)
        
        # Save scaler and threshold
        joblib.dump({
            'scaler': self.scaler,
            'threshold': self.threshold,
            'is_fitted': self.is_fitted
        }, filepath.replace('.h5', '_meta.pkl'))
        
        logger.info(f"Model saved to {filepath}")
    
    def load(self, filepath: str):
        """Load model from disk"""
        # Load Keras model
        self.model = keras.models.load_model(filepath)
        
        # Load scaler and threshold
        meta = joblib.load(filepath.replace('.h5', '_meta.pkl'))
        self.scaler = meta['scaler']
        self.threshold = meta['threshold']
        self.is_fitted = meta['is_fitted']
        
        logger.info(f"Model loaded from {filepath}")


class AttackClassifier:
    """Random Forest classifier for attack type detection"""
    
    def __init__(self, config_path: str = "config/default.yaml"):
        """
        Initialize classifier
        
        Args:
            config_path: Path to configuration file
        """
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        model_config = config['models']['random_forest']
        
        self.model = RandomForestClassifier(
            n_estimators=model_config['n_estimators'],
            max_depth=model_config['max_depth'],
            random_state=model_config['random_state'],
            n_jobs=-1
        )
        
        self.scaler = StandardScaler()
        self.is_fitted = False
    
    def train(self, X: pd.DataFrame, y: np.ndarray) -> 'AttackClassifier':
        """
        Train the classifier
        
        Args:
            X: Training features
            y: Training labels
            
        Returns:
            Self
        """
        logger.info(f"Training classifier on {len(X)} samples")
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        self.model.fit(X_scaled, y)
        self.is_fitted = True
        
        logger.info("Classifier training complete")
        return self
    
    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """
        Predict attack types
        
        Args:
            X: Features to predict
            
        Returns:
            Predicted classes
        """
        if not self.is_fitted:
            raise ValueError("Model not fitted. Call train() first.")
        
        X_scaled = self.scaler.transform(X)
        predictions = self.model.predict(X_scaled)
        
        return predictions
    
    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """
        Predict class probabilities
        
        Args:
            X: Features to predict
            
        Returns:
            Class probabilities
        """
        if not self.is_fitted:
            raise ValueError("Model not fitted. Call train() first.")
        
        X_scaled = self.scaler.transform(X)
        probabilities = self.model.predict_proba(X_scaled)
        
        return probabilities
    
    def get_feature_importance(self) -> pd.DataFrame:
        """Get feature importance scores"""
        if not self.is_fitted:
            raise ValueError("Model not fitted. Call train() first.")
        
        importance_df = pd.DataFrame({
            'feature': self.model.feature_names_in_,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        return importance_df
    
    def save(self, filepath: str):
        """Save model to disk"""
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'is_fitted': self.is_fitted
        }, filepath)
        logger.info(f"Model saved to {filepath}")
    
    def load(self, filepath: str):
        """Load model from disk"""
        data = joblib.load(filepath)
        self.model = data['model']
        self.scaler = data['scaler']
        self.is_fitted = data['is_fitted']
        logger.info(f"Model loaded from {filepath}")
