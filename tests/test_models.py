"""
Test ML Models
"""

import pytest
import pandas as pd
import numpy as np
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).parent.parent))

from src.core.model import IsolationForestModel, AttackClassifier


class TestIsolationForestModel:
    """Test cases for IsolationForestModel"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.model = IsolationForestModel()
        
        # Create sample training data
        np.random.seed(42)
        self.X_train = pd.DataFrame(np.random.randn(100, 10))
        self.X_test = pd.DataFrame(np.random.randn(20, 10))
    
    def test_model_initialization(self):
        """Test model initializes correctly"""
        assert self.model is not None
        assert hasattr(self.model, 'model')
        assert hasattr(self.model, 'scaler')
    
    def test_model_training(self):
        """Test model training"""
        self.model.train(self.X_train)
        
        assert self.model.is_fitted == True
    
    def test_model_prediction(self):
        """Test model prediction"""
        self.model.train(self.X_train)
        predictions = self.model.predict(self.X_test)
        
        # Check predictions are in valid range
        assert len(predictions) == len(self.X_test)
        assert set(predictions).issubset({-1, 1})
    
    def test_model_scoring(self):
        """Test anomaly scoring"""
        self.model.train(self.X_train)
        scores = self.model.score_samples(self.X_test)
        
        # Check scores are numeric
        assert len(scores) == len(self.X_test)
        assert np.isfinite(scores).all()


class TestAttackClassifier:
    """Test cases for AttackClassifier"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.model = AttackClassifier()
        
        # Create sample data
        np.random.seed(42)
        self.X_train = pd.DataFrame(np.random.randn(100, 10))
        self.y_train = np.random.randint(0, 3, 100)  # 3 classes
        self.X_test = pd.DataFrame(np.random.randn(20, 10))
    
    def test_model_initialization(self):
        """Test model initializes correctly"""
        assert self.model is not None
        assert hasattr(self.model, 'model')
    
    def test_model_training(self):
        """Test model training"""
        self.model.train(self.X_train, self.y_train)
        
        assert self.model.is_fitted == True
    
    def test_model_prediction(self):
        """Test model prediction"""
        self.model.train(self.X_train, self.y_train)
        predictions = self.model.predict(self.X_test)
        
        # Check predictions are valid class labels
        assert len(predictions) == len(self.X_test)
        assert set(predictions).issubset(set(self.y_train))
    
    def test_model_predict_proba(self):
        """Test probability prediction"""
        self.model.train(self.X_train, self.y_train)
        probabilities = self.model.predict_proba(self.X_test)
        
        # Check probabilities sum to 1
        assert probabilities.shape[0] == len(self.X_test)
        assert np.allclose(probabilities.sum(axis=1), 1.0)
    
    def test_feature_importance(self):
        """Test feature importance extraction"""
        self.model.train(self.X_train, self.y_train)
        importance_df = self.model.get_feature_importance()
        
        # Check feature importance is returned
        assert not importance_df.empty
        assert 'feature' in importance_df.columns
        assert 'importance' in importance_df.columns
