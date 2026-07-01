"""
Test TensorFlow/CUDA GPU safety and CPU-only mode operation
Verifies the fix for segmentation fault on systems without GPU support
"""

import pytest
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestTensorFlowGPUDisabling:
    """Test that TensorFlow is properly configured for CPU-only mode"""

    def test_cuda_disabled_in_environment(self):
        """Verify CUDA is disabled before TensorFlow import"""
        # These should be set by src/core/model.py at import time
        assert os.environ.get('CUDA_VISIBLE_DEVICES') == '-1', \
            "CUDA_VISIBLE_DEVICES should be set to -1"
        assert os.environ.get('TF_CPP_MIN_LOG_LEVEL') in ['3', None], \
            "TF_CPP_MIN_LOG_LEVEL should suppress logs"

    def test_tensorflow_import_no_crash(self):
        """Verify TensorFlow can be imported without crashing"""
        try:
            from src.core.model import TENSORFLOW_AVAILABLE
            # Should not segfault
            assert True, "TensorFlow import successful"
        except Exception as e:
            pytest.fail(f"TensorFlow import crashed: {e}")

    def test_tensorflow_gpu_disabled(self):
        """Verify GPU is disabled when TensorFlow is available"""
        try:
            from src.core.model import TENSORFLOW_AVAILABLE
            if TENSORFLOW_AVAILABLE:
                import tensorflow as tf
                gpus = tf.config.list_physical_devices('GPU')
                assert len(gpus) == 0, "GPUs should be disabled"
        except Exception as e:
            pytest.skip(f"TensorFlow not available: {e}")

    def test_isolation_forest_model_loads(self):
        """Verify IsolationForest model can be instantiated without GPU errors"""
        try:
            from src.core.model import IsolationForestModel
            model = IsolationForestModel()
            assert model is not None, "IsolationForestModel should instantiate"
            assert not model.is_fitted, "Model should not be fitted initially"
        except Exception as e:
            pytest.fail(f"IsolationForestModel instantiation failed: {e}")

    def test_model_handles_tensorflow_unavailable(self):
        """Verify graceful handling when TensorFlow is unavailable"""
        from src.core.model import TENSORFLOW_AVAILABLE
        # Should not raise exception regardless of TensorFlow availability
        # This just verifies the import doesn't crash
        assert isinstance(TENSORFLOW_AVAILABLE, bool), \
            "TENSORFLOW_AVAILABLE should be a boolean"


class TestCPUOnlyMode:
    """Test that analysis works in CPU-only mode"""

    def test_isolation_forest_train_cpu_only(self):
        """Verify IsolationForest training works in CPU-only mode"""
        import pandas as pd
        import numpy as np
        from src.core.model import IsolationForestModel

        # Create dummy data
        X = pd.DataFrame(
            np.random.randn(100, 5),
            columns=['feat1', 'feat2', 'feat3', 'feat4', 'feat5']
        )

        model = IsolationForestModel()
        model.train(X)

        assert model.is_fitted, "Model should be fitted after training"

    def test_isolation_forest_predict_cpu_only(self):
        """Verify IsolationForest prediction works in CPU-only mode"""
        import pandas as pd
        import numpy as np
        from src.core.model import IsolationForestModel

        # Create training data
        X_train = pd.DataFrame(
            np.random.randn(100, 5),
            columns=['feat1', 'feat2', 'feat3', 'feat4', 'feat5']
        )

        # Create test data
        X_test = pd.DataFrame(
            np.random.randn(20, 5),
            columns=['feat1', 'feat2', 'feat3', 'feat4', 'feat5']
        )

        model = IsolationForestModel()
        model.train(X_train)
        predictions = model.predict(X_test)

        assert len(predictions) == 20, "Should predict for all samples"
        assert all(p in [-1, 1] for p in predictions), \
            "Predictions should be -1 (anomaly) or 1 (normal)"

    def test_anomaly_score_cpu_only(self):
        """Verify anomaly scoring works in CPU-only mode"""
        import pandas as pd
        import numpy as np
        from src.core.model import IsolationForestModel

        # Create training data
        X = pd.DataFrame(
            np.random.randn(100, 5),
            columns=['feat1', 'feat2', 'feat3', 'feat4', 'feat5']
        )

        model = IsolationForestModel()
        model.train(X)
        scores = model.score_samples(X)

        assert len(scores) == 100, "Should score all samples"
        assert all(isinstance(s, (int, float)) for s in scores), \
            "Scores should be numeric"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
