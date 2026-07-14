"""Evaluation module initialization"""

from .metrics import calculate_anomaly_metrics, calculate_classification_metrics

# Lazy import for visualization - only load when needed
_NetworkVisualizer = None

def __getattr__(name):
    """Lazy load NetworkVisualizer when accessed"""
    if name == 'NetworkVisualizer':
        global _NetworkVisualizer
        if _NetworkVisualizer is None:
            try:
                from .visualization import NetworkVisualizer as NV
                _NetworkVisualizer = NV
            except ImportError as e:
                raise ImportError(f"NetworkVisualizer requires visualization dependencies: {e}")
        return _NetworkVisualizer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = ['calculate_anomaly_metrics', 'calculate_classification_metrics', 'NetworkVisualizer']

