"""ML Anomaly Detection panel."""

from PyQt6.QtWidgets import QVBoxLayout, QGroupBox, QLabel, QComboBox, QGridLayout, QFrame

from app.panels.base_panel import BaseAnalysisPanel
from app.widgets.inputs import FileSelector


class AnomalyPanel(BaseAnalysisPanel):
    TITLE = "ML Anomaly Detection"
    SUBTITLE = "Unsupervised anomaly detection using Isolation Forest or Autoencoder"
    TASK_NAME = "anomaly"
    INPUT_GUIDE = "Select the capture, then choose the model that matches your workflow. Isolation Forest is fast for general anomaly scoring, while the Autoencoder is better when you want richer behavioral outlier detection."

    def _build_option_card(self, title: str, description: str):
        card = QFrame()
        card.setObjectName("optionCard")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(14, 14, 14, 14)
        card_layout.setSpacing(4)

        title_label = QLabel(title)
        title_label.setObjectName("optionTitle")
        card_layout.addWidget(title_label)

        desc_label = QLabel(description)
        desc_label.setObjectName("fieldHelp")
        desc_label.setWordWrap(True)
        card_layout.addWidget(desc_label)
        return card

    def _build_inputs(self, layout: QVBoxLayout):
        group = QGroupBox("1. Capture Source")
        group_layout = QVBoxLayout(group)
        group_layout.setSpacing(12)

        capture_note = QLabel(
            "Use anomaly detection when you want to find statistically unusual traffic patterns instead of diagnosing one specific known symptom."
        )
        capture_note.setObjectName("fieldHelp")
        capture_note.setWordWrap(True)
        group_layout.addWidget(capture_note)

        self._file_selector = FileSelector(label="PCAP File:")
        group_layout.addWidget(self._file_selector)

        models_group = QGroupBox("2. Model Options")
        models_layout = QGridLayout(models_group)
        models_layout.setHorizontalSpacing(12)
        models_layout.setVerticalSpacing(12)
        models_layout.addWidget(self._build_option_card("Isolation Forest", "Fast baseline model for broad anomaly scoring across mixed traffic captures."), 0, 0)
        models_layout.addWidget(self._build_option_card("Autoencoder", "Better when you want richer behavioral outlier detection and more nuanced reconstruction-based scoring."), 0, 1)
        models_layout.addWidget(self._build_option_card("Random Forest", "Use only when a trained model already exists in your workflow; not ideal for ad hoc first-pass triage."), 1, 0, 1, 2)
        group_layout.addWidget(models_group)

        model_label = QLabel("Model Selection")
        model_label.setObjectName("fieldLabel")
        group_layout.addWidget(model_label)

        model_help = QLabel("Choose the model that best matches the capture type and the maturity of your detection workflow.")
        model_help.setObjectName("fieldHelp")
        model_help.setWordWrap(True)
        group_layout.addWidget(model_help)

        self._model_combo = QComboBox()
        self._model_combo.addItems([
            "Isolation Forest",
            "Autoencoder",
            "Random Forest (requires trained model)"
        ])
        group_layout.addWidget(self._model_combo)

        self._model_detail = QLabel(
            "Isolation Forest is the best default for first-pass anomaly discovery on large captures."
        )
        self._model_detail.setObjectName("fieldHelp")
        self._model_detail.setWordWrap(True)
        group_layout.addWidget(self._model_detail)
        self._model_combo.currentTextChanged.connect(self._on_model_changed)

        layout.addWidget(group)

    def _on_model_changed(self, text: str):
        details = {
            "Isolation Forest": "Fast and broadly applicable. Use this for exploratory anomaly detection and first-pass triage.",
            "Autoencoder": "Use when you want richer behavioral outlier detection and have captures that benefit from reconstruction-based scoring.",
            "Random Forest (requires trained model)": "Choose only if your workflow already provides a trained supervised model for this environment.",
        }
        self._model_detail.setText(details.get(text, ""))

    def _validate(self) -> str:
        if not self._file_selector.get_path():
            return "Please select a PCAP file"
        return ""

    def _get_params(self) -> dict:
        model_map = {
            "Isolation Forest": "isolation_forest",
            "Autoencoder": "autoencoder",
            "Random Forest (requires trained model)": "random_forest",
        }
        return {
            "pcap": self._file_selector.get_path(),
            "model_type": model_map.get(self._model_combo.currentText(), "isolation_forest"),
        }
