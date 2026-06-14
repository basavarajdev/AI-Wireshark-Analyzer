"""Base panel class for all analysis panels."""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QProgressBar, QGroupBox, QSplitter, QTextBrowser, QFrame, QScrollArea
)
from PyQt6.QtCore import Qt

from app.widgets.results_view import ResultsViewer
from app.workers import AnalysisWorker


class BaseAnalysisPanel(QWidget):
    """Base class providing common layout: inputs on top, results below."""

    TITLE = "Analysis"
    SUBTITLE = "Configure and run analysis"
    TASK_NAME = "generic"
    INPUT_GUIDE = "Select a capture, review the optional filters, and run the analysis to generate an HTML report and machine-readable output."

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker = None
        self._setup_ui()

    def _setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 24, 24, 24)
        main_layout.setSpacing(16)

        # Header
        title = QLabel(self.TITLE)
        title.setObjectName("heading")
        main_layout.addWidget(title)

        subtitle = QLabel(self.SUBTITLE)
        subtitle.setObjectName("subheading")
        subtitle.setWordWrap(True)
        main_layout.addWidget(subtitle)

        intro = QFrame()
        intro.setObjectName("panelIntro")
        intro_layout = QVBoxLayout(intro)
        intro_layout.setContentsMargins(18, 18, 18, 18)
        intro_layout.setSpacing(6)

        intro_eyebrow = QLabel("Input setup")
        intro_eyebrow.setObjectName("sectionEyebrow")
        intro_layout.addWidget(intro_eyebrow)

        intro_title = QLabel("Prepare the capture and analysis scope")
        intro_title.setObjectName("sectionTitle")
        intro_layout.addWidget(intro_title)

        intro_copy = QLabel(self.INPUT_GUIDE)
        intro_copy.setObjectName("sectionCopy")
        intro_copy.setWordWrap(True)
        intro_layout.addWidget(intro_copy)

        main_layout.addWidget(intro)

        # Splitter: top=inputs, bottom=results
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Input section
        input_container = QWidget()
        self._input_layout = QVBoxLayout(input_container)
        self._input_layout.setContentsMargins(0, 0, 0, 0)
        self._input_layout.setSpacing(14)

        # Subclass fills this
        self._build_inputs(self._input_layout)

        # Run button + progress (silent operation)
        action_row = QHBoxLayout()
        action_row.setSpacing(12)

        self._btn_run = QPushButton("▶  Run Analysis")
        self._btn_run.setObjectName("btnSuccess")
        self._btn_run.setFixedHeight(40)
        self._btn_run.setMinimumWidth(160)
        self._btn_run.clicked.connect(self._on_run)
        action_row.addWidget(self._btn_run)

        self._progress = QProgressBar()
        self._progress.setRange(0, 0)  # Indeterminate
        self._progress.setVisible(False)
        self._progress.setFixedHeight(26)
        action_row.addWidget(self._progress, 1)

        self._status_label = QLabel("")
        self._status_label.setObjectName("fieldHelp")
        self._status_label.setVisible(False)
        action_row.addWidget(self._status_label)

        action_row.addStretch()
        self._input_layout.addLayout(action_row)

        # Log area - visible to show output
        self._log = QTextBrowser()
        self._log.setMaximumHeight(200)
        self._log.setVisible(True)
        self._input_layout.addWidget(self._log)

        input_scroll = QScrollArea()
        input_scroll.setWidgetResizable(True)
        input_scroll.setFrameShape(QFrame.Shape.NoFrame)
        input_scroll.setWidget(input_container)

        splitter.addWidget(input_scroll)

        # Results section
        self._results = ResultsViewer()
        splitter.addWidget(self._results)

        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([420, 720])

        main_layout.addWidget(splitter, 1)

    def _build_inputs(self, layout):
        """Override in subclass to add input widgets."""
        pass

    def _get_params(self) -> dict:
        """Override in subclass to collect parameters."""
        return {}

    def _validate(self) -> str:
        """Override to validate inputs. Return error message or empty string."""
        return ""

    def _on_run(self):
        """Start the analysis."""
        error = self._validate()
        if error:
            self._log.clear()
            self._log.append(f"⚠ ERROR: {error}")
            return

        params = self._get_params()
        self._btn_run.setEnabled(False)
        self._progress.setVisible(True)
        self._log.clear()
        self._log.setVisible(True)
        self._results.clear()

        self._worker = AnalysisWorker(self.TASK_NAME, params)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_progress(self, msg: str):
        self._log.append(msg)

    def _on_finished(self, result: dict):
        self._btn_run.setEnabled(True)
        self._progress.setVisible(False)

        if result.get("stdout"):
            self._log.append(result["stdout"][:2000])

        json_data = result.get("json_data")
        html_path = result.get("html_path")

        self._results.show_results(
            json_data=json_data,
            html_path=html_path,
            title=f"{self.TITLE} Results"
        )

    def _on_error(self, msg: str):
        self._btn_run.setEnabled(True)
        self._progress.setVisible(False)
        self._log.append(f"ERROR: {msg}")
