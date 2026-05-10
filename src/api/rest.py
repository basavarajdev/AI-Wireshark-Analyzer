"""
REST API for AI-Wireshark-Analyzer
FastAPI endpoints for PCAP analysis
"""

from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict, List
import tempfile
import os
from pathlib import Path
import yaml
from loguru import logger
import uvicorn

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.parsers.packet_parser import PacketParser
from src.preprocessing.cleaning import DataCleaner
from src.preprocessing.feature_engineering import FeatureEngineer
from src.core.model import IsolationForestModel, AutoencoderModel
from src.protocols.tcp_analyzer import TCPAnalyzer
from src.protocols.udp_analyzer import UDPAnalyzer
from src.protocols.dns_analyzer import DNSAnalyzer
from src.protocols.http_analyzer import HTTPAnalyzer
from src.protocols.https_analyzer import HTTPSAnalyzer
from src.protocols.icmp_analyzer import ICMPAnalyzer
from src.protocols.wlan_analyzer import WLANAnalyzer
from src.protocols.dhcp_analyzer import DHCPAnalyzer


# Initialize FastAPI app
app = FastAPI(
    title="AI-Wireshark-Analyzer API",
    description="ML-powered network traffic analysis API",
    version="1.0.0"
)

# Load configuration
with open("config/default.yaml", 'r') as f:
    config = yaml.safe_load(f)


# Request/Response models
class AnalysisRequest(BaseModel):
    protocol: Optional[str] = None
    model_type: Optional[str] = "isolation_forest"
    detect_anomalies: bool = True


class HealthResponse(BaseModel):
    status: str
    version: str


class ModelInfo(BaseModel):
    name: str
    type: str
    available: bool


@app.get("/", response_model=HealthResponse)
async def root():
    """Root endpoint"""
    return {
        "status": "healthy",
        "version": "1.0.0"
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "1.0.0"
    }


@app.get("/models", response_model=List[ModelInfo])
async def list_models():
    """List available models"""
    models_dir = Path("models")
    available_models = []
    
    # Check for saved models
    if models_dir.exists():
        for model_file in models_dir.glob("*.pkl"):
            available_models.append({
                "name": model_file.stem,
                "type": "isolation_forest" if "isolation" in model_file.stem else "classifier",
                "available": True
            })
        
        for model_file in models_dir.glob("*.h5"):
            available_models.append({
                "name": model_file.stem,
                "type": "autoencoder",
                "available": True
            })
    
    # Default models
    default_models = [
        {"name": "isolation_forest", "type": "anomaly_detection", "available": True},
        {"name": "autoencoder", "type": "anomaly_detection", "available": True}
    ]
    
    return default_models + available_models


@app.post("/analyze")
async def analyze_pcap(
    file: UploadFile = File(...),
    protocol: Optional[str] = None,
    display_filter: Optional[str] = None,
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    """
    Analyze PCAP file
    
    Args:
        file: PCAP file to analyze
        protocol: Specific protocol to analyze (tcp, udp, dns, http, https, icmp, dhcp)
        display_filter: Wireshark display filter (e.g. ip.addr==192.168.1.1, ip.src==10.0.0.1)
        
    Returns:
        Analysis results
    """
    logger.info(f"Received analysis request for file: {file.filename}")
    
    # Validate file type
    if not file.filename.endswith(('.pcap', '.pcapng')):
        raise HTTPException(status_code=400, detail="Invalid file type. Only PCAP files are supported.")
    
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_file:
        content = await file.read()
        tmp_file.write(content)
        tmp_path = tmp_file.name
    
    try:
        # Parse PCAP
        parser = PacketParser()
        df = parser.parse_pcap(tmp_path)
        
        if df.empty:
            raise HTTPException(status_code=400, detail="No packets found in PCAP file")
        
        # Clean data
        cleaner = DataCleaner()
        df = cleaner.clean(df)
        
        # Basic statistics
        results = {
            "filename": file.filename,
            "total_packets": len(df),
            "protocols": df['protocol'].value_counts().to_dict() if 'protocol' in df.columns else {},
        }
        
        # Protocol-specific analysis
        if protocol:
            protocol_results = await _analyze_protocol(tmp_path, protocol.lower(), display_filter)
            results['protocol_analysis'] = protocol_results
        
        # Clean up temp file
        background_tasks.add_task(os.unlink, tmp_path)
        
        return JSONResponse(content=results)
    
    except Exception as e:
        # Clean up on error
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        logger.error(f"Analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def _analyze_protocol(pcap_file: str, protocol: str, display_filter: str = None) -> Dict:
    """Run protocol-specific analysis"""
    
    analyzers = {
        'tcp': TCPAnalyzer,
        'udp': UDPAnalyzer,
        'dns': DNSAnalyzer,
        'http': HTTPAnalyzer,
        'https': HTTPSAnalyzer,
        'icmp': ICMPAnalyzer,
        'dhcp': DHCPAnalyzer,
    }
    
    if protocol not in analyzers:
        raise HTTPException(status_code=400, detail=f"Unsupported protocol: {protocol}")
    
    analyzer = analyzers[protocol]()
    results = analyzer.analyze(pcap_file, display_filter=display_filter)
    
    return results


@app.post("/detect-anomalies")
async def detect_anomalies(
    file: UploadFile = File(...),
    model_type: str = "isolation_forest",
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    """
    Detect anomalies in network traffic
    
    Args:
        file: PCAP file to analyze
        model_type: Type of model to use ('isolation_forest' or 'autoencoder')
        
    Returns:
        Anomaly detection results
    """
    logger.info(f"Anomaly detection request - Model: {model_type}")
    
    # Validate file type
    if not file.filename.endswith(('.pcap', '.pcapng')):
        raise HTTPException(status_code=400, detail="Invalid file type")
    
    # Save uploaded file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_file:
        content = await file.read()
        tmp_file.write(content)
        tmp_path = tmp_file.name
    
    try:
        # Parse and process
        parser = PacketParser()
        df = parser.parse_pcap(tmp_path)
        
        if df.empty:
            raise HTTPException(status_code=400, detail="No packets found")
        
        cleaner = DataCleaner()
        df = cleaner.clean(df)
        
        engineer = FeatureEngineer()
        df_features = engineer.engineer_features(df)
        X = engineer.get_ml_features(df_features)
        
        # Load or create model
        if model_type == "isolation_forest":
            model = IsolationForestModel()
            model_path = Path("models/isolation_forest.pkl")
            
            if model_path.exists():
                model.load(str(model_path))
            else:
                # Train on current data
                model.train(X)
        
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported model type: {model_type}")
        
        # Predict
        predictions = model.predict(X)
        scores = model.score_samples(X)
        
        # Results
        anomaly_count = (predictions == -1).sum()
        results = {
            "filename": file.filename,
            "total_packets": len(predictions),
            "anomalies_detected": int(anomaly_count),
            "anomaly_rate": float(anomaly_count / len(predictions)),
            "model_type": model_type,
            "anomaly_scores": {
                "min": float(scores.min()),
                "max": float(scores.max()),
                "mean": float(scores.mean()),
                "std": float(scores.std())
            }
        }
        
        # Clean up
        background_tasks.add_task(os.unlink, tmp_path)
        
        return JSONResponse(content=results)
    
    except Exception as e:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        logger.error(f"Anomaly detection error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/protocols")
async def list_protocols():
    """List supported protocols"""
    return {
        "protocols": ["tcp", "udp", "dns", "http", "https", "icmp"],
        "description": "Supported protocols for analysis"
    }


def main():
    """Run the API server"""
    api_config = config['api']
    
    logger.info(f"Starting API server on {api_config['host']}:{api_config['port']}")
    
    uvicorn.run(
        "src.api.rest:app",
        host=api_config['host'],
        port=api_config['port'],
        workers=api_config.get('workers', 1),
        reload=config['app'].get('debug', False)
    )


if __name__ == "__main__":
    main()
