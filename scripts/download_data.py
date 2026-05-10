"""
Download Sample Data Script
Download or generate sample PCAP files for testing
"""

import argparse
from pathlib import Path
from loguru import logger
import urllib.request


# Sample PCAP URLs (public datasets)
SAMPLE_PCAPS = {
    'small': 'https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=http.cap',
    'dns': 'https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=dns.cap',
    'icmp': 'https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=icmp.cap',
}


def download_sample(name: str, output_dir: str = "data/raw"):
    """Download sample PCAP file"""
    if name not in SAMPLE_PCAPS:
        logger.error(f"Unknown sample: {name}")
        logger.info(f"Available samples: {list(SAMPLE_PCAPS.keys())}")
        return
    
    url = SAMPLE_PCAPS[name]
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    output_file = output_path / f"sample_{name}.pcap"
    
    logger.info(f"Downloading {name} from {url}")
    
    try:
        urllib.request.urlretrieve(url, str(output_file))
        logger.info(f"Downloaded to {output_file}")
    except Exception as e:
        logger.error(f"Download failed: {e}")
        logger.info("You can manually download PCAP samples from https://wiki.wireshark.org/SampleCaptures")


def create_sample_dataset_info():
    """Create README for data directory"""
    readme_content = """# Data Directory

## Structure

- `raw/` - Original PCAP files
- `processed/` - Extracted features (CSV files)
- `external/` - Third-party datasets

## Sample Datasets

To download sample PCAP files:

```bash
python scripts/download_data.py --sample small
python scripts/download_data.py --sample dns
python scripts/download_data.py --sample icmp
```

## Public PCAP Datasets

- Wireshark Sample Captures: https://wiki.wireshark.org/SampleCaptures
- CICIDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
- CTU-13: https://www.stratosphereips.org/datasets-ctu13

## Adding Your Own Data

Place your PCAP files in `data/raw/` directory.

Supported formats:
- .pcap
- .pcapng
"""
    
    readme_path = Path("data/README.md")
    with open(readme_path, 'w') as f:
        f.write(readme_content)
    
    logger.info(f"Created {readme_path}")


def main():
    """Main download script"""
    parser = argparse.ArgumentParser(description='Download sample network traffic data')
    parser.add_argument('--sample', '-s', choices=['small', 'dns', 'icmp', 'all'],
                       default='all', help='Sample to download')
    parser.add_argument('--output-dir', '-o', default='data/raw',
                       help='Output directory')
    
    args = parser.parse_args()
    
    # Create data directory structure
    for subdir in ['raw', 'processed', 'external']:
        Path(f"data/{subdir}").mkdir(parents=True, exist_ok=True)
    
    # Create README
    create_sample_dataset_info()
    
    # Download samples
    if args.sample == 'all':
        for name in SAMPLE_PCAPS.keys():
            download_sample(name, args.output_dir)
    else:
        download_sample(args.sample, args.output_dir)
    
    logger.info("Download process completed")
    logger.info("Note: Some downloads may fail. You can manually download samples from Wireshark wiki.")


if __name__ == '__main__':
    main()
