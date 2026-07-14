#!/usr/bin/env python3
"""
Test Suite for AI-Wireshark Enhancements (v1.6.2)
Tests connection lifecycle, protocol detection, DHCP, and data transfer analysis
"""

import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime

def run_test(pcap_path, out_prefix):
    """Run channel monitor on a PCAP file."""
    cmd = [
        'python3', 'scripts/run_channel_monitor.py',
        '--pcap', pcap_path,
        '--out', out_prefix,
        '--quiet'
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0, result.stdout, result.stderr

def validate_json(json_path):
    """Validate JSON output structure."""
    try:
        with open(json_path) as f:
            data = json.load(f)
        
        # Check required sections
        checks = {
            'generated': 'generated' in data,
            'overall': 'overall' in data,
            'windows': 'windows' in data,
            'connection_analysis': 'connection_analysis' in data,
            'protocol_analysis': 'protocol_analysis' in data,
            'dhcp_analysis': 'dhcp_analysis' in data,
            'data_transfer_analysis': 'data_transfer_analysis' in data,
        }
        
        # Validate data transfer metrics
        dta_valid = False
        if checks['data_transfer_analysis']:
            dta = data['data_transfer_analysis']
            dta_valid = all(k in dta for k in ['found', 'throughput_mbps', 'quality_assessment'])
        
        return {
            'valid': all(checks.values()),
            'checks': checks,
            'dta_metrics': {
                'throughput_mbps': data.get('data_transfer_analysis', {}).get('throughput_mbps'),
                'quality': data.get('data_transfer_analysis', {}).get('quality_assessment'),
                'retry_rate': data.get('data_transfer_analysis', {}).get('retry_rate'),
            } if dta_valid else {},
        }
    except Exception as e:
        return {'valid': False, 'error': str(e), 'checks': {}}

def main():
    pcap_dir = Path('/home/bidnal/Downloads/Wireshark_Pcaps')
    results_dir = Path('results/tests')
    results_dir.mkdir(parents=True, exist_ok=True)
    
    # Find PCAP files
    pcaps = sorted(list(pcap_dir.glob('*.pcap'))[:3])  # Test first 3
    
    if not pcaps:
        print("❌ No PCAP files found")
        return 1
    
    print(f"\n{'='*70}")
    print(f"AI-Wireshark Enhanced Test Suite (v1.6.2)")
    print(f"{'='*70}\n")
    print(f"Testing {len(pcaps)} captures...")
    print(f"Output: {results_dir}\n")
    
    test_results = []
    
    for i, pcap in enumerate(pcaps, 1):
        print(f"[{i}/{len(pcaps)}] {pcap.name}... ", end='', flush=True)
        
        out_prefix = str(results_dir / pcap.stem)
        success, stdout, stderr = run_test(str(pcap), out_prefix)
        
        if not success:
            print(f"❌ FAILED: {stderr[:100]}")
            test_results.append({'pcap': pcap.name, 'status': 'FAILED', 'error': stderr})
            continue
        
        # Validate output
        json_path = f"{out_prefix}.json"
        validation = validate_json(json_path)
        
        if validation['valid']:
            print(f"✓ PASSED")
            test_results.append({
                'pcap': pcap.name,
                'status': 'PASSED',
                'json_size_mb': round(Path(json_path).stat().st_size / (1024*1024), 2),
                'data_transfer': validation.get('dta_metrics', {}),
            })
        else:
            print(f"⚠ PARTIAL (validation issue)")
            test_results.append({
                'pcap': pcap.name,
                'status': 'PARTIAL',
                'failed_checks': [k for k, v in validation.get('checks', {}).items() if not v],
            })
    
    # Summary
    print(f"\n{'='*70}")
    print("TEST RESULTS SUMMARY")
    print(f"{'='*70}\n")
    
    passed = sum(1 for r in test_results if r['status'] == 'PASSED')
    total = len(test_results)
    
    for result in test_results:
        status_icon = '✓' if result['status'] == 'PASSED' else '❌' if result['status'] == 'FAILED' else '⚠'
        print(f"{status_icon} {result['pcap']:<40} {result['status']:<10}", end='')
        
        if result['status'] == 'PASSED':
            dta = result.get('data_transfer', {})
            if dta:
                print(f" | Throughput: {dta.get('throughput_mbps', 'N/A')} Mbps | Quality: {dta.get('quality', 'N/A')}")
            else:
                print()
        else:
            print()
    
    print(f"\n{'='*70}")
    print(f"Results: {passed}/{total} passed ({100*passed//total}%)")
    print(f"{'='*70}\n")
    
    return 0 if passed == total else 1

if __name__ == '__main__':
    sys.exit(main())
