# Sample PCAP Files

Place your PCAP files here for analysis.

## Supported Formats

- `.pcap` - PCAP format
- `.pcapng` - PCAP Next Generation format

## Sample Data Sources

You can obtain sample PCAP files from:

1. **Wireshark Sample Captures**
   - https://wiki.wireshark.org/SampleCaptures
   - Free public PCAP samples for various protocols

2. **CICIDS2017 Dataset**
   - https://www.unb.ca/cic/datasets/ids-2017.html
   - Intrusion detection dataset with labeled attacks

3. **CTU-13 Dataset**
   - https://www.stratosphereips.org/datasets-ctu13
   - Botnet traffic captures

4. **DARPA Dataset**
   - https://www.ll.mit.edu/r-d/datasets
   - Network intrusion detection data

## Download Sample Data

Run the download script to get sample files:

```bash
python scripts/download_data.py --sample all
```

## Creating Your Own Captures

Use Wireshark or tcpdump to capture your own network traffic:

### Using tcpdump:
```bash
sudo tcpdump -i eth0 -w capture.pcap
```

### Using Wireshark:
1. Open Wireshark
2. Select network interface
3. Click "Start Capturing"
4. Save as PCAP file

## File Naming Convention

For better organization:
- `protocol_description_date.pcap`
- Example: `http_malware_20260204.pcap`
