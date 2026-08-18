#!/usr/bin/env python3
"""
ai_ids.py

Improved AI-based IDS log reader that monitors Suricata and Zeek logs,
preprocesses events into numeric features, runs an IsolationForest
anomaly detector, and writes alerts to a CSV file.

Usage:
  python ai_ids.py --suricata /path/to/eve.json --zeek-conn /path/to/conn.log --zeek-dns /path/to/dns.log

Supports Docker execution (see README.md).
"""

from __future__ import annotations
import argparse
import json
import time
import logging
import sys
import signal
from datetime import datetime
from pathlib import Path
import ipaddress
import hashlib
from typing import Tuple, List

import pandas as pd
from sklearn.ensemble import IsolationForest

# ----- DEFAULT CONFIGURATION -----
DEFAULT_SURICATA_LOG = "/var/log/suricata/eve.json"
DEFAULT_ZEEK_CONN_LOG = "/home/cpe326/zeek_logs/conn.log"
DEFAULT_ZEEK_DNS_LOG = "/home/cpe326/zeek_logs/dns.log"
DEFAULT_ALERT_OUTPUT = "alerts.csv"
DEFAULT_POLL_INTERVAL = 2  # seconds
FEATURE_COLUMNS = [
    'src_ip','dest_ip','src_port','dest_port','proto',
    'duration','orig_bytes','resp_bytes',
    'query_length','num_subdomains',
    'is_nxdomain','answer_count','ttl_avg'
]

# ----- LOGGING -----
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger("ai_ids")

stop_requested = False

def handle_sigint(sig, frame):
    global stop_requested
    stop_requested = True
    logger.info("Shutdown requested, exiting gracefully...")

signal.signal(signal.SIGINT, handle_sigint)
signal.signal(signal.SIGTERM, handle_sigint)

# ----- UTILITIES -----

def load_new_lines(file_path: str, last_pos: int) -> Tuple[List[str], int]:
    """Read new lines from a file since last_pos. If file missing return empty list and pos 0."""
    try:
        with open(file_path, 'r') as f:
            f.seek(last_pos)
            lines = f.readlines()
            last_pos = f.tell()
        return lines, last_pos
    except FileNotFoundError:
        return [], 0
    except Exception as e:
        logger.debug(f"Error reading {file_path}: {e}")
        return [], last_pos


def ip_to_int(ip: str) -> int:
    """Deterministic numeric encoding for IP-like strings."""
    if not isinstance(ip, str):
        ip = str(ip)
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        # fallback: stable hash -> 32-bit int
        h = hashlib.sha256(ip.encode('utf-8')).hexdigest()[:8]
        return int(h, 16)


def proto_to_int(proto: str) -> int:
    mapping = {
        'TCP': 6,
        'UDP': 17,
        'ICMP': 1,
        'HTTP': 80,
        'HTTPS': 443,
    }
    if not isinstance(proto, str):
        proto = str(proto)
    up = proto.upper()
    if up in mapping:
        return mapping[up]
    try:
        # try numeric
        return int(proto)
    except Exception:
        return abs(hash(up)) % 65536


def encode_categoricals(df: pd.DataFrame) -> pd.DataFrame:
    df_enc = df.copy()
    df_enc['src_ip'] = df_enc['src_ip'].apply(ip_to_int)
    df_enc['dest_ip'] = df_enc['dest_ip'].apply(ip_to_int)
    df_enc['proto'] = df_enc['proto'].apply(proto_to_int)
    return df_enc

# ----- PREPROCESSING -----

def preprocess_suricata(lines: List[str]) -> Tuple[pd.DataFrame, pd.DataFrame]:
    data = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Only use events that contain an alert (Suricata) or flow info
        if 'alert' not in event and 'flow' not in event and 'event_type' in event and event.get('event_type') != 'alert':
            continue
        try:
            data.append({
                'src_ip': event.get('src_ip', '0.0.0.0'),
                'dest_ip': event.get('dest_ip', '0.0.0.0'),
                'src_port': int(event.get('src_port', 0) or 0),
                'dest_port': int(event.get('dest_port', 0) or 0),
                'proto': event.get('proto', 'UNK'),
                'duration': float(event.get('flow', {}).get('age', 0) or 0),
                'orig_bytes': int(event.get('flow', {}).get('bytes_toserver', 0) or 0),
                'resp_bytes': int(event.get('flow', {}).get('bytes_toclient', 0) or 0),
                'query_length': 0,
                'num_subdomains': 0,
                'is_nxdomain': 0,
                'answer_count': 0,
                'ttl_avg': 0,
                'timestamp': event.get('timestamp', datetime.now().isoformat())
            })
        except Exception:
            continue

    if not data:
        return pd.DataFrame(), pd.DataFrame()

    df_orig = pd.DataFrame(data)
    df_orig = df_orig.reindex(columns=FEATURE_COLUMNS + ['timestamp'], fill_value=0)
    df_enc = encode_categoricals(df_orig)
    return df_orig, df_enc


def preprocess_conn(lines: List[str]) -> Tuple[pd.DataFrame, pd.DataFrame]:
    data = []
    for line in lines:
        if line.startswith('#') or not line.strip():
            continue
        parts = line.strip().split('\t')
        try:
            data.append({
                'src_ip': parts[2],
                'dest_ip': parts[4],
                'src_port': int(parts[3]) if parts[3] != '-' else 0,
                'dest_port': int(parts[5]) if parts[5] != '-' else 0,
                'proto': parts[6],
                'duration': float(parts[8]) if len(parts) > 8 and parts[8] != '-' else 0,
                'orig_bytes': int(parts[9]) if len(parts) > 9 and parts[9] != '-' else 0,
                'resp_bytes': int(parts[10]) if len(parts) > 10 and parts[10] != '-' else 0,
                'query_length': 0,
                'num_subdomains': 0,
                'is_nxdomain': 0,
                'answer_count': 0,
                'ttl_avg': 0,
                'timestamp': parts[0]
            })
        except Exception:
            continue

    if not data:
        return pd.DataFrame(), pd.DataFrame()

    df_orig = pd.DataFrame(data)
    df_orig = df_orig.reindex(columns=FEATURE_COLUMNS + ['timestamp'], fill_value=0)
    df_enc = encode_categoricals(df_orig)
    return df_orig, df_enc


def preprocess_dns(lines: List[str]) -> Tuple[pd.DataFrame, pd.DataFrame]:
    data = []
    for line in lines:
        if line.startswith('#') or not line.strip():
            continue
        parts = line.strip().split('\t')
        try:
            query = parts[9]
            answers = parts[21] if len(parts) > 21 else '-'
            ttls = parts[22] if len(parts) > 22 else '-'
            rcode_name = parts[15] if len(parts) > 15 else '-'

            query_length = len(query)
            num_subdomains = query.count('.')
            is_nxdomain = 1 if rcode_name == 'NXDOMAIN' else 0
            answer_count = 0 if answers == '-' else len(answers.split(','))
            ttl_avg = 0.0
            if ttls != '-':
                try:
                    ttl_values = [float(x) for x in ttls.split(',') if x]
                    ttl_avg = sum(ttl_values) / len(ttl_values) if ttl_values else 0.0
                except Exception:
                    ttl_avg = 0.0

            data.append({
                'src_ip': parts[2],
                'dest_ip': parts[4],
                'src_port': int(parts[3]) if parts[3] != '-' else 0,
                'dest_port': int(parts[5]) if parts[5] != '-' else 0,
                'proto': parts[6],
                'duration': float(parts[8]) if len(parts) > 8 and parts[8] != '-' else 0,
                'orig_bytes': 0,
                'resp_bytes': 0,
                'query_length': query_length,
                'num_subdomains': num_subdomains,
                'is_nxdomain': is_nxdomain,
                'answer_count': answer_count,
                'ttl_avg': ttl_avg,
                'timestamp': parts[0]
            })
        except Exception:
            continue

    if not data:
        return pd.DataFrame(), pd.DataFrame()

    df_orig = pd.DataFrame(data)
    df_orig = df_orig.reindex(columns=FEATURE_COLUMNS + ['timestamp'], fill_value=0)
    df_enc = encode_categoricals(df_orig)
    return df_orig, df_enc

# ----- MODEL -----

MODEL_MIN_SAMPLES = 10
model = IsolationForest(contamination=0.01, n_estimators=100, random_state=42)
# initial dummy data to allow a first fit
_dummy = pd.DataFrame([{col: 0 for col in FEATURE_COLUMNS} for _ in range(MODEL_MIN_SAMPLES)])
model.fit(_dummy)

# ----- MAIN LOOP -----

def ensure_alert_file(path: str):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.write_text('timestamp,src_ip,dest_ip,src_port,dest_port,proto,anomaly\n')


def process_batch(df_orig_all: pd.DataFrame, df_enc_all: pd.DataFrame, alert_path: str):
    if df_enc_all.shape[0] < 1:
        return
    try:
        # If not enough rows to re-fit model safely, skip refit but still predict
        if df_enc_all.shape[0] >= MODEL_MIN_SAMPLES:
            # Fit using numeric feature columns
            model.fit(df_enc_all[FEATURE_COLUMNS])

        df_enc_all['anomaly'] = model.predict(df_enc_all[FEATURE_COLUMNS])
        df_orig_all['anomaly'] = df_enc_all['anomaly'].values

        suspicious = df_orig_all[df_orig_all['anomaly'] == -1]
        if not suspicious.empty:
            ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            logger.warning(f"{len(suspicious)} suspicious events detected at {ts}")
            # Write alerts (append)
            cols = ['timestamp','src_ip','dest_ip','src_port','dest_port','proto','anomaly']
            suspicious[cols].to_csv(alert_path, mode='a', header=False, index=False)
    except Exception as e:
        logger.exception(f"Error during model predict/fit: {e}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="AI-based IDS log monitor")
    parser.add_argument('--suricata', default=DEFAULT_SURICATA_LOG, help='Path to Suricata eve.json')
    parser.add_argument('--zeek-conn', default=DEFAULT_ZEEK_CONN_LOG, help='Path to Zeek conn.log')
    parser.add_argument('--zeek-dns', default=DEFAULT_ZEEK_DNS_LOG, help='Path to Zeek dns.log')
    parser.add_argument('--alert', default=DEFAULT_ALERT_OUTPUT, help='CSV file to append alerts to')
    parser.add_argument('--interval', type=float, default=DEFAULT_POLL_INTERVAL, help='Polling interval in seconds')
    parser.add_argument('--once', action='store_true', help='Run one iteration and exit (useful for testing)')
    args = parser.parse_args(argv)

    last_suricata_pos = 0
    last_zeek_pos = 0
    last_zeek_dns_pos = 0

    ensure_alert_file(args.alert)

    logger.info("AI IDS starting. Monitoring logs...")

    while not stop_requested:
        frames_orig = []
        frames_enc = []

        suricata_lines, last_suricata_pos = load_new_lines(args.suricata, last_suricata_pos)
        if suricata_lines:
            df_orig_s, df_enc_s = preprocess_suricata(suricata_lines)
            if not df_enc_s.empty:
                frames_orig.append(df_orig_s)
                frames_enc.append(df_enc_s)

        zeek_lines, last_zeek_pos = load_new_lines(args.zeek_conn, last_zeek_pos)
        if zeek_lines:
            df_orig_z, df_enc_z = preprocess_conn(zeek_lines)
            if not df_enc_z.empty:
                frames_orig.append(df_orig_z)
                frames_enc.append(df_enc_z)

        dns_lines, last_zeek_dns_pos = load_new_lines(args.zeek_dns, last_zeek_dns_pos)
        if dns_lines:
            df_orig_dns, df_enc_dns = preprocess_dns(dns_lines)
            if not df_enc_dns.empty:
                frames_orig.append(df_orig_dns)
                frames_enc.append(df_enc_dns)

        if frames_enc:
            df_orig_all = pd.concat(frames_orig, ignore_index=True)
            df_enc_all = pd.concat(frames_enc, ignore_index=True)
            process_batch(df_orig_all, df_enc_all, args.alert)

        if args.once:
            break

        time.sleep(max(0.1, args.interval))

    logger.info("AI IDS stopped.")


if __name__ == '__main__':
    main()
