"""
Shared flow-feature definition for both training and live detection.

This module defines the EXACT same feature names and order used during
training (train_flow_model.py) and live detection (live_detector.py),
so there is never a feature mismatch between training and inference.
"""

import os
import numpy as np
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, 'models')
DATASETS_DIR = os.path.join(BASE_DIR, 'datasets')

# The SAME 24 features used during training — never change order without
# also updating train_flow_model.py and live_detector.py.
NUMERIC_COLS = [
    'dst_port', 'duration', 'src_bytes', 'dst_bytes',
    'src_pkts', 'dst_pkts', 'src_ip_bytes', 'dst_ip_bytes',
]
PROTOS = ['tcp', 'udp', 'icmp']
CONN_STATES = [
    'S0', 'S1', 'S2', 'S3', 'SF', 'REJ', 'RSTO', 'RSTR',
    'RSTOS0', 'RSTRH', 'SH', 'SHR', 'OTH',
]

FEATURE_NAMES = (
    NUMERIC_COLS
    + [f'proto_{p}' for p in PROTOS]
    + [f'state_{s}' for s in CONN_STATES]
    + ['bytes_ratio', 'pkts_ratio', 'bytes_per_pkt', 'pkts_per_sec']
)


def build_features(df):
    """
    df must contain at minimum: proto, conn_state + NUMERIC_COLS.
    Returns a float32 DataFrame with exactly FEATURE_NAMES columns,
    ready for the model used in live_detector.py / train_flow_model.py.
    """
    out = pd.DataFrame(index=df.index)
    for c in NUMERIC_COLS:
        out[c] = pd.to_numeric(df[c], errors='coerce').fillna(0).astype('float64')

    proto = df['proto'].astype(str).str.lower()
    for p in PROTOS:
        out[f'proto_{p}'] = (proto == p).astype('float64')

    state = df['conn_state'].astype(str)
    for s in CONN_STATES:
        out[f'state_{s}'] = (state == s).astype('float64')

    # Derived ratios (safe against division by zero)
    out['bytes_ratio'] = (out['src_bytes'] + 1) / (out['dst_bytes'] + 1)
    out['pkts_ratio'] = (out['src_pkts'] + 1) / (out['dst_pkts'] + 1)
    total_pkts = out['src_pkts'] + out['dst_pkts']
    total_bytes = out['src_ip_bytes'] + out['dst_ip_bytes']
    out['bytes_per_pkt'] = total_bytes / total_pkts.replace(0, np.nan)
    out['bytes_per_pkt'] = out['bytes_per_pkt'].fillna(0)
    out['pkts_per_sec'] = total_pkts / out['duration'].clip(lower=0.001)

    return out[FEATURE_NAMES].astype('float32')