"""
Detection layer for the IDS.
- FlowClassifier: loads the trained model and classifies flows
- BehaviorDetector: per-device rules that catch scanning / flooding
"""

import os
import sys
import joblib
from collections import defaultdict, deque

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flow_features import FEATURE_NAMES, MODELS_DIR


class FlowClassifier:
    """Classifies finished flows using the trained model."""

    def __init__(self, path=None, threshold=0.75):
        if path is None:
            path = os.path.join(MODELS_DIR, 'flow_model.pkl')
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"Model file not found at {path}. "
                "Run: python src/train_flow_model.py")
        bundle = joblib.load(path)
        self.model = bundle['model']
        self.classes = list(bundle['classes'])
        self.threshold = threshold
        self.normal_idx = self.classes.index('normal') if 'normal' in self.classes else 0

    def classify(self, records):
        """
        Classify a list of flow records.

        :param records: list of dicts, each containing the 24 features
                        matching FEATURE_NAMES.
        :return: list of dicts with keys:
                 - is_attack: bool
                 - attack_type: str (e.g. 'backdoor', 'ddos', 'normal')
                 - confidence: float in [0, 1]
                 - attack_score: float in [0, 1]  (probability of attack)
        """
        if not records:
            return []

        df = pd.DataFrame(records)
        # Ensure every feature column from FEATURE_NAMES exists
        for c in FEATURE_NAMES:
            if c not in df:
                df[c] = 0.0

        X = df[FEATURE_NAMES].astype('float32')
        proba = self.model.predict_proba(X)

        out = []
        for i, p in enumerate(proba):
            # Probability that this flow is NOT the "normal" class
            p_not_normal = 1.0 - float(p[self.normal_idx])
            # Best attack class, excluding the normal class
            masked = p.copy()
            masked[self.normal_idx] = -1
            best_idx = int(masked.argmax())
            best_class = self.classes[best_idx]

            # Adjust threshold for standard outbound web traffic (HTTP, HTTPS, DNS, NTP)
            # to prevent routine web browsing from triggering false positives
            eff_threshold = self.threshold
            rec = records[i] if i < len(records) else {}
            dst_port = rec.get('dst_port', 0)
            if dst_port in (80, 443, 53, 853, 123):
                eff_threshold = max(self.threshold, 0.85)

            is_attack = p_not_normal >= eff_threshold
            confidence = p_not_normal if is_attack else 1.0 - p_not_normal

            out.append({
                'is_attack': bool(is_attack),
                'attack_type': best_class if is_attack else 'normal',
                'confidence': round(confidence, 4),
                'attack_score': round(p_not_normal, 4),
            })
        return out


class BehaviorDetector:
    """Looks at per-source behavior over a sliding window.

    Flags:
      - scanning  : many different ports or hosts contacted
      - ddos      : connection storm (many new flows quickly)
    """

    WINDOW = 10.0
    PORTS_PER_HOST = 25
    HOSTS_PER_SRC = 40
    NEW_FLOWS_PER_SRC = 300
    COOLDOWN = 30.0

    def __init__(self):
        self.events = defaultdict(deque)   # src -> deque[(t, dst, dport)]
        self.last_alert = {}

    def observe(self, now, src, dst, dport):
        """Record one new flow. Returns (attack_type, detail) or None."""
        q = self.events[src]
        q.append((now, dst, dport))
        # Keep only events within the WINDOW
        while q and now - q[0][0] > self.WINDOW:
            q.popleft()

        # Summarise what the source did in this window
        ports, hosts = defaultdict(set), set()
        for _, d, p in q:
            ports[d].add(p)
            hosts.add(d)

        verdict = None
        top_ports = max((len(v) for v in ports.values()), default=0)
        if top_ports >= self.PORTS_PER_HOST:
            verdict = ('scanning', f'{top_ports} different ports probed '
                       f'in {int(self.WINDOW)}s')
        elif len(hosts) >= self.HOSTS_PER_SRC:
            verdict = ('scanning', f'{len(hosts)} different hosts '
                       f'contacted in {int(self.WINDOW)}s')
        elif len(q) >= self.NEW_FLOWS_PER_SRC:
            verdict = ('ddos', f'{len(q)} new connections '
                       f'in {int(self.WINDOW)}s')

        if verdict:
            key = (src, verdict[0])
            if now - self.last_alert.get(key, 0) < self.COOLDOWN:
                return None
            self.last_alert[key] = now
            return verdict
        return None
