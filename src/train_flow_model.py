"""
Train the flow-based IDS model on the real TON_IoT network dataset.

Usage (from anywhere):
    python src/train_flow_model.py

Output (models/):
    flow_model.pkl   -> {'model', 'classes', 'feature_names', 'metrics', ...}
    flow_model_report.json
"""

import json
import os
import sys
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score)
from sklearn.model_selection import train_test_split

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flow_features import (DATASETS_DIR, FEATURE_NAMES, MODELS_DIR,
                           NUMERIC_COLS, build_features)

DATASET = os.path.join(DATASETS_DIR, 'train_test_network.csv')
RAW_COLS = ['proto', 'conn_state'] + NUMERIC_COLS + ['type']


def load_data():
    if not os.path.exists(DATASET):
        raise FileNotFoundError(
            f"{DATASET} not found. Extract 'train_test_network.csv' from the "
            "dataset zip into the datasets/ folder.")
    print(f"[INFO] Loading {DATASET}")
    df = pd.read_csv(DATASET, usecols=RAW_COLS)
    print(f"[INFO] Raw rows: {len(df)}")

    # Identical rows in train and test would inflate the score, so remove them
    df = df.drop_duplicates().reset_index(drop=True)
    print(f"[INFO] Rows after removing duplicates: {len(df)}")
    print(df['type'].value_counts().to_string())
    return df


def main():
    os.makedirs(MODELS_DIR, exist_ok=True)
    df = load_data()
    X = build_features(df)
    y = df['type'].astype(str)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    print("\n[INFO] Training Random Forest (balanced classes)...")
    model = RandomForestClassifier(
        n_estimators=200, max_depth=25, min_samples_leaf=2,
        class_weight='balanced', n_jobs=-1, random_state=42)
    model.fit(X_train, y_train)

    pred = model.predict(X_test)
    acc = accuracy_score(y_test, pred)
    macro_f1 = f1_score(y_test, pred, average='macro')
    print(f"\n[RESULT] Accuracy: {acc:.4f}   Macro-F1: {macro_f1:.4f}")
    print(classification_report(y_test, pred, digits=4))

    # Binary view: normal vs attack
    bin_true = (y_test != 'normal').astype(int)
    bin_pred = (pd.Series(pred, index=y_test.index) != 'normal').astype(int)
    tn, fp, fn, tp = confusion_matrix(bin_true, bin_pred).ravel()
    print(f"[RESULT] Normal vs Attack -> TN={tn} FP={fp} FN={fn} TP={tp}")

    importances = sorted(zip(FEATURE_NAMES, model.feature_importances_),
                         key=lambda t: -t[1])[:10]
    print("\n[INFO] Top features:")
    for n, v in importances:
        print(f"   {n:15s} {v:.4f}")

    classes = list(model.classes_)
    bundle = {
        'model': model,
        'classes': classes,
        'feature_names': FEATURE_NAMES,
        'metrics': {'accuracy': acc, 'macro_f1': macro_f1,
                    'binary_confusion': [int(tn), int(fp), int(fn), int(tp)]},
        'trained_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'dataset': 'TON_IoT train_test_network.csv',
        'train_rows': int(len(X_train)),
    }
    joblib.dump(bundle, os.path.join(MODELS_DIR, 'flow_model.pkl'), compress=3)

    report = {
        'trained_at': bundle['trained_at'],
        'accuracy': acc,
        'macro_f1': macro_f1,
        'binary_confusion [TN,FP,FN,TP]': bundle['metrics']['binary_confusion'],
        'per_class': classification_report(y_test, pred, output_dict=True),
        'top_features': [(n, float(v)) for n, v in importances],
    }
    with open(os.path.join(MODELS_DIR, 'flow_model_report.json'), 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\n[OK] Saved {os.path.join(MODELS_DIR, 'flow_model.pkl')}")


if __name__ == '__main__':
    main()
