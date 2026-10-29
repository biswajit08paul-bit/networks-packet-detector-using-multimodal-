"""
Module 1: Data Loader
Loads and preprocesses IoT intrusion detection datasets
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import os

class IoTDataLoader:
    """
    Loads and preprocesses IoT intrusion detection datasets
    """
    
    def __init__(self, dataset_path=None):
        self.dataset_path = dataset_path
        self.label_encoder = LabelEncoder()
        self.scaler = StandardScaler()
        self.feature_names = None
        
    def load_dataset(self, file_path):
        """
        Load dataset from CSV file
        """
        print(f"[INFO] Loading dataset from {file_path}")
        
        # Load dataset
        df = pd.read_csv(file_path)
        
        print(f"[INFO] Dataset shape: {df.shape}")
        print(f"[INFO] Columns: {df.columns.tolist()[:5]}...")
        
        return df
    
    def preprocess_data(self, df, target_column='label'):
        """
        Preprocess the dataset:
        - Handle missing values
        - Encode categorical features
        - Normalize numerical features
        - Separate features and labels
        """
        print("[INFO] Preprocessing data...")
        
        # Make a copy to avoid modifying original
        data = df.copy()
        
        # Handle missing values
        data = data.fillna(0)
        
        # Separate features and target
        if target_column in data.columns:
            y = data[target_column]
            X = data.drop(columns=[target_column])
        else:
            # If no target column, assume last column is target
            y = data.iloc[:, -1]
            X = data.iloc[:, :-1]
        
        # Convert target to binary (0: normal, 1: attack)
        if y.dtype == 'object':
            # If target is string, encode it
            y = self.label_encoder.fit_transform(y)
            # Consider anything not 'normal' as attack
            y = (y != 0).astype(int)
        else:
            # If numeric, assume 0 is normal, >0 is attack
            y = (y != 0).astype(int)
        
        # Store feature names
        self.feature_names = X.columns.tolist()
        for col in X.columns:
            if X[col].dtype == 'object':
                print(f"[INFO] Converting column '{col}' from object to numeric")
            # Try to convert to numeric, force errors to NaN
                X[col] = pd.to_numeric(X[col], errors='coerce')
    
    # Fill any NaN values that resulted from conversion
        X = X.fillna(0)
    
    # Select only numeric columns for scaling
        numeric_cols = X.select_dtypes(include=[np.number]).columns
    
        if len(numeric_cols) == 0:
            print("[ERROR] No numeric columns found in dataset!")
            print("Columns found:", X.columns.tolist())
            raise ValueError("Dataset must contain numeric features")
    
        print(f"[INFO] Using {len(numeric_cols)} numeric features")
        X_numeric = X[numeric_cols]
    
     # Scale numerical features
        X_scaled = self.scaler.fit_transform(X_numeric)
        X_scaled = pd.DataFrame(X_scaled, columns=numeric_cols)
    
    # Add back any remaining columns (should be none after conversion)
    # But just in case, handle categorical columns properly
        categorical_cols = X.select_dtypes(include=['object']).columns
        if len(categorical_cols) > 0:
            print(f"[INFO] One-hot encoding {len(categorical_cols)} categorical columns")
            X_encoded = pd.get_dummies(X[categorical_cols])
            X_final = pd.concat([X_scaled, X_encoded], axis=1)
        else:
            X_final = X_scaled
    
    # Final check: ensure all data is float32 for TensorFlow
        X_final = X_final.astype('float32')
    
        print(f"[INFO] Preprocessing complete. Features: {X_final.shape[1]}")
        print(f"[INFO] Data type: {X_final.dtypes.iloc[0]}")
        print(f"[INFO] Class distribution - Normal: {sum(y==0)}, Attack: {sum(y==1)}")
    
        
        # Save preprocessor for later use
        self.save_preprocessor('models/scaler.pkl')
        
        return X_final, y
    
    def split_data(self, X, y, test_size=0.2, val_size=0.1):
        """
        Split data into train, validation, and test sets
        """
        # First split: train+val vs test
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Second split: train vs val
        val_ratio = val_size / (1 - test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=val_ratio, random_state=42, stratify=y_temp
        )
        
        print(f"[INFO] Data split complete:")
        print(f"       Train: {X_train.shape[0]} samples")
        print(f"       Validation: {X_val.shape[0]} samples")
        print(f"       Test: {X_test.shape[0]} samples")
        
        return X_train, X_val, X_test, y_train, y_val, y_test
    
    def save_preprocessor(self, filepath='models/scaler.pkl'):
        """Save scaler and label encoder for later use"""
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        # Save scaler and feature names
        joblib.dump({
            'scaler': self.scaler,
            'feature_names': self.feature_names
        }, filepath)
        
        print(f"[INFO] Preprocessor saved to {filepath}")