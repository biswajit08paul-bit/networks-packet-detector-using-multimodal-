"""
Module 2: Model Training
Trains multiple ML/DL models for intrusion detection
"""

from xml.parsers.expat import model

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import tensorflow as tf
from tensorflow.keras import layers, models,backend
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
import os
import json
from datetime import datetime

# Import data loader
from data_loader import IoTDataLoader

class IDSTrainer:
    """
    Trains and evaluates multiple models for intrusion detection
    """
    
    def __init__(self, X_train, y_train, X_val, y_val, X_test, y_test):
        self.X_train = X_train
        self.y_train = y_train
        self.X_val = X_val
        self.y_val = y_val
        self.X_test = X_test
        self.y_test = y_test
        
        self.models = {}
        self.results = {}
        self.n_features = X_train.shape[1]
        
    def train_random_forest(self):
        """
        Train Random Forest classifier
        """
        print("\n[INFO] Training Random Forest...")
        
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            n_jobs=-1
        )
        
        model.fit(self.X_train, self.y_train)
        
        # Predictions
        y_pred = model.predict(self.X_test)
        
        # Metrics
        metrics = self._calculate_metrics(self.y_test, y_pred)
        
        self.models['Random Forest'] = model
        self.results['Random Forest'] = metrics
        
        print(f"[INFO] Random Forest Accuracy: {metrics['accuracy']:.4f}")
        
        return model, metrics
    
    def train_gradient_boosting(self):
        """
        Train Gradient Boosting classifier
        """
        print("\n[INFO] Training Gradient Boosting...")
        
        model = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=5,
            random_state=42
        )
        
        model.fit(self.X_train, self.y_train)
        
        # Predictions
        y_pred = model.predict(self.X_test)
        
        # Metrics
        metrics = self._calculate_metrics(self.y_test, y_pred)
        
        self.models['Gradient Boosting'] = model
        self.results['Gradient Boosting'] = metrics
        
        print(f"[INFO] Gradient Boosting Accuracy: {metrics['accuracy']:.4f}")
        
        return model, metrics
    
    def train_cnn_model(self):
        """
        Train a 1D Convolutional Neural Network
        Works with small feature sizes
        """
        print("\n[INFO] Training CNN Model...")
    
    # Ensure data is float32
        X_train = self.X_train.astype('float32')
        X_val = self.X_val.astype('float32')
        X_test = self.X_test.astype('float32')
    
    # Check feature size
        print(f"[INFO] Number of features: {self.n_features}")
    
    # Reshape data for CNN (samples, features, 1)
        X_train_cnn = X_train.values.reshape(-1, self.n_features, 1)
        X_val_cnn = X_val.values.reshape(-1, self.n_features, 1)
        X_test_cnn = X_test.values.reshape(-1, self.n_features, 1)
    
    # Adjust kernel size based on feature count
        kernel_size = min(3, self.n_features)  # Use 3 or smaller if features < 3
    
    # Build CNN model - SIMPLIFIED for small features
        model = models.Sequential()
    
    # First Conv layer
        model.add(layers.Conv1D(32, kernel_size=kernel_size, activation='relu', 
                            padding='same', input_shape=(self.n_features, 1)))
        model.add(layers.BatchNormalization())
    
    # Only add pooling if features are large enough
        if self.n_features >= 4:
          model.add(layers.MaxPooling1D(pool_size=2, padding='same'))
    
    # Second Conv layer
        model.add(layers.Conv1D(64, kernel_size=kernel_size, activation='relu', 
                            padding='same'))
        model.add(layers.BatchNormalization())
    
    # Global pooling instead of flatten (works with any size)
        model.add(layers.GlobalAveragePooling1D())
    
    # Dense layers
        model.add(layers.Dense(32, activation='relu'))
        model.add(layers.Dropout(0.3))
        model.add(layers.Dense(1, activation='sigmoid'))
    
    # Print model summary
        print("\n[INFO] CNN Model Summary:")
        model.summary()
    
    # Compile model
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
    
    # Early stopping
        early_stop = tf.keras.callbacks.EarlyStopping(
            monitor='val_loss',
            patience=5,
            restore_best_weights=True
        )
    
    # Train model
        history = model.fit(
            X_train_cnn, self.y_train,
            validation_data=(X_val_cnn, self.y_val),
            epochs=20,  # Reduced epochs
            batch_size=32,
            callbacks=[early_stop],
            verbose=1
       )
    
    # Evaluate
        y_pred_prob = model.predict(X_test_cnn, verbose=0)
        y_pred = (y_pred_prob > 0.5).astype(int).flatten()
    
    # Metrics
        metrics = self._calculate_metrics(self.y_test, y_pred)
    
        self.models['CNN'] = model
        self.results['CNN'] = metrics
    
        print(f"[INFO] CNN Accuracy: {metrics['accuracy']:.4f}")
    
        return model, metrics, history
    
    def train_hybrid_cnn_lstm(self):
        """
        Train a hybrid CNN-LSTM model - works with small features
        """
        print("\n[INFO] Training Hybrid CNN-LSTM Model...")
        
        # Ensure data is float32
        X_train = self.X_train.astype('float32')
        X_val = self.X_val.astype('float32')
        X_test = self.X_test.astype('float32')
    
        print(f"[INFO] Number of features: {self.n_features}")
    
    # Reshape data (samples, features, 1)
        X_train_reshaped = X_train.values.reshape(-1, self.n_features, 1)
        X_val_reshaped = X_val.values.reshape(-1, self.n_features, 1)
        X_test_reshaped = X_test.values.reshape(-1, self.n_features, 1)
    
        kernel_size = min(3, self.n_features)
    
    # Build hybrid model - SIMPLIFIED
        model = models.Sequential([
        # CNN layers with padding='same' to maintain dimensions
            layers.Conv1D(32, kernel_size=kernel_size, activation='relu', 
                     padding='same', input_shape=(self.n_features, 1)),
            layers.BatchNormalization(),
        
        # LSTM layer
            layers.LSTM(32, return_sequences=False),
            layers.Dropout(0.3),
        
        # Output layer
            layers.Dense(16, activation='relu'),
            layers.Dense(1, activation='sigmoid')
       ])
    
    # Print model summary
        print("\n[INFO] Hybrid Model Summary:")
        model.summary()
    
    # Compile
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
       )
    
    # Early stopping
        early_stop = tf.keras.callbacks.EarlyStopping(
            monitor='val_loss',
            patience=5,
            restore_best_weights=True
        )
    
    # Train
        history = model.fit(
            X_train_reshaped, self.y_train,
            validation_data=(X_val_reshaped, self.y_val),
            epochs=20,
            batch_size=32,
            callbacks=[early_stop],
            verbose=1
        )
    
    # Evaluate
        y_pred_prob = model.predict(X_test_reshaped, verbose=0)
        y_pred = (y_pred_prob > 0.5).astype(int).flatten()
    
    # Metrics
        metrics = self._calculate_metrics(self.y_test, y_pred)
    
        self.models['CNN-LSTM Hybrid'] = model
        self.results['CNN-LSTM Hybrid'] = metrics
    
        print(f"[INFO] CNN-LSTM Hybrid Accuracy: {metrics['accuracy']:.4f}")
    
        return model, metrics, history
    
    def _calculate_metrics(self, y_true, y_pred):
        """Calculate classification metrics"""
        return {
            'accuracy': accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred, zero_division=0),
            'recall': recall_score(y_true, y_pred, zero_division=0),
            'f1_score': f1_score(y_true, y_pred, zero_division=0),
            'confusion_matrix': confusion_matrix(y_true, y_pred).tolist()
        }
    
    def compare_models(self):
        """
        Compare all trained models and select the best one
        """
        if not self.results:
            print("[ERROR] No models trained yet!")
            return None
        
        # Create comparison dataframe
        comparison = pd.DataFrame(self.results).T
        comparison = comparison.drop(columns=['confusion_matrix'], errors='ignore')
        
        print("\n" + "="*60)
        print("MODEL COMPARISON RESULTS")
        print("="*60)
        print(comparison.round(4))
        
        # Find best model by F1-score
        best_model_name = comparison['f1_score'].idxmax()
        best_f1 = comparison.loc[best_model_name, 'f1_score']
        
        print(f"\n[INFO] Best Model: {best_model_name} (F1-Score: {best_f1:.4f})")
        
        # Plot comparison
        self._plot_comparison(comparison)
        
        return best_model_name
    
    def _plot_comparison(self, comparison):
        """Plot model comparison"""
        metrics = ['accuracy', 'precision', 'recall', 'f1_score']
        
        fig, axes = plt.subplots(2, 2, figsize=(12, 10))
        axes = axes.flatten()
        
        for i, metric in enumerate(metrics):
            comparison[metric].plot(kind='bar', ax=axes[i], color='skyblue')
            axes[i].set_title(f'{metric.capitalize()} Comparison')
            axes[i].set_ylabel(metric.capitalize())
            axes[i].set_xlabel('Model')
            axes[i].tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig('models/model_comparison.png')
        print("[INFO] Comparison plot saved to 'models/model_comparison.png'")
    
    def save_best_model(self, model_name):
        """
        Save the best model and its metrics
        """
        if model_name not in self.models:
            print(f"[ERROR] Model {model_name} not found!")
            return
        
        model = self.models[model_name]
        metrics = self.results[model_name]
        
        # Create directory
        os.makedirs('models', exist_ok=True)
        
        # Save model based on type
        if model_name in ['Random Forest', 'Gradient Boosting']:
            joblib.dump(model, f'models/best_model_{model_name}.pkl')
        else:  # Deep learning models
            model.save(f'models/best_model_{model_name}.h5')
        
        # Save metrics
        with open(f'models/best_model_{model_name}_metrics.json', 'w') as f:
            json.dump(metrics, f, indent=4)
        
        # Save model info
        info = {
            'model_name': model_name,
            'metrics': metrics,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'n_features': self.n_features
        }
        
        with open('models/best_model_info.json', 'w') as f:
            json.dump(info, f, indent=4)
        
        print(f"[INFO] Best model ({model_name}) saved successfully")


def main():
    """Main training function"""
    print("\n" + "="*60)
    print("IoT INTRUSION DETECTION - MODEL TRAINING")
    print("="*60)
    
    # Check if dataset exists
    dataset_files = []
    if os.path.exists('datasets'):
        dataset_files = [f for f in os.listdir('datasets') if f.endswith('.csv')]
    
    if not dataset_files:
        print("[ERROR] No CSV dataset found in datasets/ folder")
        print("Please download a dataset and place it in datasets/ folder")
        return
    
    dataset_path = os.path.join('datasets', dataset_files[0])
    print(f"[INFO] Using dataset: {dataset_path}")
    
    # Load and preprocess data
    loader = IoTDataLoader()
    df = loader.load_dataset(dataset_path)
    X, y = loader.preprocess_data(df)
    X_train, X_val, X_test, y_train, y_val, y_test = loader.split_data(X, y)
    
    # Train models
    trainer = IDSTrainer(X_train, y_train, X_val, y_val, X_test, y_test)
    
    trainer.train_random_forest()
    trainer.train_gradient_boosting()
    trainer.train_cnn_model()
    trainer.train_hybrid_cnn_lstm()
    
    # Try XGBoost if available
    try:
        trainer.train_xgboost()
    except:
        print("[INFO] XGBoost not available, skipping...")
    
    # Compare and save best
    best_model = trainer.compare_models()
    trainer.save_best_model(best_model)
    
    print("\n[INFO] Training completed successfully!")

if __name__ == "__main__":
    main()