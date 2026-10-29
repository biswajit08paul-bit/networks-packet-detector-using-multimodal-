import pandas as pd
import os

# Find dataset file
dataset_files = [f for f in os.listdir('datasets') if f.endswith('.csv')]
if not dataset_files:
    print("No CSV files found!")
    exit()

print(f"Checking: {dataset_files[0]}")
df = pd.read_csv(f'datasets/{dataset_files[0]}')

print(f"Shape: {df.shape}")
print(f"Columns: {df.columns.tolist()}")
print(f"Data types:\n{df.dtypes.value_counts()}")
print(f"First few values:\n{df.head()}")