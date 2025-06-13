import pandas as pd
import numpy as np
import time
import matplotlib.pyplot as plt
import seaborn as sns
import logging
import sys
from datetime import datetime
import traceback

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'ddos_detection_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

def safe_load_data(file_path):
    """Safely load the dataset with error handling"""
    try:
        logger.info(f"Attempting to load dataset from {file_path}")
        df = pd.read_csv(file_path, encoding="ISO-8859-1", encoding_errors='replace', 
                        on_bad_lines="skip", low_memory=False)
        df.columns = df.columns.str.strip()
        logger.info(f"Successfully loaded dataset with shape: {df.shape}")
        return df
    except Exception as e:
        logger.error(f"Error loading dataset: {str(e)}")
        logger.error(traceback.format_exc())
        raise

def preprocess_data(df):
    """Preprocess the data with error handling and logging"""
    try:
        logger.info("Starting data preprocessing")
        logger.info(f"Initial label distribution: \n{df['Label'].value_counts()}")
        
        # Replace infinite values with NaN
        logger.debug("Replacing infinite values with NaN")
        df = df.replace([np.inf, -np.inf], np.nan)
        
        # Drop non-numeric columns
        logger.debug("Dropping non-numeric columns")
        non_numeric_cols = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp']
        df = df.drop(non_numeric_cols, axis=1)
        
        # Log numeric and non-numeric columns
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        non_numeric_cols = df.select_dtypes(exclude=[np.number]).columns
        logger.debug(f"Found {len(numeric_cols)} numeric columns and {len(non_numeric_cols)} non-numeric columns")
        
        # Impute missing values in numeric columns
        logger.debug("Imputing missing values in numeric columns")
        numeric_imputer = SimpleImputer(strategy='mean')
        df[numeric_cols] = numeric_imputer.fit_transform(df[numeric_cols])
        
        # Drop rows with missing values in non-numeric columns
        logger.debug("Dropping rows with missing values in non-numeric columns")
        df = df.dropna()
        
        # Balance the dataset by sampling equal number of rows from each class
        logger.debug("Sampling balanced 20,000 rows from all classes")
        balanced_df = pd.DataFrame()
        for label in df['Label'].unique():
            class_df = df[df['Label'] == label]
            if len(class_df) >= 20000:
                sampled_df = class_df.sample(n=20000, random_state=42)
            else:
                sampled_df = class_df
            balanced_df = pd.concat([balanced_df, sampled_df])
        
        df = balanced_df
        
        # Final check for NaNs
        if df.isna().sum().sum() > 0:
            logger.warning(f"Remaining NaNs after preprocessing: {df.isna().sum().sum()}")
        else:
            logger.info("Preprocessing complete. Remaining NaNs: 0")
        
        logger.info(f"Final label distribution: \n{df['Label'].value_counts()}")
        return df
        
    except Exception as e:
        logger.error(f"Error in preprocessing: {str(e)}")
        logger.error(traceback.format_exc())
        raise

def evaluate_model(model, name, X_train, X_test, y_train, y_test):
    """Evaluate model with error handling and detailed logging"""
    try:
        logger.info(f"Starting evaluation of {name}")
        
        # Training
        start_train = time.time()
        logger.debug(f"Training {name}...")
        model.fit(X_train, y_train)
        train_time = time.time() - start_train
        logger.debug(f"{name} training completed in {train_time:.3f}s")
        
        # Prediction
        start_pred = time.time()
        logger.debug(f"Making predictions with {name}...")
        y_pred = model.predict(X_test)
        predict_time = time.time() - start_pred
        logger.debug(f"{name} predictions completed in {predict_time:.3f}s")
        
        # Calculate metrics
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        rec = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
        
        logger.info(f"\n{name} Results:")
        logger.info(f"Accuracy: {acc:.4f} | Precision: {prec:.4f} | Recall: {rec:.4f} | F1-Score: {f1:.4f}")
        logger.info(f"Train time: {train_time:.3f}s | Predict time: {predict_time:.4f}s")
        
        # Plot confusion matrix
        try:
            cm = confusion_matrix(y_test, y_pred)
            plt.figure(figsize=(10, 8))
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
            plt.title(f"{name} - Confusion Matrix")
            plt.xlabel("Predicted")
            plt.ylabel("Actual")
            plt.savefig(f'confusion_matrix_{name}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.png')
            plt.close()
            logger.debug(f"Confusion matrix plot saved for {name}")
        except Exception as e:
            logger.error(f"Error plotting confusion matrix for {name}: {str(e)}")
            
    except Exception as e:
        logger.error(f"Error evaluating {name}: {str(e)}")
        logger.error(traceback.format_exc())
        raise

def main():
    try:
        logger.info("Starting DDoS detection analysis")
        
        # Load and preprocess data
        df = safe_load_data("dos_ddos_dataset.csv")
        df = preprocess_data(df)
        
        # Encode labels
        logger.info("Encoding labels")
        le = LabelEncoder()
        df['Label'] = le.fit_transform(df['Label'])
        logger.info(f"Label distribution after encoding: \n{df['Label'].value_counts()}")
        
        # Features and target
        X = df.drop("Label", axis=1)
        # Ensure we only use numeric columns
        X = X.select_dtypes(include=[np.number])
        logger.info(f"Columns used for training (numeric only): {X.columns.tolist()}")
        logger.info(f"Number of features after numeric selection: {X.shape[1]}")
        y = df["Label"]
        
        # Standardize
        logger.info("Standardizing features")
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Select top 30 features
        logger.info("Selecting top 30 features")
        selector = SelectKBest(score_func=f_classif, k=30)
        X_selected = selector.fit_transform(X_scaled, y)
        selected_features = X.columns[selector.get_support()]
        logger.info(f"Selected Features: {selected_features.tolist()}")
        
        # Train-test split
        logger.info("Splitting data into train and test sets")
        X_train, X_test, y_train, y_test = train_test_split(
            X_selected, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Log class distribution in train and test sets
        logger.info(f"Training set class distribution: \n{pd.Series(y_train).value_counts()}")
        logger.info(f"Test set class distribution: \n{pd.Series(y_test).value_counts()}")
        
        # Models
        models = {
            "Logistic Regression": LogisticRegression(max_iter=1000, solver='lbfgs'),
            "SVM": SVC(),
            "KNN": KNeighborsClassifier(),
            "Random Forest": RandomForestClassifier(),
            "Decision Tree": DecisionTreeClassifier()
        }
        
        # Evaluate each model
        for name, model in models.items():
            evaluate_model(model, name, X_train, X_test, y_train, y_test)
            
        logger.info("Analysis completed successfully")
        
    except Exception as e:
        logger.error(f"Critical error in main execution: {str(e)}")
        logger.error(traceback.format_exc())
        raise

if __name__ == "__main__":
    main()
