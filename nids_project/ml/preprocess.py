"""
Data preprocessing module for Network Intrusion Detection System
Handles NSL-KDD dataset preprocessing, feature engineering, and normalization
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.decomposition import PCA
from sklearn.model_selection import train_test_split
import joblib
import os
import logging
from typing import Tuple, Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DataPreprocessor:
    """Comprehensive data preprocessor for NSL-KDD dataset"""
    
    def __init__(self, config=None):
        self.config = config
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.pca = None
        self.feature_columns = None
        self.attack_mapping = {
            'normal': 0,
            # DoS attacks
            'back': 1, 'land': 1, 'neptune': 1, 'pod': 1, 'smurf': 1, 'teardrop': 1,
            'mailbomb': 1, 'apache2': 1, 'processtable': 1, 'udpstorm': 1,
            # Probe attacks
            'satan': 2, 'ipsweep': 2, 'nmap': 2, 'portsweep': 2, 'mscan': 2, 'saint': 2,
            # R2L attacks
            'guess_passwd': 3, 'ftp_write': 3, 'imap': 3, 'phf': 3, 'multihop': 3,
            'warezmaster': 3, 'warezclient': 3, 'spy': 3, 'xlock': 3, 'xsnoop': 3,
            'snmpguess': 3, 'snmpgetattack': 3, 'httptunnel': 3, 'sendmail': 3, 'named': 3,
            # U2R attacks
            'buffer_overflow': 4, 'loadmodule': 4, 'perl': 4, 'rootkit': 4,
            'ps': 4, 'sqlattack': 4, 'xterm': 4
        }
        
    def load_nsl_kdd_data(self, train_path: str, test_path: str = None) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Load NSL-KDD dataset from CSV files
        
        Args:
            train_path: Path to training dataset
            test_path: Path to test dataset (optional)
            
        Returns:
            Tuple of (train_df, test_df)
        """
        # Column names for NSL-KDD dataset
        column_names = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
            'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
            'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
            'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
            'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
            'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
            'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
            'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
            'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
            'class', 'difficulty'
        ]
        
        try:
            # Load training data
            logger.info(f"Loading training data from {train_path}")
            train_df = pd.read_csv(train_path, names=column_names, header=None)
            
            # Load test data if provided
            test_df = None
            if test_path and os.path.exists(test_path):
                logger.info(f"Loading test data from {test_path}")
                test_df = pd.read_csv(test_path, names=column_names, header=None)
            
            # Remove difficulty column if it exists
            if 'difficulty' in train_df.columns:
                train_df = train_df.drop('difficulty', axis=1)
            if test_df is not None and 'difficulty' in test_df.columns:
                test_df = test_df.drop('difficulty', axis=1)
                
            logger.info(f"Training data shape: {train_df.shape}")
            if test_df is not None:
                logger.info(f"Test data shape: {test_df.shape}")
                
            return train_df, test_df
            
        except Exception as e:
            logger.error(f"Error loading data: {str(e)}")
            raise
    
    def create_sample_data(self, n_samples: int = 1000) -> pd.DataFrame:
        """
        Create sample synthetic data for testing when real dataset is not available
        
        Args:
            n_samples: Number of samples to generate
            
        Returns:
            Synthetic dataframe
        """
        logger.info(f"Creating synthetic sample data with {n_samples} samples")
        
        np.random.seed(42)
        
        # Generate synthetic features
        data = {
            'duration': np.random.exponential(10, n_samples),
            'protocol_type': np.random.choice(['tcp', 'udp', 'icmp'], n_samples),
            'service': np.random.choice(['http', 'ftp', 'smtp', 'ssh', 'telnet'], n_samples),
            'flag': np.random.choice(['SF', 'S0', 'REJ', 'RSTR'], n_samples),
            'src_bytes': np.random.exponential(1000, n_samples),
            'dst_bytes': np.random.exponential(1000, n_samples),
            'land': np.random.choice([0, 1], n_samples, p=[0.99, 0.01]),
            'wrong_fragment': np.random.poisson(0.1, n_samples),
            'urgent': np.random.poisson(0.05, n_samples),
            'hot': np.random.poisson(0.5, n_samples),
            'num_failed_logins': np.random.poisson(0.1, n_samples),
            'logged_in': np.random.choice([0, 1], n_samples, p=[0.3, 0.7]),
            'num_compromised': np.random.poisson(0.01, n_samples),
            'root_shell': np.random.choice([0, 1], n_samples, p=[0.95, 0.05]),
            'su_attempted': np.random.choice([0, 1], n_samples, p=[0.98, 0.02]),
            'num_root': np.random.poisson(0.1, n_samples),
            'num_file_creations': np.random.poisson(0.2, n_samples),
            'num_shells': np.random.poisson(0.05, n_samples),
            'num_access_files': np.random.poisson(0.1, n_samples),
            'num_outbound_cmds': np.random.poisson(0.01, n_samples),
            'is_host_login': np.random.choice([0, 1], n_samples, p=[0.95, 0.05]),
            'is_guest_login': np.random.choice([0, 1], n_samples, p=[0.98, 0.02]),
            'count': np.random.poisson(50, n_samples),
            'srv_count': np.random.poisson(20, n_samples),
            'serror_rate': np.random.uniform(0, 1, n_samples),
            'srv_serror_rate': np.random.uniform(0, 1, n_samples),
            'rerror_rate': np.random.uniform(0, 1, n_samples),
            'srv_rerror_rate': np.random.uniform(0, 1, n_samples),
            'same_srv_rate': np.random.uniform(0, 1, n_samples),
            'diff_srv_rate': np.random.uniform(0, 1, n_samples),
            'srv_diff_host_rate': np.random.uniform(0, 1, n_samples),
            'dst_host_count': np.random.poisson(100, n_samples),
            'dst_host_srv_count': np.random.poisson(50, n_samples),
            'dst_host_same_srv_rate': np.random.uniform(0, 1, n_samples),
            'dst_host_diff_srv_rate': np.random.uniform(0, 1, n_samples),
            'dst_host_same_src_port_rate': np.random.uniform(0, 1, n_samples),
            'dst_host_srv_diff_host_rate': np.random.uniform(0, 1, n_samples),
            'dst_host_serror_rate': np.random.uniform(0, 1, n_samples),
            'dst_host_srv_serror_rate': np.random.uniform(0, 1, n_samples),
            'dst_host_rerror_rate': np.random.uniform(0, 1, n_samples),
            'dst_host_srv_rerror_rate': np.random.uniform(0, 1, n_samples)
        }
        
        # Generate labels (70% normal, 30% attacks)
        labels = np.random.choice(
            ['normal', 'neptune', 'satan', 'guess_passwd', 'buffer_overflow'],
            n_samples, 
            p=[0.7, 0.1, 0.1, 0.05, 0.05]
        )
        data['class'] = labels
        
        return pd.DataFrame(data)
    
    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean and preprocess the dataset
        
        Args:
            df: Input dataframe
            
        Returns:
            Cleaned dataframe
        """
        logger.info("Cleaning data...")
        
        # Create a copy to avoid modifying original
        df_clean = df.copy()
        
        # Handle missing values
        df_clean = df_clean.fillna(0)
        
        # Remove duplicates
        initial_shape = df_clean.shape[0]
        df_clean = df_clean.drop_duplicates()
        logger.info(f"Removed {initial_shape - df_clean.shape[0]} duplicate rows")
        
        # Handle infinite values
        df_clean = df_clean.replace([np.inf, -np.inf], np.nan).fillna(0)
        
        # Clip extreme values for numerical columns
        numerical_cols = df_clean.select_dtypes(include=[np.number]).columns
        for col in numerical_cols:
            if col != 'class':
                # Clip to 99.9th percentile to handle outliers
                upper_limit = df_clean[col].quantile(0.999)
                df_clean[col] = np.clip(df_clean[col], 0, upper_limit)
        
        return df_clean
    
    def encode_categorical_features(self, df: pd.DataFrame, fit: bool = True) -> pd.DataFrame:
        """
        Encode categorical features using label encoding
        
        Args:
            df: Input dataframe
            fit: Whether to fit encoders (True for training, False for prediction)
            
        Returns:
            Dataframe with encoded categorical features
        """
        logger.info("Encoding categorical features...")
        
        df_encoded = df.copy()
        categorical_cols = ['protocol_type', 'service', 'flag']
        
        for col in categorical_cols:
            if col in df_encoded.columns:
                if fit:
                    # Fit new encoder
                    self.label_encoders[col] = LabelEncoder()
                    df_encoded[col] = self.label_encoders[col].fit_transform(df_encoded[col].astype(str))
                else:
                    # Use existing encoder
                    if col in self.label_encoders:
                        # Handle unseen categories
                        unique_values = set(df_encoded[col].astype(str).unique())
                        known_values = set(self.label_encoders[col].classes_)
                        
                        # Map unknown categories to a default value
                        df_encoded[col] = df_encoded[col].astype(str)
                        for val in unique_values - known_values:
                            df_encoded.loc[df_encoded[col] == val, col] = 'unknown'
                        
                        df_encoded[col] = self.label_encoders[col].transform(df_encoded[col])
                    else:
                        logger.warning(f"No encoder found for column {col}")
                        df_encoded[col] = 0
        
        return df_encoded
    
    def encode_labels(self, labels: pd.Series) -> np.ndarray:
        """
        Encode attack labels to numerical format
        
        Args:
            labels: Series of attack labels
            
        Returns:
            Numerical encoded labels
        """
        encoded_labels = labels.map(self.attack_mapping)
        
        # Handle unknown attack types
        encoded_labels = encoded_labels.fillna(0)  # Unknown -> normal
        
        return encoded_labels.values
    
    def scale_features(self, X: pd.DataFrame, fit: bool = True) -> np.ndarray:
        """
        Scale numerical features using StandardScaler
        
        Args:
            X: Feature matrix
            fit: Whether to fit scaler (True for training, False for prediction)
            
        Returns:
            Scaled feature matrix
        """
        logger.info("Scaling features...")
        
        if fit:
            X_scaled = self.scaler.fit_transform(X)
        else:
            X_scaled = self.scaler.transform(X)
        
        return X_scaled
    
    def apply_pca(self, X: np.ndarray, n_components: int = 0.95, fit: bool = True) -> np.ndarray:
        """
        Apply PCA for dimensionality reduction
        
        Args:
            X: Feature matrix
            n_components: Number of components or variance ratio to retain
            fit: Whether to fit PCA (True for training, False for prediction)
            
        Returns:
            Transformed feature matrix
        """
        logger.info(f"Applying PCA with {n_components} components...")
        
        if fit:
            self.pca = PCA(n_components=n_components, random_state=42)
            X_pca = self.pca.fit_transform(X)
            logger.info(f"PCA reduced features from {X.shape[1]} to {X_pca.shape[1]}")
            logger.info(f"Explained variance ratio: {self.pca.explained_variance_ratio_.sum():.4f}")
        else:
            if self.pca is None:
                logger.warning("PCA not fitted yet. Returning original features.")
                return X
            X_pca = self.pca.transform(X)
        
        return X_pca
    
    def preprocess_data(self, df: pd.DataFrame, apply_pca: bool = True, 
                       test_size: float = 0.2, fit: bool = True) -> Dict[str, Any]:
        """
        Complete data preprocessing pipeline
        
        Args:
            df: Input dataframe
            apply_pca: Whether to apply PCA
            test_size: Test set size for train/validation split
            fit: Whether to fit preprocessors
            
        Returns:
            Dictionary containing processed data and metadata
        """
        logger.info("Starting complete data preprocessing...")
        
        # Clean data
        df_clean = self.clean_data(df)
        
        # Separate features and labels
        if 'class' in df_clean.columns:
            X = df_clean.drop('class', axis=1)
            y = df_clean['class']
        else:
            X = df_clean
            y = None
        
        # Store feature columns
        if fit:
            self.feature_columns = X.columns.tolist()
        
        # Encode categorical features
        X_encoded = self.encode_categorical_features(X, fit=fit)
        
        # Scale features
        X_scaled = self.scale_features(X_encoded, fit=fit)
        
        # Apply PCA if requested
        if apply_pca:
            X_final = self.apply_pca(X_scaled, fit=fit)
        else:
            X_final = X_scaled
        
        # Encode labels if available
        y_encoded = None
        if y is not None:
            y_encoded = self.encode_labels(y)
        
        # Split data for training
        result = {
            'X': X_final,
            'y': y_encoded,
            'feature_names': self.feature_columns,
            'n_features': X_final.shape[1],
            'n_samples': X_final.shape[0]
        }
        
        if fit and y_encoded is not None and test_size > 0:
            X_train, X_test, y_train, y_test = train_test_split(
                X_final, y_encoded, test_size=test_size, 
                random_state=42, stratify=y_encoded
            )
            
            result.update({
                'X_train': X_train,
                'X_test': X_test,
                'y_train': y_train,
                'y_test': y_test
            })
        
        logger.info(f"Preprocessing complete. Final shape: {X_final.shape}")
        return result
    
    def save_preprocessors(self, model_dir: str):
        """
        Save fitted preprocessors to files
        
        Args:
            model_dir: Directory to save preprocessors
        """
        os.makedirs(model_dir, exist_ok=True)
        
        # Save scaler
        scaler_path = os.path.join(model_dir, 'scaler.joblib')
        joblib.dump(self.scaler, scaler_path)
        logger.info(f"Scaler saved to {scaler_path}")
        
        # Save label encoders
        encoders_path = os.path.join(model_dir, 'label_encoders.joblib')
        joblib.dump(self.label_encoders, encoders_path)
        logger.info(f"Label encoders saved to {encoders_path}")
        
        # Save PCA if fitted
        if self.pca is not None:
            pca_path = os.path.join(model_dir, 'pca.joblib')
            joblib.dump(self.pca, pca_path)
            logger.info(f"PCA saved to {pca_path}")
        
        # Save feature columns
        features_path = os.path.join(model_dir, 'feature_columns.joblib')
        joblib.dump(self.feature_columns, features_path)
        logger.info(f"Feature columns saved to {features_path}")
    
    def load_preprocessors(self, model_dir: str):
        """
        Load fitted preprocessors from files
        
        Args:
            model_dir: Directory containing preprocessors
        """
        try:
            # Load scaler
            scaler_path = os.path.join(model_dir, 'scaler.joblib')
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
                logger.info(f"Scaler loaded from {scaler_path}")
            
            # Load label encoders
            encoders_path = os.path.join(model_dir, 'label_encoders.joblib')
            if os.path.exists(encoders_path):
                self.label_encoders = joblib.load(encoders_path)
                logger.info(f"Label encoders loaded from {encoders_path}")
            
            # Load PCA
            pca_path = os.path.join(model_dir, 'pca.joblib')
            if os.path.exists(pca_path):
                self.pca = joblib.load(pca_path)
                logger.info(f"PCA loaded from {pca_path}")
            
            # Load feature columns
            features_path = os.path.join(model_dir, 'feature_columns.joblib')
            if os.path.exists(features_path):
                self.feature_columns = joblib.load(features_path)
                logger.info(f"Feature columns loaded from {features_path}")
                
        except Exception as e:
            logger.error(f"Error loading preprocessors: {str(e)}")
            raise

def main():
    """Main function for testing preprocessing"""
    # Initialize preprocessor
    preprocessor = DataPreprocessor()
    
    # Create sample data for testing
    df = preprocessor.create_sample_data(1000)
    
    # Preprocess data
    result = preprocessor.preprocess_data(df, apply_pca=True)
    
    print(f"Original features: {len(preprocessor.feature_columns)}")
    print(f"Final features after PCA: {result['n_features']}")
    print(f"Training set shape: {result['X_train'].shape}")
    print(f"Test set shape: {result['X_test'].shape}")
    
    # Save preprocessors
    preprocessor.save_preprocessors('models')
    print("Preprocessors saved successfully!")

if __name__ == "__main__":
    main()