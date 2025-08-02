"""
Prediction module for Network Intrusion Detection System
Handles real-time prediction and confidence scoring
"""

import numpy as np
import pandas as pd
import joblib
import os
import logging
from typing import Dict, List, Tuple, Any, Union
from ml.preprocess import DataPreprocessor
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IntrusionPredictor:
    """Real-time intrusion detection predictor"""
    
    def __init__(self, model_dir: str = 'models', config=None):
        self.model_dir = model_dir
        self.config = config
        self.preprocessor = DataPreprocessor(config)
        
        # Models and components
        self.primary_model = None
        self.anomaly_detector = None
        self.models = {}
        
        # Prediction cache
        self.prediction_cache = {}
        self.cache_max_size = 1000
        
        # Attack type mappings
        self.attack_names = {
            0: 'Normal',
            1: 'DoS Attack',
            2: 'Probe Attack',
            3: 'R2L Attack',
            4: 'U2R Attack'
        }
        
        # Confidence thresholds
        self.confidence_thresholds = {
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4
        }
        
        # Load models and preprocessors
        self.load_models()
    
    def load_models(self):
        """Load trained models and preprocessors"""
        logger.info("Loading trained models and preprocessors...")
        
        try:
            # Load preprocessors
            self.preprocessor.load_preprocessors(self.model_dir)
            
            # Load primary model (Random Forest by default)
            primary_model_path = os.path.join(self.model_dir, 'random_forest_model.joblib')
            if os.path.exists(primary_model_path):
                self.primary_model = joblib.load(primary_model_path)
                logger.info("Primary model (Random Forest) loaded successfully")
            else:
                # Try to load any available model
                model_files = [f for f in os.listdir(self.model_dir) if f.endswith('_model.joblib')]
                if model_files:
                    primary_model_path = os.path.join(self.model_dir, model_files[0])
                    self.primary_model = joblib.load(primary_model_path)
                    logger.info(f"Loaded {model_files[0]} as primary model")
                else:
                    logger.warning("No trained models found")
            
            # Load all available models
            model_files = [f for f in os.listdir(self.model_dir) if f.endswith('_model.joblib')]
            for model_file in model_files:
                model_name = model_file.replace('_model.joblib', '')
                model_path = os.path.join(self.model_dir, model_file)
                self.models[model_name] = joblib.load(model_path)
                logger.info(f"Loaded {model_name} model")
            
            # Load anomaly detector if available
            anomaly_path = os.path.join(self.model_dir, 'anomaly_detector.joblib')
            if os.path.exists(anomaly_path):
                self.anomaly_detector = joblib.load(anomaly_path)
                logger.info("Anomaly detector loaded successfully")
            
        except Exception as e:
            logger.error(f"Error loading models: {str(e)}")
            raise
    
    def preprocess_packet_features(self, packet_data: Dict[str, Any]) -> np.ndarray:
        """
        Preprocess packet features for prediction
        
        Args:
            packet_data: Dictionary containing packet features
            
        Returns:
            Preprocessed feature array
        """
        try:
            # Convert packet data to DataFrame format expected by preprocessor
            if isinstance(packet_data, dict):
                # Create DataFrame with single row
                df = pd.DataFrame([packet_data])
            elif isinstance(packet_data, pd.DataFrame):
                df = packet_data.copy()
            else:
                raise ValueError("Packet data must be dictionary or DataFrame")
            
            # Ensure all required columns are present
            required_columns = self.preprocessor.feature_columns
            for col in required_columns:
                if col not in df.columns:
                    df[col] = 0  # Default value for missing features
            
            # Select only required columns in correct order
            df = df[required_columns]
            
            # Apply preprocessing pipeline
            result = self.preprocessor.preprocess_data(df, apply_pca=True, fit=False)
            
            return result['X']
            
        except Exception as e:
            logger.error(f"Error preprocessing packet features: {str(e)}")
            raise
    
    def predict_single_packet(self, packet_data: Dict[str, Any], 
                             use_ensemble: bool = False) -> Dict[str, Any]:
        """
        Predict intrusion for a single packet
        
        Args:
            packet_data: Dictionary containing packet features
            use_ensemble: Whether to use ensemble of all models
            
        Returns:
            Prediction result dictionary
        """
        start_time = time.time()
        
        try:
            # Check cache first
            cache_key = str(sorted(packet_data.items()))
            if cache_key in self.prediction_cache:
                logger.debug("Returning cached prediction")
                return self.prediction_cache[cache_key]
            
            # Preprocess features
            X = self.preprocess_packet_features(packet_data)
            
            if use_ensemble and len(self.models) > 1:
                # Ensemble prediction
                predictions = []
                confidences = []
                
                for model_name, model in self.models.items():
                    if hasattr(model, 'predict_proba'):
                        pred_proba = model.predict_proba(X)[0]
                        pred_class = np.argmax(pred_proba)
                        confidence = np.max(pred_proba)
                    else:
                        pred_class = model.predict(X)[0]
                        confidence = 0.5  # Default confidence for models without probability
                    
                    predictions.append(pred_class)
                    confidences.append(confidence)
                
                # Majority voting for final prediction
                unique_preds, counts = np.unique(predictions, return_counts=True)
                final_prediction = unique_preds[np.argmax(counts)]
                
                # Average confidence for final prediction
                matching_confidences = [conf for pred, conf in zip(predictions, confidences) 
                                      if pred == final_prediction]
                final_confidence = np.mean(matching_confidences)
                
                ensemble_info = {
                    'individual_predictions': predictions,
                    'individual_confidences': confidences,
                    'model_names': list(self.models.keys())
                }
            
            else:
                # Single model prediction
                if self.primary_model is None:
                    raise ValueError("No trained model available for prediction")
                
                if hasattr(self.primary_model, 'predict_proba'):
                    pred_proba = self.primary_model.predict_proba(X)[0]
                    final_prediction = np.argmax(pred_proba)
                    final_confidence = np.max(pred_proba)
                    probabilities = pred_proba.tolist()
                else:
                    final_prediction = self.primary_model.predict(X)[0]
                    final_confidence = 0.5
                    probabilities = None
                
                ensemble_info = None
            
            # Anomaly detection (if available)
            anomaly_score = None
            is_anomaly = False
            if self.anomaly_detector is not None:
                anomaly_score = self.anomaly_detector.decision_function(X)[0]
                is_anomaly = self.anomaly_detector.predict(X)[0] == -1
            
            # Determine confidence level
            confidence_level = self._get_confidence_level(final_confidence)
            
            # Create result dictionary
            result = {
                'prediction': int(final_prediction),
                'attack_type': self.attack_names[final_prediction],
                'confidence': float(final_confidence),
                'confidence_level': confidence_level,
                'is_attack': final_prediction > 0,
                'is_anomaly': is_anomaly,
                'anomaly_score': float(anomaly_score) if anomaly_score is not None else None,
                'prediction_time': time.time() - start_time,
                'probabilities': probabilities,
                'ensemble_info': ensemble_info,
                'packet_features': packet_data,
                'alert_level': self._determine_alert_level(final_prediction, final_confidence)
            }
            
            # Cache result
            if len(self.prediction_cache) >= self.cache_max_size:
                # Remove oldest entry
                oldest_key = next(iter(self.prediction_cache))
                del self.prediction_cache[oldest_key]
            
            self.prediction_cache[cache_key] = result
            
            return result
            
        except Exception as e:
            logger.error(f"Error in prediction: {str(e)}")
            return {
                'prediction': 0,
                'attack_type': 'Error',
                'confidence': 0.0,
                'confidence_level': 'low',
                'is_attack': False,
                'error': str(e)
            }
    
    def predict_batch(self, packet_batch: List[Dict[str, Any]], 
                     use_ensemble: bool = False) -> List[Dict[str, Any]]:
        """
        Predict intrusions for a batch of packets
        
        Args:
            packet_batch: List of packet feature dictionaries
            use_ensemble: Whether to use ensemble of all models
            
        Returns:
            List of prediction results
        """
        logger.info(f"Processing batch of {len(packet_batch)} packets")
        
        results = []
        start_time = time.time()
        
        try:
            # Convert batch to DataFrame for efficient processing
            df_batch = pd.DataFrame(packet_batch)
            
            # Preprocess entire batch
            X_batch = self.preprocess_packet_features(df_batch)
            
            if use_ensemble and len(self.models) > 1:
                # Ensemble prediction for batch
                all_predictions = []
                all_confidences = []
                
                for model_name, model in self.models.items():
                    if hasattr(model, 'predict_proba'):
                        pred_proba = model.predict_proba(X_batch)
                        pred_classes = np.argmax(pred_proba, axis=1)
                        confidences = np.max(pred_proba, axis=1)
                    else:
                        pred_classes = model.predict(X_batch)
                        confidences = np.full(len(pred_classes), 0.5)
                    
                    all_predictions.append(pred_classes)
                    all_confidences.append(confidences)
                
                # Combine predictions using majority voting
                all_predictions = np.array(all_predictions).T  # Shape: (n_samples, n_models)
                final_predictions = []
                final_confidences = []
                
                for i in range(len(packet_batch)):
                    sample_preds = all_predictions[i]
                    unique_preds, counts = np.unique(sample_preds, return_counts=True)
                    final_pred = unique_preds[np.argmax(counts)]
                    
                    # Average confidence for final prediction
                    matching_confidences = [all_confidences[j][i] for j in range(len(self.models)) 
                                          if sample_preds[j] == final_pred]
                    final_conf = np.mean(matching_confidences)
                    
                    final_predictions.append(final_pred)
                    final_confidences.append(final_conf)
            
            else:
                # Single model prediction for batch
                if self.primary_model is None:
                    raise ValueError("No trained model available for prediction")
                
                if hasattr(self.primary_model, 'predict_proba'):
                    pred_proba = self.primary_model.predict_proba(X_batch)
                    final_predictions = np.argmax(pred_proba, axis=1)
                    final_confidences = np.max(pred_proba, axis=1)
                else:
                    final_predictions = self.primary_model.predict(X_batch)
                    final_confidences = np.full(len(final_predictions), 0.5)
            
            # Anomaly detection for batch
            anomaly_scores = None
            anomaly_predictions = None
            if self.anomaly_detector is not None:
                anomaly_scores = self.anomaly_detector.decision_function(X_batch)
                anomaly_predictions = self.anomaly_detector.predict(X_batch)
            
            # Create results for each packet
            for i, packet_data in enumerate(packet_batch):
                result = {
                    'prediction': int(final_predictions[i]),
                    'attack_type': self.attack_names[final_predictions[i]],
                    'confidence': float(final_confidences[i]),
                    'confidence_level': self._get_confidence_level(final_confidences[i]),
                    'is_attack': final_predictions[i] > 0,
                    'is_anomaly': anomaly_predictions[i] == -1 if anomaly_predictions is not None else False,
                    'anomaly_score': float(anomaly_scores[i]) if anomaly_scores is not None else None,
                    'packet_features': packet_data,
                    'alert_level': self._determine_alert_level(final_predictions[i], final_confidences[i])
                }
                results.append(result)
            
            total_time = time.time() - start_time
            logger.info(f"Batch prediction completed in {total_time:.3f} seconds")
            
        except Exception as e:
            logger.error(f"Error in batch prediction: {str(e)}")
            # Return error results for all packets
            for packet_data in packet_batch:
                results.append({
                    'prediction': 0,
                    'attack_type': 'Error',
                    'confidence': 0.0,
                    'confidence_level': 'low',
                    'is_attack': False,
                    'error': str(e)
                })
        
        return results
    
    def _get_confidence_level(self, confidence: float) -> str:
        """Determine confidence level based on confidence score"""
        if confidence >= self.confidence_thresholds['high']:
            return 'high'
        elif confidence >= self.confidence_thresholds['medium']:
            return 'medium'
        elif confidence >= self.confidence_thresholds['low']:
            return 'low'
        else:
            return 'very_low'
    
    def _determine_alert_level(self, prediction: int, confidence: float) -> str:
        """Determine alert level based on prediction and confidence"""
        if prediction == 0:  # Normal traffic
            return 'none'
        
        # Attack detected
        if confidence >= self.confidence_thresholds['high']:
            if prediction in [1, 4]:  # DoS or U2R attacks
                return 'critical'
            else:
                return 'high'
        elif confidence >= self.confidence_thresholds['medium']:
            return 'medium'
        else:
            return 'low'
    
    def extract_packet_features(self, packet_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract standard features from packet information for prediction
        
        Args:
            packet_info: Raw packet information
            
        Returns:
            Dictionary of extracted features
        """
        # Initialize features with default values
        features = {
            'duration': 0,
            'protocol_type': packet_info.get('protocol', 'tcp'),
            'service': packet_info.get('service', 'http'),
            'flag': packet_info.get('flag', 'SF'),
            'src_bytes': packet_info.get('src_bytes', 0),
            'dst_bytes': packet_info.get('dst_bytes', 0),
            'land': 1 if packet_info.get('src_ip') == packet_info.get('dst_ip') else 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 1,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': packet_info.get('count', 1),
            'srv_count': packet_info.get('srv_count', 1),
            'serror_rate': packet_info.get('serror_rate', 0.0),
            'srv_serror_rate': packet_info.get('srv_serror_rate', 0.0),
            'rerror_rate': packet_info.get('rerror_rate', 0.0),
            'srv_rerror_rate': packet_info.get('srv_rerror_rate', 0.0),
            'same_srv_rate': packet_info.get('same_srv_rate', 1.0),
            'diff_srv_rate': packet_info.get('diff_srv_rate', 0.0),
            'srv_diff_host_rate': packet_info.get('srv_diff_host_rate', 0.0),
            'dst_host_count': packet_info.get('dst_host_count', 1),
            'dst_host_srv_count': packet_info.get('dst_host_srv_count', 1),
            'dst_host_same_srv_rate': packet_info.get('dst_host_same_srv_rate', 1.0),
            'dst_host_diff_srv_rate': packet_info.get('dst_host_diff_srv_rate', 0.0),
            'dst_host_same_src_port_rate': packet_info.get('dst_host_same_src_port_rate', 0.0),
            'dst_host_srv_diff_host_rate': packet_info.get('dst_host_srv_diff_host_rate', 0.0),
            'dst_host_serror_rate': packet_info.get('dst_host_serror_rate', 0.0),
            'dst_host_srv_serror_rate': packet_info.get('dst_host_srv_serror_rate', 0.0),
            'dst_host_rerror_rate': packet_info.get('dst_host_rerror_rate', 0.0),
            'dst_host_srv_rerror_rate': packet_info.get('dst_host_srv_rerror_rate', 0.0)
        }
        
        # Update with provided packet info
        features.update({k: v for k, v in packet_info.items() if k in features})
        
        return features
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models"""
        return {
            'primary_model': type(self.primary_model).__name__ if self.primary_model else None,
            'available_models': list(self.models.keys()),
            'has_anomaly_detector': self.anomaly_detector is not None,
            'feature_count': len(self.preprocessor.feature_columns) if self.preprocessor.feature_columns else 0,
            'attack_types': self.attack_names
        }
    
    def clear_cache(self):
        """Clear prediction cache"""
        self.prediction_cache.clear()
        logger.info("Prediction cache cleared")

def main():
    """Main function for testing prediction"""
    # Initialize predictor
    predictor = IntrusionPredictor()
    
    # Test with sample packet
    sample_packet = {
        'duration': 10,
        'protocol_type': 'tcp',
        'service': 'http',
        'flag': 'SF',
        'src_bytes': 1024,
        'dst_bytes': 2048,
        'count': 5,
        'srv_count': 3
    }
    
    print("Testing single packet prediction...")
    result = predictor.predict_single_packet(sample_packet)
    
    print(f"Prediction: {result['attack_type']}")
    print(f"Confidence: {result['confidence']:.4f}")
    print(f"Alert Level: {result['alert_level']}")
    
    # Test batch prediction
    print("\nTesting batch prediction...")
    batch = [sample_packet for _ in range(5)]
    batch_results = predictor.predict_batch(batch)
    
    print(f"Processed {len(batch_results)} packets")
    for i, result in enumerate(batch_results):
        print(f"Packet {i+1}: {result['attack_type']} (confidence: {result['confidence']:.4f})")

if __name__ == "__main__":
    main()