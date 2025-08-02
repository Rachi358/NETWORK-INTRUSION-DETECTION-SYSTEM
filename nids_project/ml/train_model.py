"""
Machine Learning model training module for Network Intrusion Detection System
Supports multiple algorithms with comprehensive evaluation and comparison
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix, roc_auc_score, roc_curve
)
from sklearn.model_selection import cross_val_score, GridSearchCV
import joblib
import os
import json
import time
import logging
from typing import Dict, List, Tuple, Any
import matplotlib.pyplot as plt
import seaborn as sns
from ml.preprocess import DataPreprocessor

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ModelTrainer:
    """Comprehensive ML model trainer for intrusion detection"""
    
    def __init__(self, config=None):
        self.config = config
        self.models = {}
        self.model_metrics = {}
        self.preprocessor = DataPreprocessor(config)
        
        # Initialize model configurations
        self.model_configs = {
            'random_forest': {
                'model': RandomForestClassifier(
                    n_estimators=100,
                    max_depth=20,
                    min_samples_split=5,
                    min_samples_leaf=2,
                    random_state=42,
                    n_jobs=-1
                ),
                'params': {
                    'n_estimators': [50, 100, 200],
                    'max_depth': [10, 20, None],
                    'min_samples_split': [2, 5, 10]
                }
            },
            'decision_tree': {
                'model': DecisionTreeClassifier(
                    max_depth=20,
                    min_samples_split=5,
                    min_samples_leaf=2,
                    random_state=42
                ),
                'params': {
                    'max_depth': [10, 20, 30],
                    'min_samples_split': [2, 5, 10],
                    'min_samples_leaf': [1, 2, 5]
                }
            },
            'naive_bayes': {
                'model': GaussianNB(),
                'params': {
                    'var_smoothing': [1e-9, 1e-8, 1e-7]
                }
            },
            'logistic_regression': {
                'model': LogisticRegression(
                    max_iter=1000,
                    random_state=42,
                    n_jobs=-1
                ),
                'params': {
                    'C': [0.1, 1.0, 10.0],
                    'penalty': ['l1', 'l2'],
                    'solver': ['liblinear', 'saga']
                }
            },
            'svm': {
                'model': SVC(
                    kernel='rbf',
                    probability=True,
                    random_state=42
                ),
                'params': {
                    'C': [0.1, 1.0, 10.0],
                    'kernel': ['rbf', 'linear'],
                    'gamma': ['scale', 'auto']
                }
            }
        }
        
        # Attack type names for reporting
        self.attack_names = {
            0: 'Normal',
            1: 'DoS',
            2: 'Probe',
            3: 'R2L',
            4: 'U2R'
        }
    
    def load_and_preprocess_data(self, data_path: str = None, use_sample: bool = True) -> Dict[str, Any]:
        """
        Load and preprocess training data
        
        Args:
            data_path: Path to dataset file
            use_sample: Whether to use sample data if real dataset not available
            
        Returns:
            Preprocessed data dictionary
        """
        logger.info("Loading and preprocessing data...")
        
        if data_path and os.path.exists(data_path):
            # Load real NSL-KDD dataset
            train_df, test_df = self.preprocessor.load_nsl_kdd_data(data_path)
            df = train_df
        elif use_sample:
            # Create sample data for demonstration
            logger.info("Using sample synthetic data for training")
            df = self.preprocessor.create_sample_data(5000)
        else:
            raise ValueError("No valid data source provided")
        
        # Preprocess the data
        processed_data = self.preprocessor.preprocess_data(
            df, apply_pca=True, test_size=0.2, fit=True
        )
        
        logger.info(f"Data preprocessing complete. Training samples: {processed_data['X_train'].shape[0]}")
        return processed_data
    
    def train_model(self, model_name: str, X_train: np.ndarray, y_train: np.ndarray,
                   hyperparameter_tuning: bool = False) -> Tuple[Any, Dict[str, float]]:
        """
        Train a single model with optional hyperparameter tuning
        
        Args:
            model_name: Name of the model to train
            X_train: Training features
            y_train: Training labels
            hyperparameter_tuning: Whether to perform grid search
            
        Returns:
            Tuple of (trained_model, training_metrics)
        """
        logger.info(f"Training {model_name} model...")
        
        if model_name not in self.model_configs:
            raise ValueError(f"Unknown model: {model_name}")
        
        config = self.model_configs[model_name]
        
        start_time = time.time()
        
        if hyperparameter_tuning and len(config['params']) > 0:
            # Perform grid search for hyperparameter tuning
            logger.info(f"Performing hyperparameter tuning for {model_name}")
            
            grid_search = GridSearchCV(
                config['model'],
                config['params'],
                cv=3,
                scoring='accuracy',
                n_jobs=-1,
                verbose=1
            )
            
            grid_search.fit(X_train, y_train)
            model = grid_search.best_estimator_
            
            logger.info(f"Best parameters for {model_name}: {grid_search.best_params_}")
        else:
            # Train with default parameters
            model = config['model']
            model.fit(X_train, y_train)
        
        training_time = time.time() - start_time
        
        # Cross-validation scores
        cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='accuracy')
        
        training_metrics = {
            'training_time': training_time,
            'cv_mean_accuracy': cv_scores.mean(),
            'cv_std_accuracy': cv_scores.std(),
            'cv_scores': cv_scores.tolist()
        }
        
        logger.info(f"{model_name} training completed in {training_time:.2f} seconds")
        logger.info(f"Cross-validation accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        
        return model, training_metrics
    
    def evaluate_model(self, model: Any, X_test: np.ndarray, y_test: np.ndarray,
                      model_name: str) -> Dict[str, Any]:
        """
        Comprehensive model evaluation
        
        Args:
            model: Trained model
            X_test: Test features
            y_test: Test labels
            model_name: Name of the model
            
        Returns:
            Dictionary containing all evaluation metrics
        """
        logger.info(f"Evaluating {model_name} model...")
        
        # Predictions
        y_pred = model.predict(X_test)
        y_pred_proba = None
        
        if hasattr(model, 'predict_proba'):
            y_pred_proba = model.predict_proba(X_test)
        
        # Basic metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
        
        # Per-class metrics
        precision_per_class = precision_score(y_test, y_pred, average=None, zero_division=0)
        recall_per_class = recall_score(y_test, y_pred, average=None, zero_division=0)
        f1_per_class = f1_score(y_test, y_pred, average=None, zero_division=0)
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        
        # Classification report
        class_report = classification_report(
            y_test, y_pred, 
            target_names=[self.attack_names.get(i, f'Class_{i}') for i in range(len(np.unique(y_test)))],
            output_dict=True, zero_division=0
        )
        
        # AUC-ROC (for binary classification or one-vs-rest)
        auc_scores = {}
        if y_pred_proba is not None:
            try:
                if len(np.unique(y_test)) == 2:
                    # Binary classification
                    auc_scores['binary'] = roc_auc_score(y_test, y_pred_proba[:, 1])
                else:
                    # Multi-class (one-vs-rest)
                    auc_scores['macro'] = roc_auc_score(y_test, y_pred_proba, 
                                                      multi_class='ovr', average='macro')
                    auc_scores['weighted'] = roc_auc_score(y_test, y_pred_proba, 
                                                         multi_class='ovr', average='weighted')
            except Exception as e:
                logger.warning(f"Could not compute AUC scores: {str(e)}")
        
        evaluation_metrics = {
            'model_name': model_name,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'precision_per_class': precision_per_class.tolist(),
            'recall_per_class': recall_per_class.tolist(),
            'f1_per_class': f1_per_class.tolist(),
            'confusion_matrix': cm.tolist(),
            'classification_report': class_report,
            'auc_scores': auc_scores,
            'predictions': y_pred.tolist(),
            'true_labels': y_test.tolist()
        }
        
        logger.info(f"{model_name} evaluation completed:")
        logger.info(f"  Accuracy: {accuracy:.4f}")
        logger.info(f"  Precision: {precision:.4f}")
        logger.info(f"  Recall: {recall:.4f}")
        logger.info(f"  F1-Score: {f1:.4f}")
        
        return evaluation_metrics
    
    def train_all_models(self, processed_data: Dict[str, Any], 
                        models_to_train: List[str] = None,
                        hyperparameter_tuning: bool = False) -> Dict[str, Any]:
        """
        Train and evaluate all specified models
        
        Args:
            processed_data: Preprocessed data dictionary
            models_to_train: List of model names to train (None for all)
            hyperparameter_tuning: Whether to perform hyperparameter tuning
            
        Returns:
            Dictionary containing all trained models and their metrics
        """
        if models_to_train is None:
            models_to_train = list(self.model_configs.keys())
        
        logger.info(f"Training {len(models_to_train)} models...")
        
        X_train = processed_data['X_train']
        X_test = processed_data['X_test']
        y_train = processed_data['y_train']
        y_test = processed_data['y_test']
        
        all_results = {}
        
        for model_name in models_to_train:
            try:
                # Train model
                model, training_metrics = self.train_model(
                    model_name, X_train, y_train, hyperparameter_tuning
                )
                
                # Evaluate model
                evaluation_metrics = self.evaluate_model(
                    model, X_test, y_test, model_name
                )
                
                # Combine metrics
                combined_metrics = {**training_metrics, **evaluation_metrics}
                
                # Store results
                self.models[model_name] = model
                self.model_metrics[model_name] = combined_metrics
                all_results[model_name] = combined_metrics
                
            except Exception as e:
                logger.error(f"Error training {model_name}: {str(e)}")
                continue
        
        return all_results
    
    def train_anomaly_detector(self, X_train: np.ndarray) -> Any:
        """
        Train unsupervised anomaly detection model for zero-day attacks
        
        Args:
            X_train: Training features (normal traffic only)
            
        Returns:
            Trained anomaly detector
        """
        logger.info("Training anomaly detection model...")
        
        # Use only normal traffic for training
        normal_indices = np.where(self.processed_data['y_train'] == 0)[0]
        X_normal = X_train[normal_indices]
        
        # Train Isolation Forest
        anomaly_detector = IsolationForest(
            contamination=0.1,  # Expected proportion of anomalies
            random_state=42,
            n_jobs=-1
        )
        
        anomaly_detector.fit(X_normal)
        
        logger.info("Anomaly detection model training completed")
        return anomaly_detector
    
    def generate_model_comparison_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive model comparison report
        
        Returns:
            Model comparison data
        """
        logger.info("Generating model comparison report...")
        
        if not self.model_metrics:
            logger.warning("No trained models available for comparison")
            return {}
        
        # Extract key metrics for comparison
        comparison_data = []
        
        for model_name, metrics in self.model_metrics.items():
            comparison_data.append({
                'model_name': model_name,
                'accuracy': metrics['accuracy'],
                'precision': metrics['precision'],
                'recall': metrics['recall'],
                'f1_score': metrics['f1_score'],
                'training_time': metrics['training_time'],
                'cv_mean_accuracy': metrics['cv_mean_accuracy']
            })
        
        # Sort by accuracy
        comparison_data.sort(key=lambda x: x['accuracy'], reverse=True)
        
        # Find best model
        best_model = comparison_data[0] if comparison_data else None
        
        report = {
            'comparison_data': comparison_data,
            'best_model': best_model,
            'total_models': len(comparison_data),
            'metrics_summary': {
                'max_accuracy': max([m['accuracy'] for m in comparison_data]) if comparison_data else 0,
                'min_accuracy': min([m['accuracy'] for m in comparison_data]) if comparison_data else 0,
                'avg_accuracy': np.mean([m['accuracy'] for m in comparison_data]) if comparison_data else 0,
                'std_accuracy': np.std([m['accuracy'] for m in comparison_data]) if comparison_data else 0
            }
        }
        
        logger.info("Model comparison report generated")
        if best_model:
            logger.info(f"Best model: {best_model['model_name']} with accuracy: {best_model['accuracy']:.4f}")
        
        return report
    
    def save_models(self, model_dir: str, save_best_only: bool = False):
        """
        Save trained models and metrics
        
        Args:
            model_dir: Directory to save models
            save_best_only: Whether to save only the best performing model
        """
        os.makedirs(model_dir, exist_ok=True)
        
        if save_best_only:
            # Find best model
            best_model_name = max(self.model_metrics.keys(), 
                                key=lambda k: self.model_metrics[k]['accuracy'])
            models_to_save = {best_model_name: self.models[best_model_name]}
        else:
            models_to_save = self.models
        
        # Save models
        for model_name, model in models_to_save.items():
            model_path = os.path.join(model_dir, f'{model_name}_model.joblib')
            joblib.dump(model, model_path)
            logger.info(f"Model {model_name} saved to {model_path}")
        
        # Save metrics
        metrics_path = os.path.join(model_dir, 'model_metrics.json')
        with open(metrics_path, 'w') as f:
            json.dump(self.model_metrics, f, indent=2, default=str)
        logger.info(f"Model metrics saved to {metrics_path}")
        
        # Save preprocessors
        self.preprocessor.save_preprocessors(model_dir)
    
    def create_visualization_plots(self, save_dir: str):
        """
        Create visualization plots for model performance
        
        Args:
            save_dir: Directory to save plots
        """
        os.makedirs(save_dir, exist_ok=True)
        
        if not self.model_metrics:
            logger.warning("No model metrics available for visualization")
            return
        
        # Model comparison plot
        models = list(self.model_metrics.keys())
        accuracies = [self.model_metrics[m]['accuracy'] for m in models]
        f1_scores = [self.model_metrics[m]['f1_score'] for m in models]
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Accuracy comparison
        ax1.bar(models, accuracies, color='skyblue', alpha=0.7)
        ax1.set_title('Model Accuracy Comparison')
        ax1.set_xlabel('Models')
        ax1.set_ylabel('Accuracy')
        ax1.tick_params(axis='x', rotation=45)
        
        # F1-Score comparison
        ax2.bar(models, f1_scores, color='lightcoral', alpha=0.7)
        ax2.set_title('Model F1-Score Comparison')
        ax2.set_xlabel('Models')
        ax2.set_ylabel('F1-Score')
        ax2.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig(os.path.join(save_dir, 'model_comparison.png'), dpi=300, bbox_inches='tight')
        plt.close()
        
        # Confusion matrix for best model
        best_model_name = max(self.model_metrics.keys(), 
                             key=lambda k: self.model_metrics[k]['accuracy'])
        cm = np.array(self.model_metrics[best_model_name]['confusion_matrix'])
        
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                   xticklabels=list(self.attack_names.values()),
                   yticklabels=list(self.attack_names.values()))
        plt.title(f'Confusion Matrix - {best_model_name}')
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        plt.savefig(os.path.join(save_dir, f'confusion_matrix_{best_model_name}.png'), 
                   dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Visualization plots saved to {save_dir}")

def main():
    """Main function for training models"""
    # Initialize trainer
    trainer = ModelTrainer()
    
    # Load and preprocess data
    processed_data = trainer.load_and_preprocess_data(use_sample=True)
    trainer.processed_data = processed_data
    
    # Train all models
    results = trainer.train_all_models(
        processed_data,
        models_to_train=['random_forest', 'decision_tree', 'naive_bayes', 'logistic_regression'],
        hyperparameter_tuning=False
    )
    
    # Generate comparison report
    comparison_report = trainer.generate_model_comparison_report()
    
    # Save models and results
    trainer.save_models('models', save_best_only=False)
    
    # Create visualizations
    trainer.create_visualization_plots('static/plots')
    
    # Print summary
    print("\n" + "="*50)
    print("TRAINING SUMMARY")
    print("="*50)
    
    for model_name, metrics in results.items():
        print(f"\n{model_name.upper()}:")
        print(f"  Accuracy: {metrics['accuracy']:.4f}")
        print(f"  Precision: {metrics['precision']:.4f}")
        print(f"  Recall: {metrics['recall']:.4f}")
        print(f"  F1-Score: {metrics['f1_score']:.4f}")
        print(f"  Training Time: {metrics['training_time']:.2f}s")
    
    if comparison_report['best_model']:
        best = comparison_report['best_model']
        print(f"\nBEST MODEL: {best['model_name']} (Accuracy: {best['accuracy']:.4f})")
    
    print("\nTraining completed successfully!")

if __name__ == "__main__":
    main()