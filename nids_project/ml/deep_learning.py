"""
Advanced Deep Learning module for Network Intrusion Detection
Implements LSTM, CNN, and Transformer architectures for enhanced threat detection
"""

import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader, TensorDataset
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import logging
from typing import Tuple, Dict, List, Optional
import time
from datetime import datetime
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PacketSequenceDataset(Dataset):
    """Dataset for sequential packet analysis"""
    
    def __init__(self, sequences, labels, sequence_length=50):
        self.sequences = sequences
        self.labels = labels
        self.sequence_length = sequence_length
    
    def __len__(self):
        return len(self.sequences)
    
    def __getitem__(self, idx):
        sequence = self.sequences[idx]
        label = self.labels[idx]
        
        # Pad or truncate sequence to fixed length
        if len(sequence) < self.sequence_length:
            # Pad with zeros
            padded = np.zeros((self.sequence_length, sequence.shape[1]))
            padded[:len(sequence)] = sequence
            sequence = padded
        else:
            # Truncate to sequence length
            sequence = sequence[:self.sequence_length]
        
        return torch.FloatTensor(sequence), torch.LongTensor([label])

class LSTMIntrusionDetector(nn.Module):
    """LSTM-based intrusion detection model"""
    
    def __init__(self, input_size, hidden_size=128, num_layers=2, num_classes=5, dropout=0.3):
        super(LSTMIntrusionDetector, self).__init__()
        
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        
        # LSTM layers
        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0,
            bidirectional=True
        )
        
        # Attention mechanism
        self.attention = nn.Linear(hidden_size * 2, 1)
        
        # Classification layers
        self.dropout = nn.Dropout(dropout)
        self.fc1 = nn.Linear(hidden_size * 2, hidden_size)
        self.fc2 = nn.Linear(hidden_size, hidden_size // 2)
        self.fc3 = nn.Linear(hidden_size // 2, num_classes)
        
        # Batch normalization
        self.bn1 = nn.BatchNorm1d(hidden_size)
        self.bn2 = nn.BatchNorm1d(hidden_size // 2)
    
    def forward(self, x):
        batch_size = x.size(0)
        
        # LSTM forward pass
        lstm_out, (hidden, cell) = self.lstm(x)
        
        # Apply attention mechanism
        attention_weights = F.softmax(self.attention(lstm_out), dim=1)
        context_vector = torch.sum(attention_weights * lstm_out, dim=1)
        
        # Classification
        out = self.dropout(context_vector)
        out = F.relu(self.bn1(self.fc1(out)))
        out = self.dropout(out)
        out = F.relu(self.bn2(self.fc2(out)))
        out = self.dropout(out)
        out = self.fc3(out)
        
        return out

class CNNIntrusionDetector(nn.Module):
    """CNN-based intrusion detection for packet payload analysis"""
    
    def __init__(self, input_channels=1, num_classes=5, dropout=0.3):
        super(CNNIntrusionDetector, self).__init__()
        
        # Convolutional layers
        self.conv1 = nn.Conv1d(input_channels, 64, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(64, 128, kernel_size=3, padding=1)
        self.conv3 = nn.Conv1d(128, 256, kernel_size=3, padding=1)
        
        # Batch normalization
        self.bn1 = nn.BatchNorm1d(64)
        self.bn2 = nn.BatchNorm1d(128)
        self.bn3 = nn.BatchNorm1d(256)
        
        # Pooling
        self.pool = nn.MaxPool1d(2)
        self.adaptive_pool = nn.AdaptiveAvgPool1d(1)
        
        # Classification layers
        self.dropout = nn.Dropout(dropout)
        self.fc1 = nn.Linear(256, 128)
        self.fc2 = nn.Linear(128, 64)
        self.fc3 = nn.Linear(64, num_classes)
    
    def forward(self, x):
        # If input is 2D, add channel dimension
        if len(x.shape) == 2:
            x = x.unsqueeze(1)
        
        # Convolutional layers
        x = F.relu(self.bn1(self.conv1(x)))
        x = self.pool(x)
        
        x = F.relu(self.bn2(self.conv2(x)))
        x = self.pool(x)
        
        x = F.relu(self.bn3(self.conv3(x)))
        x = self.adaptive_pool(x)
        
        # Flatten
        x = x.view(x.size(0), -1)
        
        # Classification
        x = self.dropout(x)
        x = F.relu(self.fc1(x))
        x = self.dropout(x)
        x = F.relu(self.fc2(x))
        x = self.dropout(x)
        x = self.fc3(x)
        
        return x

class TransformerIntrusionDetector(nn.Module):
    """Transformer-based intrusion detection model"""
    
    def __init__(self, input_size, d_model=256, nhead=8, num_layers=6, num_classes=5, dropout=0.1):
        super(TransformerIntrusionDetector, self).__init__()
        
        self.d_model = d_model
        
        # Input projection
        self.input_projection = nn.Linear(input_size, d_model)
        
        # Positional encoding
        self.pos_encoding = PositionalEncoding(d_model, dropout)
        
        # Transformer encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=d_model * 4,
            dropout=dropout,
            activation='relu',
            batch_first=True
        )
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_layers)
        
        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(d_model // 2, d_model // 4),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(d_model // 4, num_classes)
        )
    
    def forward(self, x):
        # Project input to model dimension
        x = self.input_projection(x) * np.sqrt(self.d_model)
        
        # Add positional encoding
        x = self.pos_encoding(x)
        
        # Transformer encoding
        x = self.transformer_encoder(x)
        
        # Global average pooling
        x = torch.mean(x, dim=1)
        
        # Classification
        x = self.classifier(x)
        
        return x

class PositionalEncoding(nn.Module):
    """Positional encoding for transformer"""
    
    def __init__(self, d_model, dropout=0.1, max_len=5000):
        super(PositionalEncoding, self).__init__()
        self.dropout = nn.Dropout(p=dropout)
        
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * 
                           (-np.log(10000.0) / d_model))
        
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0).transpose(0, 1)
        self.register_buffer('pe', pe)
    
    def forward(self, x):
        x = x + self.pe[:x.size(0), :].transpose(0, 1)
        return self.dropout(x)

class DeepLearningTrainer:
    """Advanced trainer for deep learning models"""
    
    def __init__(self, model_type='lstm', device=None):
        self.model_type = model_type
        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        
        logger.info(f"Using device: {self.device}")
    
    def create_model(self, input_size, num_classes=5):
        """Create model based on type"""
        if self.model_type == 'lstm':
            self.model = LSTMIntrusionDetector(
                input_size=input_size,
                hidden_size=128,
                num_layers=2,
                num_classes=num_classes,
                dropout=0.3
            )
        elif self.model_type == 'cnn':
            self.model = CNNIntrusionDetector(
                input_channels=1,
                num_classes=num_classes,
                dropout=0.3
            )
        elif self.model_type == 'transformer':
            self.model = TransformerIntrusionDetector(
                input_size=input_size,
                d_model=256,
                nhead=8,
                num_layers=6,
                num_classes=num_classes,
                dropout=0.1
            )
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")
        
        self.model.to(self.device)
        return self.model
    
    def prepare_data(self, df, sequence_length=50, test_size=0.2):
        """Prepare data for deep learning training"""
        # Separate features and labels
        if 'class' in df.columns:
            X = df.drop('class', axis=1)
            y = df['class']
        else:
            raise ValueError("Dataset must contain 'class' column")
        
        # Encode labels
        y_encoded = self.label_encoder.fit_transform(y)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        if self.model_type == 'lstm' or self.model_type == 'transformer':
            # Create sequences for sequential models
            X_sequences, y_sequences = self._create_sequences(X_scaled, y_encoded, sequence_length)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X_sequences, y_sequences, test_size=test_size, random_state=42, stratify=y_sequences
            )
            
            # Create datasets
            train_dataset = PacketSequenceDataset(X_train, y_train, sequence_length)
            test_dataset = PacketSequenceDataset(X_test, y_test, sequence_length)
            
        else:  # CNN
            # For CNN, treat each sample as individual
            X_train, X_test, y_train, y_test = train_test_split(
                X_scaled, y_encoded, test_size=test_size, random_state=42, stratify=y_encoded
            )
            
            # Create tensor datasets
            train_dataset = TensorDataset(
                torch.FloatTensor(X_train),
                torch.LongTensor(y_train)
            )
            test_dataset = TensorDataset(
                torch.FloatTensor(X_test),
                torch.LongTensor(y_test)
            )
        
        return train_dataset, test_dataset
    
    def _create_sequences(self, X, y, sequence_length):
        """Create sequences for LSTM/Transformer training"""
        sequences = []
        labels = []
        
        # Create overlapping sequences
        for i in range(len(X) - sequence_length + 1):
            seq = X[i:i + sequence_length]
            label = y[i + sequence_length - 1]  # Label for the last item in sequence
            sequences.append(seq)
            labels.append(label)
        
        return np.array(sequences), np.array(labels)
    
    def train_model(self, train_dataset, test_dataset, epochs=100, batch_size=32, learning_rate=0.001):
        """Train the deep learning model"""
        if self.model is None:
            raise ValueError("Model not created. Call create_model first.")
        
        # Create data loaders
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)
        
        # Loss function and optimizer
        criterion = nn.CrossEntropyLoss()
        optimizer = optim.Adam(self.model.parameters(), lr=learning_rate, weight_decay=1e-5)
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=10, factor=0.5)
        
        # Training history
        train_losses = []
        train_accuracies = []
        test_accuracies = []
        
        best_test_acc = 0.0
        patience_counter = 0
        patience = 20
        
        logger.info(f"Starting training for {epochs} epochs...")
        start_time = time.time()
        
        for epoch in range(epochs):
            # Training phase
            self.model.train()
            train_loss = 0.0
            train_correct = 0
            train_total = 0
            
            for batch_idx, (data, target) in enumerate(train_loader):
                data, target = data.to(self.device), target.to(self.device)
                target = target.squeeze()
                
                optimizer.zero_grad()
                output = self.model(data)
                loss = criterion(output, target)
                loss.backward()
                optimizer.step()
                
                train_loss += loss.item()
                _, predicted = torch.max(output.data, 1)
                train_total += target.size(0)
                train_correct += (predicted == target).sum().item()
            
            train_acc = 100.0 * train_correct / train_total
            avg_train_loss = train_loss / len(train_loader)
            
            # Validation phase
            test_acc = self.evaluate_model(test_loader)
            
            # Update learning rate
            scheduler.step(avg_train_loss)
            
            # Save best model
            if test_acc > best_test_acc:
                best_test_acc = test_acc
                patience_counter = 0
                # Save best model state
                torch.save(self.model.state_dict(), f'best_{self.model_type}_model.pth')
            else:
                patience_counter += 1
            
            # Record history
            train_losses.append(avg_train_loss)
            train_accuracies.append(train_acc)
            test_accuracies.append(test_acc)
            
            # Early stopping
            if patience_counter >= patience:
                logger.info(f"Early stopping at epoch {epoch+1}")
                break
            
            # Log progress
            if (epoch + 1) % 10 == 0:
                logger.info(f'Epoch [{epoch+1}/{epochs}], Train Loss: {avg_train_loss:.4f}, '
                           f'Train Acc: {train_acc:.2f}%, Test Acc: {test_acc:.2f}%')
        
        training_time = time.time() - start_time
        logger.info(f"Training completed in {training_time:.2f} seconds")
        logger.info(f"Best test accuracy: {best_test_acc:.2f}%")
        
        # Load best model
        self.model.load_state_dict(torch.load(f'best_{self.model_type}_model.pth'))
        
        return {
            'training_time': training_time,
            'best_accuracy': best_test_acc,
            'train_losses': train_losses,
            'train_accuracies': train_accuracies,
            'test_accuracies': test_accuracies
        }
    
    def evaluate_model(self, test_loader):
        """Evaluate model on test set"""
        self.model.eval()
        correct = 0
        total = 0
        
        with torch.no_grad():
            for data, target in test_loader:
                data, target = data.to(self.device), target.to(self.device)
                target = target.squeeze()
                
                output = self.model(data)
                _, predicted = torch.max(output.data, 1)
                total += target.size(0)
                correct += (predicted == target).sum().item()
        
        accuracy = 100.0 * correct / total
        return accuracy
    
    def predict(self, X):
        """Make predictions on new data"""
        self.model.eval()
        
        # Preprocess data
        X_scaled = self.scaler.transform(X)
        
        if self.model_type in ['lstm', 'transformer']:
            # For sequential models, create sequences
            sequence_length = 50  # Should match training
            if len(X_scaled) < sequence_length:
                # Pad if too short
                padded = np.zeros((sequence_length, X_scaled.shape[1]))
                padded[:len(X_scaled)] = X_scaled
                X_scaled = padded.reshape(1, sequence_length, -1)
            else:
                # Take last sequence_length samples
                X_scaled = X_scaled[-sequence_length:].reshape(1, sequence_length, -1)
        else:
            # For CNN, reshape for batch
            X_scaled = X_scaled.reshape(X_scaled.shape[0], -1)
        
        # Convert to tensor
        X_tensor = torch.FloatTensor(X_scaled).to(self.device)
        
        with torch.no_grad():
            output = self.model(X_tensor)
            probabilities = F.softmax(output, dim=1)
            _, predicted = torch.max(output, 1)
        
        return {
            'prediction': self.label_encoder.inverse_transform(predicted.cpu().numpy()),
            'probabilities': probabilities.cpu().numpy(),
            'confidence': torch.max(probabilities, 1)[0].cpu().numpy()
        }
    
    def save_model(self, filepath):
        """Save complete model with preprocessing"""
        torch.save({
            'model_state_dict': self.model.state_dict(),
            'model_type': self.model_type,
            'scaler': self.scaler,
            'label_encoder': self.label_encoder,
            'model_config': {
                'input_size': self.model.input_projection.in_features if hasattr(self.model, 'input_projection') else None,
                'num_classes': len(self.label_encoder.classes_)
            }
        }, filepath)
        logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath):
        """Load complete model with preprocessing"""
        checkpoint = torch.load(filepath, map_location=self.device)
        
        self.model_type = checkpoint['model_type']
        self.scaler = checkpoint['scaler']
        self.label_encoder = checkpoint['label_encoder']
        
        # Recreate model
        config = checkpoint['model_config']
        self.create_model(config['input_size'], config['num_classes'])
        
        # Load weights
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.model.eval()
        
        logger.info(f"Model loaded from {filepath}")

def train_all_deep_models(df, model_dir='models/deep_learning'):
    """Train all deep learning models and compare performance"""
    os.makedirs(model_dir, exist_ok=True)
    
    results = {}
    model_types = ['lstm', 'cnn', 'transformer']
    
    for model_type in model_types:
        logger.info(f"Training {model_type.upper()} model...")
        
        try:
            trainer = DeepLearningTrainer(model_type=model_type)
            
            # Prepare data
            train_dataset, test_dataset = trainer.prepare_data(df)
            
            # Get input size from first batch
            sample_batch = next(iter(DataLoader(train_dataset, batch_size=1)))
            if model_type in ['lstm', 'transformer']:
                input_size = sample_batch[0].shape[2]
            else:
                input_size = sample_batch[0].shape[1]
            
            # Create and train model
            trainer.create_model(input_size=input_size)
            training_results = trainer.train_model(train_dataset, test_dataset, epochs=50)
            
            # Save model
            model_path = os.path.join(model_dir, f'{model_type}_model.pth')
            trainer.save_model(model_path)
            
            results[model_type] = {
                'accuracy': training_results['best_accuracy'],
                'training_time': training_results['training_time'],
                'model_path': model_path
            }
            
            logger.info(f"{model_type.upper()} model trained successfully!")
            logger.info(f"Best accuracy: {training_results['best_accuracy']:.2f}%")
            
        except Exception as e:
            logger.error(f"Error training {model_type} model: {str(e)}")
            results[model_type] = {'error': str(e)}
    
    return results

def main():
    """Main function for testing deep learning models"""
    # Import data preprocessor
    from ml.preprocess import DataPreprocessor
    
    # Initialize preprocessor and create sample data
    preprocessor = DataPreprocessor()
    df = preprocessor.create_sample_data(5000)
    
    # Train all models
    results = train_all_deep_models(df)
    
    # Print results
    print("\n" + "="*60)
    print("DEEP LEARNING MODELS TRAINING RESULTS")
    print("="*60)
    
    for model_type, result in results.items():
        print(f"\n{model_type.upper()} Model:")
        if 'error' in result:
            print(f"  Error: {result['error']}")
        else:
            print(f"  Accuracy: {result['accuracy']:.2f}%")
            print(f"  Training Time: {result['training_time']:.2f}s")
    
    print("\nDeep learning models training completed!")

if __name__ == "__main__":
    main()