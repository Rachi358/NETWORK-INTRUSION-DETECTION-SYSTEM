#!/usr/bin/env python3
"""
Test script for Network Intrusion Detection System (NIDS)
Tests all major components to ensure system functionality
"""

import sys
import os
import time
import subprocess
import importlib

def test_imports():
    """Test all critical imports"""
    print("🔍 Testing imports...")
    
    try:
        import flask
        print("✅ Flask imported successfully")
    except ImportError as e:
        print(f"❌ Flask import failed: {e}")
        return False
    
    try:
        import pandas
        print("✅ Pandas imported successfully")
    except ImportError as e:
        print(f"❌ Pandas import failed: {e}")
        return False
    
    try:
        import numpy
        print("✅ NumPy imported successfully")
    except ImportError as e:
        print(f"❌ NumPy import failed: {e}")
        return False
    
    try:
        import sklearn
        print("✅ Scikit-learn imported successfully")
    except ImportError as e:
        print(f"❌ Scikit-learn import failed: {e}")
        return False
    
    try:
        import psutil
        print("✅ psutil imported successfully")
    except ImportError as e:
        print(f"❌ psutil import failed: {e}")
        return False
    
    return True

def test_project_structure():
    """Test project structure and files"""
    print("\n📁 Testing project structure...")
    
    required_files = [
        'app.py',
        'config.py',
        'requirements.txt',
        'templates/layout.html',
        'templates/index.html',
        'templates/dashboard.html',
        'ml/__init__.py',
        'ml/preprocess.py',
        'ml/train_model.py',
        'ml/predict.py',
        'utils/__init__.py',
        'utils/db_handler.py',
        'utils/packet_sniffer.py'
    ]
    
    missing_files = []
    for file in required_files:
        if os.path.exists(file):
            print(f"✅ {file}")
        else:
            print(f"❌ {file} - MISSING")
            missing_files.append(file)
    
    return len(missing_files) == 0

def test_ml_components():
    """Test ML components"""
    print("\n🤖 Testing ML components...")
    
    try:
        # Test data preprocessor
        from ml.preprocess import DataPreprocessor
        preprocessor = DataPreprocessor()
        sample_data = preprocessor.create_sample_data(100)
        print(f"✅ Data preprocessing: Generated {len(sample_data)} sample records")
        
        # Test model trainer
        from ml.train_model import ModelTrainer
        trainer = ModelTrainer()
        print("✅ Model trainer initialized successfully")
        
        # Test predictor (without models)
        from ml.predict import IntrusionPredictor
        # This might fail without trained models, which is expected
        print("✅ ML predict module imported successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ ML components test failed: {e}")
        return False

def test_database():
    """Test database functionality"""
    print("\n💾 Testing database...")
    
    try:
        from utils.db_handler import DatabaseHandler, DetectionLog
        
        # Create a test database handler
        db_handler = DatabaseHandler()
        print("✅ Database handler created successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False

def test_packet_sniffer():
    """Test packet sniffer components"""
    print("\n📡 Testing packet sniffer...")
    
    try:
        from utils.packet_sniffer import PacketSniffer, SimulatedPacketGenerator
        
        # Test simulated packet generator
        generator = SimulatedPacketGenerator()
        print("✅ Simulated packet generator created successfully")
        
        # Generate a test packet
        test_packet = generator._create_random_packet()
        if test_packet and 'src_ip' in test_packet:
            print("✅ Test packet generated successfully")
        else:
            print("❌ Test packet generation failed")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Packet sniffer test failed: {e}")
        return False

def test_flask_app():
    """Test Flask application creation"""
    print("\n🌐 Testing Flask application...")
    
    try:
        from app import create_app
        
        app, socketio = create_app('development')
        print("✅ Flask app created successfully")
        
        # Test if routes are registered
        with app.app_context():
            routes = [rule.rule for rule in app.url_map.iter_rules()]
            expected_routes = ['/', '/dashboard', '/api/status', '/api/predict']
            
            for route in expected_routes:
                if route in routes:
                    print(f"✅ Route {route} registered")
                else:
                    print(f"❌ Route {route} missing")
                    return False
        
        return True
        
    except Exception as e:
        print(f"❌ Flask app test failed: {e}")
        return False

def test_basic_prediction():
    """Test basic ML prediction functionality"""
    print("\n🔮 Testing basic prediction...")
    
    try:
        from ml.preprocess import DataPreprocessor
        from ml.train_model import ModelTrainer
        
        # Create sample data
        preprocessor = DataPreprocessor()
        sample_data = preprocessor.create_sample_data(1000)
        print(f"✅ Generated {len(sample_data)} training samples")
        
        # Process data
        processed_data = preprocessor.preprocess_data(sample_data, apply_pca=False)
        print("✅ Data preprocessing completed")
        
        # Train a simple model
        trainer = ModelTrainer()
        results = trainer.train_all_models(
            processed_data, 
            models_to_train=['random_forest'],
            hyperparameter_tuning=False
        )
        
        if 'random_forest' in results:
            accuracy = results['random_forest']['accuracy']
            print(f"✅ Model training completed (accuracy: {accuracy:.3f})")
            return True
        else:
            print("❌ Model training failed")
            return False
        
    except Exception as e:
        print(f"❌ Basic prediction test failed: {e}")
        return False

def create_directories():
    """Create necessary directories"""
    print("\n📂 Creating necessary directories...")
    
    directories = ['models', 'logs', 'static/plots', 'templates']
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            print(f"✅ Directory created: {directory}")
        except Exception as e:
            print(f"❌ Failed to create directory {directory}: {e}")

def install_requirements():
    """Install requirements if needed"""
    print("\n📦 Checking requirements installation...")
    
    try:
        # Check if key packages are installed
        import flask
        import pandas
        import sklearn
        print("✅ Key packages are already installed")
        return True
    except ImportError:
        print("❌ Some packages are missing. Please run: pip install -r requirements.txt")
        return False

def main():
    """Run all tests"""
    print("🚀 NIDS System Test Suite")
    print("=" * 50)
    
    # Change to project directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    tests = [
        ("Imports", test_imports),
        ("Project Structure", test_project_structure),
        ("Database", test_database),
        ("Packet Sniffer", test_packet_sniffer),
        ("ML Components", test_ml_components),
        ("Flask App", test_flask_app),
        ("Basic Prediction", test_basic_prediction)
    ]
    
    # Create directories first
    create_directories()
    
    # Check requirements
    if not install_requirements():
        print("\n❌ Requirements check failed. Please install missing packages.")
        return False
    
    # Run tests
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                print(f"❌ {test_name} test failed")
        except Exception as e:
            print(f"❌ {test_name} test crashed: {e}")
    
    # Results
    print("\n" + "=" * 50)
    print("🏁 TEST RESULTS")
    print("=" * 50)
    print(f"Passed: {passed}/{total}")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! System is ready to run.")
        print("\nTo start the NIDS system, run:")
        print("  python app.py")
        print("\nThen open: http://localhost:5000")
        return True
    else:
        print(f"\n⚠️  {total - passed} tests failed. Please fix the issues above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)