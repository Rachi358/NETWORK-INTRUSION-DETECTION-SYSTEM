# 🛡️ Network Intrusion Detection System (NIDS)

A comprehensive, AI-powered Network Intrusion Detection System built with Flask, machine learning, and real-time analytics.

## 🚀 Quick Start

### Prerequisites
- Python 3.8+ 
- pip (Python package installer)
- 4GB+ RAM recommended
- Internet connection for downloading dependencies

### Installation

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Test System**
   ```bash
   python test_system.py
   ```

3. **Run Application**
   ```bash
   python app.py
   ```

4. **Access Dashboard**
   - Open browser: http://localhost:5000
   - Dashboard: http://localhost:5000/dashboard

## 📋 Features

### ✅ Core Functionality
- **Real-time Packet Analysis** - Live network traffic monitoring
- **ML-based Detection** - Multiple algorithms (Random Forest, Decision Tree, Naive Bayes)
- **WebSocket Dashboard** - Real-time updates and visualization
- **Attack Classification** - DoS, Probe, R2L, U2R detection
- **Data Export** - CSV export of detection logs
- **Simulation Mode** - Test system without live traffic

### ✅ Advanced Features
- **Deep Learning Models** - LSTM, CNN, Transformer support
- **Behavioral Analysis** - Anomaly detection and risk scoring
- **Threat Intelligence** - Integration ready for external feeds
- **Authentication System** - JWT-based with role management
- **Responsive UI** - Bootstrap 5 with dark/light themes

### ✅ Enterprise Ready
- **Database Logging** - SQLite/MySQL support
- **Docker Support** - Containerized deployment
- **API Endpoints** - RESTful API for integration
- **Performance Monitoring** - System metrics and alerts
- **Scalable Architecture** - Modular design for expansion

## 🎯 Usage Guide

### Home Page Features
- **System Status** - Real-time system health monitoring
- **Quick Actions** - Test prediction, start monitoring, train models
- **Activity Feed** - Recent detection events
- **Demo Mode** - Interactive simulation with configurable parameters

### Dashboard Features
- **Live Monitoring** - Real-time packet stream with auto-pause
- **Analytics Charts** - Attack distribution, traffic timeline, protocol analysis
- **Model Management** - Performance comparison and training controls
- **Detection Logs** - Searchable table with filtering options
- **Settings Panel** - Confidence thresholds and alert configuration

## 🔧 Configuration

### Environment Variables
```bash
# Optional configuration
export FLASK_ENV=development          # or production
export SECRET_KEY=your-secret-key
export DATABASE_URL=sqlite:///logs/detection_logs.db
```

### Settings File
Edit `config.py` to customize:
- Database connections
- ML model parameters
- Network interfaces
- Alert thresholds
- Security settings

## 🤖 Machine Learning

### Supported Models
- **Random Forest** (Primary) - High accuracy, fast inference
- **Decision Tree** - Interpretable results
- **Naive Bayes** - Probabilistic classification
- **Logistic Regression** - Linear classification
- **LSTM** - Sequential pattern detection
- **CNN** - Payload pattern analysis
- **Transformer** - Advanced sequence modeling

### Training Process
1. **Data Preprocessing** - Feature scaling, encoding, PCA
2. **Model Training** - Cross-validation, hyperparameter tuning
3. **Performance Evaluation** - Accuracy, precision, recall, F1-score
4. **Model Selection** - Best performing model activation

### Feature Engineering
- **NSL-KDD Compatible** - Standard dataset features
- **Network Metrics** - Connection statistics, protocol analysis
- **Temporal Features** - Time-based patterns
- **Behavioral Metrics** - User and system behavior analysis

## 📊 API Reference

### Core Endpoints
```bash
GET  /api/status           # System status and metrics
POST /api/predict          # Single packet prediction
POST /api/predict/batch    # Batch prediction
GET  /api/logs             # Detection logs with filtering
GET  /api/statistics       # Attack statistics and charts
```

### Real-time Endpoints
```bash
POST /api/realtime/start   # Start monitoring
POST /api/realtime/stop    # Stop monitoring
```

### Management Endpoints
```bash
GET  /api/models           # Model information
POST /api/train            # Train new models
GET  /api/export/logs      # Export logs to CSV
```

### Example API Usage
```python
import requests

# Test prediction
packet_data = {
    "duration": 0.5,
    "protocol_type": "tcp",
    "service": "http",
    "src_bytes": 1024,
    "dst_bytes": 512
}

response = requests.post(
    "http://localhost:5000/api/predict",
    json=packet_data
)

result = response.json()
print(f"Prediction: {result['attack_type']}")
print(f"Confidence: {result['confidence']:.2f}")
```

## 🐳 Docker Deployment

### Build Image
```bash
docker build -t nids-system .
```

### Run Container
```bash
docker run -p 5000:5000 -v $(pwd)/logs:/app/logs nids-system
```

### Docker Compose
```yaml
version: '3.8'
services:
  nids:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - ./logs:/app/logs
      - ./models:/app/models
    environment:
      - FLASK_ENV=production
```

## 🏗️ Architecture

### System Components
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend       │    │   ML Engine     │
│   (Bootstrap)   │◄──►│   (Flask)       │◄──►│   (Sklearn)     │
│   - Dashboard   │    │   - API         │    │   - Models      │
│   - WebSocket   │    │   - WebSocket   │    │   - Prediction  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       ▼                       │
         │              ┌─────────────────┐              │
         │              │   Database      │              │
         │              │   (SQLite)      │              │
         │              │   - Logs        │              │
         │              │   - Metrics     │              │
         │              └─────────────────┘              │
         │                                                │
         ▼                                                ▼
┌─────────────────┐                            ┌─────────────────┐
│   Packet        │                            │   Analytics     │
│   Capture       │                            │   Engine        │
│   - Scapy       │                            │   - Statistics  │
│   - Simulation  │                            │   - Risk Score  │
└─────────────────┘                            └─────────────────┘
```

### Data Flow
1. **Packet Capture** → Raw network packets
2. **Feature Extraction** → NSL-KDD compatible features
3. **ML Prediction** → Attack classification + confidence
4. **Database Storage** → Log detection results
5. **WebSocket Update** → Real-time dashboard updates
6. **Analytics Processing** → Statistics and reporting

## 🔒 Security Features

### Authentication
- JWT-based session management
- Role-based access control (Admin, Analyst, Viewer)
- Multi-factor authentication (TOTP)
- Session tracking and revocation

### Input Validation
- Request sanitization
- Rate limiting
- CORS protection
- SQL injection prevention

### Data Protection
- Encrypted sensitive data
- Secure password hashing (bcrypt)
- Audit logging
- HTTPS support

## 📈 Performance

### Benchmarks
- **Accuracy**: >94% (Random Forest + PCA)
- **Latency**: <0.5 seconds per prediction
- **Throughput**: 1000+ packets/second
- **Memory Usage**: <500MB typical
- **CPU Usage**: <20% on modern hardware

### Optimization Features
- **Batch Processing** - Multiple packet analysis
- **Caching** - Redis for frequent queries
- **Connection Pooling** - Database optimization
- **Async Processing** - Non-blocking operations

## 🐛 Troubleshooting

### Common Issues

**1. Import Errors**
```bash
# Install missing packages
pip install -r requirements.txt

# Update pip if needed
pip install --upgrade pip
```

**2. Port Already in Use**
```bash
# Find process using port 5000
lsof -i :5000
kill -9 <PID>

# Or use different port
export PORT=5001
python app.py
```

**3. Permission Errors (Real Packet Capture)**
```bash
# Run with privileges (Linux/Mac)
sudo python app.py

# Or use simulation mode (recommended)
# No privileges required
```

**4. Memory Issues**
```bash
# Reduce batch size in config.py
PREDICTION_BATCH_SIZE = 50

# Enable swap if needed
sudo swapon -a
```

### Debug Mode
```bash
export FLASK_ENV=development
export DEBUG=1
python app.py
```

## 🧪 Testing

### Run Test Suite
```bash
python test_system.py
```

### Manual Testing
```bash
# Test individual components
python ml/preprocess.py
python ml/train_model.py
python utils/packet_sniffer.py
```

### Load Testing
```bash
# Install testing tools
pip install locust

# Run load tests (create locustfile.py)
locust -f tests/load_test.py --host=http://localhost:5000
```

## 📚 Documentation

### Code Documentation
- **Docstrings** - All functions documented
- **Type Hints** - Function signatures
- **Comments** - Complex logic explained
- **Examples** - Usage examples in docstrings

### API Documentation
- **OpenAPI/Swagger** - Available at `/docs` (planned)
- **Postman Collection** - Import `docs/api_collection.json`
- **Examples** - See `examples/` directory

## 🤝 Contributing

### Development Setup
```bash
# Clone repository
git clone <repository-url>
cd nids_project

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # If available
```

### Code Standards
- **PEP 8** - Python style guide
- **Type Hints** - Use typing module
- **Testing** - Write tests for new features
- **Documentation** - Update docs for changes

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **NSL-KDD Dataset** - Network intrusion detection dataset
- **Scikit-learn** - Machine learning library
- **Flask** - Web framework
- **Bootstrap** - UI framework
- **Chart.js** - Data visualization
- **Scapy** - Packet manipulation

---

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section above
2. Run `python test_system.py` to verify installation
3. Enable debug mode for detailed error messages
4. Check logs in `logs/` directory

**Happy threat hunting! 🛡️**