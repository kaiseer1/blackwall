# Blackwall Framework  
## operation phantom liberty 

An AI-driven cybersecurity framework for proactive defense against modern threats.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)
![Version](https://img.shields.io/badge/version-2.0-orange.svg)

## 🛡️ Overview

Blackwall is an integrated AI-driven framework implementing three core modules that work together to provide comprehensive cybersecurity defense:

- **RZA (Reverse Zero-day Algorithm)**: ML-powered vulnerability detection with pattern recognition
- **TVM (Trust Verification Module)**: Adaptive zero-trust access control with contextual awareness
- **FPP (False Positive Protocol)**: Strategic deception deployment with attacker profiling

Based on research paper: *"Blackwall: An integrated AI-driven Framework for proactive Cybersecurity Defense"* by Basil Abdullah Alzahrani.

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/kaiseer1/blackwall.git
cd blackwall

# Install dependencies
pip install -r requirements.txt

# Run the framework
python blackwall.py
```

## 📊 Version Comparison

### Core Differences: `blackwall_v1.py` vs `blackwall.py` (v2.0)

| Feature | blackwall_v1.py | blackwall.py (v2.0) |
|---------|------------------|---------------------|
| **Lines of Code** | ~560 | ~1,570+ |
| **Logging** | Basic stdout | File + console logging |
| **Analytics** | None | Real-time streaming |
| **Pattern Detection** | Simple regex | ML + entropy + temporal |
| **Trust Evaluation** | Static logic | Adaptive + trend-based |
| **Deception Module** | Honeypot only | Strategy + profiling |
| **Performance Tracking** | Limited | Full metrics dashboard |


### 🧩 Module Enhancement Comparison

| Module | `blackwall_v1.py` Features | `blackwall.py` (v2.0) Enhancements |
|--------|-----------------------------|------------------------------------|
| **RZA** | • Simple pattern matching  
• Fixed thresholds  
• Basic anomaly detection | • ML feature extraction  
• Contextual thresholds  
• Pattern caching  
• Temporal correlation  
• Entropy analysis |
| **TVM** | • Basic trust scoring  
• Static policies  
• Simple location checks | • Trust trend analysis  
• Impossible travel detection  
• Device fingerprinting  
• Historical trust tracking  
• Resource-based sensitivity |
| **FPP** | • Random honeypots  
• Basic deception | • Attacker profiling  
• Strategic deception selection  
• Progressive tar pits  
• Success rate tracking  
• Context-aware deployment |

### 📈 Performance Metrics Comparison

| Metric                   | `blackwall_v1.py` (Legacy) | `blackwall.py` (v2.0) |
|--------------------------|-----------------------------|------------------------|
| Average Response Time    | ~100ms                      | ~41ms                  |
| Detection Rate           | ~70%                        | ~85%                   |
| False Positive Rate      | ~10%                        | <5%                    |
| Deception Success        | ~60%                        | ~86%                   |
| Memory Usage             | Low                         | Moderate               |
| CPU Usage                | Low                         | Low–Moderate           |


## 🔧 Architecture

### Decision Formula

The framework implements the unified decision formula:

```
Y = Block + deceive, if δ(t) > μ + kσ AND T(u,c) < τ AND F(x) > θ
```

Where:
- `δ(t)` = Anomaly score at time t
- `μ + kσ` = Dynamic anomaly threshold
- `T(u,c)` = Trust score for user u in context c
- `τ` = Trust threshold
- `F(x)` = Deception score
- `θ` = Deception threshold

### Signal Flow

```
Input → RZA (Vulnerability Detection)
         ↓
       TVM (Trust Evaluation)
         ↓
       FPP (Deception Decision)
         ↓
    Response Action
```

## 📈 Key Features

### 🔍 Enhanced Detection (RZA)
- **ML Feature Extraction**: Entropy, character distribution, pattern density
- **Contextual Awareness**: Time-based sensitivity adjustments
- **Pattern Learning**: Updates patterns based on confirmed attacks
- **Performance**: Sub-50ms analysis with caching

### 🔐 Adaptive Trust (TVM)
- **Multi-factor Trust**: Location, device, behavior, and history
- **Trend Analysis**: Tracks trust changes over time
- **Smart Policies**: Resource-sensitive thresholds
- **Zero-Trust**: Never trust, always verify

### 🎭 Strategic Deception (FPP)
- **Attacker Profiling**: Categorizes attackers (aggressive, targeted, automated)
- **Smart Honeypots**: Deploys appropriate deceptions based on attack type
- **Progressive Delays**: Exponential tar pit delays for persistent attackers
- **Success Tracking**: Learns from successful deceptions

### 📊 Real-time Analytics
- **Streaming Analysis**: Continuous monitoring of threats
- **Trend Detection**: Identifies coordinated attacks
- **Burst Detection**: Alerts on sudden threat increases
- **Pattern Entropy**: Measures attack diversity

## 🛠️ Configuration

### Adaptive Thresholds

The framework automatically adjusts thresholds based on:

| Context | Adjustment | Reasoning |
|---------|------------|-----------|
| **Night Hours** (10PM-6AM) | -20% threshold | Higher sensitivity during off-hours |
| **Weekends** | -15% threshold | Increased vigilance on weekends |
| **High Activity** | +20% threshold | Reduce false positives during busy periods |
| **Attack Burst** | -20% deception threshold | More aggressive deception during attacks |

### Resource Sensitivity

| Resource | Trust Multiplier | Security Level |
|----------|-----------------|----------------|
| `web_app` | 1.0x | Standard |
| `file_server` | 1.1x | Elevated |
| `database` | 1.2x | High |
| `system` | 1.3x | High |
| `admin_panel` | 1.5x | Critical |

## 📁 Project Structure

```
blackwall/
├── blackwall.py          # Enhanced framework (v2.0)
├── basil.py             # Original implementation (v1.0)
├── requirements.txt     # Dependencies
├── LICENSE             # Apache 2.0 License
├── README.md           # This file
└── blackwall_logs/     # Generated log files
    ├── blackwall_*.log # Main framework logs
    ├── rza_analysis.log # RZA module logs
    ├── tvm_trust.log   # TVM module logs
    └── fpp_deception.log # FPP module logs
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Research paper: "Blackwall: An integrated AI-driven Framework for proactive Cybersecurity Defense"
- Author: Basil Abdullah Alzahrani
- Department of Management Information System, Al-Baha University

## ⚠️ Disclaimer

This is a research implementation for educational purposes. It can change depending on new discoveries or new developments. **❤️**

## 📞 Contact

For questions or support, please open an issue on GitHub.

---

<p align="center">Made with ❤️ for cybersecurity</p>
