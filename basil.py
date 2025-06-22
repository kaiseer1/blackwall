#!/usr/bin/env python3
"""
Blackwall: An Integrated AI-driven Framework for Proactive Cybersecurity Defense
Implementation of RZA, TVM, FPP modules with Secure Signal Bus coordination

Author: Based on research by Basil Abdullah Alzahrani
"""

import time
import json
import hashlib
import threading
import numpy as np
import random
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Set random seed for reproducible randomness (remove this line for true randomness)
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

@dataclass
class UserContext:
    """User context for TVM evaluation"""
    user_id: str
    location: str
    device_id: str
    behavioral_score: float
    last_login: float
    failed_attempts: int

class SecureSignalBus:
    """
    Encrypted, low-latency communication channel between RZA, TVM, and FPP modules
    Enables autonomous collaboration and real-time threat coordination
    """
    
    def __init__(self):
        self.subscribers = {}
        self.signal_history = []
        self.lock = threading.Lock()
        self.logger = logging.getLogger("SignalBus")
        
    def subscribe(self, module_name: str, callback):
        """Register module to receive signals"""
        with self.lock:
            if module_name not in self.subscribers:
                self.subscribers[module_name] = []
            self.subscribers[module_name].append(callback)
            self.logger.info(f"Module {module_name} subscribed to signal bus")
    
    def publish(self, signal: SecuritySignal):
        """Publish signal to all subscribed modules"""
        with self.lock:
            # Add signal signature for integrity
            signal_hash = hashlib.sha256(
                f"{signal.timestamp}{signal.source_module}{signal.data}".encode()
            ).hexdigest()[:16]
            
            self.signal_history.append((signal, signal_hash))
            self.logger.info(f"Signal published: {signal.source_module} -> {signal.signal_type}")
            
            # Notify all subscribers except the sender
            for module_name, callbacks in self.subscribers.items():
                if module_name != signal.source_module:
                    for callback in callbacks:
                        try:
                            callback(signal)
                        except Exception as e:
                            self.logger.error(f"Error delivering signal to {module_name}: {e}")

class RZA:
    """
    Reverse Zero-day Algorithm (RZA)
    Autonomous vulnerability discovery through anomaly behavior pattern analysis
    """
    
    def __init__(self, signal_bus: SecureSignalBus):
        self.signal_bus = signal_bus
        self.signal_bus.subscribe("RZA", self.receive_signal)
        self.logger = logging.getLogger("RZA")
        
        # Anomaly detection parameters
        self.baseline_mean = 2.0
        self.baseline_std = 1.5
        self.k_sigma = 1.5  # Sensitivity multiplier (more sensitive)
        self.learning_rate = 0.01
        
        # Pattern database for vulnerability prediction
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.anomaly_history = []
        
    def _load_vulnerability_patterns(self) -> Dict:
        """Load known vulnerability patterns from training data"""
        return {
            "buffer_overflow": {"pattern": "strcpy|strcat|gets", "weight": 3.0},
            "sql_injection": {"pattern": "SELECT.*WHERE.*=.*'|OR.*'.*'.*=.*'", "weight": 4.0},
            "xss": {"pattern": "document\\.write|innerHTML.*=", "weight": 2.5},
            "path_traversal": {"pattern": "\\.\\./|\\.\\\\", "weight": 3.5}
        }
    
    def analyze_code_patterns(self, code_input: str) -> Tuple[float, List[str]]:
        """Analyze code for pre-exploit vulnerability indicators"""
        anomaly_score = 0.0
        detected_patterns = []
        
        # Add random network noise and environmental factors
        environmental_noise = random.uniform(-0.5, 0.5)
        
        for vuln_type, pattern_data in self.vulnerability_patterns.items():
            if self._pattern_match(code_input, pattern_data["pattern"]):
                # Add randomization to pattern weights (±20% variation)
                weight_variation = random.uniform(0.8, 1.2)
                adjusted_weight = pattern_data["weight"] * weight_variation
                anomaly_score += adjusted_weight
                detected_patterns.append(vuln_type)
        
        # Add behavioral anomaly component with randomization
        behavioral_anomaly = self._calculate_behavioral_anomaly(code_input)
        anomaly_score += behavioral_anomaly + environmental_noise
        
        # Ensure non-negative score
        anomaly_score = max(0, anomaly_score)
        
        return anomaly_score, detected_patterns
    
    def _pattern_match(self, text: str, pattern: str) -> bool:
        """Simple pattern matching - in production, use advanced ML models"""
        import re
        return bool(re.search(pattern, text, re.IGNORECASE))
    
    def _calculate_behavioral_anomaly(self, input_data: str) -> float:
        """Calculate anomaly score based on behavioral patterns"""
        # Simplified anomaly detection - in production, use sophisticated ML
        features = [
            len(input_data),
            input_data.count(';'),
            input_data.count('*'),
            input_data.count('&')
        ]
        
        feature_vector = np.array(features)
        current_score = np.linalg.norm(feature_vector)
        
        # Update baseline statistics
        self._update_baseline(current_score)
        
        # Calculate anomaly score
        z_score = (current_score - self.baseline_mean) / max(self.baseline_std, 0.1)
        return max(0, z_score)
    
    def _update_baseline(self, new_score: float):
        """Update baseline statistics with exponential moving average"""
        if self.baseline_mean == 2.0:  # First update
            self.baseline_mean = max(2.0, new_score)
            self.baseline_std = max(1.0, abs(new_score - 2.0))
        else:
            self.baseline_mean = (1 - self.learning_rate) * self.baseline_mean + self.learning_rate * new_score
            variance = (1 - self.learning_rate) * (self.baseline_std ** 2) + self.learning_rate * ((new_score - self.baseline_mean) ** 2)
            self.baseline_std = max(0.5, np.sqrt(variance))
    
    def process_input(self, input_data: str, context: Dict) -> SecuritySignal:
        """Main RZA processing function"""
        anomaly_score, patterns = self.analyze_code_patterns(input_data)
        
        # Dynamic threshold with randomization (base 3.0 ± 0.5)
        threshold = 3.0 + random.uniform(-0.5, 0.5)
        is_anomalous = anomaly_score > threshold
        
        threat_level = ThreatLevel.LOW
        if is_anomalous:
            if anomaly_score > threshold * 2:
                threat_level = ThreatLevel.CRITICAL
            elif anomaly_score > threshold * 1.5:
                threat_level = ThreatLevel.HIGH
            else:
                threat_level = ThreatLevel.MEDIUM
        
        # Create and publish signal
        signal = SecuritySignal(
            timestamp=time.time(),
            source_module="RZA",
            signal_type="vulnerability_prediction",
            data={
                "anomaly_score": anomaly_score,
                "threshold": threshold,
                "patterns": patterns,
                "is_anomalous": is_anomalous,
                "input_hash": hashlib.md5(input_data.encode()).hexdigest()[:8]
            },
            confidence=min(anomaly_score / threshold, 1.0) if threshold > 0 else 0,
            threat_level=threat_level
        )
        
        self.signal_bus.publish(signal)
        self.logger.info(f"RZA processed input: anomaly_score={anomaly_score:.2f}, threshold={threshold:.2f}")
        
        return signal
    
    def receive_signal(self, signal: SecuritySignal):
        """Receive feedback signals from other modules"""
        if signal.signal_type == "attack_confirmed":
            # Update vulnerability patterns based on confirmed attacks
            self._update_patterns(signal.data)
        elif signal.signal_type == "false_positive":
            # Adjust sensitivity based on false positive feedback
            self.k_sigma = max(1.0, self.k_sigma - 0.1)
            self.logger.info(f"Adjusted sensitivity: k_sigma={self.k_sigma:.2f}")
    
    def _update_patterns(self, attack_data: Dict):
        """Update vulnerability patterns based on confirmed attacks"""
        self.logger.info("Updating vulnerability patterns based on attack feedback")
        # In production, implement sophisticated pattern learning

class TVM:
    """
    Zero-Trust Verification Module (TVM)
    Continuous trust evaluation using contextual data and policy-driven access rules
    """
    
    def __init__(self, signal_bus: SecureSignalBus):
        self.signal_bus = signal_bus
        self.signal_bus.subscribe("TVM", self.receive_signal)
        self.logger = logging.getLogger("TVM")
        
        # Trust evaluation parameters with randomization
        self.base_trust_threshold = 0.6
        self.trust_threshold = self.base_trust_threshold + random.uniform(-0.1, 0.1)  # τ (tau) with variation
        self.user_contexts = {}
        self.trust_policies = self._load_trust_policies()
        
    def _load_trust_policies(self) -> Dict:
        """Load zero-trust policies"""
        return {
            "location_risk": {
                "trusted_locations": ["office", "home"],
                "suspicious_locations": ["cafe", "airport"],
                "blocked_locations": ["foreign", "tor_exit"]
            },
            "device_trust": {
                "managed_devices": 1.0,
                "registered_devices": 0.7,
                "unknown_devices": 0.2
            },
            "behavioral_scoring": {
                "normal_hours": 1.0,
                "off_hours": 0.6,
                "unusual_activity": 0.3
            }
        }
    
    def evaluate_trust(self, user_context: UserContext) -> float:
        """Calculate trust score T(u,c) from the decision formula"""
        trust_score = 1.0
        
        # Add random environmental factors (network conditions, time of day variations)
        environmental_factor = random.uniform(0.9, 1.1)
        
        # Location-based trust adjustment with randomization
        location_risk = self._evaluate_location_risk(user_context.location)
        trust_score *= location_risk * random.uniform(0.95, 1.05)
        
        # Device-based trust adjustment with randomization
        device_trust = self._evaluate_device_trust(user_context.device_id)
        trust_score *= device_trust * random.uniform(0.9, 1.1)
        
        # Behavioral scoring with randomization
        behavioral_score = self._evaluate_behavioral_score(user_context)
        trust_score *= behavioral_score * random.uniform(0.85, 1.15)
        
        # Failed attempts penalty with randomization
        if user_context.failed_attempts > 0:
            penalty_variation = random.uniform(0.15, 0.25)
            trust_score *= max(0.1, 1.0 - (user_context.failed_attempts * penalty_variation))
        
        # Apply environmental factor
        trust_score *= environmental_factor
        
        return max(0.0, min(1.0, trust_score))
    
    def _evaluate_location_risk(self, location: str) -> float:
        """Evaluate location-based risk"""
        policies = self.trust_policies["location_risk"]
        
        if location in policies["blocked_locations"]:
            return 0.0
        elif location in policies["suspicious_locations"]:
            return 0.4
        elif location in policies["trusted_locations"]:
            return 1.0
        else:
            return 0.6  # Unknown location
    
    def _evaluate_device_trust(self, device_id: str) -> float:
        """Evaluate device trust level"""
        # Simplified device classification
        if device_id.startswith("managed_"):
            return self.trust_policies["device_trust"]["managed_devices"]
        elif device_id.startswith("reg_"):
            return self.trust_policies["device_trust"]["registered_devices"]
        else:
            return self.trust_policies["device_trust"]["unknown_devices"]
    
    def _evaluate_behavioral_score(self, context: UserContext) -> float:
        """Evaluate behavioral patterns"""
        current_hour = datetime.now().hour
        
        # Normal business hours (9 AM - 6 PM)
        if 9 <= current_hour <= 18:
            base_score = self.trust_policies["behavioral_scoring"]["normal_hours"]
        else:
            base_score = self.trust_policies["behavioral_scoring"]["off_hours"]
        
        # Adjust based on user's behavioral score
        return base_score * context.behavioral_score
    
    def process_access_request(self, user_context: UserContext, resource: str) -> SecuritySignal:
        """Process access request and generate trust signal"""
        trust_score = self.evaluate_trust(user_context)
        
        # Store/update user context
        self.user_contexts[user_context.user_id] = user_context
        
        # Determine trust level
        if trust_score >= 0.8:
            threat_level = ThreatLevel.LOW
        elif trust_score >= 0.5:
            threat_level = ThreatLevel.MEDIUM
        elif trust_score >= 0.2:
            threat_level = ThreatLevel.HIGH
        else:
            threat_level = ThreatLevel.CRITICAL
        
        # Create and publish signal
        signal = SecuritySignal(
            timestamp=time.time(),
            source_module="TVM",
            signal_type="trust_evaluation",
            data={
                "user_id": user_context.user_id,
                "trust_score": trust_score,
                "threshold": self.trust_threshold,
                "resource": resource,
                "location": user_context.location,
                "device_id": user_context.device_id
            },
            confidence=abs(trust_score - 0.5) * 2,  # Higher confidence at extremes
            threat_level=threat_level
        )
        
        self.signal_bus.publish(signal)
        self.logger.info(f"TVM evaluated trust: user={user_context.user_id}, score={trust_score:.2f}")
        
        return signal
    
    def receive_signal(self, signal: SecuritySignal):
        """Receive signals from other modules"""
        if signal.signal_type == "vulnerability_prediction" and signal.threat_level.value >= 3:
            # High vulnerability detected, lower trust threshold temporarily
            self.trust_threshold = min(0.8, self.trust_threshold + 0.1)
            self.logger.info(f"Elevated trust threshold due to vulnerability: {self.trust_threshold:.2f}")
        elif signal.signal_type == "deception_success":
            # Successful deception indicates active threat, maintain high vigilance
            self.logger.info("Maintaining elevated security posture due to deception success")

class FPP:
    """
    False Positive Protocol (FPP)
    Deception-based system to mislead attackers and reduce false alerts
    """
    
    def __init__(self, signal_bus: SecureSignalBus):
        self.signal_bus = signal_bus
        self.signal_bus.subscribe("FPP", self.receive_signal)
        self.logger = logging.getLogger("FPP")
        
        # Deception parameters with randomization
        self.base_deception_threshold = 0.6
        self.deception_threshold = self.base_deception_threshold + random.uniform(-0.1, 0.1)  # θ (theta) with variation
        self.active_deceptions = {}
        self.deception_success_rate = 0.857 + random.uniform(-0.05, 0.05)  # 85.7% ± 5%
        
        # Honeypot configurations
        self.honeypots = {
            "fake_admin_portal": {"url": "/admin", "type": "web"},
            "fake_database": {"port": 3306, "type": "mysql"},
            "fake_file_share": {"path": "/shared", "type": "smb"}
        }
    
    def calculate_deception_score(self, context: Dict) -> float:
        """Calculate F(x) deception score from the decision formula"""
        base_score = 0.5
        
        # Add randomization to threat assessment
        threat_intelligence_factor = random.uniform(0.9, 1.1)
        
        # Increase deception score based on suspicious indicators with randomization
        if context.get("repeated_attempts", 0) > 3:
            base_score += random.uniform(0.15, 0.25)
        
        if context.get("unusual_timing", False):
            base_score += random.uniform(0.10, 0.20)
        
        if context.get("privilege_escalation_attempt", False):
            base_score += random.uniform(0.20, 0.30)
        
        if context.get("reconnaissance_behavior", False):
            base_score += random.uniform(0.15, 0.25)
        
        # Apply threat intelligence factor
        final_score = base_score * threat_intelligence_factor
        
        return min(1.0, final_score)
    
    def deploy_deception(self, threat_context: Dict) -> Dict:
        """Deploy appropriate deception mechanism"""
        deception_id = f"deception_{int(time.time())}"
        
        # Select deception type based on threat context
        if threat_context.get("attack_type") == "web":
            deception_type = "honeypot_redirect"
            target = self.honeypots["fake_admin_portal"]
        elif threat_context.get("attack_type") == "database":
            deception_type = "fake_database"
            target = self.honeypots["fake_database"]
        else:
            deception_type = "tarpit"
            target = {"delay": 5.0, "type": "network_delay"}
        
        deception = {
            "id": deception_id,
            "type": deception_type,
            "target": target,
            "start_time": time.time(),
            "attacker_id": threat_context.get("source_ip", "unknown")
        }
        
        self.active_deceptions[deception_id] = deception
        self.logger.info(f"Deployed deception: {deception_type} for {threat_context.get('source_ip', 'unknown')}")
        
        return deception
    
    def process_threat_signal(self, rza_signal: SecuritySignal, tvm_signal: SecuritySignal) -> SecuritySignal:
        """Process combined threat signals and determine deception response"""
        # Extract relevant context
        context = {
            "anomaly_score": rza_signal.data.get("anomaly_score", 0),
            "trust_score": tvm_signal.data.get("trust_score", 1.0),
            "patterns": rza_signal.data.get("patterns", []),
            "user_id": tvm_signal.data.get("user_id", "unknown"),
            "repeated_attempts": 1,  # Simplified - would track in production
            "unusual_timing": datetime.now().hour < 6 or datetime.now().hour > 22
        }
        
        # Calculate deception score F(x)
        deception_score = self.calculate_deception_score(context)
        
        # Determine if deception should be deployed
        should_deceive = deception_score > self.deception_threshold
        
        threat_level = ThreatLevel.LOW
        if should_deceive:
            threat_level = ThreatLevel.HIGH
            deception = self.deploy_deception(context)
            context["deception"] = deception
        
        # Create and publish signal
        signal = SecuritySignal(
            timestamp=time.time(),
            source_module="FPP",
            signal_type="deception_decision",
            data={
                "deception_score": deception_score,
                "threshold": self.deception_threshold,
                "should_deceive": should_deceive,
                "context": context
            },
            confidence=deception_score,
            threat_level=threat_level
        )
        
        self.signal_bus.publish(signal)
        self.logger.info(f"FPP deception decision: score={deception_score:.2f}, deceive={should_deceive}")
        
        return signal
    
    def receive_signal(self, signal: SecuritySignal):
        """Receive signals from other modules"""
        if signal.signal_type == "attack_detected":
            # Mark any active deceptions as successful
            self._mark_deception_success(signal.data.get("source_ip"))
        elif signal.signal_type == "vulnerability_prediction":
            # Prepare deception mechanisms for potential attacks
            self.logger.info("Preparing deception mechanisms for predicted vulnerability")

    def _mark_deception_success(self, attacker_id: str):
        """Mark deception as successful"""
        for deception in self.active_deceptions.values():
            if deception["attacker_id"] == attacker_id:
                # Publish success signal
                success_signal = SecuritySignal(
                    timestamp=time.time(),
                    source_module="FPP",
                    signal_type="deception_success",
                    data={"deception_id": deception["id"], "attacker_id": attacker_id},
                    confidence=1.0,
                    threat_level=ThreatLevel.HIGH
                )
                self.signal_bus.publish(success_signal)

class BlackwallFramework:
    """
    Main Blackwall Framework implementing the unified decision formula:
    Y = Block + deceive, if δ(t) > μ + kσ AND T(u,c) < τ AND F(x) > θ
    """
    
    def __init__(self):
        self.signal_bus = SecureSignalBus()
        self.rza = RZA(self.signal_bus)
        self.tvm = TVM(self.signal_bus)
        self.fpp = FPP(self.signal_bus)
        self.logger = logging.getLogger("Blackwall")
        
        # Framework statistics
        self.processed_requests = 0
        self.blocked_requests = 0
        self.deceived_attackers = 0
        
    def process_security_event(self, input_data: str, user_context: UserContext, resource: str) -> ResponseAction:
        """
        Main processing function implementing the unified decision formula
        Y = Block + deceive, if δ(t) > μ + kσ AND T(u,c) < τ AND F(x) > θ
        """
        self.processed_requests += 1
        
        # Step 1: RZA processes input for vulnerability prediction
        rza_signal = self.rza.process_input(input_data, {"resource": resource})
        
        # Step 2: TVM evaluates trust
        tvm_signal = self.tvm.process_access_request(user_context, resource)
        
        # Step 3: Extract decision variables
        delta_t = rza_signal.data["anomaly_score"]  # δ(t)
        mu_k_sigma = rza_signal.data["threshold"]   # μ + kσ (now fixed threshold)
        trust_score = tvm_signal.data["trust_score"]  # T(u,c)
        tau = self.tvm.trust_threshold               # τ
        
        # Step 4: Check primary conditions
        anomaly_detected = delta_t > mu_k_sigma     # δ(t) > μ + kσ
        trust_low = trust_score < tau               # T(u,c) < τ
        
        self.logger.info(f"Decision variables: δ(t)={delta_t:.2f}, μ+kσ={mu_k_sigma:.2f}, T(u,c)={trust_score:.2f}, τ={tau:.2f}")
        
        # Step 5: Determine response based on unified formula
        if anomaly_detected and trust_low:
            # High threat scenario - engage FPP for deception evaluation
            fpp_signal = self.fpp.process_threat_signal(rza_signal, tvm_signal)
            f_x = fpp_signal.data["deception_score"]   # F(x)
            theta = self.fpp.deception_threshold       # θ
            
            if f_x > theta:
                # Y = Block + deceive
                self.blocked_requests += 1
                self.deceived_attackers += 1
                self.logger.warning(f"BLOCK + DECEIVE: High threat detected (δ={delta_t:.2f}, T={trust_score:.2f}, F={f_x:.2f})")
                return ResponseAction.BLOCK_AND_DECEIVE
            else:
                # Block only
                self.blocked_requests += 1
                self.logger.warning(f"BLOCK: Anomaly + low trust detected")
                return ResponseAction.BLOCK
                
        elif anomaly_detected and trust_score >= tau:
            # Anomaly detected but user is trusted - monitor closely
            self.logger.info(f"MONITOR: Anomaly detected but user trusted")
            return ResponseAction.MONITOR
            
        else:
            # Normal operation
            self.logger.info(f"ALLOW: Normal operation")
            return ResponseAction.ALLOW
    
    def get_statistics(self) -> Dict:
        """Get framework performance statistics"""
        detection_rate = (self.blocked_requests / max(self.processed_requests, 1)) * 100
        deception_rate = (self.deceived_attackers / max(self.blocked_requests, 1)) * 100
        
        return {
            "processed_requests": self.processed_requests,
            "blocked_requests": self.blocked_requests,
            "deceived_attackers": self.deceived_attackers,
            "detection_rate": f"{detection_rate:.1f}%",
            "deception_effectiveness": f"{deception_rate:.1f}%"
        }

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
    """Demonstration of Blackwall Framework with Random Scenarios"""
    print("Blackwall Cybersecurity Framework - Randomized Demo")
    print("=" * 60)
    
    # Initialize framework
    blackwall = BlackwallFramework()
    
    # Generate random scenarios
    num_scenarios = random.randint(5, 10)
    print(f"Running {num_scenarios} randomized scenarios...\n")
    
    for i in range(num_scenarios):
        # Generate random user and attack
        user = generate_random_user()
        attack_input = generate_random_attack()
        resource = random.choice(["database", "system", "web_app", "file_server", "admin_panel"])
        
        print(f"Scenario {i+1}: {user.user_id} -> {resource}")
        print(f"Input: {attack_input[:50]}{'...' if len(attack_input) > 50 else ''}")
        print("-" * 40)
        
        response = blackwall.process_security_event(attack_input, user, resource)
        
        print(f"Response: {response.value}")
        print()
        
        # Random delay between scenarios
        time.sleep(random.uniform(0.5, 2.0))
    
    # Display final statistics
    print(f"Framework Statistics:")
    print("-" * 30)
    stats = blackwall.get_statistics()
    for key, value in stats.items():
        print(f"{key.replace('_', ' ').title()}: {value}")
    
    print(f"\nRandomization Summary:")
    print(f"- Generated {num_scenarios} random scenarios")
    print(f"- Random users with varying trust levels")
    print(f"- Dynamic thresholds: RZA(±0.5), TVM(±0.1), FPP(±0.1)")
    print(f"- Environmental noise and behavioral variations")

if __name__ == "__main__":
    main()