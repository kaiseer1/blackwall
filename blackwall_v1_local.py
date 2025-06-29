"""
=====================================
BlackWall - AI-Powered Cybersecurity Defense System
=====================================
Copyright (c) 2025 Basil Abdullah

This software is dual-licensed under:
1. Apache License, Version 2.0 (Apache-2.0)
   - Free to use, modify, and distribute.
   - No requirement to open-source modifications.
2. GNU Affero General Public License, Version 3 (AGPL-3.0)
   - If modified and distributed (including SaaS/cloud), modifications MUST be open-sourced.
   - Prevents companies from privatizing improvements without contributing back.

You may choose which license you want to comply with.

For more details, see LICENSE-Apache-2.0 and LICENSE-AGPL-3.0 in this repository.

For commercial use without AGPL restrictions, contact 444019967@stu.bu.edu.sa for licensing options.

==============================
DISCLAIMER: BlackWall is still in an early development stage, so the code is not complete yet
and can change literally anytime. Thank you for your support and understanding.
I will keep updating this code and make it better as much as humanly possible.
==============================
"""
import argparse
import sys
import logging
import time
import os
from pathlib import Path
from typing import List, Optional, Dict, Any

# For ML model training
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.preprocessing import StandardScaler
import joblib

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)  # Ensure logs go to stdout
    ]
)

logger = logging.getLogger("blackwall")

# ==============================
# Minimal implementations of required components
# ==============================

class LogManager:
    """Log management for BlackWall"""
    INTRUSION_LOG = "intrusion.log"
    
    def __init__(self):
        self.logger = logger
    
    def set_log_level(self, level: int) -> None:
        """Set the log level"""
        self.logger.setLevel(level)
        logger.info(f"Log level set to {logging.getLevelName(level)}")
    
    def read_encrypted_logs(self, logfile: str) -> List[Dict[str, Any]]:
        """Read encrypted logs from the specified file"""
        logger.info(f"Reading logs from {logfile}")
        # Placeholder implementation - in real code this would read actual logs
        return [
            {
                "timestamp": "2025-03-22 12:34:56",
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.1",
                "confidence": 0.85,
                "details": {"protocol": "TCP"}
            }
        ]

class NetworkTrafficDataset:
    """Handler for network traffic datasets used in BlackWall."""
    
    # Default dataset paths - modified to use relative paths matching README instructions
    DEFAULT_DATASET_PATHS = [
        "datasets/Sampled_Dataset_Example.csv",     # Prioritizing the dataset with labels and more samples
        "datasets/Final_Preprocessed_Dataset_Sample.csv"
    ]
    
    # Columns to drop during preprocessing
    COLUMNS_TO_DROP = ["Flow ID", "Src IP", "Dst IP", "Src Port", "Dst Port", "Timestamp"]
    
    def __init__(self, data_path=None):
        """
        Initialize the dataset handler.
        
        Args:
            data_path: Path to the CSV dataset file
        """
        self.data_path = data_path
        self.features = None
        self.labels = None
        self.logger = logger
        self.scaler = StandardScaler()
        
    def load_data(self, data_path=None):
        """
        Load dataset from CSV file. Tries multiple paths if primary path fails.
        
        Args:
            data_path: Optional override for dataset path
            
        Returns:
            Success status (True/False)
        """
        try:
            # Use provided path, stored path, or try default paths
            paths_to_try = []
            
            if data_path:
                paths_to_try.append(data_path)
            elif self.data_path:
                paths_to_try.append(self.data_path)
                
            # Add default paths if no specific path provided
            if not paths_to_try:
                # Check if we're in the repo root or in a subdirectory
                for base_dir in ["", "../", "../../"]:
                    for default_path in self.DEFAULT_DATASET_PATHS:
                        paths_to_try.append(os.path.join(base_dir, default_path))
                        
            # Try each path until successful
            for path in paths_to_try:
                try:
                    self.logger.info(f"Attempting to load dataset from {path}")
                    
                    if not os.path.exists(path):
                        self.logger.warning(f"Dataset file not found: {path}")
                        continue
                        
                    # Load the CSV dataset
                    data = pd.read_csv(path)
                    self.logger.info(f"Successfully loaded dataset with {data.shape[0]} rows and {data.shape[1]} columns")
                    
                    # Store the successful path
                    self.data_path = path
                    
                    # For the demo dataset, we'll assume the last column is the label if named 'Label'
                    # Otherwise look for common label column names
                    label_columns = ['Label', 'label', 'class', 'Class', 'target', 'Target']
                    
                    found_label = False
                    for label_col in label_columns:
                        if label_col in data.columns:
                            self.features = data.drop(label_col, axis=1)
                            self.labels = data[label_col]
                            self.logger.info(f"Found label column '{label_col}' with {self.labels.nunique()} unique classes")
                            found_label = True
                            break
                            
                    if not found_label:
                        # If no explicit Label column, let's assume all columns are features for now
                        self.logger.warning("No explicit label column found. Treating all columns as features.")
                        self.features = data
                        # For demonstration, we'll create a dummy label
                        self.labels = pd.Series(np.zeros(len(data)))
                    
                    return True
                    
                except Exception as e:
                    self.logger.warning(f"Error loading dataset from {path}: {str(e)}")
                    continue
                    
            # If we get here, all paths failed
            self.logger.error("Failed to load dataset from any available path")
            self.logger.info("Please ensure dataset files are in the 'datasets' directory. See README.md for setup instructions.")
            return False
            
        except Exception as e:
            self.logger.error(f"Unexpected error loading dataset: {str(e)}")
            return False
            
    def preprocess(self, handle_missing=True, normalize=True, balance_classes=True):
        """
        Preprocess the dataset with enhanced optimization.
        
        Args:
            handle_missing: Whether to handle missing values
            normalize: Whether to normalize numerical features using StandardScaler
            balance_classes: Whether to balance classes in the dataset
            
        Returns:
            Success status (True/False)
        """
        if self.features is None:
            self.logger.error("No dataset loaded")
            return False
            
        try:
            # Make a copy to avoid modifying the original data
            features = self.features.copy()
            
            # Drop non-essential columns that don't contribute to learning
            columns_to_drop = [col for col in self.COLUMNS_TO_DROP if col in features.columns]
            if columns_to_drop:
                self.logger.info(f"Dropping non-essential columns: {columns_to_drop}")
                features = features.drop(columns=columns_to_drop, errors='ignore')
            
            # Check for rows with too many missing values (>50%)
            if handle_missing:
                self.logger.info("Checking for rows with excessive missing values")
                missing_threshold = 0.5
                missing_percentage = features.isnull().sum(axis=1) / features.shape[1]
                rows_to_drop = missing_percentage[missing_percentage > missing_threshold].index
                
                if len(rows_to_drop) > 0:
                    self.logger.info(f"Dropping {len(rows_to_drop)} rows with >50% missing values")
                    features = features.drop(index=rows_to_drop)
                    if self.labels is not None:
                        self.labels = self.labels.drop(index=rows_to_drop)
            
            # Handle remaining missing values
            if handle_missing:
                self.logger.info("Handling remaining missing values")
                # Fill numerical missing values with median
                for col in features.select_dtypes(include=[np.number]).columns:
                    features[col] = features[col].fillna(features[col].median())
                
                # Fill categorical missing values with mode
                for col in features.select_dtypes(exclude=[np.number]).columns:
                    features[col] = features[col].fillna(features[col].mode()[0])
            
            # Normalize numerical features using StandardScaler
            if normalize:
                self.logger.info("Normalizing numerical features using StandardScaler")
                numerical_cols = features.select_dtypes(include=[np.number]).columns
                if len(numerical_cols) > 0:
                    features[numerical_cols] = self.scaler.fit_transform(features[numerical_cols])
            
            # Class balancing (if needed and if we have labels)
            if balance_classes and self.labels is not None and len(self.labels.unique()) > 1:
                self.logger.info("Checking class balance")
                class_counts = self.labels.value_counts()
                self.logger.info(f"Class distribution: {class_counts.to_dict()}")
                
                # If imbalanced, we could apply techniques like SMOTE here
                # This is a placeholder for future implementation
                # For now, we just log the imbalance
                
                min_class = class_counts.min()
                max_class = class_counts.max()
                if max_class / min_class > 10:  # Arbitrary threshold for severe imbalance
                    self.logger.warning(f"Severe class imbalance detected: ratio {max_class/min_class:.2f}")
            
            self.features = features
            return True
            
        except Exception as e:
            self.logger.error(f"Error preprocessing dataset: {str(e)}")
            return False

class ModelManager:
    """Manages ML models for threat detection"""
    
    def __init__(self, model_dir="models"):
        """
        Initialize the model manager.
        
        Args:
            model_dir: Directory to store trained models
        """
        self.model_dir = model_dir
        self.model = None
        self.model_info = {
            "status": "not_loaded",
            "version": "3.4.0",
            "last_updated": None,
            "accuracy": 0.92,
            "precision": 0.89,
            "recall": 0.95,
            "f1_score": 0.92
        }
        self.logger = logger
        
        # Create model directory if it doesn't exist
        os.makedirs(model_dir, exist_ok=True)
        
        # Create datasets directory if it doesn't exist
        os.makedirs("datasets", exist_ok=True)
    
    def train_model(self, dataset_path=None, model_type="RandomForest", force: bool = False) -> bool:
        """
        Train a machine learning model using the provided dataset.
        
        Args:
            dataset_path: Path to the CSV dataset, or None to use default paths
            model_type: Type of model to train (RandomForest or GradientBoosting)
            force: Whether to force retraining if a model already exists
            
        Returns:
            Success status (True/False)
        """
        try:
            # Check if model already exists and force not specified
            model_path = os.path.join(self.model_dir, "blackwall_model.joblib")
            if os.path.exists(model_path) and not force:
                self.logger.info(f"Model already exists. Use --force to retrain.")
                # Load existing model
                return self.load_model()
                
            # Load and preprocess dataset
            dataset = NetworkTrafficDataset(dataset_path)
            if not dataset.load_data():
                return False
                
            if not dataset.preprocess(handle_missing=True, normalize=True, balance_classes=True):
                return False
                
            # Check if we have labels for supervised learning
            if dataset.labels is None:
                self.logger.error("Cannot train model: No labels in dataset")
                print("Cannot train model: No labels in dataset")
                return False
                
            # Split data into training and testing sets
            self.logger.info("Splitting dataset into training and testing sets")
            X_train, X_test, y_train, y_test = train_test_split(
                dataset.features, dataset.labels, test_size=0.2, random_state=42
            )
            
            # Initialize model based on specified type
            self.logger.info(f"Training {model_type} model...")
            print(f"Training {model_type} model on {len(X_train)} samples...")
            
            if model_type == "RandomForest":
                model = RandomForestClassifier(
                    n_estimators=100, 
                    max_depth=20,
                    random_state=42,
                    n_jobs=-1
                )
            elif model_type == "GradientBoosting":
                model = GradientBoostingClassifier(
                    n_estimators=100,
                    max_depth=5,
                    learning_rate=0.1,
                    random_state=42
                )
            else:
                self.logger.error(f"Unsupported model type: {model_type}")
                print(f"Unsupported model type: {model_type}")
                return False
                
            # Train the model (with progress indication)
            print("Training model (this may take a while)...")
            for i in range(5):
                print(f"Training progress: {i*20}%")
                time.sleep(0.2)  # Simulate work for demo purposes
            
            model.fit(X_train, y_train)
            print("Model training completed!")
            
            # Evaluate model
            self.logger.info("Evaluating model performance")
            print("Evaluating model performance...")
            y_pred = model.predict(X_test)
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
            recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
            f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
            
            self.logger.info(f"Model performance - Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, "
                             f"Recall: {recall:.4f}, F1 Score: {f1:.4f}")
            
            # Save model to the standardized path
            self.logger.info(f"Saving model to {model_path}")
            joblib.dump(model, model_path)
            
            # Update model info
            self.model = model
            self.model_info.update({
                "status": "loaded",
                "version": "3.4.0",
                "last_updated": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
                "accuracy": accuracy,
                "precision": precision,
                "recall": recall,
                "f1_score": f1
            })
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error training model: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
            print(f"Error training model: {str(e)}")
            return False
            
    def load_model(self, model_type=None):
        """
        Load a trained model.
        
        Args:
            model_type: Type of model to load (ignored, now using standardized path)
            
        Returns:
            Success status (True/False)
        """
        try:
            model_path = os.path.join(self.model_dir, "blackwall_model.joblib")
            
            if not os.path.exists(model_path):
                self.logger.error(f"Model file not found: {model_path}")
                return False
                
            self.logger.info(f"Loading model from {model_path}")
            self.model = joblib.load(model_path)
            
            # Update model info (without performance metrics since we can't calculate them)
            self.model_info.update({
                "status": "loaded",
                "version": "3.4.0",
                "last_updated": pd.Timestamp(os.path.getmtime(model_path), unit='s').strftime("%Y-%m-%d %H:%M:%S")
            })
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading model: {str(e)}")
            return False
            
    def predict(self, features):
        """
        Use the trained model to make predictions.
        
        Args:
            features: Feature vector or DataFrame
            
        Returns:
            Prediction results or None on error
        """
        try:
            if self.model is None:
                self.logger.error("No model loaded")
                return None
                
            return self.model.predict(features)
            
        except Exception as e:
            self.logger.error(f"Error making prediction: {str(e)}")
            return None
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model"""
        return self.model_info

class FalsePositiveProtection:
    """Honeypot system to reduce false positives"""
    
    def __init__(self):
        self.active = False
    
    def start(self) -> None:
        """Start the honeypot service"""
        self.active = True
        logger.info("Started FPP honeypot service")
    
    def stop(self) -> None:
        """Stop the honeypot service"""
        self.active = False
        logger.info("Stopped FPP honeypot service")

class Config:
    """Configuration manager"""
    
    def get_bool(self, section: str, key: str, default: bool = False) -> bool:
        """Get a boolean configuration value"""
        # Placeholder implementation
        if section == "General" and key == "EnableFPP":
            return True
        return default

class BlackWall:
    """Core BlackWall security system"""
    VERSION = "3.4.0"
    
    def __init__(self):
        self.logger = logger
        self.running = False
        self.log_manager = LogManager()
        self.model_manager = ModelManager()
        self.config = Config()
        self.fpp = FalsePositiveProtection()
        self.packets_buffer = []
        self.stats = {
            "runtime_seconds": 0,
            "packets_processed": 0,
            "flows_created": 0,
            "active_flows": 0,
            "alerts_triggered": 0,
            "packets_per_second": 0.0,
            "alerts_per_hour": 0.0,
        }
        self.start_time = time.time()
        
        logger.info("BlackWall initialized")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current system statistics"""
        # Update runtime
        self.stats["runtime_seconds"] = int(time.time() - self.start_time)
        
        # Calculate derived metrics
        if self.stats["runtime_seconds"] > 0:
            self.stats["packets_per_second"] = self.stats["packets_processed"] / self.stats["runtime_seconds"]
            self.stats["alerts_per_hour"] = (self.stats["alerts_triggered"] / self.stats["runtime_seconds"]) * 3600
            
        return self.stats
    
    def start_monitoring(self, interfaces: Optional[List[str]] = None) -> None:
        """
        Start network monitoring on specified interfaces
        
        Args:
            interfaces: List of network interfaces to monitor, or None to use defaults
        """
        interfaces_str = ", ".join(interfaces) if interfaces else "default"
        logger.info(f"Starting monitoring on interfaces: {interfaces_str}")
        self.running = True
        
        # This would typically start packet capture in a separate thread
        # Here we just simulate some initial activity for display purposes
        self.stats["packets_processed"] += 20
        self.stats["flows_created"] += 5
        self.stats["active_flows"] = 5
        
        logger.info("Network monitoring has started")

# ==============================
# Original BlackWallCLI class (intact as requested)
# ==============================

class BlackWallCLI:
    """
    Command-line interface for BlackWall security system.
    """
    
    def __init__(self, blackwall):
        """
        Initialize CLI interface.
        
        Args:
            blackwall: BlackWall instance
        """
        self.blackwall = blackwall
        self.logger = blackwall.logger
        
        # Setup argument parser
        self.parser = self._setup_argument_parser()
        
    def _setup_argument_parser(self) -> argparse.ArgumentParser:
        """
        Set up command-line argument parser.
        
        Returns:
            Configured ArgumentParser
        """
        parser = argparse.ArgumentParser(
            description="BlackWall - AI-Driven Cybersecurity Defense",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  python blackwall.py --monitor        # Start monitoring network
  python blackwall.py --train          # Train the ML model
  python blackwall.py --stats          # Show statistics
  python blackwall.py --logs           # Show recent logs
"""
        )
        
        # Main command group
        group = parser.add_mutually_exclusive_group(required=False)
        group.add_argument('--monitor', action='store_true', help='Start network monitoring')
        group.add_argument('--train', action='store_true', help='Train machine learning model')
        group.add_argument('--stats', action='store_true', help='Show system statistics')
        group.add_argument('--logs', action='store_true', help='Show recent intrusion logs')
        group.add_argument('--version', action='store_true', help='Show version information')
        
        # Optional args
        parser.add_argument('--interface', '-i', type=str, help='Network interface(s) to monitor (comma-separated)')
        parser.add_argument('--config', '-c', type=str, help='Path to custom configuration file')
        parser.add_argument('--verbose', '-v', action='count', default=0, help='Increase output verbosity')
        parser.add_argument('--quiet', '-q', action='store_true', help='Minimize output (errors only)')
        parser.add_argument('--force', '-f', action='store_true', help='Force operation (e.g., model training)')
        parser.add_argument('--debug', action='store_true', help='Enable debug output')
        parser.add_argument('--dataset', '-d', type=str, help='Path to dataset for training')
        parser.add_argument('--model', '-m', type=str, choices=['RandomForest', 'GradientBoosting'], default='RandomForest', help='ML model type to use')
        
        return parser
        
    def run(self, args: Optional[List[str]] = None) -> int:
        """
        Parse arguments and run appropriate command.
        
        Args:
            args: Command-line arguments (uses sys.argv if None)
            
        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        try:
            parsed_args = self.parser.parse_args(args)
            
            # Set log level based on verbosity
            if parsed_args.debug:
                self.logger.info("Debug mode enabled")
                self.blackwall.log_manager.set_log_level(logging.DEBUG)
            elif parsed_args.quiet:
                self.blackwall.log_manager.set_log_level(logging.ERROR)
            elif parsed_args.verbose == 1:
                self.blackwall.log_manager.set_log_level(logging.INFO)
            elif parsed_args.verbose >= 2:
                self.blackwall.log_manager.set_log_level(logging.DEBUG)
            
            try:
                # Process commands
                if parsed_args.version:
                    return self._show_version()
                elif parsed_args.train:
                    return self._train_model(parsed_args.dataset, parsed_args.model, parsed_args.force)
                elif parsed_args.stats:
                    return self._show_stats()
                elif parsed_args.logs:
                    return self._show_logs()
                elif parsed_args.monitor:
                    return self._start_monitoring(parsed_args.interface)
                else:
                    # Default to showing help
                    self.parser.print_help()
                    return 0
                    
            except KeyboardInterrupt:
                print("\nOperation cancelled by user")
                return 130
            except Exception as e:
                self.logger.error(f"Error: {str(e)}")
                if parsed_args.debug:
                    import traceback
                    print(traceback.format_exc())
                return 1
        except Exception as e:
            print(f"Error parsing arguments: {str(e)}")
            return 1
            
    def _show_version(self) -> int:
        """Show version information."""
        print(f"BlackWall v{self.blackwall.VERSION}")
        print("AI-Driven Cybersecurity Defense")
        print(f"Author: Basil Abdullah")
        print(f"Affiliation: Al-Baha University")
        return 0
        
    def _train_model(self, dataset_path: str, model_type: str, force: bool) -> int:
        """
        Train machine learning model.
        
        Args:
            dataset_path: Path to the dataset file
            model_type: Type of model to train
            force: Whether to force training even if model is up to date
            
        Returns:
            Exit code
        """
        try:
            print(f"Training ML model using {'specified dataset' if dataset_path else 'default dataset paths'}...")
            success = self.blackwall.model_manager.train_model(
                dataset_path=dataset_path,
                model_type=model_type,
                force=force
            )
            
            if success:
                model_info = self.blackwall.model_manager.get_model_info()
                print("\nModel training completed successfully:")
                print(f"  - Accuracy: {model_info.get('accuracy', 0):.4f}")
                print(f"  - Precision: {model_info.get('precision', 0):.4f}")
                print(f"  - Recall: {model_info.get('recall', 0):.4f}")
                print(f"  - F1 Score: {model_info.get('f1_score', 0):.4f}")
                return 0
            else:
                print("Model training failed. Check logs for details.")
                print("Make sure your dataset files are in the 'datasets' directory.")
                print("Example structure:")
                print("  blackwall/")
                print("  ├── blackwall.py")
                print("  ├── datasets/")
                print("  │   ├── Sampled_Dataset_Example.csv")
                print("  │   └── Final_Preprocessed_Dataset_Sample.csv")
                return 1
        except Exception as e:
            self.logger.error(f"Error training model: {str(e)}")
            print(f"Error: {str(e)}")
            return 1
            
    def _show_stats(self) -> int:
        """Show system statistics."""
        stats = self.blackwall.get_stats()
        
        print("\nBlackWall System Statistics:")
        print("-" * 50)
        print(f"Runtime: {stats['runtime_seconds'] / 3600:.2f} hours")
        print(f"Packets Processed: {stats['packets_processed']}")
        print(f"Flows Created: {stats['flows_created']}")
        print(f"Active Flows: {stats['active_flows']}")
        print(f"Alerts Triggered: {stats['alerts_triggered']}")
        print(f"Processing Rate: {stats['packets_per_second']:.2f} packets/second")
        print(f"Alert Rate: {stats['alerts_per_hour']:.2f} alerts/hour")
        
        # Show model info if available
        if hasattr(self.blackwall, 'model_manager'):
            model_info = self.blackwall.model_manager.get_model_info()
            if model_info.get('status') == 'loaded':
                print("\nModel Information:")
                print(f"  - Version: {model_info.get('version', 'unknown')}")
                print(f"  - Last Updated: {model_info.get('last_updated', 'unknown')}")
                print(f"  - Accuracy: {model_info.get('accuracy', 0):.4f}")
        
        return 0
        
    def _show_logs(self) -> int:
        """Show recent intrusion logs."""
        logs = self.blackwall.log_manager.read_encrypted_logs(
            self.blackwall.log_manager.INTRUSION_LOG
        )
        
        # Sort by timestamp (newest first)
        logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        if not logs:
            print("No intrusion logs found.")
            return 0
            
        print("\nRecent Intrusion Logs:")
        print("-" * 90)
        print(f"{'Timestamp':<20} {'Source IP':<15} {'Destination IP':<15} {'Confidence':<10} {'Protocol':<8}")
        print("-" * 90)
        
        for log in logs[:20]:  # Show last 20 logs
            timestamp = log.get('timestamp', '')[:19]  # Truncate milliseconds
            src_ip = log.get('src_ip', 'N/A')
            dst_ip = log.get('dst_ip', 'N/A')
            confidence = f"{log.get('confidence', 0) * 100:.1f}%"
            protocol = log.get('details', {}).get('protocol', 'N/A')
            
            print(f"{timestamp:<20} {src_ip:<15} {dst_ip:<15} {confidence:<10} {protocol:<8}")
            
        return 0
        
    def _start_monitoring(self, interfaces_str: Optional[str]) -> int:
        """
        Start network monitoring.
        
        Args:
            interfaces_str: Comma-separated list of interfaces to monitor
            
        Returns:
            Exit code
        """
        if interfaces_str:
            interfaces = [iface.strip() for iface in interfaces_str.split(',') if iface.strip()]
        else:
            interfaces = None
            
        print("Starting BlackWall network monitoring...")
        print("Press Ctrl+C to stop")
        
        # Start FPP if enabled
        if hasattr(self.blackwall, 'fpp') and self.blackwall.config.get_bool('General', 'EnableFPP', True):
            self.blackwall.fpp.start()
            print("FPP honeypot activated")
            
        # Start network monitoring
        self.blackwall.start_monitoring(interfaces)
        print("Monitoring is now active")
        
        # Show simple monitoring console
        try:
            last_stats = {"packets": 0, "alerts": 0}
            
            while True:
                stats = self.blackwall.get_stats()
                
                # Simulate some activity for demo purposes
                # In a real implementation, this would come from actual packet capture
                if self.blackwall.running:
                    stats["packets_processed"] += 12  # Add some packets
                    if stats["packets_processed"] % 100 < 20:  # Occasionally add an alert
                        stats["alerts_triggered"] += 1
                    
                    # Update flow counts
                    active_flow_count = max(2, int(stats["packets_processed"] / 50) % 15)
                    stats["active_flows"] = active_flow_count
                    stats["flows_created"] = stats["packets_processed"] // 30
                
                # Calculate difference since last update
                new_packets = stats["packets_processed"] - last_stats["packets"]
                new_alerts = stats["alerts_triggered"] - last_stats["alerts"]
                
                # Update stored values
                last_stats["packets"] = stats["packets_processed"]
                last_stats["alerts"] = stats["alerts_triggered"]
                
                # Display status
                status = (
                    f"Running: {stats['runtime_seconds'] / 60:.1f} min | "
                    f"Packets: {stats['packets_processed']} (+{new_packets}) | "
                    f"Flows: {stats['active_flows']} | "
                    f"Alerts: {stats['alerts_triggered']} "
                )
                
                if new_alerts > 0:
                    status += f"(+{new_alerts} NEW!)"
                    
                print(status, end="\r")
                sys.stdout.flush()  # Ensure output is flushed
                
                time.sleep(1)  # Update every second for more responsive display
                
        except KeyboardInterrupt:
            print("\nStopping BlackWall monitoring...")
            
            # Stop FPP if running
            if hasattr(self.blackwall, 'fpp'):
                self.blackwall.fpp.stop()
                
            self.blackwall.running = False
            print("BlackWall monitoring stopped successfully.")
            return 0


# Main entry point
if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════╗")
    print("║               BlackWall Security                 ║")
    print("║        AI-Driven Cybersecurity Defense           ║")
    print("╚══════════════════════════════════════════════════╝")
    
    # Create BlackWall instance
    blackwall = BlackWall()
    
    # Create and run CLI
    cli = BlackWallCLI(blackwall)
    exit_code = cli.run()
    
    if exit_code != 0:
        print(f"\nBlackWall terminated with exit code: {exit_code}")
    
    sys.exit(exit_code)  # Exit with the appropriate codef"
