"""
Logging system for WiFi Security Tester

Author: @mirvaId
Contact: Telegram @mirvaId
License: MIT License
"""

import logging
import os
from datetime import datetime
from pathlib import Path

# Global logger instance
_logger_instance = None

def setup_logger(log_level=logging.INFO) -> logging.Logger:
    """Setup and configure the main logger"""
    global _logger_instance
    
    if _logger_instance is not None:
        return _logger_instance
    
    # Create logs directory
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Create logger
    logger = logging.getLogger("wifi_security_tester")
    logger.setLevel(log_level)
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    simple_formatter = logging.Formatter(
        '%(levelname)s: %(message)s'
    )
    
    # File handler for detailed logging
    log_filename = f"wifi_security_tester_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = logging.FileHandler(log_dir / log_filename)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(detailed_formatter)
    
    # Console handler for important messages
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(simple_formatter)
    
    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    _logger_instance = logger
    return logger

def get_logger(name: str = None) -> logging.Logger:
    """Get a logger instance"""
    if _logger_instance is None:
        setup_logger()
    
    if name:
        return logging.getLogger(f"wifi_security_tester.{name}")
    return _logger_instance

def log_security_event(event_type: str, details: str):
    """Log security-related events for audit trail"""
    logger = get_logger("security")
    logger.warning(f"SECURITY_EVENT: {event_type} - {details}")

def log_operation(operation: str, target: str = None, result: str = None):
    """Log operational events"""
    logger = get_logger("operations")
    message = f"OPERATION: {operation}"
    if target:
        message += f" - Target: {target}"
    if result:
        message += f" - Result: {result}"
    logger.info(message)