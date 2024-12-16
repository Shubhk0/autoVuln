import logging
import os
from datetime import datetime

class LoggingManager:
    def __init__(self):
        # Create log directories
        self.log_dirs = {
            'debug': 'logs/debug',
            'error': 'logs/error',
            'scan': 'logs/scan',
            'results': 'results'
        }
        
        # Create directories
        for dir_path in self.log_dirs.values():
            os.makedirs(dir_path, exist_ok=True)

        # Configure root logger first
        self.setup_root_logger()
        
        # Create specific loggers
        self.loggers = {
            'debug': self.setup_logger('debug', logging.DEBUG),
            'error': self.setup_logger('error', logging.ERROR),
            'scan': self.setup_logger('scan', logging.INFO)
        }

    def setup_root_logger(self):
        """Configure root logger"""
        root = logging.getLogger()
        root.setLevel(logging.INFO)
        
        # Remove existing handlers
        for handler in root.handlers[:]:
            root.removeHandler(handler)
            
        # Add new handler
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - [%(name)s] %(message)s'
        ))
        root.addHandler(handler)

    def setup_logger(self, name, level):
        """Setup a specific logger"""
        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.propagate = False  # Don't propagate to root logger
        
        # Create file handler
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        handler = logging.FileHandler(
            f"{self.log_dirs[name]}/{name}_{timestamp}.log"
        )
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - [%(name)s] %(message)s'
        )
        handler.setFormatter(formatter)
        
        # Add handler to logger
        logger.addHandler(handler)
        
        return logger

    def log_error(self, message, exc_info=None):
        """Log error with exception info"""
        self.loggers['error'].error(message, exc_info=exc_info)

    def log_debug(self, message):
        """Log debug message"""
        self.loggers['debug'].debug(message)

    def log_scan(self, message, level=logging.INFO):
        """Log scan related message"""
        self.loggers['scan'].log(level, message)

    def get_logger(self, name):
        """Get a specific logger"""
        return logging.getLogger(name) 