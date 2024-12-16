"""Custom exceptions for vulnerability scanner"""

class ScannerError(Exception):
    """Base exception for scanner errors"""
    pass

class ConfigurationError(ScannerError):
    """Configuration related errors"""
    pass

class SessionError(ScannerError):
    """Session management errors"""
    pass

class ScanError(ScannerError):
    """Scanning operation errors"""
    pass 