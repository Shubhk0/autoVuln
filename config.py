"""Configuration management for vulnerability scanner"""

from pydantic import BaseSettings, validator
from typing import List, Dict
import os
from dotenv import load_dotenv

load_dotenv()

class ScannerConfig(BaseSettings):
    """Scanner configuration with validation"""
    
    # HTTP Settings
    USER_AGENT: str = "Mozilla/5.0 (compatible; SecurityScanner/1.0)"
    REQUEST_TIMEOUT: int = 30
    MAX_REDIRECTS: int = 5
    VERIFY_SSL: bool = True
    
    # Scan Settings
    MAX_URLS_PER_SCAN: int = 100
    MAX_DEPTH: int = 3
    CONCURRENT_SCANS: int = 10
    
    # Rate Limiting
    REQUESTS_PER_SECOND: int = 10
    BURST_SIZE: int = 20
    
    # Paths/Extensions to Exclude
    EXCLUDE_PATHS: List[str] = [
        "/logout", "/signout", "/delete",
        "/static", "/assets", "/images"
    ]
    
    EXCLUDE_EXTENSIONS: List[str] = [
        ".jpg", ".jpeg", ".png", ".gif",
        ".css", ".js", ".ico", ".svg"
    ]
    
    @validator("REQUEST_TIMEOUT")
    def validate_timeout(cls, v):
        if v < 1:
            raise ValueError("Timeout must be at least 1 second")
        return v
    
    class Config:
        env_prefix = "SCANNER_"
        case_sensitive = True 