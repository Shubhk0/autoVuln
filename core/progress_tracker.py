import time
from typing import Dict, Optional
import logging
from dataclasses import dataclass
from enum import Enum

class ScanStage(Enum):
    INITIALIZING = "initializing"
    CRAWLING = "crawling"
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    REPORTING = "reporting"
    COMPLETED = "completed"
    ERROR = "error"

@dataclass
class ScanProgress:
    stage: ScanStage
    progress: float
    message: str
    details: Optional[dict] = None
    error: Optional[str] = None

class ProgressTracker:
    def __init__(self):
        self.logger = logging.getLogger('ProgressTracker')
        self._progress: Dict[str, ScanProgress] = {}
        self._stage_weights = {
            ScanStage.INITIALIZING: 10,
            ScanStage.CRAWLING: 20,
            ScanStage.SCANNING: 50,
            ScanStage.ANALYZING: 15,
            ScanStage.REPORTING: 5
        }

    def start_scan(self, scan_id: str):
        """Initialize progress tracking for a scan"""
        self._progress[scan_id] = ScanProgress(
            stage=ScanStage.INITIALIZING,
            progress=0.0,
            message="Initializing scan..."
        )
        self.logger.info(f"Started tracking progress for scan {scan_id}")

    def update_progress(self, scan_id: str, stage: ScanStage, progress: float, message: str, details: dict = None):
        """Update scan progress"""
        if scan_id not in self._progress:
            self.start_scan(scan_id)

        # Calculate overall progress based on stage weights
        stage_base = sum(self._stage_weights[s] for s in ScanStage if s.value < stage.value)
        stage_progress = progress * self._stage_weights[stage] / 100
        overall_progress = (stage_base + stage_progress) / 100

        self._progress[scan_id] = ScanProgress(
            stage=stage,
            progress=overall_progress,
            message=message,
            details=details
        )
        
        self.logger.debug(f"Scan {scan_id}: {stage.value} - {progress:.1f}% - {message}")

    def get_progress(self, scan_id: str) -> Optional[ScanProgress]:
        """Get current progress for a scan"""
        return self._progress.get(scan_id)

    def mark_completed(self, scan_id: str, message: str = "Scan completed"):
        """Mark a scan as completed"""
        if scan_id in self._progress:
            self._progress[scan_id] = ScanProgress(
                stage=ScanStage.COMPLETED,
                progress=100.0,
                message=message
            )
            self.logger.info(f"Scan {scan_id} completed: {message}")

    def mark_error(self, scan_id: str, error: str):
        """Mark a scan as failed"""
        if scan_id in self._progress:
            self._progress[scan_id] = ScanProgress(
                stage=ScanStage.ERROR,
                progress=self._progress[scan_id].progress,
                message="Scan failed",
                error=error
            )
            self.logger.error(f"Scan {scan_id} failed: {error}")

    def cleanup(self, scan_id: str):
        """Cleanup progress data for a scan"""
        if scan_id in self._progress:
            del self._progress[scan_id]
            self.logger.debug(f"Cleaned up progress data for scan {scan_id}") 