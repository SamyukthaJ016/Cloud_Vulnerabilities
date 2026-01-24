# backend/utils/audit_logger.py

import os
import json
import logging
import time
from datetime import datetime
from typing import Dict, Any, Optional, List
from enum import Enum

logger = logging.getLogger("audit_logger")

class ExecutionStatus(Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    BROKEN = "BROKEN"

class AuditLogger:
    """
    Centralized auditor for tool execution.
    Saves JSON logs of inputs, outputs, and health status for explainability.
    """
    
    def __init__(self, tool_name: str, category: str, provider: str = "generic"):
        self.tool_name = tool_name
        self.category = category
        self.provider = provider
        self.start_time = time.time()
        self.timestamp = datetime.utcnow()
        self.log_dir = os.path.join("logs", "audit")
        
        # Ensure log directory exists
        os.makedirs(self.log_dir, exist_ok=True)
        
        self.metadata = {
            "tool": tool_name,
            "category": category,
            "provider": provider,
            "timestamp": self.timestamp.isoformat(),
            "status": ExecutionStatus.BROKEN.value,
            "duration_sec": 0.0,
            "input": {},
            "output": None,
            "error": None
        }

    def log_input(self, arguments: Dict[str, Any]):
        """Capture tool input arguments"""
        # Sanitize sensitive arguments if necessary
        sanitized = arguments.copy()
        sensitive_keys = ["api_key", "secret", "password", "token", "AWS_SECRET_ACCESS_KEY"]
        for key in sensitive_keys:
            if key in sanitized:
                sanitized[key] = "********"
        
        self.metadata["input"] = sanitized

    def log_success(self, result: Any):
        """Log successful execution with result"""
        self.metadata["status"] = ExecutionStatus.SUCCESS.value
        self.metadata["output"] = result
        self._finalize()

    def log_failure(self, error: str, output: Any = None):
        """Log failed execution with error message"""
        self.metadata["status"] = ExecutionStatus.FAILED.value
        self.metadata["error"] = error
        if output:
            self.metadata["output"] = output
        self._finalize()

    def _finalize(self):
        """Calculate duration and save to disk"""
        self.metadata["duration_sec"] = round(time.time() - self.start_time, 3)
        
        filename = f"audit_{self.timestamp.strftime('%Y%md_%H%M%S')}_{self.tool_name.replace('/', '_')}.json"
        filepath = os.path.join(self.log_dir, filename)
        
        try:
            with open(filepath, "w") as f:
                json.dump(self.metadata, f, indent=2, default=str)
            logger.debug(f"Audit log saved: {filepath}")
        except Exception as e:
            logger.error(f"Failed to save audit log: {e}")

    @classmethod
    def wrap_subprocess(cls, tool_name: str, category: str, cmd: List[str], stdout: str, stderr: str, returncode: int):
        """Helper to log subprocess calls directly"""
        auditor = cls(tool_name, category)
        auditor.log_input({"command": cmd})
        
        if returncode == 0:
            # Try to parse stdout as JSON for better auditability
            try:
                result = json.loads(stdout)
            except:
                result = stdout
            auditor.log_success(result)
        else:
            auditor.log_failure(stderr or "Subprocess exited with non-zero code", output=stdout)
        return auditor
