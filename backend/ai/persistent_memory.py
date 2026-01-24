# backend/ai/persistent_memory.py

"""
Persistent Memory System for CloudGuard
Tracks findings across scans, maintains task lists, and builds security knowledge base
"""

import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum

from backend.database import get_conn

logger = logging.getLogger("persistent_memory")


class TaskStatus(Enum):
    """Task status states"""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    WONT_FIX = "wont_fix"
    RECURRING = "recurring"


class TaskPriority(Enum):
    """Task priority levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SecurityTask:
    """Security remediation task"""
    id: Optional[int]
    finding_id: int
    resource_name: str
    provider: str
    issue: str
    description: str
    recommendation: str
    priority: TaskPriority
    status: TaskStatus
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime]
    notes: List[str]
    related_tasks: List[int]


@dataclass
class FindingMemory:
    """Memory of a security finding across scans"""
    finding_hash: str  # Unique identifier for the finding
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int
    resource_name: str
    provider: str
    issue: str
    severity: str
    status: str  # new, recurring, resolved, regressed
    scan_ids: List[int]
    notes: List[Dict[str, Any]]


@dataclass
class SecurityNote:
    """Note about a finding or resource"""
    id: Optional[int]
    finding_hash: str
    note_type: str  # investigation, remediation, observation
    content: str
    author: str
    created_at: datetime
    tags: List[str]


class PersistentMemorySystem:
    """
    Persistent memory system that tracks security state across scans
    """
    
    def __init__(self):
        self._ensure_tables_exist()
    
    def _ensure_tables_exist(self):
        """Create memory tables if they don't exist"""
        conn = get_conn()
        with conn.cursor() as cur:
            # Finding memory table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS finding_memory (
                    id SERIAL PRIMARY KEY,
                    finding_hash VARCHAR(64) UNIQUE NOT NULL,
                    first_seen TIMESTAMP NOT NULL,
                    last_seen TIMESTAMP NOT NULL,
                    occurrence_count INTEGER DEFAULT 1,
                    resource_name VARCHAR(500),
                    provider VARCHAR(50),
                    issue TEXT,
                    severity VARCHAR(20),
                    status VARCHAR(50) DEFAULT 'new',
                    scan_ids JSONB DEFAULT '[]',
                    metadata JSONB DEFAULT '{}'
                )
            """)
            
            # Security tasks table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS security_tasks (
                    id SERIAL PRIMARY KEY,
                    finding_id INTEGER REFERENCES findings(id),
                    finding_hash VARCHAR(64),
                    resource_name VARCHAR(500),
                    provider VARCHAR(50),
                    issue TEXT,
                    description TEXT,
                    recommendation TEXT,
                    priority VARCHAR(20),
                    status VARCHAR(50) DEFAULT 'open',
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW(),
                    resolved_at TIMESTAMP,
                    related_tasks JSONB DEFAULT '[]',
                    metadata JSONB DEFAULT '{}'
                )
            """)
            
            # Security notes table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS security_notes (
                    id SERIAL PRIMARY KEY,
                    finding_hash VARCHAR(64),
                    task_id INTEGER REFERENCES security_tasks(id),
                    note_type VARCHAR(50),
                    content TEXT,
                    author VARCHAR(200) DEFAULT 'system',
                    created_at TIMESTAMP DEFAULT NOW(),
                    tags JSONB DEFAULT '[]'
                )
            """)
            
            # Knowledge base table (for learned patterns)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS security_knowledge (
                    id SERIAL PRIMARY KEY,
                    pattern_type VARCHAR(100),
                    pattern_data JSONB,
                    confidence FLOAT DEFAULT 0.5,
                    evidence_count INTEGER DEFAULT 1,
                    last_updated TIMESTAMP DEFAULT NOW(),
                    metadata JSONB DEFAULT '{}'
                )
            """)
            
            conn.commit()
            logger.info("✅ Persistent memory tables initialized")
    
    def process_scan_findings(self, scan_id: int, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Process new scan findings and update memory
        
        Returns:
            Summary of new/recurring/resolved findings
        """
        logger.info(f"📝 Processing {len(findings)} findings for scan {scan_id}")
        
        stats = {
            "new_findings": 0,
            "recurring_findings": 0,
            "resolved_findings": 0,
            "regressed_findings": 0,
            "tasks_created": 0
        }
        
        conn = get_conn()
        
        # Track which findings we've seen in this scan
        current_finding_hashes = set()
        
        for finding in findings:
            finding_hash = self._generate_finding_hash(finding)
            current_finding_hashes.add(finding_hash)
            
            # Check if we've seen this before
            memory = self._get_finding_memory(finding_hash)
            
            if memory:
                # Update existing memory
                stats["recurring_findings"] += 1
                
                # Check if this was previously resolved (regression)
                if memory.status == "resolved":
                    stats["regressed_findings"] += 1
                    logger.warning(f"⚠️ REGRESSION: {finding['issue']} on {finding['resource_name']}")
                    
                    # Create high-priority task for regression
                    self._create_task(
                        finding=finding,
                        priority=TaskPriority.HIGH,
                        note=f"REGRESSION: This issue was previously resolved but has reappeared"
                    )
                    stats["tasks_created"] += 1
                
                self._update_finding_memory(
                    finding_hash=finding_hash,
                    scan_id=scan_id,
                    status="recurring" if memory.status != "resolved" else "regressed"
                )
            else:
                # New finding
                stats["new_findings"] += 1
                logger.info(f"🆕 NEW: {finding['issue']} on {finding['resource_name']}")
                
                self._create_finding_memory(
                    finding_hash=finding_hash,
                    scan_id=scan_id,
                    finding=finding
                )
                
                # Create task for critical/high severity new findings
                if finding.get('severity') in ['CRITICAL', 'HIGH']:
                    priority = TaskPriority.CRITICAL if finding['severity'] == 'CRITICAL' else TaskPriority.HIGH
                    self._create_task(finding=finding, priority=priority)
                    stats["tasks_created"] += 1
        
        # Check for resolved findings (in memory but not in current scan)
        stats["resolved_findings"] = self._check_resolved_findings(
            scan_id=scan_id,
            current_hashes=current_finding_hashes
        )
        
        conn.commit()
        
        logger.info(f"✅ Scan processing complete: {stats}")
        return stats
    
    def _generate_finding_hash(self, finding: Dict[str, Any]) -> str:
        """Generate unique hash for a finding"""
        import hashlib
        
        # Use resource + issue + provider as unique identifier
        identifier = f"{finding.get('provider')}::{finding.get('resource_name')}::{finding.get('issue')}"
        return hashlib.sha256(identifier.encode()).hexdigest()[:16]
    
    def _get_finding_memory(self, finding_hash: str) -> Optional[FindingMemory]:
        """Retrieve finding memory from database"""
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT finding_hash, first_seen, last_seen, occurrence_count,
                       resource_name, provider, issue, severity, status, scan_ids
                FROM finding_memory
                WHERE finding_hash = %s
            """, (finding_hash,))
            
            row = cur.fetchone()
            if not row:
                return None
            
            return FindingMemory(
                finding_hash=row[0],
                first_seen=row[1],
                last_seen=row[2],
                occurrence_count=row[3],
                resource_name=row[4],
                provider=row[5],
                issue=row[6],
                severity=row[7],
                status=row[8],
                scan_ids=json.loads(row[9]) if row[9] else [],
                notes=[]
            )
    
    def _create_finding_memory(self, finding_hash: str, scan_id: int, finding: Dict[str, Any]):
        """Create new finding memory entry"""
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO finding_memory
                (finding_hash, first_seen, last_seen, resource_name, provider, issue, severity, scan_ids)
                VALUES (%s, NOW(), NOW(), %s, %s, %s, %s, %s::jsonb)
            """, (
                finding_hash,
                finding.get('resource_name'),
                finding.get('provider'),
                finding.get('issue'),
                finding.get('severity'),
                json.dumps([scan_id])
            ))
    
    def _update_finding_memory(self, finding_hash: str, scan_id: int, status: str):
        """Update existing finding memory"""
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE finding_memory
                SET last_seen = NOW(),
                    occurrence_count = occurrence_count + 1,
                    status = %s,
                    scan_ids = scan_ids || %s::jsonb
                WHERE finding_hash = %s
            """, (status, json.dumps([scan_id]), finding_hash))
    
    def _check_resolved_findings(self, scan_id: int, current_hashes: set) -> int:
        """Check for findings that were present before but not in current scan"""
        conn = get_conn()
        resolved_count = 0
        
        with conn.cursor() as cur:
            # Get findings that were active (not resolved) but not in current scan
            cur.execute("""
                SELECT finding_hash, resource_name, issue
                FROM finding_memory
                WHERE status IN ('new', 'recurring', 'regressed')
                  AND last_seen < (SELECT started_at FROM scans WHERE id = %s)
            """, (scan_id,))
            
            for row in cur.fetchall():
                finding_hash, resource_name, issue = row
                
                if finding_hash not in current_hashes:
                    # Mark as resolved
                    cur.execute("""
                        UPDATE finding_memory
                        SET status = 'resolved'
                        WHERE finding_hash = %s
                    """, (finding_hash,))
                    
                    # Resolve associated tasks
                    cur.execute("""
                        UPDATE security_tasks
                        SET status = 'resolved',
                            resolved_at = NOW(),
                            updated_at = NOW()
                        WHERE finding_hash = %s
                          AND status IN ('open', 'in_progress')
                    """, (finding_hash,))
                    
                    resolved_count += 1
                    logger.info(f"✅ RESOLVED: {issue} on {resource_name}")
                    
                    # Add resolution note
                    self._add_note(
                        finding_hash=finding_hash,
                        note_type="observation",
                        content=f"Finding resolved - no longer detected in scan {scan_id}",
                        author="system"
                    )
        
        return resolved_count
    
    def _create_task(self, finding: Dict[str, Any], priority: TaskPriority, note: str = None):
        """Create a security remediation task"""
        finding_hash = self._generate_finding_hash(finding)
        
        conn = get_conn()
        with conn.cursor() as cur:
            # Check if task already exists for this finding
            cur.execute("""
                SELECT id FROM security_tasks
                WHERE finding_hash = %s AND status IN ('open', 'in_progress')
            """, (finding_hash,))
            
            if cur.fetchone():
                logger.debug(f"Task already exists for {finding_hash}")
                return
            
            # Create new task
            cur.execute("""
                INSERT INTO security_tasks
                (finding_hash, resource_name, provider, issue, description, recommendation, priority, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'open')
                RETURNING id
            """, (
                finding_hash,
                finding.get('resource_name'),
                finding.get('provider'),
                finding.get('issue'),
                finding.get('description'),
                finding.get('recommendation'),
                priority.value
            ))
            
            task_id = cur.fetchone()[0]
            
            # Add creation note
            if note:
                self._add_note(
                    finding_hash=finding_hash,
                    note_type="investigation",
                    content=note,
                    author="system"
                )
            
            logger.info(f"📋 Created task #{task_id} for {finding['issue']}")
    
    def _add_note(self, finding_hash: str, note_type: str, content: str, author: str = "system"):
        """Add a note to a finding"""
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO security_notes
                (finding_hash, note_type, content, author)
                VALUES (%s, %s, %s, %s)
            """, (finding_hash, note_type, content, author))
    
    def get_open_tasks(self, priority: Optional[TaskPriority] = None) -> List[Dict[str, Any]]:
        """Get all open security tasks"""
        conn = get_conn()
        with conn.cursor() as cur:
            query = """
                SELECT id, finding_hash, resource_name, provider, issue,
                       description, recommendation, priority, status,
                       created_at, updated_at
                FROM security_tasks
                WHERE status IN ('open', 'in_progress')
            """
            
            if priority:
                query += " AND priority = %s"
                cur.execute(query + " ORDER BY created_at DESC", (priority.value,))
            else:
                query += " ORDER BY CASE priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, created_at DESC"
                cur.execute(query)
            
            tasks = []
            for row in cur.fetchall():
                tasks.append({
                    "id": row[0],
                    "finding_hash": row[1],
                    "resource_name": row[2],
                    "provider": row[3],
                    "issue": row[4],
                    "description": row[5],
                    "recommendation": row[6],
                    "priority": row[7],
                    "status": row[8],
                    "created_at": row[9].isoformat() if row[9] else None,
                    "updated_at": row[10].isoformat() if row[10] else None
                })
            
            return tasks
    
    def get_finding_history(self, finding_hash: str) -> Dict[str, Any]:
        """Get complete history of a finding"""
        conn = get_conn()
        with conn.cursor() as cur:
            # Get memory
            cur.execute("""
                SELECT finding_hash, first_seen, last_seen, occurrence_count,
                       resource_name, provider, issue, severity, status, scan_ids
                FROM finding_memory
                WHERE finding_hash = %s
            """, (finding_hash,))
            
            memory_row = cur.fetchone()
            if not memory_row:
                return {}
            
            # Get notes
            cur.execute("""
                SELECT note_type, content, author, created_at
                FROM security_notes
                WHERE finding_hash = %s
                ORDER BY created_at DESC
            """, (finding_hash,))
            
            notes = [
                {
                    "type": row[0],
                    "content": row[1],
                    "author": row[2],
                    "created_at": row[3].isoformat()
                }
                for row in cur.fetchall()
            ]
            
            # Get associated tasks
            cur.execute("""
                SELECT id, priority, status, created_at, resolved_at
                FROM security_tasks
                WHERE finding_hash = %s
                ORDER BY created_at DESC
            """, (finding_hash,))
            
            tasks = [
                {
                    "id": row[0],
                    "priority": row[1],
                    "status": row[2],
                    "created_at": row[3].isoformat(),
                    "resolved_at": row[4].isoformat() if row[4] else None
                }
                for row in cur.fetchall()
            ]
            
            return {
                "finding_hash": memory_row[0],
                "first_seen": memory_row[1].isoformat(),
                "last_seen": memory_row[2].isoformat(),
                "occurrence_count": memory_row[3],
                "resource_name": memory_row[4],
                "provider": memory_row[5],
                "issue": memory_row[6],
                "severity": memory_row[7],
                "status": memory_row[8],
                "scan_ids": json.loads(memory_row[9]) if memory_row[9] else [],
                "notes": notes,
                "tasks": tasks
            }
    
    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Get summary for dashboard"""
        conn = get_conn()
        with conn.cursor() as cur:
            # Open tasks by priority
            cur.execute("""
                SELECT priority, COUNT(*)
                FROM security_tasks
                WHERE status IN ('open', 'in_progress')
                GROUP BY priority
            """)
            
            tasks_by_priority = {row[0]: row[1] for row in cur.fetchall()}
            
            # Recurring findings
            cur.execute("""
                SELECT COUNT(*)
                FROM finding_memory
                WHERE status = 'recurring' AND occurrence_count > 3
            """)
            chronic_issues = cur.fetchone()[0]
            
            # Recently resolved
            cur.execute("""
                SELECT COUNT(*)
                FROM finding_memory
                WHERE status = 'resolved' AND last_seen > NOW() - INTERVAL '7 days'
            """)
            recently_resolved = cur.fetchone()[0]
            
            # Regressions
            cur.execute("""
                SELECT COUNT(*)
                FROM finding_memory
                WHERE status = 'regressed'
            """)
            regressions = cur.fetchone()[0]
            
            return {
                "open_tasks": {
                    "critical": tasks_by_priority.get("critical", 0),
                    "high": tasks_by_priority.get("high", 0),
                    "medium": tasks_by_priority.get("medium", 0),
                    "low": tasks_by_priority.get("low", 0),
                    "total": sum(tasks_by_priority.values())
                },
                "chronic_issues": chronic_issues,
                "recently_resolved": recently_resolved,
                "regressions": regressions
            }


# Singleton instance
memory_system = PersistentMemorySystem()


if __name__ == "__main__":
    print("✅ Persistent Memory System loaded")