# backend/ai/agentic_core.py

"""
Production Agentic AI Core
Implements ReAct (Reasoning + Acting) planning loop
"""

import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from openai import OpenAI

from backend.ai.persistent_memory import memory_system
from backend.mcp.mcp_base import mcp_registry

logger = logging.getLogger("agentic_core")


class AgentState(Enum):
    """Agent execution states"""
    PLANNING = "planning"
    ACTING = "acting"
    OBSERVING = "observing"
    REFLECTING = "reflecting"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AgentAction:
    """Single agent action"""
    action_type: str  # scan, analyze, investigate, remediate
    tool: str  # aws_scan, cloudfox_secrets, memory_query
    parameters: Dict[str, Any]
    reasoning: str
    confidence: float
    estimated_cost: float = 0.0
    estimated_time: float = 0.0


@dataclass
class AgentObservation:
    """Result of an action"""
    action: AgentAction
    success: bool
    result: Any
    error: Optional[str] = None
    execution_time: float = 0.0
    actual_cost: float = 0.0


@dataclass
class AgentPlan:
    """Multi-step execution plan"""
    goal: str
    steps: List[AgentAction] = field(default_factory=list)
    completed_steps: List[AgentObservation] = field(default_factory=list)
    current_step: int = 0
    plan_version: int = 1
    created_at: datetime = field(default_factory=datetime.utcnow)
    revised_at: Optional[datetime] = None
    revision_reason: Optional[str] = None


class ToolRegistry:
    """
    Registry of available tools with metadata
    Agents query this to decide which tools to use
    """
    
    def __init__(self):
        self.tools = self._initialize_tools()
    
    def _initialize_tools(self) -> Dict[str, Dict[str, Any]]:
        """Define available tools with capabilities"""
        return {
            # Scanning tools
            "aws_config_scan": {
                "description": "Scan AWS resources for configuration issues",
                "cost_per_execution": 0.0,  # Free (uses existing credentials)
                "avg_time_seconds": 45.0,
                "outputs": ["resources", "findings"],
                "requires": ["aws_credentials"],
                "best_for": ["configuration_audit", "compliance_check"]
            },
            
            "cloudfox_secrets": {
                "description": "Find exposed secrets in AWS (offensive scan)",
                "cost_per_execution": 0.0,
                "avg_time_seconds": 120.0,
                "outputs": ["secrets", "attack_paths"],
                "requires": ["aws_credentials", "cloudfox_installed"],
                "best_for": ["secret_discovery", "attack_simulation"]
            },
            
            "cloudfox_privilege_escalation": {
                "description": "Enumerate privilege escalation paths",
                "cost_per_execution": 0.0,
                "avg_time_seconds": 90.0,
                "outputs": ["escalation_paths", "iam_risks"],
                "requires": ["aws_credentials", "cloudfox_installed"],
                "best_for": ["iam_audit", "privilege_review"]
            },
            
            "vulnerability_scan": {
                "description": "Deep vulnerability scan with multiple tools",
                "cost_per_execution": 0.0,
                "avg_time_seconds": 180.0,
                "outputs": ["vulnerabilities", "cve_list"],
                "requires": ["resource_access"],
                "best_for": ["vulnerability_assessment", "patch_management"]
            },
            
            # Analysis tools
            "memory_query": {
                "description": "Query past findings and patterns",
                "cost_per_execution": 0.0,
                "avg_time_seconds": 1.0,
                "outputs": ["historical_context", "recurring_issues"],
                "requires": ["database_access"],
                "best_for": ["trend_analysis", "regression_detection"]
            },
            
            "risk_prioritization": {
                "description": "AI-powered risk scoring and prioritization",
                "cost_per_execution": 0.01,
                "avg_time_seconds": 5.0,
                "outputs": ["risk_scores", "priority_order"],
                "requires": ["openai_api"],
                "best_for": ["remediation_planning", "resource_allocation"]
            },
            
            # Investigation tools
            "resource_timeline": {
                "description": "Build timeline of resource changes",
                "cost_per_execution": 0.0,
                "avg_time_seconds": 10.0,
                "outputs": ["timeline", "change_events"],
                "requires": ["database_access"],
                "best_for": ["incident_investigation", "change_tracking"]
            },
            
            "compliance_check": {
                "description": "Check against compliance frameworks",
                "cost_per_execution": 0.0,
                "avg_time_seconds": 30.0,
                "outputs": ["compliance_status", "violations"],
                "requires": ["findings_data"],
                "best_for": ["compliance_audit", "framework_mapping"]
            }
        }
    
    def get_tool(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get tool metadata"""
        return self.tools.get(tool_name)
    
    def list_tools(self, capability: Optional[str] = None) -> List[str]:
        """List available tools, optionally filtered by capability"""
        if not capability:
            return list(self.tools.keys())
        
        return [
            name for name, meta in self.tools.items()
            if capability in meta.get("best_for", [])
        ]
    
    def estimate_cost(self, tool_name: str) -> float:
        """Get estimated cost for tool"""
        tool = self.get_tool(tool_name)
        return tool.get("cost_per_execution", 0.0) if tool else 0.0


class AgenticPlanner:
    """
    Planning agent that creates multi-step execution plans
    Uses LLM reasoning to decide what to do
    """
    
    def __init__(self, client: OpenAI, tool_registry: ToolRegistry):
        self.client = client
        self.tools = tool_registry
        self.model = "gpt-4o-mini"
    
    async def create_plan(
        self,
        goal: str,
        context: Dict[str, Any],
        constraints: Optional[Dict[str, Any]] = None
    ) -> AgentPlan:
        """
        Create multi-step plan to achieve goal
        
        Args:
            goal: What we want to accomplish
            context: Current state (credentials, past scans, etc.)
            constraints: Budget, time limits, etc.
        """
        logger.info(f"🧠 Planning for goal: {goal}")
        
        # Get historical context from memory
        historical_context = self._get_historical_context(goal, context)
        
        # Get available tools
        available_tools = self._format_tools_for_llm()
        
        # Build planning prompt
        prompt = self._build_planning_prompt(
            goal=goal,
            context=context,
            historical_context=historical_context,
            available_tools=available_tools,
            constraints=constraints or {}
        )
        
        # Get plan from LLM
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": self._get_planner_system_prompt()
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.2,
                response_format={"type": "json_object"}
            )
            
            plan_data = json.loads(response.choices[0].message.content)
            
            # Convert to AgentPlan
            steps = []
            for step in plan_data.get("steps", []):
                tool_name = step.get("tool")
                tool_meta = self.tools.get_tool(tool_name)
                
                if not tool_meta:
                    logger.warning(f"Unknown tool: {tool_name}, skipping")
                    continue
                
                steps.append(AgentAction(
                    action_type=step.get("action_type", "scan"),
                    tool=tool_name,
                    parameters=step.get("parameters", {}),
                    reasoning=step.get("reasoning", ""),
                    confidence=step.get("confidence", 0.5),
                    estimated_cost=tool_meta.get("cost_per_execution", 0.0),
                    estimated_time=tool_meta.get("avg_time_seconds", 0.0)
                ))
            
            plan = AgentPlan(
                goal=goal,
                steps=steps
            )
            
            logger.info(f"✅ Created plan with {len(steps)} steps")
            return plan
        
        except Exception as e:
            logger.error(f"Planning failed: {e}")
            # Return simple fallback plan
            return self._create_fallback_plan(goal, context)
    
    def _get_planner_system_prompt(self) -> str:
        """System prompt for planning agent"""
        return """You are an expert cloud security planner.

Your job: Create multi-step execution plans to achieve security goals.

You have access to various tools (scans, analysis, investigation).

RULES:
1. Start with reconnaissance (memory queries, context gathering)
2. Then execute actions (scans, checks)
3. Finally analyze and prioritize
4. Consider cost and time for each step
5. Avoid redundant scans if recent data exists
6. If past scans found issues, focus on those areas
7. Return valid JSON with this structure:

{
  "reasoning": "why this approach",
  "steps": [
    {
      "action_type": "scan|analyze|investigate",
      "tool": "tool_name",
      "parameters": {},
      "reasoning": "why this step",
      "confidence": 0.8
    }
  ],
  "estimated_total_time": 120,
  "estimated_total_cost": 0.05
}"""
    
    def _build_planning_prompt(
        self,
        goal: str,
        context: Dict[str, Any],
        historical_context: Dict[str, Any],
        available_tools: str,
        constraints: Dict[str, Any]
    ) -> str:
        """Build planning prompt"""
        return f"""
GOAL: {goal}

CURRENT CONTEXT:
- User: {context.get('user_id', 'unknown')}
- Providers Available: {', '.join(context.get('providers', []))}
- Recent Scans: {historical_context.get('recent_scans_count', 0)}
- Open Tasks: {historical_context.get('open_tasks_count', 0)}
- Known Issues: {historical_context.get('known_issues_count', 0)}

HISTORICAL PATTERNS:
{json.dumps(historical_context.get('patterns', {}), indent=2)}

AVAILABLE TOOLS:
{available_tools}

CONSTRAINTS:
- Max Time: {constraints.get('max_time_seconds', 300)} seconds
- Max Cost: ${constraints.get('max_cost', 0.50)}
- Required: {', '.join(constraints.get('required_outputs', ['findings']))}

Create an optimal plan to achieve the goal.
"""
    
    def _format_tools_for_llm(self) -> str:
        """Format tool registry for LLM"""
        tools_desc = []
        for name, meta in self.tools.tools.items():
            tools_desc.append(
                f"- {name}: {meta['description']}\n"
                f"  Cost: ${meta['cost_per_execution']}, "
                f"Time: ~{meta['avg_time_seconds']}s, "
                f"Best for: {', '.join(meta['best_for'])}"
            )
        return "\n".join(tools_desc)
    
    def _get_historical_context(self, goal: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Query memory for relevant historical context"""
        try:
            summary = memory_system.get_dashboard_summary()
            
            # Get recurring issues
            from backend.database import get_conn
            conn = get_conn()
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT issue, COUNT(*) as count
                    FROM finding_memory
                    WHERE status = 'recurring' AND occurrence_count > 2
                    GROUP BY issue
                    ORDER BY count DESC
                    LIMIT 5
                """)
                recurring = [{"issue": r[0], "count": r[1]} for r in cur.fetchall()]
            
            return {
                "recent_scans_count": 0,  # TODO: implement
                "open_tasks_count": summary["open_tasks"]["total"],
                "known_issues_count": summary["chronic_issues"],
                "patterns": {
                    "recurring_issues": recurring,
                    "regressions": summary["regressions"]
                }
            }
        except Exception as e:
            logger.error(f"Failed to get historical context: {e}")
            return {}
    
    def _create_fallback_plan(self, goal: str, context: Dict[str, Any]) -> AgentPlan:
        """Create simple fallback plan when LLM planning fails"""
        logger.warning("Using fallback plan")
        
        steps = []
        
        # Always start with memory query
        steps.append(AgentAction(
            action_type="analyze",
            tool="memory_query",
            parameters={"query": goal},
            reasoning="Check historical context",
            confidence=1.0,
            estimated_cost=0.0,
            estimated_time=1.0
        ))
        
        # Add scan for each provider
        for provider in context.get("providers", ["aws"]):
            steps.append(AgentAction(
                action_type="scan",
                tool=f"{provider}_config_scan",
                parameters={"deep_scan": False},
                reasoning=f"Basic {provider} security scan",
                confidence=0.8,
                estimated_cost=0.0,
                estimated_time=45.0
            ))
        
        return AgentPlan(goal=goal, steps=steps)
    
    async def revise_plan(
        self,
        original_plan: AgentPlan,
        observations: List[AgentObservation],
        reason: str
    ) -> AgentPlan:
        """
        Revise plan based on execution results
        Called when something unexpected happens
        """
        logger.info(f"🔄 Revising plan: {reason}")
        
        # Analyze what went wrong
        failed_steps = [obs for obs in observations if not obs.success]
        successful_steps = [obs for obs in observations if obs.success]
        
        prompt = f"""
Original Goal: {original_plan.goal}

COMPLETED STEPS:
{json.dumps([{
    'tool': obs.action.tool,
    'success': obs.success,
    'error': obs.error
} for obs in observations], indent=2)}

REVISION REASON: {reason}

Create a revised plan that:
1. Avoids repeating failed steps
2. Leverages successful results
3. Adapts to new information
4. Still achieves the original goal

Return JSON with same format as before.
"""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self._get_planner_system_prompt()},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                response_format={"type": "json_object"}
            )
            
            plan_data = json.loads(response.choices[0].message.content)
            
            # Convert to new plan
            revised_plan = AgentPlan(
                goal=original_plan.goal,
                steps=self._parse_steps(plan_data.get("steps", [])),
                plan_version=original_plan.plan_version + 1,
                revised_at=datetime.utcnow(),
                revision_reason=reason
            )
            
            logger.info(f"✅ Revised plan created (v{revised_plan.plan_version})")
            return revised_plan
        
        except Exception as e:
            logger.error(f"Plan revision failed: {e}")
            # Return original plan with remaining steps
            return original_plan
    
    def _parse_steps(self, steps_data: List[Dict]) -> List[AgentAction]:
        """Parse step data into AgentAction objects"""
        steps = []
        for step in steps_data:
            tool_name = step.get("tool")
            tool_meta = self.tools.get_tool(tool_name)
            
            if tool_meta:
                steps.append(AgentAction(
                    action_type=step.get("action_type", "scan"),
                    tool=tool_name,
                    parameters=step.get("parameters", {}),
                    reasoning=step.get("reasoning", ""),
                    confidence=step.get("confidence", 0.5),
                    estimated_cost=tool_meta.get("cost_per_execution", 0.0),
                    estimated_time=tool_meta.get("avg_time_seconds", 0.0)
                ))
        return steps


class AgenticExecutor:
    """
    Executor agent that runs planned actions
    Handles tool calls, error recovery, observation recording
    """
    
    def __init__(self, tool_registry: ToolRegistry):
        self.tools = tool_registry
    
    async def execute_action(self, action: AgentAction, context: Dict[str, Any]) -> AgentObservation:
        """Execute a single action and return observation"""
        logger.info(f"⚡ Executing: {action.tool} ({action.reasoning})")
        
        start_time = datetime.utcnow()
        
        try:
            # Route to appropriate executor
            if action.tool.startswith("aws_"):
                result = await self._execute_aws_tool(action, context)
            elif action.tool.startswith("cloudfox_"):
                result = await self._execute_cloudfox_tool(action, context)
            elif action.tool == "memory_query":
                result = await self._execute_memory_query(action, context)
            elif action.tool == "risk_prioritization":
                result = await self._execute_risk_prioritization(action, context)
            else:
                raise ValueError(f"Unknown tool: {action.tool}")
            
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            
            return AgentObservation(
                action=action,
                success=True,
                result=result,
                execution_time=execution_time,
                actual_cost=action.estimated_cost
            )
        
        except Exception as e:
            logger.error(f"Action failed: {e}")
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            
            return AgentObservation(
                action=action,
                success=False,
                result=None,
                error=str(e),
                execution_time=execution_time
            )
    
    async def _execute_aws_tool(self, action: AgentAction, context: Dict[str, Any]) -> Any:
        """Execute AWS scanning tool"""
        from backend.mcp_scanner import mcp_scanner
        
        result = await mcp_scanner.scan_multi_cloud(
            user_id=context.get("user_id", "anonymous"),
            providers=["aws"],
            account_ids=action.parameters.get("account_ids", {}),
            deep_scan=action.parameters.get("deep_scan", False)
        )
        
        return result
    
    async def _execute_cloudfox_tool(self, action: AgentAction, context: Dict[str, Any]) -> Any:
        """Execute CloudFox offensive tool"""
        from backend.mcp_scanner import mcp_scanner
        
        result = await mcp_scanner.run_offensive_scan(
            user_id=context.get("user_id", "anonymous"),
            profile=action.parameters.get("profile", "default"),
            region=action.parameters.get("region", "us-east-1")
        )
        
        return result
    
    async def _execute_memory_query(self, action: AgentAction, context: Dict[str, Any]) -> Any:
        """Query persistent memory"""
        query = action.parameters.get("query", "")
        
        # Get relevant historical data
        summary = memory_system.get_dashboard_summary()
        open_tasks = memory_system.get_open_tasks()[:10]
        
        return {
            "summary": summary,
            "open_tasks": open_tasks,
            "query": query
        }
    
    async def _execute_risk_prioritization(self, action: AgentAction, context: Dict[str, Any]) -> Any:
        """AI-powered risk prioritization"""
        # This would use AI to score and prioritize findings
        # For now, simple implementation
        
        findings = action.parameters.get("findings", [])
        
        # Sort by severity and exposure
        prioritized = sorted(
            findings,
            key=lambda f: (
                {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(f.get("severity", "LOW"), 0),
                int(f.get("is_public", False))
            ),
            reverse=True
        )
        
        return {
            "prioritized_findings": prioritized[:20],
            "top_actions": [f.get("recommendation") for f in prioritized[:5]]
        }




