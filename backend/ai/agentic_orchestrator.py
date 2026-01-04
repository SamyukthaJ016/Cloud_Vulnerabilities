# backend/ai/agentic_orchestrator.py (continuation)

"""
Main Agentic Orchestrator - Implements ReAct loop
"""

import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from openai import OpenAI

from backend.ai.agentic_core import (
    AgentState,
    AgentPlan,
    AgentAction,
    AgentObservation,
    ToolRegistry,
    AgenticPlanner,
    AgenticExecutor
)
from backend.ai.persistent_memory import memory_system

logger = logging.getLogger("agentic_orchestrator")


class AgenticReflector:
    """
    Reflector agent that evaluates execution results
    Decides: continue, revise plan, or stop
    """
    
    def __init__(self, client: OpenAI):
        self.client = client
        self.model = "gpt-4o-mini"
    
    async def reflect(
        self,
        plan: AgentPlan,
        observations: List[AgentObservation],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Reflect on execution results
        
        Returns:
            {
                "decision": "continue|revise|complete|fail",
                "reasoning": "why",
                "suggestions": ["what to do next"],
                "quality_score": 0.8
            }
        """
        logger.info(f"🤔 Reflecting on {len(observations)} observations")
        
        # Analyze observations
        total_steps = len(plan.steps)
        completed = len(observations)
        successful = len([o for o in observations if o.success])
        failed = len([o for o in observations if not o.success])
        
        # Build reflection prompt
        prompt = f"""
You are evaluating a security scan execution.

GOAL: {plan.goal}

PLAN: {total_steps} steps total
EXECUTED: {completed} steps
SUCCESS: {successful}
FAILED: {failed}

OBSERVATIONS:
{json.dumps([{
    'step': i+1,
    'tool': obs.action.tool,
    'success': obs.success,
    'result_summary': str(obs.result)[:200] if obs.result else None,
    'error': obs.error,
    'time': obs.execution_time
} for i, obs in enumerate(observations)], indent=2)}

Evaluate:
1. Did we achieve the goal?
2. Are failures recoverable?
3. Is the plan still valid?
4. What should happen next?

Return JSON:
{{
  "decision": "continue|revise|complete|fail",
  "reasoning": "detailed explanation",
  "goal_achieved": true/false,
  "quality_score": 0.0-1.0,
  "suggestions": ["next actions"],
  "key_insights": ["important findings"]
}}
"""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a critical evaluator. Be honest about failures and successes."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.2,
                response_format={"type": "json_object"}
            )
            
            reflection = json.loads(response.choices[0].message.content)
            
            logger.info(f"📊 Reflection: {reflection['decision']} (score: {reflection.get('quality_score', 0)})")
            return reflection
        
        except Exception as e:
            logger.error(f"Reflection failed: {e}")
            
            # Fallback: simple heuristic
            if failed == 0 and completed == total_steps:
                return {
                    "decision": "complete",
                    "reasoning": "All steps completed successfully",
                    "goal_achieved": True,
                    "quality_score": 1.0,
                    "suggestions": []
                }
            elif failed > successful:
                return {
                    "decision": "fail",
                    "reasoning": "More failures than successes",
                    "goal_achieved": False,
                    "quality_score": 0.3,
                    "suggestions": ["Review tool availability", "Check credentials"]
                }
            else:
                return {
                    "decision": "continue",
                    "reasoning": "Some progress made, continue with plan",
                    "goal_achieved": False,
                    "quality_score": 0.6,
                    "suggestions": ["Continue with remaining steps"]
                }


class AgenticOrchestrator:
    """
    Main orchestrator implementing ReAct loop:
    Plan → Act → Observe → Reflect → (repeat if needed)
    """
    
    def __init__(self, api_key: str):
        self.client = OpenAI(api_key=api_key)
        self.tool_registry = ToolRegistry()
        self.planner = AgenticPlanner(self.client, self.tool_registry)
        self.executor = AgenticExecutor(self.tool_registry)
        self.reflector = AgenticReflector(self.client)
        
        # Execution limits
        self.max_iterations = 5
        self.max_plan_revisions = 3
        self.max_total_time = 600  # 10 minutes
    
    async def run(
        self,
        goal: str,
        context: Dict[str, Any],
        constraints: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Run complete agentic workflow
        
        Args:
            goal: What to accomplish (e.g., "Scan AWS for critical security issues")
            context: Execution context (user, credentials, etc.)
            constraints: Optional limits (time, cost, etc.)
        
        Returns:
            Complete execution trace with results
        """
        logger.info(f"🚀 Starting agentic workflow: {goal}")
        
        start_time = datetime.utcnow()
        
        # Initialize execution state
        state = {
            "goal": goal,
            "context": context,
            "constraints": constraints or {},
            "state": AgentState.PLANNING,
            "iterations": 0,
            "plan_revisions": 0,
            "current_plan": None,
            "all_observations": [],
            "reflections": [],
            "final_result": None,
            "total_cost": 0.0,
            "start_time": start_time.isoformat()
        }
        
        try:
            # Main ReAct loop
            while state["iterations"] < self.max_iterations:
                state["iterations"] += 1
                elapsed = (datetime.utcnow() - start_time).total_seconds()
                
                logger.info(f"🔄 Iteration {state['iterations']}/{self.max_iterations}")
                
                # Check time limit
                if elapsed > self.max_total_time:
                    logger.warning("⏰ Time limit exceeded")
                    state["state"] = AgentState.FAILED
                    state["final_result"] = {
                        "error": "Time limit exceeded",
                        "partial_results": state["all_observations"]
                    }
                    break
                
                # ========== PLANNING PHASE ==========
                if state["state"] == AgentState.PLANNING:
                    logger.info("📋 PLANNING...")
                    
                    if state["current_plan"] is None:
                        # Initial plan
                        plan = await self.planner.create_plan(
                            goal=goal,
                            context=context,
                            constraints=constraints
                        )
                    else:
                        # Revision
                        if state["plan_revisions"] >= self.max_plan_revisions:
                            logger.warning("Max plan revisions reached")
                            state["state"] = AgentState.COMPLETED
                            break
                        
                        plan = await self.planner.revise_plan(
                            original_plan=state["current_plan"],
                            observations=state["all_observations"],
                            reason="Previous execution needs adjustment"
                        )
                        state["plan_revisions"] += 1
                    
                    state["current_plan"] = plan
                    state["state"] = AgentState.ACTING
                
                # ========== ACTING PHASE ==========
                elif state["state"] == AgentState.ACTING:
                    logger.info("⚡ ACTING...")
                    
                    plan = state["current_plan"]
                    observations = []
                    
                    # Execute remaining steps
                    for i in range(plan.current_step, len(plan.steps)):
                        step = plan.steps[i]
                        
                        logger.info(f"Step {i+1}/{len(plan.steps)}: {step.tool}")
                        
                        # Execute
                        observation = await self.executor.execute_action(step, context)
                        observations.append(observation)
                        state["all_observations"].append(observation)
                        state["total_cost"] += observation.actual_cost
                        
                        # Early stop on critical failure
                        if not observation.success and step.action_type == "scan":
                            logger.warning(f"Critical step failed: {step.tool}")
                            break
                    
                    plan.completed_steps.extend(observations)
                    plan.current_step = len(plan.completed_steps)
                    
                    state["state"] = AgentState.REFLECTING
                
                # ========== REFLECTING PHASE ==========
                elif state["state"] == AgentState.REFLECTING:
                    logger.info("🤔 REFLECTING...")
                    
                    reflection = await self.reflector.reflect(
                        plan=state["current_plan"],
                        observations=state["all_observations"],
                        context=context
                    )
                    
                    state["reflections"].append(reflection)
                    
                    # Act on reflection
                    decision = reflection.get("decision", "continue")
                    
                    if decision == "complete":
                        logger.info("✅ Goal achieved!")
                        state["state"] = AgentState.COMPLETED
                        state["final_result"] = self._synthesize_results(state)
                        break
                    
                    elif decision == "fail":
                        logger.error("❌ Execution failed")
                        state["state"] = AgentState.FAILED
                        state["final_result"] = {
                            "error": reflection.get("reasoning"),
                            "partial_results": state["all_observations"]
                        }
                        break
                    
                    elif decision == "revise":
                        logger.info("🔄 Revising plan...")
                        state["state"] = AgentState.PLANNING
                    
                    else:  # continue
                        if state["current_plan"].current_step >= len(state["current_plan"].steps):
                            # Completed all steps
                            state["state"] = AgentState.COMPLETED
                            state["final_result"] = self._synthesize_results(state)
                            break
                        else:
                            state["state"] = AgentState.ACTING
                
                else:
                    # Unknown state, exit
                    break
            
            # If loop exhausted
            if state["state"] not in [AgentState.COMPLETED, AgentState.FAILED]:
                state["state"] = AgentState.COMPLETED
                state["final_result"] = self._synthesize_results(state)
            
            # Calculate final stats
            end_time = datetime.utcnow()
            execution_time = (end_time - start_time).total_seconds()
            
            return {
                "status": state["state"].value,
                "goal": goal,
                "iterations": state["iterations"],
                "plan_revisions": state["plan_revisions"],
                "total_steps_executed": len(state["all_observations"]),
                "successful_steps": len([o for o in state["all_observations"] if o.success]),
                "failed_steps": len([o for o in state["all_observations"] if not o.success]),
                "total_cost": state["total_cost"],
                "execution_time_seconds": execution_time,
                "reflections": state["reflections"],
                "final_result": state["final_result"],
                "architecture": "agentic_react",
                "timestamp": end_time.isoformat()
            }
        
        except Exception as e:
            logger.exception("Orchestrator crashed")
            return {
                "status": "error",
                "error": str(e),
                "partial_state": state
            }
    
    def _synthesize_results(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Synthesize all observations into final result"""
        
        # Collect all results
        scan_results = []
        findings = []
        insights = []
        
        for obs in state["all_observations"]:
            if obs.success and obs.result:
                result = obs.result
                
                # Extract scan results
                if isinstance(result, dict):
                    if "results" in result:
                        scan_results.append(result)
                    
                    if "findings" in result:
                        findings.extend(result["findings"])
                    
                    if "summary" in result:
                        insights.append(result["summary"])
        
        # Collect reflection insights
        for reflection in state["reflections"]:
            insights.extend(reflection.get("key_insights", []))
        
        return {
            "scan_results": scan_results,
            "total_findings": len(findings),
            "findings_sample": findings[:20],  # Top 20
            "insights": insights,
            "execution_summary": {
                "total_steps": len(state["all_observations"]),
                "successful": len([o for o in state["all_observations"] if o.success]),
                "failed": len([o for o in state["all_observations"] if not o.success]),
                "iterations": state["iterations"],
                "plan_revisions": state["plan_revisions"]
            }
        }


# Global singleton
_orchestrator = None


def get_agentic_orchestrator(api_key: str) -> AgenticOrchestrator:
    """Get or create orchestrator singleton"""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = AgenticOrchestrator(api_key)
    return _orchestrator


# Usage example
if __name__ == "__main__":
    import asyncio
    import os
    
    async def test_agentic():
        orchestrator = get_agentic_orchestrator(os.getenv("OPENAI_API_KEY"))
        
        result = await orchestrator.run(
            goal="Perform complete security audit of AWS environment focusing on IAM and S3",
            context={
                "user_id": "test_user",
                "providers": ["aws"],
                "credentials_available": True
            },
            constraints={
                "max_time_seconds": 300,
                "max_cost": 0.50
            }
        )
        
        print(json.dumps(result, indent=2, default=str))
    
    # asyncio.run(test_agentic())
    print("✅ Agentic Orchestrator loaded")