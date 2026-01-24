# backend/mcp_servers/base_server.py

"""
MCP Server Base - Implements Model Context Protocol for cloud security scanning
Each cloud provider runs as a dedicated MCP server
"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from enum import Enum
from backend.utils.audit_logger import AuditLogger

logger = logging.getLogger("mcp_server")


class ToolCategory(Enum):
    """Tool categories for MCP"""
    DISCOVERY = "discovery"
    CONFIG_CHECK = "config_check"
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"


@dataclass
class MCPTool:
    """MCP Tool definition"""
    name: str
    description: str
    category: ToolCategory
    input_schema: Dict[str, Any]
    handler: Optional[Callable] = None


@dataclass
class MCPResource:
    """MCP Resource definition"""
    uri: str
    name: str
    description: str
    mime_type: str = "application/json"


@dataclass
class MCPServerInfo:
    """Server capabilities and metadata"""
    name: str
    version: str
    provider: str
    capabilities: List[str]
    tools: List[Dict[str, Any]]
    resources: List[Dict[str, Any]]


class MCPMessage:
    """MCP Protocol Message"""
    
    def __init__(self, method: str, params: Dict = None, id: Optional[str] = None):
        self.jsonrpc = "2.0"
        self.method = method
        self.params = params or {}
        self.id = id or self._generate_id()
    
    @staticmethod
    def _generate_id() -> str:
        import uuid
        return str(uuid.uuid4())
    
    def to_dict(self) -> Dict:
        result = {
            "jsonrpc": self.jsonrpc,
            "method": self.method,
            "params": self.params
        }
        if self.id:
            result["id"] = self.id
        return result
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'MCPMessage':
        return cls(
            method=data.get("method", ""),
            params=data.get("params", {}),
            id=data.get("id")
        )


class MCPResponse:
    """MCP Protocol Response"""
    
    def __init__(self, result: Any = None, error: Dict = None, id: str = None):
        self.jsonrpc = "2.0"
        self.result = result
        self.error = error
        self.id = id
    
    def to_dict(self) -> Dict:
        response = {"jsonrpc": self.jsonrpc, "id": self.id}
        if self.error:
            response["error"] = self.error
        else:
            response["result"] = self.result
        return response
    
    @classmethod
    def success(cls, result: Any, id: str) -> 'MCPResponse':
        return cls(result=result, id=id)
    
    @classmethod
    def error(cls, code: int, message: str, id: str = None) -> 'MCPResponse':
        return cls(
            error={"code": code, "message": message},
            id=id
        )


class BaseMCPServer(ABC):
    """
    Base MCP Server - All cloud provider servers inherit from this
    
    Implements the Model Context Protocol specification for cloud security scanning
    """
    
    def __init__(self, provider: str, config: Dict[str, Any]):
        self.provider = provider
        self.config = config
        self.tools: Dict[str, MCPTool] = {}
        self.resources: Dict[str, MCPResource] = {}
        self.running = False
        self._setup_tools()
        self._setup_resources()
    
    @abstractmethod
    def _setup_tools(self) -> None:
        """Setup available tools for this provider"""
        pass
    
    @abstractmethod
    def _setup_resources(self) -> None:
        """Setup available resources for this provider"""
        pass
    
    def register_tool(self, tool: MCPTool) -> None:
        """Register a tool with the server"""
        self.tools[tool.name] = tool
        logger.info(f"[{self.provider}] Registered tool: {tool.name}")
    
    def register_resource(self, resource: MCPResource) -> None:
        """Register a resource with the server"""
        self.resources[resource.uri] = resource
        logger.info(f"[{self.provider}] Registered resource: {resource.name}")
    
    async def handle_request(self, message: MCPMessage) -> MCPResponse:
        """Handle incoming MCP request"""
        try:
            method = message.method
            
            # Protocol methods
            if method == "initialize":
                return await self._handle_initialize(message)
            elif method == "tools/list":
                return await self._handle_list_tools(message)
            elif method == "tools/call":
                return await self._handle_call_tool(message)
            elif method == "resources/list":
                return await self._handle_list_resources(message)
            elif method == "resources/read":
                return await self._handle_read_resource(message)
            else:
                return MCPResponse.error(
                    code=-32601,
                    message=f"Method not found: {method}",
                    id=message.id
                )
        
        except Exception as e:
            logger.error(f"Error handling request: {e}")
            return MCPResponse.error(
                code=-32603,
                message=f"Internal error: {str(e)}",
                id=message.id
            )
    
    async def _handle_initialize(self, message: MCPMessage) -> MCPResponse:
        """Handle initialize request"""
        server_info = MCPServerInfo(
            name=f"{self.provider.upper()} Security Scanner",
            version="1.0.0",
            provider=self.provider,
            capabilities=[
                "tools",
                "resources",
                "scanning",
                "vulnerability_detection"
            ],
            tools=[
                {
                    "name": tool.name,
                    "description": tool.description,
                    "category": tool.category.value,
                    "inputSchema": tool.input_schema
                }
                for tool in self.tools.values()
            ],
            resources=[
                {
                    "uri": res.uri,
                    "name": res.name,
                    "description": res.description,
                    "mimeType": res.mime_type
                }
                for res in self.resources.values()
            ]
        )
        
        return MCPResponse.success(asdict(server_info), message.id)
    
    async def _handle_list_tools(self, message: MCPMessage) -> MCPResponse:
        """List available tools"""
        tools_list = [
            {
                "name": tool.name,
                "description": tool.description,
                "category": tool.category.value,
                "inputSchema": tool.input_schema
            }
            for tool in self.tools.values()
        ]
        
        return MCPResponse.success({"tools": tools_list}, message.id)
    
    async def _handle_call_tool(self, message: MCPMessage) -> MCPResponse:
        """Call a tool"""
        tool_name = message.params.get("name")
        arguments = message.params.get("arguments", {})
        
        if tool_name not in self.tools:
            return MCPResponse.error(
                code=-32602,
                message=f"Tool not found: {tool_name}",
                id=message.id
            )
        
        tool = self.tools[tool_name]
    
        # Audit logging start
        auditor = AuditLogger(tool_name, tool.category.value if tool.category else "unknown", self.provider)
        auditor.log_input(arguments)
        
        if not tool.handler:
            error_msg = f"Tool {tool_name} has no handler"
            auditor.log_failure(error_msg)
            return MCPResponse.error(
                code=-32603,
                message=error_msg,
                id=message.id
            )
        
        try:
            result = await tool.handler(**arguments)
            auditor.log_success(result)
            return MCPResponse.success(result, message.id)
        
        except Exception as e:
            error_msg = f"Tool execution failed: {str(e)}"
            logger.error(f"Tool execution error: {e}")
            auditor.log_failure(error_msg)
            return MCPResponse.error(
                code=-32603,
                message=error_msg,
                id=message.id
            )
    
    async def _handle_list_resources(self, message: MCPMessage) -> MCPResponse:
        """List available resources"""
        resources_list = [
            {
                "uri": res.uri,
                "name": res.name,
                "description": res.description,
                "mimeType": res.mime_type
            }
            for res in self.resources.values()
        ]
        
        return MCPResponse.success({"resources": resources_list}, message.id)
    
    async def _handle_read_resource(self, message: MCPMessage) -> MCPResponse:
        """Read a resource"""
        uri = message.params.get("uri")
        
        if uri not in self.resources:
            return MCPResponse.error(
                code=-32602,
                message=f"Resource not found: {uri}",
                id=message.id
            )
        
        resource = self.resources[uri]
        
        try:
            # Fetch resource content
            content = await self._fetch_resource_content(uri)
            
            return MCPResponse.success({
                "contents": [{
                    "uri": uri,
                    "mimeType": resource.mime_type,
                    "text": content
                }]
            }, message.id)
        
        except Exception as e:
            logger.error(f"Resource read error: {e}")
            return MCPResponse.error(
                code=-32603,
                message=f"Failed to read resource: {str(e)}",
                id=message.id
            )
    
    @abstractmethod
    async def _fetch_resource_content(self, uri: str) -> str:
        """Fetch content for a resource URI"""
        pass
    
    async def start(self) -> None:
        """Start the MCP server"""
        self.running = True
        logger.info(f"[{self.provider}] MCP Server started")
    
    async def stop(self) -> None:
        """Stop the MCP server"""
        self.running = False
        logger.info(f"[{self.provider}] MCP Server stopped")
    
    def get_info(self) -> Dict[str, Any]:
        """Get server information"""
        return {
            "provider": self.provider,
            "tools_count": len(self.tools),
            "resources_count": len(self.resources),
            "running": self.running
        }


class MCPServerManager:
    """Manages multiple MCP servers"""
    
    def __init__(self):
        self.servers: Dict[str, BaseMCPServer] = {}
    
    def register_server(self, server: BaseMCPServer) -> None:
        """Register an MCP server"""
        self.servers[server.provider] = server
        logger.info(f"Registered MCP server: {server.provider}")
    
    def get_server(self, provider: str) -> Optional[BaseMCPServer]:
        """Get an MCP server by provider"""
        return self.servers.get(provider)
    
    async def start_all(self) -> None:
        """Start all registered servers"""
        for server in self.servers.values():
            await server.start()
    
    async def stop_all(self) -> None:
        """Stop all registered servers"""
        for server in self.servers.values():
            await server.stop()
    
    async def send_request(self, provider: str, message: MCPMessage) -> MCPResponse:
        """Send a request to a specific server"""
        server = self.get_server(provider)
        
        if not server:
            return MCPResponse.error(
                code=-32602,
                message=f"Server not found: {provider}",
                id=message.id
            )
        
        return await server.handle_request(message)
    
    def list_servers(self) -> List[Dict[str, Any]]:
        """List all registered servers"""
        return [
            {
                "provider": provider,
                **server.get_info()
            }
            for provider, server in self.servers.items()
        ]


# Global server manager
mcp_server_manager = MCPServerManager()