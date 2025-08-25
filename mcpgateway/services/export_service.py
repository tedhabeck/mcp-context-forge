# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/services/export_service.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Mihai Criveti

Export Service Implementation.
This module implements comprehensive configuration export functionality according to the export specification.
It handles:
- Entity collection from all entity types (Tools, Gateways, Servers, Prompts, Resources, Roots)
- Secure authentication data encryption using AES-256-GCM
- Dependency resolution and inclusion
- Filtering by entity types, tags, and active/inactive status
- Export format validation and schema compliance
- Only exports locally configured entities (not federated content)
"""

# Standard
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional

# Third-Party
from sqlalchemy import select
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.config import settings
from mcpgateway.db import Gateway as DbGateway
from mcpgateway.db import Tool as DbTool
from mcpgateway.services.gateway_service import GatewayService
from mcpgateway.services.prompt_service import PromptService
from mcpgateway.services.resource_service import ResourceService
from mcpgateway.services.root_service import RootService
from mcpgateway.services.server_service import ServerService
from mcpgateway.services.tool_service import ToolService

logger = logging.getLogger(__name__)


class ExportError(Exception):
    """Base class for export-related errors."""


class ExportValidationError(ExportError):
    """Raised when export data validation fails."""


class ExportService:
    """Service for exporting MCP Gateway configuration and data.

    This service provides comprehensive export functionality including:
    - Collection of all entity types (tools, gateways, servers, prompts, resources, roots)
    - Secure handling of authentication data with encryption
    - Dependency resolution between entities
    - Filtering options (by type, tags, status)
    - Export format validation

    The service only exports locally configured entities, excluding dynamic content
    from federated sources to ensure exports contain only configuration data.
    """

    def __init__(self):
        """Initialize the export service with required dependencies."""
        self.gateway_service = GatewayService()
        self.tool_service = ToolService()
        self.resource_service = ResourceService()
        self.prompt_service = PromptService()
        self.server_service = ServerService()
        self.root_service = RootService()

    async def initialize(self) -> None:
        """Initialize the export service."""
        logger.info("Export service initialized")

    async def shutdown(self) -> None:
        """Shutdown the export service."""
        logger.info("Export service shutdown")

    async def export_configuration(
        self,
        db: Session,
        include_types: Optional[List[str]] = None,
        exclude_types: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        include_inactive: bool = False,
        include_dependencies: bool = True,
        exported_by: str = "system",
    ) -> Dict[str, Any]:
        """Export complete gateway configuration to a standardized format.

        Args:
            db: Database session
            include_types: List of entity types to include (tools, gateways, servers, prompts, resources, roots)
            exclude_types: List of entity types to exclude
            tags: Filter entities by tags (only export entities with these tags)
            include_inactive: Whether to include inactive entities
            include_dependencies: Whether to include dependent entities automatically
            exported_by: Username of the person performing the export

        Returns:
            Dict containing the complete export data in the specified schema format

        Raises:
            ExportError: If export fails
            ExportValidationError: If validation fails
        """
        try:
            logger.info(f"Starting configuration export by {exported_by}")

            # Determine which entity types to include
            all_types = ["tools", "gateways", "servers", "prompts", "resources", "roots"]
            if include_types:
                entity_types = [t.lower() for t in include_types if t.lower() in all_types]
            else:
                entity_types = all_types

            if exclude_types:
                entity_types = [t for t in entity_types if t.lower() not in [e.lower() for e in exclude_types]]

            # Initialize export structure
            export_data = {
                "version": settings.protocol_version,
                "exported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "exported_by": exported_by,
                "source_gateway": f"http://{settings.host}:{settings.port}",
                "encryption_method": "AES-256-GCM",
                "entities": {},
                "metadata": {
                    "entity_counts": {},
                    "dependencies": {},
                    "export_options": {"include_inactive": include_inactive, "include_dependencies": include_dependencies, "selected_types": entity_types, "filter_tags": tags or []},
                },
            }

            # Export each entity type
            if "tools" in entity_types:
                export_data["entities"]["tools"] = await self._export_tools(db, tags, include_inactive)

            if "gateways" in entity_types:
                export_data["entities"]["gateways"] = await self._export_gateways(db, tags, include_inactive)

            if "servers" in entity_types:
                export_data["entities"]["servers"] = await self._export_servers(db, tags, include_inactive)

            if "prompts" in entity_types:
                export_data["entities"]["prompts"] = await self._export_prompts(db, tags, include_inactive)

            if "resources" in entity_types:
                export_data["entities"]["resources"] = await self._export_resources(db, tags, include_inactive)

            if "roots" in entity_types:
                export_data["entities"]["roots"] = await self._export_roots()

            # Add dependency information
            if include_dependencies:
                export_data["metadata"]["dependencies"] = await self._extract_dependencies(db, export_data["entities"])

            # Calculate entity counts
            for entity_type, entities in export_data["entities"].items():
                export_data["metadata"]["entity_counts"][entity_type] = len(entities)

            # Validate export data
            self._validate_export_data(export_data)

            logger.info(f"Export completed successfully with {sum(export_data['metadata']['entity_counts'].values())} total entities")
            return export_data

        except Exception as e:
            logger.error(f"Export failed: {str(e)}")
            raise ExportError(f"Failed to export configuration: {str(e)}")

    async def _export_tools(self, db: Session, tags: Optional[List[str]], include_inactive: bool) -> List[Dict[str, Any]]:
        """Export tools with encrypted authentication data.

        Args:
            db: Database session
            tags: Filter by tags
            include_inactive: Include inactive tools

        Returns:
            List of exported tool dictionaries
        """
        tools = await self.tool_service.list_tools(db, tags=tags, include_inactive=include_inactive)
        exported_tools = []

        for tool in tools:
            # Only export locally created REST tools, not MCP tools from gateways
            if tool.integration_type == "MCP" and tool.gateway_id:
                continue

            tool_data = {
                "name": tool.original_name,  # Use original name, not the slugified version
                "displayName": tool.displayName,  # Export displayName field from ToolRead
                "url": str(tool.url),
                "integration_type": tool.integration_type,
                "request_type": tool.request_type,
                "description": tool.description,
                "headers": tool.headers or {},
                "input_schema": tool.input_schema or {"type": "object", "properties": {}},
                "annotations": tool.annotations or {},
                "jsonpath_filter": tool.jsonpath_filter,
                "tags": tool.tags or [],
                "rate_limit": getattr(tool, "rate_limit", None),
                "timeout": getattr(tool, "timeout", None),
                "is_active": tool.enabled,
                "created_at": tool.created_at.isoformat() if hasattr(tool.created_at, "isoformat") and tool.created_at else None,
                "updated_at": tool.updated_at.isoformat() if hasattr(tool.updated_at, "isoformat") and tool.updated_at else None,
            }

            # Handle authentication data securely - get raw encrypted values
            if hasattr(tool, "auth") and tool.auth:
                auth_data = tool.auth
                if hasattr(auth_data, "auth_type") and hasattr(auth_data, "auth_value"):
                    # Check if auth_value is masked, if so get raw value from DB
                    if auth_data.auth_value == settings.masked_auth_value:
                        # Get the raw encrypted auth_value from database
                        db_tool = db.execute(select(DbTool).where(DbTool.id == tool.id)).scalar_one_or_none()
                        if db_tool and db_tool.auth_value:
                            tool_data["auth_type"] = auth_data.auth_type
                            tool_data["auth_value"] = db_tool.auth_value  # Raw encrypted value
                    else:
                        # Auth value is not masked, use as-is
                        tool_data["auth_type"] = auth_data.auth_type
                        tool_data["auth_value"] = auth_data.auth_value  # Already encrypted

            exported_tools.append(tool_data)

        return exported_tools

    async def _export_gateways(self, db: Session, tags: Optional[List[str]], include_inactive: bool) -> List[Dict[str, Any]]:
        """Export gateways with encrypted authentication data.

        Args:
            db: Database session
            tags: Filter by tags
            include_inactive: Include inactive gateways

        Returns:
            List of exported gateway dictionaries
        """
        gateways = await self.gateway_service.list_gateways(db, include_inactive=include_inactive)
        exported_gateways = []

        for gateway in gateways:
            # Filter by tags if specified
            if tags and not any(tag in (gateway.tags or []) for tag in tags):
                continue

            gateway_data = {
                "name": gateway.name,
                "url": str(gateway.url),
                "description": gateway.description,
                "transport": gateway.transport,
                "capabilities": gateway.capabilities or {},
                "health_check": {"url": f"{gateway.url}/health", "interval": 30, "timeout": 10, "retries": 3},
                "is_active": gateway.enabled,
                "federation_enabled": True,
                "tags": gateway.tags or [],
                "passthrough_headers": gateway.passthrough_headers or [],
            }

            # Handle authentication data securely - get raw encrypted values
            if gateway.auth_type and gateway.auth_value:
                # Check if auth_value is masked, if so get raw value from DB
                if gateway.auth_value == settings.masked_auth_value:
                    # Get the raw encrypted auth_value from database
                    db_gateway = db.execute(select(DbGateway).where(DbGateway.id == gateway.id)).scalar_one_or_none()
                    if db_gateway and db_gateway.auth_value:
                        gateway_data["auth_type"] = gateway.auth_type
                        gateway_data["auth_value"] = db_gateway.auth_value  # Raw encrypted value
                else:
                    # Auth value is not masked, use as-is
                    gateway_data["auth_type"] = gateway.auth_type
                    gateway_data["auth_value"] = gateway.auth_value  # Already encrypted

            exported_gateways.append(gateway_data)

        return exported_gateways

    async def _export_servers(self, db: Session, tags: Optional[List[str]], include_inactive: bool) -> List[Dict[str, Any]]:
        """Export virtual servers with their tool associations.

        Args:
            db: Database session
            tags: Filter by tags
            include_inactive: Include inactive servers

        Returns:
            List of exported server dictionaries
        """
        servers = await self.server_service.list_servers(db, tags=tags, include_inactive=include_inactive)
        exported_servers = []

        for server in servers:
            server_data = {
                "name": server.name,
                "description": server.description,
                "tool_ids": list(server.associated_tools),
                "sse_endpoint": f"/servers/{server.id}/sse",
                "websocket_endpoint": f"/servers/{server.id}/ws",
                "jsonrpc_endpoint": f"/servers/{server.id}/jsonrpc",
                "capabilities": {"tools": {"list_changed": True}, "prompts": {"list_changed": True}},
                "is_active": server.is_active,
                "tags": server.tags or [],
            }

            exported_servers.append(server_data)

        return exported_servers

    async def _export_prompts(self, db: Session, tags: Optional[List[str]], include_inactive: bool) -> List[Dict[str, Any]]:
        """Export prompts with their templates and schemas.

        Args:
            db: Database session
            tags: Filter by tags
            include_inactive: Include inactive prompts

        Returns:
            List of exported prompt dictionaries
        """
        prompts = await self.prompt_service.list_prompts(db, tags=tags, include_inactive=include_inactive)
        exported_prompts = []

        for prompt in prompts:
            prompt_data = {
                "name": prompt.name,
                "template": prompt.template,
                "description": prompt.description,
                "input_schema": {"type": "object", "properties": {}, "required": []},
                "tags": prompt.tags or [],
                "is_active": prompt.is_active,
            }

            # Convert arguments to input schema format
            if prompt.arguments:
                properties = {}
                required = []
                for arg in prompt.arguments:
                    properties[arg.name] = {"type": "string", "description": arg.description or ""}
                    if arg.required:
                        required.append(arg.name)

                prompt_data["input_schema"]["properties"] = properties
                prompt_data["input_schema"]["required"] = required

            exported_prompts.append(prompt_data)

        return exported_prompts

    async def _export_resources(self, db: Session, tags: Optional[List[str]], include_inactive: bool) -> List[Dict[str, Any]]:
        """Export resources with their content metadata.

        Args:
            db: Database session
            tags: Filter by tags
            include_inactive: Include inactive resources

        Returns:
            List of exported resource dictionaries
        """
        resources = await self.resource_service.list_resources(db, tags=tags, include_inactive=include_inactive)
        exported_resources = []

        for resource in resources:
            resource_data = {
                "name": resource.name,
                "uri": resource.uri,
                "description": resource.description,
                "mime_type": resource.mime_type,
                "tags": resource.tags or [],
                "is_active": resource.is_active,
                "last_modified": resource.updated_at.isoformat() if resource.updated_at else None,
            }

            exported_resources.append(resource_data)

        return exported_resources

    async def _export_roots(self) -> List[Dict[str, Any]]:
        """Export filesystem roots.

        Returns:
            List of exported root dictionaries
        """
        roots = await self.root_service.list_roots()
        exported_roots = []

        for root in roots:
            root_data = {"uri": str(root.uri), "name": root.name}
            exported_roots.append(root_data)

        return exported_roots

    async def _extract_dependencies(self, db: Session, entities: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:  # pylint: disable=unused-argument
        """Extract dependency relationships between entities.

        Args:
            db: Database session
            entities: Dictionary of exported entities

        Returns:
            Dictionary containing dependency mappings
        """
        dependencies = {"servers_to_tools": {}, "servers_to_resources": {}, "servers_to_prompts": {}}

        # Extract server-to-tool dependencies
        if "servers" in entities and "tools" in entities:
            for server in entities["servers"]:
                if server.get("tool_ids"):
                    dependencies["servers_to_tools"][server["name"]] = server["tool_ids"]

        return dependencies

    def _validate_export_data(self, export_data: Dict[str, Any]) -> None:
        """Validate export data against the schema.

        Args:
            export_data: The export data to validate

        Raises:
            ExportValidationError: If validation fails
        """
        required_fields = ["version", "exported_at", "exported_by", "entities", "metadata"]

        for field in required_fields:
            if field not in export_data:
                raise ExportValidationError(f"Missing required field: {field}")

        # Validate version format
        if not export_data["version"]:
            raise ExportValidationError("Version cannot be empty")

        # Validate entities structure
        if not isinstance(export_data["entities"], dict):
            raise ExportValidationError("Entities must be a dictionary")

        # Validate metadata structure
        metadata = export_data["metadata"]
        if not isinstance(metadata.get("entity_counts"), dict):
            raise ExportValidationError("Metadata entity_counts must be a dictionary")

        logger.debug("Export data validation passed")

    async def export_selective(self, db: Session, entity_selections: Dict[str, List[str]], include_dependencies: bool = True, exported_by: str = "system") -> Dict[str, Any]:
        """Export specific entities by their IDs/names.

        Args:
            db: Database session
            entity_selections: Dict mapping entity types to lists of IDs/names to export
            include_dependencies: Whether to include dependent entities
            exported_by: Username of the person performing the export

        Returns:
            Dict containing the selective export data

        Example:
            entity_selections = {
                "tools": ["tool1", "tool2"],
                "servers": ["server1"],
                "prompts": ["prompt1"]
            }
        """
        logger.info(f"Starting selective export by {exported_by}")

        export_data = {
            "version": settings.protocol_version,
            "exported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "exported_by": exported_by,
            "source_gateway": f"http://{settings.host}:{settings.port}",
            "encryption_method": "AES-256-GCM",
            "entities": {},
            "metadata": {"entity_counts": {}, "dependencies": {}, "export_options": {"selective": True, "include_dependencies": include_dependencies, "selections": entity_selections}},
        }

        # Export selected entities for each type
        for entity_type, selected_ids in entity_selections.items():
            if entity_type == "tools":
                export_data["entities"]["tools"] = await self._export_selected_tools(db, selected_ids)
            elif entity_type == "gateways":
                export_data["entities"]["gateways"] = await self._export_selected_gateways(db, selected_ids)
            elif entity_type == "servers":
                export_data["entities"]["servers"] = await self._export_selected_servers(db, selected_ids)
            elif entity_type == "prompts":
                export_data["entities"]["prompts"] = await self._export_selected_prompts(db, selected_ids)
            elif entity_type == "resources":
                export_data["entities"]["resources"] = await self._export_selected_resources(db, selected_ids)
            elif entity_type == "roots":
                export_data["entities"]["roots"] = await self._export_selected_roots(selected_ids)

        # Add dependencies if requested
        if include_dependencies:
            export_data["metadata"]["dependencies"] = await self._extract_dependencies(db, export_data["entities"])

        # Calculate entity counts
        for entity_type, entities in export_data["entities"].items():
            export_data["metadata"]["entity_counts"][entity_type] = len(entities)

        self._validate_export_data(export_data)

        logger.info(f"Selective export completed with {sum(export_data['metadata']['entity_counts'].values())} entities")
        return export_data

    async def _export_selected_tools(self, db: Session, tool_ids: List[str]) -> List[Dict[str, Any]]:
        """Export specific tools by their IDs.

        Args:
            db: Database session
            tool_ids: List of tool IDs to export

        Returns:
            List of exported tool dictionaries
        """
        tools = []
        for tool_id in tool_ids:
            try:
                tool = await self.tool_service.get_tool(db, tool_id)
                if tool.integration_type == "REST":  # Only export local REST tools
                    tool_data = await self._export_tools(db, None, True)
                    tools.extend([t for t in tool_data if t["name"] == tool.original_name])
            except Exception as e:
                logger.warning(f"Could not export tool {tool_id}: {str(e)}")
        return tools

    async def _export_selected_gateways(self, db: Session, gateway_ids: List[str]) -> List[Dict[str, Any]]:
        """Export specific gateways by their IDs.

        Args:
            db: Database session
            gateway_ids: List of gateway IDs to export

        Returns:
            List of exported gateway dictionaries
        """
        gateways = []
        for gateway_id in gateway_ids:
            try:
                gateway = await self.gateway_service.get_gateway(db, gateway_id)
                gateway_data = await self._export_gateways(db, None, True)
                gateways.extend([g for g in gateway_data if g["name"] == gateway.name])
            except Exception as e:
                logger.warning(f"Could not export gateway {gateway_id}: {str(e)}")
        return gateways

    async def _export_selected_servers(self, db: Session, server_ids: List[str]) -> List[Dict[str, Any]]:
        """Export specific servers by their IDs.

        Args:
            db: Database session
            server_ids: List of server IDs to export

        Returns:
            List of exported server dictionaries
        """
        servers = []
        for server_id in server_ids:
            try:
                server = await self.server_service.get_server(db, server_id)
                server_data = await self._export_servers(db, None, True)
                servers.extend([s for s in server_data if s["name"] == server.name])
            except Exception as e:
                logger.warning(f"Could not export server {server_id}: {str(e)}")
        return servers

    async def _export_selected_prompts(self, db: Session, prompt_names: List[str]) -> List[Dict[str, Any]]:
        """Export specific prompts by their names.

        Args:
            db: Database session
            prompt_names: List of prompt names to export

        Returns:
            List of exported prompt dictionaries
        """
        prompts = []
        for prompt_name in prompt_names:
            try:
                # Use get_prompt with empty args to get metadata
                await self.prompt_service.get_prompt(db, prompt_name, {})
                prompt_data = await self._export_prompts(db, None, True)
                prompts.extend([p for p in prompt_data if p["name"] == prompt_name])
            except Exception as e:
                logger.warning(f"Could not export prompt {prompt_name}: {str(e)}")
        return prompts

    async def _export_selected_resources(self, db: Session, resource_uris: List[str]) -> List[Dict[str, Any]]:
        """Export specific resources by their URIs.

        Args:
            db: Database session
            resource_uris: List of resource URIs to export

        Returns:
            List of exported resource dictionaries
        """
        resources = []
        for resource_uri in resource_uris:
            try:
                resource_data = await self._export_resources(db, None, True)
                resources.extend([r for r in resource_data if r["uri"] == resource_uri])
            except Exception as e:
                logger.warning(f"Could not export resource {resource_uri}: {str(e)}")
        return resources

    async def _export_selected_roots(self, root_uris: List[str]) -> List[Dict[str, Any]]:
        """Export specific roots by their URIs.

        Args:
            root_uris: List of root URIs to export

        Returns:
            List of exported root dictionaries
        """
        all_roots = await self._export_roots()
        return [r for r in all_roots if r["uri"] in root_uris]
