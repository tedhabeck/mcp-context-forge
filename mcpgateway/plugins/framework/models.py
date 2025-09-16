# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/plugins/framework/models.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor, Mihai Criveti

Pydantic models for plugins.
This module implements the pydantic models associated with
the base plugin layer including configurations, and contexts.
"""

# Standard
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Generic, Optional, Self, TypeVar

# Third-Party
from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator, model_validator, PrivateAttr, RootModel, ValidationInfo

# First-Party
from mcpgateway.models import PromptResult
from mcpgateway.plugins.framework.constants import AFTER, EXTERNAL_PLUGIN_TYPE, IGNORE_CONFIG_EXTERNAL, PYTHON_SUFFIX, SCRIPT, URL
from mcpgateway.schemas import TransportType
from mcpgateway.validators import SecurityValidator

T = TypeVar("T")


class HookType(str, Enum):
    """MCP Forge Gateway hook points.

    Attributes:
        http_pre_forwarding_call: The pre hook before an http forwarding request.
        http_post_forwarding_call: The post hook after an http forwarding request.
        prompt_pre_fetch: The prompt pre hook.
        prompt_post_fetch: The prompt post hook.
        tool_pre_invoke: The tool pre invoke hook.
        tool_post_invoke: The tool post invoke hook.
        resource_pre_fetch: The resource pre fetch hook.
        resource_post_fetch: The resource post fetch hook.

    Examples:
        >>> HookType.PROMPT_PRE_FETCH
        <HookType.PROMPT_PRE_FETCH: 'prompt_pre_fetch'>
        >>> HookType.PROMPT_PRE_FETCH.value
        'prompt_pre_fetch'
        >>> HookType('prompt_post_fetch')
        <HookType.PROMPT_POST_FETCH: 'prompt_post_fetch'>
        >>> list(HookType)  # doctest: +ELLIPSIS
        [<HookType.PROMPT_PRE_FETCH: 'prompt_pre_fetch'>, <HookType.PROMPT_POST_FETCH: 'prompt_post_fetch'>, <HookType.TOOL_PRE_INVOKE: 'tool_pre_invoke'>, <HookType.TOOL_POST_INVOKE: 'tool_post_invoke'>, ...]
    """

    HTTP_PRE_FORWARDING_CALL = "http_pre_forwarding_call"
    HTTP_POST_FORWARDING_CALL = "http_post_forwarding_call"
    PROMPT_PRE_FETCH = "prompt_pre_fetch"
    PROMPT_POST_FETCH = "prompt_post_fetch"
    TOOL_PRE_INVOKE = "tool_pre_invoke"
    TOOL_POST_INVOKE = "tool_post_invoke"
    RESOURCE_PRE_FETCH = "resource_pre_fetch"
    RESOURCE_POST_FETCH = "resource_post_fetch"


class PluginMode(str, Enum):
    """Plugin modes of operation.

    Attributes:
       enforce: enforces the plugin result, and blocks execution when there is an error.
       enforce_ignore_error: enforces the plugin result, but allows execution when there is an error.
       permissive: audits the result.
       disabled: plugin disabled.

    Examples:
        >>> PluginMode.ENFORCE
        <PluginMode.ENFORCE: 'enforce'>
        >>> PluginMode.ENFORCE_IGNORE_ERROR
        <PluginMode.ENFORCE_IGNORE_ERROR: 'enforce_ignore_error'>
        >>> PluginMode.PERMISSIVE.value
        'permissive'
        >>> PluginMode('disabled')
        <PluginMode.DISABLED: 'disabled'>
        >>> 'enforce' in [m.value for m in PluginMode]
        True
    """

    ENFORCE = "enforce"
    ENFORCE_IGNORE_ERROR = "enforce_ignore_error"
    PERMISSIVE = "permissive"
    DISABLED = "disabled"


class BaseTemplate(BaseModel):
    """Base Template.The ToolTemplate, PromptTemplate and ResourceTemplate could be extended using this

    Attributes:
        context (Optional[list[str]]): specifies the keys of context to be extracted. The context could be global (shared between the plugins) or
        local (shared within the plugin). Example: global.key1.
        extensions (Optional[dict[str, Any]]): add custom keys for your specific plugin. Example - 'policy'
        key for opa plugin.

    Examples:
        >>> base = BaseTemplate(context=["global.key1.key2", "local.key1.key2"])
        >>> base.context
        ['global.key1.key2', 'local.key1.key2']
        >>> base = BaseTemplate(context=["global.key1.key2"], extensions={"policy" : "sample policy"})
        >>> base.extensions
        {'policy': 'sample policy'}
    """

    context: Optional[list[str]] = None
    extensions: Optional[dict[str, Any]] = None


class ToolTemplate(BaseTemplate):
    """Tool Template.

    Attributes:
        tool_name (str): the name of the tool.
        fields (Optional[list[str]]): the tool fields that are affected.
        result (bool): analyze tool output if true.

    Examples:
        >>> tool = ToolTemplate(tool_name="my_tool")
        >>> tool.tool_name
        'my_tool'
        >>> tool.result
        False
        >>> tool2 = ToolTemplate(tool_name="analyzer", fields=["input", "params"], result=True)
        >>> tool2.fields
        ['input', 'params']
        >>> tool2.result
        True
    """

    tool_name: str
    fields: Optional[list[str]] = None
    result: bool = False


class PromptTemplate(BaseTemplate):
    """Prompt Template.

    Attributes:
        prompt_name (str): the name of the prompt.
        fields (Optional[list[str]]): the prompt fields that are affected.
        result (bool): analyze tool output if true.

    Examples:
        >>> prompt = PromptTemplate(prompt_name="greeting")
        >>> prompt.prompt_name
        'greeting'
        >>> prompt.result
        False
        >>> prompt2 = PromptTemplate(prompt_name="question", fields=["context"], result=True)
        >>> prompt2.fields
        ['context']
    """

    prompt_name: str
    fields: Optional[list[str]] = None
    result: bool = False


class ResourceTemplate(BaseTemplate):
    """Resource Template.

    Attributes:
        resource_uri (str): the URI of the resource.
        fields (Optional[list[str]]): the resource fields that are affected.
        result (bool): analyze resource output if true.

    Examples:
        >>> resource = ResourceTemplate(resource_uri="file:///data.txt")
        >>> resource.resource_uri
        'file:///data.txt'
        >>> resource.result
        False
        >>> resource2 = ResourceTemplate(resource_uri="http://api/data", fields=["content"], result=True)
        >>> resource2.fields
        ['content']
    """

    resource_uri: str
    fields: Optional[list[str]] = None
    result: bool = False


class PluginCondition(BaseModel):
    """Conditions for when plugin should execute.

    Attributes:
        server_ids (Optional[set[str]]): set of server ids.
        tenant_ids (Optional[set[str]]): set of tenant ids.
        tools (Optional[set[str]]): set of tool names.
        prompts (Optional[set[str]]): set of prompt names.
        resources (Optional[set[str]]): set of resource URIs.
        user_pattern (Optional[list[str]]): list of user patterns.
        content_types (Optional[list[str]]): list of content types.

    Examples:
        >>> cond = PluginCondition(server_ids={"server1", "server2"})
        >>> "server1" in cond.server_ids
        True
        >>> cond2 = PluginCondition(tools={"tool1"}, prompts={"prompt1"})
        >>> cond2.tools
        {'tool1'}
        >>> cond3 = PluginCondition(user_patterns=["admin", "root"])
        >>> len(cond3.user_patterns)
        2
    """

    server_ids: Optional[set[str]] = None
    tenant_ids: Optional[set[str]] = None
    tools: Optional[set[str]] = None
    prompts: Optional[set[str]] = None
    resources: Optional[set[str]] = None
    user_patterns: Optional[list[str]] = None
    content_types: Optional[list[str]] = None

    @field_serializer("server_ids", "tenant_ids", "tools", "prompts")
    def serialize_set(self, value: set[str] | None) -> list[str] | None:
        """Serialize set objects in PluginCondition for MCP.

        Args:
            value: a set of server ids, tenant ids, tools or prompts.

        Returns:
            The set as a serializable list.
        """
        if value:
            values = []
            for key in value:
                values.append(key)
            return values
        return None


class AppliedTo(BaseModel):
    """What tools/prompts/resources and fields the plugin will be applied to.

    Attributes:
        tools (Optional[list[ToolTemplate]]): tools and fields to be applied.
        prompts (Optional[list[PromptTemplate]]): prompts and fields to be applied.
        resources (Optional[list[ResourceTemplate]]): resources and fields to be applied.
        global_context (Optional[list[str]]): keys in the context to be applied on globally
        local_context(Optional[list[str]]): keys in the context to be applied on locally
    """

    tools: Optional[list[ToolTemplate]] = None
    prompts: Optional[list[PromptTemplate]] = None
    resources: Optional[list[ResourceTemplate]] = None


class MCPConfig(BaseModel):
    """An MCP configuration for external MCP plugin objects.

    Attributes:
        type (TransportType): The MCP transport type. Can be SSE, STDIO, or STREAMABLEHTTP
        url (Optional[str]): An MCP URL. Only valid when MCP transport type is SSE or STREAMABLEHTTP.
        script (Optional[str]): The path and name to the STDIO script that runs the plugin server. Only valid for STDIO type.
    """

    proto: TransportType
    url: Optional[str] = None
    script: Optional[str] = None

    @field_validator(URL, mode=AFTER)
    @classmethod
    def validate_url(cls, url: str | None) -> str | None:
        """Validate a MCP url for streamable HTTP connections.

        Args:
            url: the url to be validated.

        Raises:
            ValueError: if the URL fails validation.

        Returns:
            The validated URL or None if none is set.
        """
        if url:
            result = SecurityValidator.validate_url(url)
            return result
        return url

    @field_validator(SCRIPT, mode=AFTER)
    @classmethod
    def validate_script(cls, script: str | None) -> str | None:
        """Validate an MCP stdio script.

        Args:
            script: the script to be validated.

        Raises:
            ValueError: if the script doesn't exist or doesn't have a .py suffix.

        Returns:
            The validated string or None if none is set.
        """
        if script:
            file_path = Path(script)
            if not file_path.is_file():
                raise ValueError(f"MCP server script {script} does not exist.")
            if file_path.suffix != PYTHON_SUFFIX:
                raise ValueError(f"MCP server script {script} does not have a .py suffix.")
        return script


class PluginConfig(BaseModel):
    """A plugin configuration.

    Attributes:
        name (str): The unique name of the plugin.
        description (str): A description of the plugin.
        author (str): The author of the plugin.
        kind (str): The kind or type of plugin. Usually a fully qualified object type.
        namespace (str): The namespace where the plugin resides.
        version (str): version of the plugin.
        hooks (list[str]): a list of the hook points where the plugin will be called.
        tags (list[str]): a list of tags for making the plugin searchable.
        mode (bool): whether the plugin is active.
        priority (int): indicates the order in which the plugin is run. Lower = higher priority.
        conditions (Optional[list[PluginCondition]]): the conditions on which the plugin is run.
        applied_to (Optional[list[AppliedTo]]): the tools, fields, that the plugin is applied to.
        config (dict[str, Any]): the plugin specific configurations.
        mcp (Optional[MCPConfig]): MCP configuration for external plugin when kind is "external".
    """

    name: str
    description: Optional[str] = None
    author: Optional[str] = None
    kind: str
    namespace: Optional[str] = None
    version: Optional[str] = None
    hooks: Optional[list[HookType]] = None
    tags: Optional[list[str]] = None
    mode: PluginMode = PluginMode.ENFORCE
    priority: Optional[int] = None  # Lower = higher priority
    conditions: Optional[list[PluginCondition]] = None  # When to apply
    applied_to: Optional[AppliedTo] = None  # Fields to apply to.
    config: Optional[dict[str, Any]] = None
    mcp: Optional[MCPConfig] = None

    @model_validator(mode=AFTER)
    def check_url_or_script_filled(self) -> Self:  # pylint: disable=bad-classmethod-argument
        """Checks to see that at least one of url or script are set depending on MCP server configuration.

        Raises:
            ValueError: if the script attribute is not defined with STDIO set, or the URL not defined with HTTP transports.

        Returns:
            The model after validation.
        """
        if not self.mcp:
            return self
        if self.mcp.proto == TransportType.STDIO and not self.mcp.script:
            raise ValueError(f"Plugin {self.name} has transport type set to SSE but no script value")
        if self.mcp.proto in (TransportType.STREAMABLEHTTP, TransportType.SSE) and not self.mcp.url:
            raise ValueError(f"Plugin {self.name} has transport type set to StreamableHTTP but no url value")
        if self.mcp.proto not in (TransportType.SSE, TransportType.STREAMABLEHTTP, TransportType.STDIO):
            raise ValueError(f"Plugin {self.name} must set transport type to either SSE or STREAMABLEHTTP or STDIO")
        return self

    @model_validator(mode=AFTER)
    def check_config_and_external(self, info: ValidationInfo) -> Self:  # pylint: disable=bad-classmethod-argument
        """Checks to see that a plugin's 'config' section is not defined if the kind is 'external'. This is because developers cannot override items in the plugin config section for external plugins.

        Args:
            info: the contextual information passed into the pydantic model during model validation. Used to determine validation sequence.

        Raises:
            ValueError: if the script attribute is not defined with STDIO set, or the URL not defined with HTTP transports.

        Returns:
            The model after validation.
        """
        ignore_config_external = False
        if info and info.context and IGNORE_CONFIG_EXTERNAL in info.context:
            ignore_config_external = info.context[IGNORE_CONFIG_EXTERNAL]

        if not ignore_config_external and self.config and self.kind == EXTERNAL_PLUGIN_TYPE:
            raise ValueError(f"""Cannot have {self.name} plugin defined as 'external' with 'config' set.""" """ 'config' section settings can only be set on the plugin server.""")

        if self.kind == EXTERNAL_PLUGIN_TYPE and not self.mcp:
            raise ValueError(f"Must set 'mcp' section for external plugin {self.name}")

        return self


class PluginManifest(BaseModel):
    """Plugin manifest.

    Attributes:
        description (str): A description of the plugin.
        author (str): The author of the plugin.
        version (str): version of the plugin.
        tags (list[str]): a list of tags for making the plugin searchable.
        available_hooks (list[str]): a list of the hook points where the plugin is callable.
        default_config (dict[str, Any]): the default configurations.
    """

    description: str
    author: str
    version: str
    tags: list[str]
    available_hooks: list[str]
    default_config: dict[str, Any]


class PluginErrorModel(BaseModel):
    """A plugin error, used to denote exceptions/errors inside external plugins.

    Attributes:
        message (str): the reason for the error.
        code (str): an error code.
        details: (dict[str, Any]): additional error details.
        plugin_name (str): the plugin name.
    """

    message: str
    code: Optional[str] = ""
    details: Optional[dict[str, Any]] = Field(default_factory=dict)
    plugin_name: str


class PluginViolation(BaseModel):
    """A plugin violation, used to denote policy violations.

    Attributes:
        reason (str): the reason for the violation.
        description (str): a longer description of the violation.
        code (str): a violation code.
        details: (dict[str, Any]): additional violation details.
        _plugin_name (str): the plugin name, private attribute set by the plugin manager.

    Examples:
        >>> violation = PluginViolation(
        ...     reason="Invalid input",
        ...     description="The input contains prohibited content",
        ...     code="PROHIBITED_CONTENT",
        ...     details={"field": "message", "value": "test"}
        ... )
        >>> violation.reason
        'Invalid input'
        >>> violation.code
        'PROHIBITED_CONTENT'
        >>> violation.plugin_name = "content_filter"
        >>> violation.plugin_name
        'content_filter'
    """

    reason: str
    description: str
    code: str
    details: dict[str, Any]
    _plugin_name: str = PrivateAttr(default="")

    @property
    def plugin_name(self) -> str:
        """Getter for the plugin name attribute.

        Returns:
            The plugin name associated with the violation.
        """
        return self._plugin_name

    @plugin_name.setter
    def plugin_name(self, name: str) -> None:
        """Setter for the plugin_name attribute.

        Args:
            name: the plugin name.

        Raises:
            ValueError: if name is empty or not a string.
        """
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Name must be a non-empty string.")
        self._plugin_name = name


class PluginSettings(BaseModel):
    """Global plugin settings.

    Attributes:
        parallel_execution_within_band (bool): execute plugins with same priority in parallel.
        plugin_timeout (int):  timeout value for plugins operations.
        fail_on_plugin_error (bool): error when there is a plugin connectivity or ignore.
        enable_plugin_api (bool): enable or disable plugins globally.
        plugin_health_check_interval (int): health check interval check.
    """

    parallel_execution_within_band: bool = False
    plugin_timeout: int = 30
    fail_on_plugin_error: bool = False
    enable_plugin_api: bool = False
    plugin_health_check_interval: int = 60


class Config(BaseModel):
    """Configurations for plugins.

    Attributes:
        plugins: the list of plugins to enable.
        plugin_dirs: The directories in which to look for plugins.
        plugin_settings: global settings for plugins.
    """

    plugins: Optional[list[PluginConfig]] = []
    plugin_dirs: list[str] = []
    plugin_settings: PluginSettings


class PromptPrehookPayload(BaseModel):
    """A prompt payload for a prompt prehook.

    Attributes:
        name (str): The name of the prompt template.
        args (dic[str,str]): The prompt template arguments.

    Examples:
        >>> payload = PromptPrehookPayload(name="test_prompt", args={"user": "alice"})
        >>> payload.name
        'test_prompt'
        >>> payload.args
        {'user': 'alice'}
        >>> payload2 = PromptPrehookPayload(name="empty")
        >>> payload2.args
        {}
        >>> p = PromptPrehookPayload(name="greeting", args={"name": "Bob", "time": "morning"})
        >>> p.name
        'greeting'
        >>> p.args["name"]
        'Bob'
    """

    name: str
    args: Optional[dict[str, str]] = Field(default_factory=dict)


class PromptPosthookPayload(BaseModel):
    """A prompt payload for a prompt posthook.

    Attributes:
        name (str): The prompt name.
        result (PromptResult): The prompt after its template is rendered.

     Examples:
        >>> from mcpgateway.models import PromptResult, Message, TextContent
        >>> msg = Message(role="user", content=TextContent(type="text", text="Hello World"))
        >>> result = PromptResult(messages=[msg])
        >>> payload = PromptPosthookPayload(name="greeting", result=result)
        >>> payload.name
        'greeting'
        >>> payload.result.messages[0].content.text
        'Hello World'
        >>> from mcpgateway.models import PromptResult, Message, TextContent
        >>> msg = Message(role="assistant", content=TextContent(type="text", text="Test output"))
        >>> r = PromptResult(messages=[msg])
        >>> p = PromptPosthookPayload(name="test", result=r)
        >>> p.name
        'test'
    """

    name: str
    result: PromptResult


class PluginResult(BaseModel, Generic[T]):
    """A result of the plugin hook processing. The actual type is dependent on the hook.

    Attributes:
            continue_processing (bool): Whether to stop processing.
            modified_payload (Optional[Any]): The modified payload if the plugin is a transformer.
            violation (Optional[PluginViolation]): violation object.
            metadata (Optional[dict[str, Any]]): additional metadata.

     Examples:
        >>> result = PluginResult()
        >>> result.continue_processing
        True
        >>> result.metadata
        {}
        >>> from mcpgateway.plugins.framework import PluginViolation
        >>> violation = PluginViolation(
        ...     reason="Test", description="Test desc", code="TEST", details={}
        ... )
        >>> result2 = PluginResult(continue_processing=False, violation=violation)
        >>> result2.continue_processing
        False
        >>> result2.violation.code
        'TEST'
        >>> r = PluginResult(metadata={"key": "value"})
        >>> r.metadata["key"]
        'value'
        >>> r2 = PluginResult(continue_processing=False)
        >>> r2.continue_processing
        False
    """

    continue_processing: bool = True
    modified_payload: Optional[T] = None
    violation: Optional[PluginViolation] = None
    metadata: Optional[dict[str, Any]] = Field(default_factory=dict)


PromptPrehookResult = PluginResult[PromptPrehookPayload]
PromptPosthookResult = PluginResult[PromptPosthookPayload]


class HttpHeaderPayload(RootModel[dict[str, str]]):
    """An HTTP dictionary of headers used in the pre/post HTTP forwarding hooks."""

    def __iter__(self):
        """Custom iterator function to override root attribute.

        Returns:
            A custom iterator for header dictionary.
        """
        return iter(self.root)

    def __getitem__(self, item: str) -> str:
        """Custom getitem function to override root attribute.

        Args:
            item: The http header key.

        Returns:
            A custom accesser for the header dictionary.
        """
        return self.root[item]

    def __len__(self):
        """Custom len function to override root attribute.

        Returns:
            The len of the header dictionary.
        """
        return len(self.root)


HttpHeaderPayloadResult = PluginResult[HttpHeaderPayload]


class ToolPreInvokePayload(BaseModel):
    """A tool payload for a tool pre-invoke hook.

    Args:
        name: The tool name.
        args: The tool arguments for invocation.
        headers: The http pass through headers.

    Examples:
        >>> payload = ToolPreInvokePayload(name="test_tool", args={"input": "data"})
        >>> payload.name
        'test_tool'
        >>> payload.args
        {'input': 'data'}
        >>> payload2 = ToolPreInvokePayload(name="empty")
        >>> payload2.args
        {}
        >>> p = ToolPreInvokePayload(name="calculator", args={"operation": "add", "a": 5, "b": 3})
        >>> p.name
        'calculator'
        >>> p.args["operation"]
        'add'

    """

    name: str
    args: Optional[dict[str, Any]] = Field(default_factory=dict)
    headers: Optional[HttpHeaderPayload] = None


class ToolPostInvokePayload(BaseModel):
    """A tool payload for a tool post-invoke hook.

    Args:
        name: The tool name.
        result: The tool invocation result.

    Examples:
        >>> payload = ToolPostInvokePayload(name="calculator", result={"result": 8, "status": "success"})
        >>> payload.name
        'calculator'
        >>> payload.result
        {'result': 8, 'status': 'success'}
        >>> p = ToolPostInvokePayload(name="analyzer", result={"confidence": 0.95, "sentiment": "positive"})
        >>> p.name
        'analyzer'
        >>> p.result["confidence"]
        0.95
    """

    name: str
    result: Any


ToolPreInvokeResult = PluginResult[ToolPreInvokePayload]
ToolPostInvokeResult = PluginResult[ToolPostInvokePayload]


class GlobalContext(BaseModel):
    """The global context, which shared across all plugins.

    Attributes:
            request_id (str): ID of the HTTP request.
            user (str): user ID associated with the request.
            tenant_id (str): tenant ID.
            server_id (str): server ID.
            metadata (Optional[dict[str,Any]]): a global shared metadata across plugins (Read-only from plugin's perspective).
            state (Optional[dict[str,Any]]): a global shared state across plugins.

    Examples:
        >>> ctx = GlobalContext(request_id="req-123")
        >>> ctx.request_id
        'req-123'
        >>> ctx.user is None
        True
        >>> ctx2 = GlobalContext(request_id="req-456", user="alice", tenant_id="tenant1")
        >>> ctx2.user
        'alice'
        >>> ctx2.tenant_id
        'tenant1'
        >>> c = GlobalContext(request_id="123", server_id="srv1")
        >>> c.request_id
        '123'
        >>> c.server_id
        'srv1'
    """

    request_id: str
    user: Optional[str] = None
    tenant_id: Optional[str] = None
    server_id: Optional[str] = None
    state: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PluginContext(BaseModel):
    """The plugin's context, which lasts a request lifecycle.

    Attributes:
       state:  the inmemory state of the request.
       global_context: the context that is shared across plugins.
       metadata: plugin meta data.

    Examples:
        >>> gctx = GlobalContext(request_id="req-123")
        >>> ctx = PluginContext(global_context=gctx)
        >>> ctx.global_context.request_id
        'req-123'
        >>> ctx.global_context.user is None
        True
        >>> ctx.state["somekey"] = "some value"
        >>> ctx.state["somekey"]
        'some value'
    """

    state: dict[str, Any] = Field(default_factory=dict)
    global_context: GlobalContext
    metadata: dict[str, Any] = Field(default_factory=dict)

    def get_state(self, key: str, default: Any = None) -> Any:
        """Get value from shared state.

        Args:
            key: The key to access the shared state.
            default: A default value if one doesn't exist.

        Returns:
            The state value.
        """
        return self.state.get(key, default)

    def set_state(self, key: str, value: Any) -> None:
        """Set value in shared state.

        Args:
            key: the key to add to the state.
            value: the value to add to the state.
        """
        self.state[key] = value

    async def cleanup(self) -> None:
        """Cleanup context resources."""
        self.state.clear()
        self.metadata.clear()

    def is_empty(self) -> bool:
        """Check whether the state and metadata objects are empty.

        Returns:
            True if the context state and metadata are empty.
        """
        return not (self.state or self.metadata or self.global_context.state)


PluginContextTable = dict[str, PluginContext]


class ResourcePreFetchPayload(BaseModel):
    """A resource payload for a resource pre-fetch hook.

    Attributes:
            uri: The resource URI.
            metadata: Optional metadata for the resource request.

    Examples:
        >>> payload = ResourcePreFetchPayload(uri="file:///data.txt")
        >>> payload.uri
        'file:///data.txt'
        >>> payload2 = ResourcePreFetchPayload(uri="http://api/data", metadata={"Accept": "application/json"})
        >>> payload2.metadata
        {'Accept': 'application/json'}
        >>> p = ResourcePreFetchPayload(uri="file:///docs/readme.md", metadata={"version": "1.0"})
        >>> p.uri
        'file:///docs/readme.md'
        >>> p.metadata["version"]
        '1.0'
    """

    uri: str
    metadata: Optional[dict[str, Any]] = Field(default_factory=dict)


class ResourcePostFetchPayload(BaseModel):
    """A resource payload for a resource post-fetch hook.

    Attributes:
        uri: The resource URI.
        content: The fetched resource content.

    Examples:
        >>> from mcpgateway.models import ResourceContent
        >>> content = ResourceContent(type="resource", uri="file:///data.txt",
        ...     text="Hello World")
        >>> payload = ResourcePostFetchPayload(uri="file:///data.txt", content=content)
        >>> payload.uri
        'file:///data.txt'
        >>> payload.content.text
        'Hello World'
        >>> from mcpgateway.models import ResourceContent
        >>> resource_content = ResourceContent(type="resource", uri="test://resource", text="Test data")
        >>> p = ResourcePostFetchPayload(uri="test://resource", content=resource_content)
        >>> p.uri
        'test://resource'
    """

    uri: str
    content: Any


ResourcePreFetchResult = PluginResult[ResourcePreFetchPayload]
ResourcePostFetchResult = PluginResult[ResourcePostFetchPayload]


class ToolMetaData(BaseModel):
    """Meta data about the tool on which the pre/post tool hook is being called."""

    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    original_name: str
    url: Optional[str] = None
    description: Optional[str]
    integration_type: str
    request_type: str
    headers: Optional[dict[str, str]]
    input_schema: dict[str, Any]
    annotations: Optional[dict[str, Any]]
    created_at: datetime
    updated_at: datetime
    enabled: bool
    reachable: bool
    jsonpath_filter: str
    tags: list[str]

    # Comprehensive metadata for audit tracking
    created_by: Optional[str]
    created_from_ip: Optional[str]
    created_via: Optional[str]
    created_user_agent: Optional[str]

    modified_by: Optional[str]
    modified_from_ip: Optional[str]
    modified_via: Optional[str]
    modified_user_agent: Optional[str]

    import_batch_id: Optional[str]
    federation_source: Optional[str]
    version: int

    # Request type and authentication fields
    auth_type: Optional[str]  # "basic", "bearer", or None
    auth_value: Optional[str]

    # custom_name,custom_name_slug, display_name
    custom_name: Optional[str]
    custom_name_slug: Optional[str]
    display_name: Optional[str]

    # Federation relationship with a local gateway
    gateway_id: Optional[str]

    # Team scoping fields for resource organization
    team_id: Optional[str]
    owner_email: Optional[str]
    visibility: str


class GatewayMetaData(BaseModel):
    """Meta data about the gateway on which the pre/post hooks are being called."""

    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    slug: str
    url: Optional[str] = None
    description: Optional[str]
    transport: str
    capabilities: dict[str, Any]
    created_at: datetime
    updated_at: datetime
    enabled: bool
    reachable: bool
    last_seen: Optional[datetime]
    tags: list[str]

    # Comprehensive metadata for audit tracking
    created_by: Optional[str]
    created_from_ip: Optional[str]
    created_via: Optional[str]
    created_user_agent: Optional[str]

    modified_by: Optional[str]
    modified_from_ip: Optional[str]
    modified_via: Optional[str]
    modified_user_agent: Optional[str]

    import_batch_id: Optional[str]
    federation_source: Optional[str]
    version: int

    # Header passthrough configuration
    passthrough_headers: Optional[list[str]]  # Store list of strings as JSON array
    # Request type and authentication fields
    auth_type: Optional[str]  # "basic", "bearer", "headers", "oauth" or None
    auth_value: Optional[dict[str, str]]

    # Team scoping fields for resource organization
    team_id: Optional[str]
    owner_email: Optional[str]
    visibility: str
