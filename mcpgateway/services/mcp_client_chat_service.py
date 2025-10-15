# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/services/mcp_client_chat_service.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Keval Mahajan

MCP Client Service Module.

This module provides a comprehensive client implementation for interacting with
MCP servers, managing LLM providers, and orchestrating conversational AI agents.
It supports multiple transport protocols and LLM providers.

The module consists of several key components:
- Configuration classes for MCP servers and LLM providers
- LLM provider factory and implementations
- MCP client for tool management
- Chat history manager for Redis and in-memory storage
- Chat service for conversational interactions
"""

# Standard
from datetime import datetime, timezone
import json
import os
import time
from typing import Any, AsyncGenerator, Dict, List, Literal, Optional, Union
from uuid import uuid4

try:
    # Third-Party
    from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
    from langchain_core.tools import BaseTool
    from langchain_mcp_adapters.client import MultiServerMCPClient
    from langchain_ollama import ChatOllama
    from langchain_openai import AzureChatOpenAI, ChatOpenAI
    from langgraph.prebuilt import create_react_agent

    _LLMCHAT_AVAILABLE = True
except ImportError:
    # Optional dependencies for LLM chat feature not installed
    # These are only needed if LLMCHAT_ENABLED=true
    _LLMCHAT_AVAILABLE = False
    AIMessage = None  # type: ignore
    BaseMessage = None  # type: ignore
    HumanMessage = None  # type: ignore
    BaseTool = None  # type: ignore
    MultiServerMCPClient = None  # type: ignore
    ChatOllama = None  # type: ignore
    AzureChatOpenAI = None  # type: ignore
    ChatOpenAI = None  # type: ignore
    create_react_agent = None  # type: ignore

# Try to import Anthropic and Bedrock providers (they may not be installed)
try:
    # Third-Party
    from langchain_anthropic import ChatAnthropic

    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False
    ChatAnthropic = None  # type: ignore

try:
    # Third-Party
    from langchain_aws import ChatBedrock

    _BEDROCK_AVAILABLE = True
except ImportError:
    _BEDROCK_AVAILABLE = False
    ChatBedrock = None  # type: ignore

# Third-Party
from pydantic import BaseModel, Field, field_validator, model_validator

# First-Party
from mcpgateway.services.logging_service import LoggingService

logging_service = LoggingService()
logger = logging_service.get_logger(__name__)


class MCPServerConfig(BaseModel):
    """
    Configuration for MCP server connection.

    This class defines the configuration parameters required to connect to an
    MCP (Model Context Protocol) server using various transport mechanisms.

    Attributes:
        url: MCP server URL for streamable_http/sse transports.
        command: Command to run for stdio transport.
        args: Command-line arguments for stdio command.
        transport: Transport type (streamable_http, sse, or stdio).
        auth_token: Authentication token for HTTP-based transports.
        headers: Additional HTTP headers for request customization.

    Examples:
        >>> # HTTP-based transport
        >>> config = MCPServerConfig(
        ...     url="https://mcp-server.example.com/mcp",
        ...     transport="streamable_http",
        ...     auth_token="secret-token"
        ... )
        >>> config.transport
        'streamable_http'

        >>> # Stdio transport
        >>> config = MCPServerConfig(
        ...     command="python",
        ...     args=["server.py"],
        ...     transport="stdio"
        ... )
        >>> config.command
        'python'

    Note:
        The auth_token is automatically added to headers as a Bearer token
        for HTTP-based transports.
    """

    url: Optional[str] = Field(None, description="MCP server URL for streamable_http/sse transports")
    command: Optional[str] = Field(None, description="Command to run for stdio transport")
    args: Optional[list[str]] = Field(None, description="Arguments for stdio command")
    transport: Literal["streamable_http", "sse", "stdio"] = Field(default="streamable_http", description="Transport type for MCP connection")
    auth_token: Optional[str] = Field(None, description="Authentication token for the server")
    headers: Optional[Dict[str, str]] = Field(default=None, description="Additional headers for HTTP-based transports")

    @model_validator(mode="before")
    @classmethod
    def add_auth_to_headers(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        """
        Automatically add authentication token to headers if provided.

        This validator ensures that if an auth_token is provided for HTTP-based
        transports, it's automatically added to the headers as a Bearer token.

        Args:
            values: Dictionary of field values before validation.

        Returns:
            Dict[str, Any]: Updated values with auth token in headers.

        Examples:
            >>> values = {
            ...     "url": "https://api.example.com",
            ...     "transport": "streamable_http",
            ...     "auth_token": "token123"
            ... }
            >>> result = MCPServerConfig.add_auth_to_headers(values)
            >>> result['headers']['Authorization']
            'Bearer token123'
        """
        auth_token = values.get("auth_token")
        transport = values.get("transport")
        headers = values.get("headers") or {}

        if auth_token and transport in ["streamable_http", "sse"]:
            if "Authorization" not in headers:
                headers["Authorization"] = f"Bearer {auth_token}"
            values["headers"] = headers

        return values

    @field_validator("url")
    @classmethod
    def validate_url_for_transport(cls, v: Optional[str], info) -> Optional[str]:
        """
        Validate that URL is provided for HTTP-based transports.

        Args:
            v: The URL value to validate.
            info: Validation context containing other field values.

        Returns:
            Optional[str]: The validated URL.

        Raises:
            ValueError: If URL is missing for streamable_http or sse transport.

        Examples:
            >>> # Valid case
            >>> MCPServerConfig(
            ...     url="https://example.com",
            ...     transport="streamable_http"
            ... ).url
            'https://example.com'
        """
        transport = info.data.get("transport")
        if transport in ["streamable_http", "sse"] and not v:
            raise ValueError(f"URL is required for {transport} transport")
        return v

    @field_validator("command")
    @classmethod
    def validate_command_for_stdio(cls, v: Optional[str], info) -> Optional[str]:
        """
        Validate that command is provided for stdio transport.

        Args:
            v: The command value to validate.
            info: Validation context containing other field values.

        Returns:
            Optional[str]: The validated command.

        Raises:
            ValueError: If command is missing for stdio transport.

        Examples:
            >>> config = MCPServerConfig(
            ...     command="python",
            ...     args=["server.py"],
            ...     transport="stdio"
            ... )
            >>> config.command
            'python'
        """
        transport = info.data.get("transport")
        if transport == "stdio" and not v:
            raise ValueError("Command is required for stdio transport")
        return v

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"url": "https://mcp-server.example.com/mcp", "transport": "streamable_http", "auth_token": "your-token-here"},
                {"command": "python", "args": ["server.py"], "transport": "stdio"},
            ]
        }
    }


class AzureOpenAIConfig(BaseModel):
    """
    Configuration for Azure OpenAI provider.

    Defines all necessary parameters to connect to and use Azure OpenAI services,
    including API credentials, endpoints, model settings, and request parameters.

    Attributes:
        api_key: Azure OpenAI API authentication key.
        azure_endpoint: Azure OpenAI service endpoint URL.
        api_version: API version to use for requests.
        azure_deployment: Name of the deployed model.
        model: Model identifier for logging and tracing.
        temperature: Sampling temperature for response generation (0.0-2.0).
        max_tokens: Maximum number of tokens to generate.
        timeout: Request timeout duration in seconds.
        max_retries: Maximum number of retry attempts for failed requests.

    Examples:
        >>> config = AzureOpenAIConfig(
        ...     api_key="your-api-key",
        ...     azure_endpoint="https://your-resource.openai.azure.com/",
        ...     azure_deployment="gpt-4",
        ...     temperature=0.7
        ... )
        >>> config.model
        'gpt-4'
        >>> config.temperature
        0.7
    """

    api_key: str = Field(..., description="Azure OpenAI API key")
    azure_endpoint: str = Field(..., description="Azure OpenAI endpoint URL")
    api_version: str = Field(default="2024-05-01-preview", description="Azure OpenAI API version")
    azure_deployment: str = Field(..., description="Azure OpenAI deployment name")
    model: str = Field(default="gpt-4", description="Model name for tracing")
    temperature: float = Field(default=0.7, ge=0.0, le=2.0, description="Sampling temperature")
    max_tokens: Optional[int] = Field(None, gt=0, description="Maximum tokens to generate")
    timeout: Optional[float] = Field(None, gt=0, description="Request timeout in seconds")
    max_retries: int = Field(default=2, ge=0, description="Maximum number of retries")

    model_config = {
        "json_schema_extra": {
            "example": {
                "api_key": "your-api-key",
                "azure_endpoint": "https://your-resource.openai.azure.com/",
                "api_version": "2024-05-01-preview",
                "azure_deployment": "gpt-4",
                "model": "gpt-4",
                "temperature": 0.7,
            }
        }
    }


class OllamaConfig(BaseModel):
    """
    Configuration for Ollama provider.

    Defines parameters for connecting to a local or remote Ollama instance
    for running open-source language models.

    Attributes:
        base_url: Ollama server base URL.
        model: Name of the Ollama model to use.
        temperature: Sampling temperature for response generation (0.0-2.0).
        timeout: Request timeout duration in seconds.
        num_ctx: Context window size for the model.

    Examples:
        >>> config = OllamaConfig(
        ...     base_url="http://localhost:11434",
        ...     model="llama2",
        ...     temperature=0.5
        ... )
        >>> config.model
        'llama2'
        >>> config.base_url
        'http://localhost:11434'
    """

    base_url: str = Field(default="http://localhost:11434", description="Ollama base URL")
    model: str = Field(default="llama2", description="Model name to use")
    temperature: float = Field(default=0.7, ge=0.0, le=2.0, description="Sampling temperature")
    timeout: Optional[float] = Field(None, gt=0, description="Request timeout in seconds")
    num_ctx: Optional[int] = Field(None, gt=0, description="Context window size")

    model_config = {"json_schema_extra": {"example": {"base_url": "http://localhost:11434", "model": "llama2", "temperature": 0.7}}}


class OpenAIConfig(BaseModel):
    """
    Configuration for OpenAI provider (non-Azure).

    Defines parameters for connecting to OpenAI API (or OpenAI-compatible endpoints).

    Attributes:
        api_key: OpenAI API authentication key.
        base_url: Optional base URL for OpenAI-compatible endpoints.
        model: Model identifier (e.g., gpt-4, gpt-3.5-turbo).
        temperature: Sampling temperature for response generation (0.0-2.0).
        max_tokens: Maximum number of tokens to generate.
        timeout: Request timeout duration in seconds.
        max_retries: Maximum number of retry attempts for failed requests.

    Examples:
        >>> config = OpenAIConfig(
        ...     api_key="sk-...",
        ...     model="gpt-4",
        ...     temperature=0.7
        ... )
        >>> config.model
        'gpt-4'
    """

    api_key: str = Field(..., description="OpenAI API key")
    base_url: Optional[str] = Field(None, description="Base URL for OpenAI-compatible endpoints")
    model: str = Field(default="gpt-4o-mini", description="Model name (e.g., gpt-4, gpt-3.5-turbo)")
    temperature: float = Field(default=0.7, ge=0.0, le=2.0, description="Sampling temperature")
    max_tokens: Optional[int] = Field(None, gt=0, description="Maximum tokens to generate")
    timeout: Optional[float] = Field(None, gt=0, description="Request timeout in seconds")
    max_retries: int = Field(default=2, ge=0, description="Maximum number of retries")

    model_config = {
        "json_schema_extra": {
            "example": {
                "api_key": "sk-...",
                "model": "gpt-4o-mini",
                "temperature": 0.7,
            }
        }
    }


class AnthropicConfig(BaseModel):
    """
    Configuration for Anthropic Claude provider.

    Defines parameters for connecting to Anthropic's Claude API.

    Attributes:
        api_key: Anthropic API authentication key.
        model: Claude model identifier (e.g., claude-3-5-sonnet-20241022, claude-3-opus).
        temperature: Sampling temperature for response generation (0.0-1.0).
        max_tokens: Maximum number of tokens to generate.
        timeout: Request timeout duration in seconds.
        max_retries: Maximum number of retry attempts for failed requests.

    Examples:
        >>> config = AnthropicConfig(
        ...     api_key="sk-ant-...",
        ...     model="claude-3-5-sonnet-20241022",
        ...     temperature=0.7
        ... )
        >>> config.model
        'claude-3-5-sonnet-20241022'
    """

    api_key: str = Field(..., description="Anthropic API key")
    model: str = Field(default="claude-3-5-sonnet-20241022", description="Claude model name")
    temperature: float = Field(default=0.7, ge=0.0, le=1.0, description="Sampling temperature")
    max_tokens: int = Field(default=4096, gt=0, description="Maximum tokens to generate")
    timeout: Optional[float] = Field(None, gt=0, description="Request timeout in seconds")
    max_retries: int = Field(default=2, ge=0, description="Maximum number of retries")

    model_config = {
        "json_schema_extra": {
            "example": {
                "api_key": "sk-ant-...",
                "model": "claude-3-5-sonnet-20241022",
                "temperature": 0.7,
                "max_tokens": 4096,
            }
        }
    }


class AWSBedrockConfig(BaseModel):
    """
    Configuration for AWS Bedrock provider.

    Defines parameters for connecting to AWS Bedrock LLM services.

    Attributes:
        model_id: Bedrock model identifier (e.g., anthropic.claude-v2, amazon.titan-text-express-v1).
        region_name: AWS region name (e.g., us-east-1, us-west-2).
        aws_access_key_id: Optional AWS access key ID (uses default credential chain if not provided).
        aws_secret_access_key: Optional AWS secret access key.
        aws_session_token: Optional AWS session token for temporary credentials.
        temperature: Sampling temperature for response generation (0.0-1.0).
        max_tokens: Maximum number of tokens to generate.

    Examples:
        >>> config = AWSBedrockConfig(
        ...     model_id="anthropic.claude-v2",
        ...     region_name="us-east-1",
        ...     temperature=0.7
        ... )
        >>> config.model_id
        'anthropic.claude-v2'
    """

    model_id: str = Field(..., description="Bedrock model ID")
    region_name: str = Field(default="us-east-1", description="AWS region name")
    aws_access_key_id: Optional[str] = Field(None, description="AWS access key ID")
    aws_secret_access_key: Optional[str] = Field(None, description="AWS secret access key")
    aws_session_token: Optional[str] = Field(None, description="AWS session token")
    temperature: float = Field(default=0.7, ge=0.0, le=1.0, description="Sampling temperature")
    max_tokens: int = Field(default=4096, gt=0, description="Maximum tokens to generate")

    model_config = {
        "json_schema_extra": {
            "example": {
                "model_id": "anthropic.claude-v2",
                "region_name": "us-east-1",
                "temperature": 0.7,
                "max_tokens": 4096,
            }
        }
    }


class LLMConfig(BaseModel):
    """
    Configuration for LLM provider.

    Unified configuration class that supports multiple LLM providers through
    a discriminated union pattern.

    Attributes:
        provider: Type of LLM provider (azure_openai, openai, anthropic, aws_bedrock, or ollama).
        config: Provider-specific configuration object.

    Examples:
        >>> # Azure OpenAI configuration
        >>> config = LLMConfig(
        ...     provider="azure_openai",
        ...     config=AzureOpenAIConfig(
        ...         api_key="key",
        ...         azure_endpoint="https://example.com/",
        ...         azure_deployment="gpt-4"
        ...     )
        ... )
        >>> config.provider
        'azure_openai'

        >>> # OpenAI configuration
        >>> config = LLMConfig(
        ...     provider="openai",
        ...     config=OpenAIConfig(
        ...         api_key="sk-...",
        ...         model="gpt-4"
        ...     )
        ... )
        >>> config.provider
        'openai'

        >>> # Ollama configuration
        >>> config = LLMConfig(
        ...     provider="ollama",
        ...     config=OllamaConfig(model="llama2")
        ... )
        >>> config.provider
        'ollama'
    """

    provider: Literal["azure_openai", "openai", "anthropic", "aws_bedrock", "ollama"] = Field(..., description="LLM provider type")
    config: Union[AzureOpenAIConfig, OpenAIConfig, AnthropicConfig, AWSBedrockConfig, OllamaConfig] = Field(..., description="Provider-specific configuration")

    @field_validator("config", mode="before")
    @classmethod
    def validate_config_type(cls, v: Any, info) -> Union[AzureOpenAIConfig, OpenAIConfig, AnthropicConfig, AWSBedrockConfig, OllamaConfig]:
        """
        Validate and convert config dictionary to appropriate provider type.

        Args:
            v: Configuration value (dict or config object).
            info: Validation context containing provider information.

        Returns:
            Union[AzureOpenAIConfig, OpenAIConfig, AnthropicConfig, AWSBedrockConfig, OllamaConfig]: Validated configuration object.

        Examples:
            >>> # Automatically converts dict to appropriate config type
            >>> config_dict = {
            ...     "api_key": "key",
            ...     "azure_endpoint": "https://example.com/",
            ...     "azure_deployment": "gpt-4"
            ... }
            >>> # Used internally by Pydantic during validation
        """
        provider = info.data.get("provider")

        if isinstance(v, dict):
            if provider == "azure_openai":
                return AzureOpenAIConfig(**v)
            if provider == "openai":
                return OpenAIConfig(**v)
            if provider == "anthropic":
                return AnthropicConfig(**v)
            if provider == "aws_bedrock":
                return AWSBedrockConfig(**v)
            if provider == "ollama":
                return OllamaConfig(**v)

        return v


class MCPClientConfig(BaseModel):
    """
    Main configuration for MCP client service.

    Aggregates all configuration parameters required for the complete MCP client
    service, including server connection, LLM provider, and operational settings.

    Attributes:
        mcp_server: MCP server connection configuration.
        llm: LLM provider configuration.
        chat_history_max_messages: Maximum messages to retain in chat history.
        enable_streaming: Whether to enable streaming responses.

    Examples:
        >>> config = MCPClientConfig(
        ...     mcp_server=MCPServerConfig(
        ...         url="https://mcp-server.example.com/mcp",
        ...         transport="streamable_http"
        ...     ),
        ...     llm=LLMConfig(
        ...         provider="ollama",
        ...         config=OllamaConfig(model="llama2")
        ...     ),
        ...     chat_history_max_messages=100,
        ...     enable_streaming=True
        ... )
        >>> config.chat_history_max_messages
        100
        >>> config.enable_streaming
        True
    """

    mcp_server: MCPServerConfig = Field(..., description="MCP server configuration")
    llm: LLMConfig = Field(..., description="LLM provider configuration")
    chat_history_max_messages: int = Field(default=50, gt=0, description="Maximum messages to keep in chat history")
    enable_streaming: bool = Field(default=True, description="Enable streaming responses")

    model_config = {
        "json_schema_extra": {
            "example": {
                "mcp_server": {"url": "https://mcp-server.example.com/mcp", "transport": "streamable_http", "auth_token": "your-token"},
                "llm": {
                    "provider": "azure_openai",
                    "config": {"api_key": "your-key", "azure_endpoint": "https://your-resource.openai.azure.com/", "azure_deployment": "gpt-4", "api_version": "2024-05-01-preview"},
                },
            }
        }
    }


# ==================== LLM PROVIDER IMPLEMENTATIONS ====================


class AzureOpenAIProvider:
    """
    Azure OpenAI provider implementation.

    Manages connection and interaction with Azure OpenAI services.

    Attributes:
        config: Azure OpenAI configuration object.

    Examples:
        >>> config = AzureOpenAIConfig(
        ...     api_key="key",
        ...     azure_endpoint="https://example.openai.azure.com/",
        ...     azure_deployment="gpt-4"
        ... )
        >>> provider = AzureOpenAIProvider(config)
        >>> provider.get_model_name()
        'gpt-4'

    Note:
        The LLM instance is lazily initialized on first access for
        improved startup performance.
    """

    def __init__(self, config: AzureOpenAIConfig):
        """
        Initialize Azure OpenAI provider.

        Args:
            config: Azure OpenAI configuration with API credentials and settings.

        Examples:
            >>> config = AzureOpenAIConfig(
            ...     api_key="key",
            ...     azure_endpoint="https://example.openai.azure.com/",
            ...     azure_deployment="gpt-4"
            ... )
            >>> provider = AzureOpenAIProvider(config)
        """
        self.config = config
        self._llm = None
        logger.info(f"Initializing Azure OpenAI provider with deployment: {config.azure_deployment}")

    def get_llm(self) -> AzureChatOpenAI:
        """
        Get Azure OpenAI LLM instance with lazy initialization.

        Creates and caches the Azure OpenAI chat model instance on first call.
        Subsequent calls return the cached instance.

        Returns:
            AzureChatOpenAI: Configured Azure OpenAI chat model.

        Raises:
            Exception: If LLM initialization fails (e.g., invalid credentials).

        Examples:
            >>> config = AzureOpenAIConfig(
            ...     api_key="key",
            ...     azure_endpoint="https://example.openai.azure.com/",
            ...     azure_deployment="gpt-4"
            ... )
            >>> provider = AzureOpenAIProvider(config)
            >>> # llm = provider.get_llm()  # Returns AzureChatOpenAI instance
        """
        if self._llm is None:
            try:
                self._llm = AzureChatOpenAI(
                    api_key=self.config.api_key,
                    azure_endpoint=self.config.azure_endpoint,
                    api_version=self.config.api_version,
                    azure_deployment=self.config.azure_deployment,
                    model=self.config.model,
                    temperature=self.config.temperature,
                    max_tokens=self.config.max_tokens,
                    timeout=self.config.timeout,
                    max_retries=self.config.max_retries,
                )
                logger.info("Azure OpenAI LLM instance created successfully")
            except Exception as e:
                logger.error(f"Failed to create Azure OpenAI LLM: {e}")
                raise

        return self._llm

    def get_model_name(self) -> str:
        """
        Get the Azure OpenAI model name.

        Returns:
            str: The model name configured for this provider.

        Examples:
            >>> config = AzureOpenAIConfig(
            ...     api_key="key",
            ...     azure_endpoint="https://example.openai.azure.com/",
            ...     azure_deployment="gpt-4",
            ...     model="gpt-4"
            ... )
            >>> provider = AzureOpenAIProvider(config)
            >>> provider.get_model_name()
            'gpt-4'
        """
        return self.config.model


class OllamaProvider:
    """
    Ollama provider implementation.

    Manages connection and interaction with Ollama instances for running
    open-source language models locally or remotely.

    Attributes:
        config: Ollama configuration object.

    Examples:
        >>> config = OllamaConfig(
        ...     base_url="http://localhost:11434",
        ...     model="llama2"
        ... )
        >>> provider = OllamaProvider(config)
        >>> provider.get_model_name()
        'llama2'

    Note:
        Requires Ollama to be running and accessible at the configured base_url.
    """

    def __init__(self, config: OllamaConfig):
        """
        Initialize Ollama provider.

        Args:
            config: Ollama configuration with server URL and model settings.

        Examples:
            >>> config = OllamaConfig(model="llama2")
            >>> provider = OllamaProvider(config)
        """
        self.config = config
        self._llm = None
        logger.info(f"Initializing Ollama provider with model: {config.model}")

    def get_llm(self) -> ChatOllama:
        """
        Get Ollama LLM instance with lazy initialization.

        Creates and caches the Ollama chat model instance on first call.
        Subsequent calls return the cached instance.

        Returns:
            ChatOllama: Configured Ollama chat model.

        Raises:
            Exception: If LLM initialization fails (e.g., Ollama not running).

        Examples:
            >>> config = OllamaConfig(model="llama2")
            >>> provider = OllamaProvider(config)
            >>> # llm = provider.get_llm()  # Returns ChatOllama instance
        """
        if self._llm is None:
            try:
                # Build model kwargs
                model_kwargs = {}
                if self.config.num_ctx is not None:
                    model_kwargs["num_ctx"] = self.config.num_ctx

                self._llm = ChatOllama(base_url=self.config.base_url, model=self.config.model, temperature=self.config.temperature, timeout=self.config.timeout, **model_kwargs)

                logger.info("Ollama LLM instance created successfully")
            except Exception as e:
                logger.error(f"Failed to create Ollama LLM: {e}")
                raise

        return self._llm

    def get_model_name(self) -> str:
        """Get the model name.

        Returns:
            str: The model name
        """
        return self.config.model


class OpenAIProvider:
    """
    OpenAI provider implementation (non-Azure).

    Manages connection and interaction with OpenAI API or OpenAI-compatible endpoints.

    Attributes:
        config: OpenAI configuration object.

    Examples:
        >>> config = OpenAIConfig(
        ...     api_key="sk-...",
        ...     model="gpt-4"
        ... )
        >>> provider = OpenAIProvider(config)
        >>> provider.get_model_name()
        'gpt-4'

    Note:
        The LLM instance is lazily initialized on first access for
        improved startup performance.
    """

    def __init__(self, config: OpenAIConfig):
        """
        Initialize OpenAI provider.

        Args:
            config: OpenAI configuration with API key and settings.

        Examples:
            >>> config = OpenAIConfig(
            ...     api_key="sk-...",
            ...     model="gpt-4"
            ... )
            >>> provider = OpenAIProvider(config)
        """
        self.config = config
        self._llm = None
        logger.info(f"Initializing OpenAI provider with model: {config.model}")

    def get_llm(self) -> ChatOpenAI:
        """
        Get OpenAI LLM instance with lazy initialization.

        Creates and caches the OpenAI chat model instance on first call.
        Subsequent calls return the cached instance.

        Returns:
            ChatOpenAI: Configured OpenAI chat model.

        Raises:
            Exception: If LLM initialization fails (e.g., invalid credentials).

        Examples:
            >>> config = OpenAIConfig(
            ...     api_key="sk-...",
            ...     model="gpt-4"
            ... )
            >>> provider = OpenAIProvider(config)
            >>> # llm = provider.get_llm()  # Returns ChatOpenAI instance
        """
        if self._llm is None:
            try:
                kwargs = {
                    "api_key": self.config.api_key,
                    "model": self.config.model,
                    "temperature": self.config.temperature,
                    "max_tokens": self.config.max_tokens,
                    "timeout": self.config.timeout,
                    "max_retries": self.config.max_retries,
                }

                if self.config.base_url:
                    kwargs["base_url"] = self.config.base_url

                self._llm = ChatOpenAI(**kwargs)

                logger.info("OpenAI LLM instance created successfully")
            except Exception as e:
                logger.error(f"Failed to create OpenAI LLM: {e}")
                raise

        return self._llm

    def get_model_name(self) -> str:
        """
        Get the OpenAI model name.

        Returns:
            str: The model name configured for this provider.

        Examples:
            >>> config = OpenAIConfig(
            ...     api_key="sk-...",
            ...     model="gpt-4"
            ... )
            >>> provider = OpenAIProvider(config)
            >>> provider.get_model_name()
            'gpt-4'
        """
        return self.config.model


class AnthropicProvider:
    """
    Anthropic Claude provider implementation.

    Manages connection and interaction with Anthropic's Claude API.

    Attributes:
        config: Anthropic configuration object.

    Examples:
        >>> config = AnthropicConfig(  # doctest: +SKIP
        ...     api_key="sk-ant-...",
        ...     model="claude-3-5-sonnet-20241022"
        ... )
        >>> provider = AnthropicProvider(config)  # doctest: +SKIP
        >>> provider.get_model_name()  # doctest: +SKIP
        'claude-3-5-sonnet-20241022'

    Note:
        Requires langchain-anthropic package to be installed.
    """

    def __init__(self, config: AnthropicConfig):
        """
        Initialize Anthropic provider.

        Args:
            config: Anthropic configuration with API key and settings.

        Raises:
            ImportError: If langchain-anthropic is not installed.

        Examples:
            >>> config = AnthropicConfig(  # doctest: +SKIP
            ...     api_key="sk-ant-...",
            ...     model="claude-3-5-sonnet-20241022"
            ... )
            >>> provider = AnthropicProvider(config)  # doctest: +SKIP
        """
        if not _ANTHROPIC_AVAILABLE:
            raise ImportError("Anthropic provider requires langchain-anthropic package. Install it with: pip install langchain-anthropic")

        self.config = config
        self._llm = None
        logger.info(f"Initializing Anthropic provider with model: {config.model}")

    def get_llm(self) -> ChatAnthropic:
        """
        Get Anthropic LLM instance with lazy initialization.

        Creates and caches the Anthropic chat model instance on first call.
        Subsequent calls return the cached instance.

        Returns:
            ChatAnthropic: Configured Anthropic chat model.

        Raises:
            Exception: If LLM initialization fails (e.g., invalid credentials).

        Examples:
            >>> config = AnthropicConfig(  # doctest: +SKIP
            ...     api_key="sk-ant-...",
            ...     model="claude-3-5-sonnet-20241022"
            ... )
            >>> provider = AnthropicProvider(config)  # doctest: +SKIP
            >>> # llm = provider.get_llm()  # Returns ChatAnthropic instance
        """
        if self._llm is None:
            try:
                self._llm = ChatAnthropic(
                    api_key=self.config.api_key,
                    model=self.config.model,
                    temperature=self.config.temperature,
                    max_tokens=self.config.max_tokens,
                    timeout=self.config.timeout,
                    max_retries=self.config.max_retries,
                )
                logger.info("Anthropic LLM instance created successfully")
            except Exception as e:
                logger.error(f"Failed to create Anthropic LLM: {e}")
                raise

        return self._llm

    def get_model_name(self) -> str:
        """
        Get the Anthropic model name.

        Returns:
            str: The model name configured for this provider.

        Examples:
            >>> config = AnthropicConfig(  # doctest: +SKIP
            ...     api_key="sk-ant-...",
            ...     model="claude-3-5-sonnet-20241022"
            ... )
            >>> provider = AnthropicProvider(config)  # doctest: +SKIP
            >>> provider.get_model_name()  # doctest: +SKIP
            'claude-3-5-sonnet-20241022'
        """
        return self.config.model


class AWSBedrockProvider:
    """
    AWS Bedrock provider implementation.

    Manages connection and interaction with AWS Bedrock LLM services.

    Attributes:
        config: AWS Bedrock configuration object.

    Examples:
        >>> config = AWSBedrockConfig(  # doctest: +SKIP
        ...     model_id="anthropic.claude-v2",
        ...     region_name="us-east-1"
        ... )
        >>> provider = AWSBedrockProvider(config)  # doctest: +SKIP
        >>> provider.get_model_name()  # doctest: +SKIP
        'anthropic.claude-v2'

    Note:
        Requires langchain-aws package and boto3 to be installed.
        Uses AWS default credential chain if credentials not explicitly provided.
    """

    def __init__(self, config: AWSBedrockConfig):
        """
        Initialize AWS Bedrock provider.

        Args:
            config: AWS Bedrock configuration with model ID and settings.

        Raises:
            ImportError: If langchain-aws is not installed.

        Examples:
            >>> config = AWSBedrockConfig(  # doctest: +SKIP
            ...     model_id="anthropic.claude-v2",
            ...     region_name="us-east-1"
            ... )
            >>> provider = AWSBedrockProvider(config)  # doctest: +SKIP
        """
        if not _BEDROCK_AVAILABLE:
            raise ImportError("AWS Bedrock provider requires langchain-aws package. Install it with: pip install langchain-aws boto3")

        self.config = config
        self._llm = None
        logger.info(f"Initializing AWS Bedrock provider with model: {config.model_id}")

    def get_llm(self) -> ChatBedrock:
        """
        Get AWS Bedrock LLM instance with lazy initialization.

        Creates and caches the Bedrock chat model instance on first call.
        Subsequent calls return the cached instance.

        Returns:
            ChatBedrock: Configured AWS Bedrock chat model.

        Raises:
            Exception: If LLM initialization fails (e.g., invalid credentials, permissions).

        Examples:
            >>> config = AWSBedrockConfig(  # doctest: +SKIP
            ...     model_id="anthropic.claude-v2",
            ...     region_name="us-east-1"
            ... )
            >>> provider = AWSBedrockProvider(config)  # doctest: +SKIP
            >>> # llm = provider.get_llm()  # Returns ChatBedrock instance
        """
        if self._llm is None:
            try:
                # Build credentials dict if provided
                credentials_kwargs = {}
                if self.config.aws_access_key_id:
                    credentials_kwargs["aws_access_key_id"] = self.config.aws_access_key_id
                if self.config.aws_secret_access_key:
                    credentials_kwargs["aws_secret_access_key"] = self.config.aws_secret_access_key
                if self.config.aws_session_token:
                    credentials_kwargs["aws_session_token"] = self.config.aws_session_token

                self._llm = ChatBedrock(
                    model_id=self.config.model_id,
                    region_name=self.config.region_name,
                    model_kwargs={
                        "temperature": self.config.temperature,
                        "max_tokens": self.config.max_tokens,
                    },
                    **credentials_kwargs,
                )
                logger.info("AWS Bedrock LLM instance created successfully")
            except Exception as e:
                logger.error(f"Failed to create AWS Bedrock LLM: {e}")
                raise

        return self._llm

    def get_model_name(self) -> str:
        """
        Get the AWS Bedrock model ID.

        Returns:
            str: The model ID configured for this provider.

        Examples:
            >>> config = AWSBedrockConfig(  # doctest: +SKIP
            ...     model_id="anthropic.claude-v2",
            ...     region_name="us-east-1"
            ... )
            >>> provider = AWSBedrockProvider(config)  # doctest: +SKIP
            >>> provider.get_model_name()  # doctest: +SKIP
            'anthropic.claude-v2'
        """
        return self.config.model_id


class LLMProviderFactory:
    """
    Factory for creating LLM providers.

    Implements the Factory pattern to instantiate the appropriate LLM provider
    based on configuration, abstracting away provider-specific initialization.

    Examples:
        >>> config = LLMConfig(
        ...     provider="ollama",
        ...     config=OllamaConfig(model="llama2")
        ... )
        >>> provider = LLMProviderFactory.create(config)
        >>> provider.get_model_name()
        'llama2'

    Note:
        This factory supports dynamic provider registration and ensures
        type safety through the LLMConfig discriminated union.
    """

    @staticmethod
    def create(llm_config: LLMConfig) -> Union[AzureOpenAIProvider, OpenAIProvider, AnthropicProvider, AWSBedrockProvider, OllamaProvider]:
        """
        Create an LLM provider based on configuration.

        Args:
            llm_config: LLM configuration specifying provider type and settings.

        Returns:
            Union[AzureOpenAIProvider, OpenAIProvider, AnthropicProvider, AWSBedrockProvider, OllamaProvider]: Instantiated provider.

        Raises:
            ValueError: If provider type is not supported.
            ImportError: If required provider package is not installed.

        Examples:
            >>> # Create Azure OpenAI provider
            >>> config = LLMConfig(
            ...     provider="azure_openai",
            ...     config=AzureOpenAIConfig(
            ...         api_key="key",
            ...         azure_endpoint="https://example.com/",
            ...         azure_deployment="gpt-4"
            ...     )
            ... )
            >>> provider = LLMProviderFactory.create(config)
            >>> isinstance(provider, AzureOpenAIProvider)
            True

            >>> # Create OpenAI provider
            >>> config = LLMConfig(
            ...     provider="openai",
            ...     config=OpenAIConfig(
            ...         api_key="sk-...",
            ...         model="gpt-4"
            ...     )
            ... )
            >>> provider = LLMProviderFactory.create(config)
            >>> isinstance(provider, OpenAIProvider)
            True

            >>> # Create Ollama provider
            >>> config = LLMConfig(
            ...     provider="ollama",
            ...     config=OllamaConfig(model="llama2")
            ... )
            >>> provider = LLMProviderFactory.create(config)
            >>> isinstance(provider, OllamaProvider)
            True
        """
        provider_map = {
            "azure_openai": AzureOpenAIProvider,
            "openai": OpenAIProvider,
            "anthropic": AnthropicProvider,
            "aws_bedrock": AWSBedrockProvider,
            "ollama": OllamaProvider,
        }

        provider_class = provider_map.get(llm_config.provider)

        if not provider_class:
            raise ValueError(f"Unsupported LLM provider: {llm_config.provider}. Supported providers: {list(provider_map.keys())}")

        logger.info(f"Creating LLM provider: {llm_config.provider}")
        return provider_class(llm_config.config)


# ==================== CHAT HISTORY MANAGER ====================


class ChatHistoryManager:
    """
    Centralized chat history management with Redis and in-memory fallback.

    Provides a unified interface for storing and retrieving chat histories across
    multiple workers using Redis, with automatic fallback to in-memory storage
    when Redis is not available.

    This class eliminates duplication between router and service layers by
    providing a single source of truth for all chat history operations.

    Attributes:
        redis_client: Optional Redis async client for distributed storage.
        max_messages: Maximum number of messages to retain per user.
        ttl: Time-to-live for Redis entries in seconds.
        _memory_store: In-memory dict fallback when Redis unavailable.

    Examples:
        >>> import asyncio
        >>> # Create manager without Redis (in-memory mode)
        >>> manager = ChatHistoryManager(redis_client=None, max_messages=50)
        >>> # asyncio.run(manager.save_history("user123", [{"role": "user", "content": "Hello"}]))
        >>> # history = asyncio.run(manager.get_history("user123"))
        >>> # len(history) >= 0
        True

    Note:
        Thread-safe for Redis operations. In-memory mode suitable for
        single-worker deployments only.
    """

    def __init__(self, redis_client: Optional[Any] = None, max_messages: int = 50, ttl: int = 3600):
        """
        Initialize chat history manager.

        Args:
            redis_client: Optional Redis async client. If None, uses in-memory storage.
            max_messages: Maximum messages to retain per user (default: 50).
            ttl: Time-to-live for Redis entries in seconds (default: 3600).

        Examples:
            >>> manager = ChatHistoryManager(redis_client=None, max_messages=100)
            >>> manager.max_messages
            100
            >>> manager.ttl
            3600
        """
        self.redis_client = redis_client
        self.max_messages = max_messages
        self.ttl = ttl
        self._memory_store: Dict[str, List[Dict[str, str]]] = {}

        if redis_client:
            logger.info("ChatHistoryManager initialized with Redis backend")
        else:
            logger.info("ChatHistoryManager initialized with in-memory backend")

    def _history_key(self, user_id: str) -> str:
        """
        Generate Redis key for user's chat history.

        Args:
            user_id: User identifier.

        Returns:
            str: Redis key string.

        Examples:
            >>> manager = ChatHistoryManager()
            >>> manager._history_key("user123")
            'chat_history:user123'
        """
        return f"chat_history:{user_id}"

    async def get_history(self, user_id: str) -> List[Dict[str, str]]:
        """
        Retrieve chat history for a user.

        Fetches history from Redis if available, otherwise from in-memory store.

        Args:
            user_id: User identifier.

        Returns:
            List[Dict[str, str]]: List of message dictionaries with 'role' and 'content' keys.
                                 Returns empty list if no history exists.

        Examples:
            >>> import asyncio
            >>> manager = ChatHistoryManager()
            >>> # history = asyncio.run(manager.get_history("user123"))
            >>> # isinstance(history, list)
            True

        Note:
            Automatically handles JSON deserialization errors by returning empty list.
        """
        if self.redis_client:
            try:
                data = await self.redis_client.get(self._history_key(user_id))
                if not data:
                    return []
                return json.loads(data)
            except json.JSONDecodeError:
                logger.warning(f"Failed to decode chat history for user {user_id}")
                return []
            except Exception as e:
                logger.error(f"Error retrieving chat history from Redis for user {user_id}: {e}")
                return []
        else:
            return self._memory_store.get(user_id, [])

    async def save_history(self, user_id: str, history: List[Dict[str, str]]) -> None:
        """
        Save chat history for a user.

        Stores history in Redis (with TTL) if available, otherwise in memory.
        Automatically trims history to max_messages before saving.

        Args:
            user_id: User identifier.
            history: List of message dictionaries to save.

        Examples:
            >>> import asyncio
            >>> manager = ChatHistoryManager(max_messages=50)
            >>> messages = [{"role": "user", "content": "Hello"}]
            >>> # asyncio.run(manager.save_history("user123", messages))

        Note:
            History is automatically trimmed to max_messages limit before storage.
        """
        # Trim history before saving
        trimmed = self._trim_messages(history)

        if self.redis_client:
            try:
                await self.redis_client.set(self._history_key(user_id), json.dumps(trimmed), ex=self.ttl)
            except Exception as e:
                logger.error(f"Error saving chat history to Redis for user {user_id}: {e}")
        else:
            self._memory_store[user_id] = trimmed

    async def append_message(self, user_id: str, role: str, content: str) -> None:
        """
        Append a single message to user's chat history.

        Convenience method that fetches current history, appends the message,
        trims if needed, and saves back.

        Args:
            user_id: User identifier.
            role: Message role ('user' or 'assistant').
            content: Message content text.

        Examples:
            >>> import asyncio
            >>> manager = ChatHistoryManager()
            >>> # asyncio.run(manager.append_message("user123", "user", "Hello!"))

        Note:
            This method performs a read-modify-write operation which may
            not be atomic in distributed environments.
        """
        history = await self.get_history(user_id)
        history.append({"role": role, "content": content})
        await self.save_history(user_id, history)

    async def clear_history(self, user_id: str) -> None:
        """
        Clear all chat history for a user.

        Deletes history from Redis or memory store.

        Args:
            user_id: User identifier.

        Examples:
            >>> import asyncio
            >>> manager = ChatHistoryManager()
            >>> # asyncio.run(manager.clear_history("user123"))

        Note:
            This operation cannot be undone.
        """
        if self.redis_client:
            try:
                await self.redis_client.delete(self._history_key(user_id))
            except Exception as e:
                logger.error(f"Error clearing chat history from Redis for user {user_id}: {e}")
        else:
            self._memory_store.pop(user_id, None)

    def _trim_messages(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Trim message list to max_messages limit.

        Keeps the most recent messages up to max_messages count.

        Args:
            messages: List of message dictionaries.

        Returns:
            List[Dict[str, str]]: Trimmed message list.

        Examples:
            >>> manager = ChatHistoryManager(max_messages=2)
            >>> messages = [
            ...     {"role": "user", "content": "1"},
            ...     {"role": "assistant", "content": "2"},
            ...     {"role": "user", "content": "3"}
            ... ]
            >>> trimmed = manager._trim_messages(messages)
            >>> len(trimmed)
            2
            >>> trimmed[0]["content"]
            '2'
        """
        if len(messages) > self.max_messages:
            return messages[-self.max_messages :]
        return messages

    async def get_langchain_messages(self, user_id: str) -> List[BaseMessage]:
        """
        Get chat history as LangChain message objects.

        Converts stored history dictionaries to LangChain HumanMessage and
        AIMessage objects for use with LangChain agents.

        Args:
            user_id: User identifier.

        Returns:
            List[BaseMessage]: List of LangChain message objects.

        Examples:
            >>> import asyncio
            >>> manager = ChatHistoryManager()
            >>> # messages = asyncio.run(manager.get_langchain_messages("user123"))
            >>> # isinstance(messages, list)
            True

        Note:
            Returns empty list if LangChain is not available or history is empty.
        """
        if not _LLMCHAT_AVAILABLE:
            return []

        history = await self.get_history(user_id)
        lc_messages = []

        for msg in history:
            role = msg.get("role")
            content = msg.get("content", "")

            if role == "user":
                lc_messages.append(HumanMessage(content=content))
            elif role == "assistant":
                lc_messages.append(AIMessage(content=content))

        return lc_messages


# ==================== MCP CLIENT ====================


class MCPClient:
    """
    Manages MCP server connections and tool loading.

    Provides a high-level interface for connecting to MCP servers, retrieving
    available tools, and managing connection health. Supports multiple transport
    protocols including HTTP, SSE, and stdio.

    Attributes:
        config: MCP server configuration.

    Examples:
        >>> import asyncio
        >>> config = MCPServerConfig(
        ...     url="https://mcp-server.example.com/mcp",
        ...     transport="streamable_http"
        ... )
        >>> client = MCPClient(config)
        >>> client.is_connected
        False
        >>> # asyncio.run(client.connect())
        >>> # tools = asyncio.run(client.get_tools())

    Note:
        All methods are async and should be called using asyncio or within
        an async context.
    """

    def __init__(self, config: MCPServerConfig):
        """
        Initialize MCP client.

        Args:
            config: MCP server configuration with connection parameters.

        Examples:
            >>> config = MCPServerConfig(
            ...     url="https://example.com/mcp",
            ...     transport="streamable_http"
            ... )
            >>> client = MCPClient(config)
            >>> client.config.transport
            'streamable_http'
        """
        self.config = config
        self._client: Optional[MultiServerMCPClient] = None
        self._tools: Optional[List[BaseTool]] = None
        self._connected = False
        logger.info(f"MCP client initialized with transport: {config.transport}")

    async def connect(self) -> None:
        """
        Connect to the MCP server.

        Establishes connection to the configured MCP server using the specified
        transport protocol. Subsequent calls are no-ops if already connected.

        Raises:
            ConnectionError: If connection to MCP server fails.

        Examples:
            >>> import asyncio
            >>> config = MCPServerConfig(
            ...     url="https://example.com/mcp",
            ...     transport="streamable_http"
            ... )
            >>> client = MCPClient(config)
            >>> # asyncio.run(client.connect())
            >>> # client.is_connected -> True

        Note:
            Connection is idempotent - calling multiple times is safe.
        """
        if self._connected:
            logger.warning("MCP client already connected")
            return

        try:
            logger.info(f"Connecting to MCP server via {self.config.transport}...")

            # Build server configuration for MultiServerMCPClient
            server_config = {
                "transport": self.config.transport,
            }

            if self.config.transport in ["streamable_http", "sse"]:
                server_config["url"] = self.config.url
                if self.config.headers:
                    server_config["headers"] = self.config.headers
            elif self.config.transport == "stdio":
                server_config["command"] = self.config.command
                if self.config.args:
                    server_config["args"] = self.config.args

            # Create MultiServerMCPClient with single server
            self._client = MultiServerMCPClient({"default": server_config})
            self._connected = True
            logger.info("Successfully connected to MCP server")

        except Exception as e:
            logger.error(f"Failed to connect to MCP server: {e}")
            self._connected = False
            raise ConnectionError(f"Failed to connect to MCP server: {e}") from e

    async def disconnect(self) -> None:
        """
        Disconnect from the MCP server.

        Cleanly closes the connection and releases resources. Safe to call
        even if not connected.

        Raises:
            Exception: If cleanup operations fail.

        Examples:
            >>> import asyncio
            >>> config = MCPServerConfig(
            ...     url="https://example.com/mcp",
            ...     transport="streamable_http"
            ... )
            >>> client = MCPClient(config)
            >>> # asyncio.run(client.connect())
            >>> # asyncio.run(client.disconnect())
            >>> # client.is_connected -> False

        Note:
            Clears cached tools upon disconnection.
        """
        if not self._connected:
            logger.warning("MCP client not connected")
            return

        try:
            if self._client:
                # MultiServerMCPClient manages connections internally
                self._client = None

            self._connected = False
            self._tools = None
            logger.info("Disconnected from MCP server")

        except Exception as e:
            logger.error(f"Error during disconnect: {e}")
            raise

    async def get_tools(self, force_reload: bool = False) -> List[BaseTool]:
        """
        Get tools from the MCP server.

        Retrieves available tools from the connected MCP server. Results are
        cached unless force_reload is True.

        Args:
            force_reload: Force reload tools even if cached (default: False).

        Returns:
            List[BaseTool]: List of available tools from the server.

        Raises:
            ConnectionError: If not connected to MCP server.
            Exception: If tool loading fails.

        Examples:
            >>> import asyncio
            >>> config = MCPServerConfig(
            ...     url="https://example.com/mcp",
            ...     transport="streamable_http"
            ... )
            >>> client = MCPClient(config)
            >>> # asyncio.run(client.connect())
            >>> # tools = asyncio.run(client.get_tools())
            >>> # len(tools) >= 0 -> True

        Note:
            Tools are cached after first successful load for performance.
        """
        if not self._connected or not self._client:
            raise ConnectionError("Not connected to MCP server. Call connect() first.")

        if self._tools and not force_reload:
            logger.debug(f"Returning {len(self._tools)} cached tools")
            return self._tools

        try:
            logger.info("Loading tools from MCP server...")
            self._tools = await self._client.get_tools()
            logger.info(f"Successfully loaded {len(self._tools)} tools")
            return self._tools

        except Exception as e:
            logger.error(f"Failed to load tools: {e}")
            raise

    @property
    def is_connected(self) -> bool:
        """
        Check if client is connected.

        Returns:
            bool: True if connected to MCP server, False otherwise.

        Examples:
            >>> config = MCPServerConfig(
            ...     url="https://example.com/mcp",
            ...     transport="streamable_http"
            ... )
            >>> client = MCPClient(config)
            >>> client.is_connected
            False
        """
        return self._connected


# ==================== MCP CHAT SERVICE ====================


class MCPChatService:
    """
    Main chat service for MCP client backend.
    Orchestrates chat sessions with LLM and MCP server integration.

    Provides a high-level interface for managing conversational AI sessions
    that combine LLM capabilities with MCP server tools. Handles conversation
    history management, tool execution, and streaming responses.

    This service integrates:
    - LLM providers (Azure OpenAI, OpenAI, Anthropic, AWS Bedrock, Ollama)
    - MCP server tools
    - Centralized chat history management (Redis or in-memory)
    - Streaming and non-streaming response modes

    Attributes:
        config: Complete MCP client configuration.
        user_id: Optional user identifier for history management.

    Examples:
        >>> import asyncio
        >>> config = MCPClientConfig(
        ...     mcp_server=MCPServerConfig(
        ...         url="https://example.com/mcp",
        ...         transport="streamable_http"
        ...     ),
        ...     llm=LLMConfig(
        ...         provider="ollama",
        ...         config=OllamaConfig(model="llama2")
        ...     )
        ... )
        >>> service = MCPChatService(config)
        >>> service.is_initialized
        False
        >>> # asyncio.run(service.initialize())

    Note:
        Must call initialize() before using chat methods.
    """

    def __init__(self, config: MCPClientConfig, user_id: Optional[str] = None, redis_client: Optional[Any] = None):
        """
        Initialize MCP chat service.

        Args:
            config: Complete MCP client configuration.
            user_id: Optional user identifier for chat history management.
            redis_client: Optional Redis client for distributed history storage.

        Examples:
            >>> config = MCPClientConfig(
            ...     mcp_server=MCPServerConfig(
            ...         url="https://example.com/mcp",
            ...         transport="streamable_http"
            ...     ),
            ...     llm=LLMConfig(
            ...         provider="ollama",
            ...         config=OllamaConfig(model="llama2")
            ...     )
            ... )
            >>> service = MCPChatService(config, user_id="user123")
            >>> service.user_id
            'user123'
        """
        self.config = config
        self.user_id = user_id
        self.mcp_client = MCPClient(config.mcp_server)
        self.llm_provider = LLMProviderFactory.create(config.llm)

        # Initialize centralized chat history manager
        self.history_manager = ChatHistoryManager(redis_client=redis_client, max_messages=config.chat_history_max_messages, ttl=int(os.getenv("CHAT_HISTORY_TTL", "3600")))

        self._agent = None
        self._initialized = False
        self._tools: List[BaseTool] = []

        logger.info(f"MCPChatService initialized for user: {user_id or 'anonymous'}")

    async def initialize(self) -> None:
        """
        Initialize the chat service.

        Connects to MCP server, loads tools, initializes LLM, and creates the
        conversational agent. Must be called before using chat functionality.

        Raises:
            ConnectionError: If MCP server connection fails.
            Exception: If initialization fails.

        Examples:
            >>> import asyncio
            >>> config = MCPClientConfig(
            ...     mcp_server=MCPServerConfig(
            ...         url="https://example.com/mcp",
            ...         transport="streamable_http"
            ...     ),
            ...     llm=LLMConfig(
            ...         provider="ollama",
            ...         config=OllamaConfig(model="llama2")
            ...     )
            ... )
            >>> service = MCPChatService(config)
            >>> # asyncio.run(service.initialize())
            >>> # service.is_initialized -> True

        Note:
            Automatically loads tools from MCP server and creates agent.
        """
        if self._initialized:
            logger.warning("Chat service already initialized")
            return

        try:
            logger.info("Initializing chat service...")

            # Connect to MCP server and load tools
            await self.mcp_client.connect()
            self._tools = await self.mcp_client.get_tools()

            # Create LLM instance
            llm = self.llm_provider.get_llm()

            # Create ReAct agent with tools
            self._agent = create_react_agent(llm, self._tools)

            self._initialized = True
            logger.info(f"Chat service initialized successfully with {len(self._tools)} tools")

        except Exception as e:
            logger.error(f"Failed to initialize chat service: {e}")
            self._initialized = False
            raise

    async def chat(self, message: str) -> str:
        """
        Send a message and get a complete response.

        Processes the user's message through the LLM with tool access,
        manages conversation history, and returns the complete response.

        Args:
            message: User's message text.

        Returns:
            str: Complete AI response text.

        Raises:
            RuntimeError: If service not initialized.
            ValueError: If message is empty.
            Exception: If processing fails.

        Examples:
            >>> import asyncio
            >>> # Assuming service is initialized
            >>> # response = asyncio.run(service.chat("Hello!"))
            >>> # isinstance(response, str)
            True

        Note:
            Automatically saves conversation history after response.
        """
        if not self._initialized or not self._agent:
            raise RuntimeError("Chat service not initialized. Call initialize() first.")

        if not message or not message.strip():
            raise ValueError("Message cannot be empty")

        try:
            logger.debug("Processing chat message...")

            # Get conversation history from manager
            lc_messages = await self.history_manager.get_langchain_messages(self.user_id) if self.user_id else []

            # Add user message
            user_message = HumanMessage(content=message)
            lc_messages.append(user_message)

            # Invoke agent
            response = await self._agent.ainvoke({"messages": lc_messages})

            # Extract AI response
            ai_message = response["messages"][-1]
            response_text = ai_message.content if hasattr(ai_message, "content") else str(ai_message)

            # Save history if user_id provided
            if self.user_id:
                await self.history_manager.append_message(self.user_id, "user", message)
                await self.history_manager.append_message(self.user_id, "assistant", response_text)

            logger.debug("Chat message processed successfully")
            return response_text

        except Exception as e:
            logger.error(f"Error processing chat message: {e}")
            raise

    async def chat_with_metadata(self, message: str) -> Dict[str, Any]:
        """
        Send a message and get response with metadata.

        Similar to chat() but collects all events and returns detailed
        information about tool usage and timing.

        Args:
            message: User's message text.

        Returns:
            Dict[str, Any]: Dictionary containing:
                - text (str): Complete response text
                - tool_used (bool): Whether any tools were invoked
                - tools (List[str]): Names of tools that were used
                - tool_invocations (List[dict]): Detailed tool invocation data
                - elapsed_ms (int): Processing time in milliseconds

        Raises:
            RuntimeError: If service not initialized.
            ValueError: If message is empty.

        Examples:
            >>> import asyncio
            >>> # Assuming service is initialized
            >>> # result = asyncio.run(service.chat_with_metadata("What's 2+2?"))
            >>> # 'text' in result and 'elapsed_ms' in result
            True

        Note:
            This method collects all events and returns them as a single response.
        """
        text = ""
        tool_invocations: list[dict[str, Any]] = []
        final: dict[str, Any] = {}

        async for ev in self.chat_events(message):
            t = ev.get("type")
            if t == "token":
                text += ev.get("content", "")
            elif t in ("tool_start", "tool_end", "tool_error"):
                tool_invocations.append(ev)
            elif t == "final":
                final = ev

        return {
            "text": text,
            "tool_used": final.get("tool_used", False),
            "tools": final.get("tools", []),
            "tool_invocations": tool_invocations,
            "elapsed_ms": final.get("elapsed_ms"),
        }

    async def chat_stream(self, message: str) -> AsyncGenerator[str, None]:
        """
        Send a message and stream the response.

        Yields response chunks as they're generated, enabling real-time display
        of the AI's response.

        Args:
            message: User's message text.

        Yields:
            str: Chunks of AI response text.

        Raises:
            RuntimeError: If service not initialized.
            Exception: If streaming fails.

        Examples:
            >>> import asyncio
            >>> async def stream_example():
            ...     # Assuming service is initialized
            ...     chunks = []
            ...     async for chunk in service.chat_stream("Hello"):
            ...         chunks.append(chunk)
            ...     return ''.join(chunks)
            >>> # full_response = asyncio.run(stream_example())

        Note:
            Falls back to non-streaming if enable_streaming is False in config.
        """
        if not self._initialized or not self._agent:
            raise RuntimeError("Chat service not initialized. Call initialize() first.")

        if not self.config.enable_streaming:
            # Fall back to non-streaming
            response = await self.chat(message)
            yield response
            return

        try:
            logger.debug("Processing streaming chat message...")

            # Get conversation history
            lc_messages = await self.history_manager.get_langchain_messages(self.user_id) if self.user_id else []

            # Add user message
            user_message = HumanMessage(content=message)
            lc_messages.append(user_message)

            # Stream agent response
            full_response = ""
            async for event in self._agent.astream_events({"messages": lc_messages}, version="v2"):
                kind = event["event"]

                # Stream LLM tokens
                if kind == "on_chat_model_stream":
                    chunk = event.get("data", {}).get("chunk")
                    if chunk and hasattr(chunk, "content"):
                        content = chunk.content
                        if content:
                            full_response += content
                            yield content

            # Save history
            if self.user_id and full_response:
                await self.history_manager.append_message(self.user_id, "user", message)
                await self.history_manager.append_message(self.user_id, "assistant", full_response)

            logger.debug("Streaming chat message processed successfully")

        except Exception as e:
            logger.error(f"Error processing streaming chat message: {e}")
            raise

    async def chat_events(self, message: str) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Stream structured events during chat processing.

        Provides granular visibility into the chat processing pipeline by yielding
        structured events for tokens, tool invocations, errors, and final results.

        Args:
            message: User's message text.

        Yields:
            dict: Event dictionaries with type-specific fields:
                - token: {"type": "token", "content": str}
                - tool_start: {"type": "tool_start", "id": str, "name": str,
                              "input": Any, "start": str}
                - tool_end: {"type": "tool_end", "id": str, "name": str,
                            "output": Any, "end": str}
                - tool_error: {"type": "tool_error", "id": str, "error": str,
                              "time": str}
                - final: {"type": "final", "content": str, "tool_used": bool,
                         "tools": List[str], "elapsed_ms": int}

        Raises:
            RuntimeError: If service not initialized.
            ValueError: If message is empty or whitespace only.

        Examples:
            >>> import asyncio
            >>> async def event_example():
            ...     # Assuming service is initialized
            ...     events = []
            ...     async for event in service.chat_events("Hello"):
            ...         events.append(event['type'])
            ...     return events
            >>> # event_types = asyncio.run(event_example())
            >>> # 'final' in event_types -> True

        Note:
            This is the most detailed chat method, suitable for building
            interactive UIs or detailed logging systems.
        """
        if not self._initialized or not self._agent:
            raise RuntimeError("Chat service not initialized. Call initialize() first.")

        # Validate message
        if not message or not message.strip():
            raise ValueError("Message cannot be empty")

        # Get conversation history
        lc_messages = await self.history_manager.get_langchain_messages(self.user_id) if self.user_id else []

        # Append user message
        user_message = HumanMessage(content=message)
        lc_messages.append(user_message)

        full_response = ""
        start_ts = time.time()
        tool_runs: dict[str, dict[str, Any]] = {}

        try:
            async for event in self._agent.astream_events({"messages": lc_messages}, version="v2"):
                kind = event.get("event")
                now_iso = datetime.now(timezone.utc).isoformat()

                try:
                    if kind == "on_tool_start":
                        run_id = str(event.get("run_id") or uuid4())
                        name = event.get("name") or event.get("data", {}).get("name") or event.get("data", {}).get("tool")
                        input_data = event.get("data", {}).get("input")

                        tool_runs[run_id] = {"name": name, "start": now_iso, "input": input_data}

                        yield {"type": "tool_start", "id": run_id, "tool": name, "input": input_data, "start": now_iso}

                    elif kind == "on_tool_end":
                        run_id = str(event.get("run_id") or uuid4())
                        output = event.get("data", {}).get("output")

                        if run_id in tool_runs:
                            tool_runs[run_id]["end"] = now_iso

                            if hasattr(output, "content"):
                                tool_runs[run_id]["output"] = output.content
                            elif (hasattr(output, "__class__")) or (hasattr(output, "dict") and callable(output.dict)):
                                tool_runs[run_id]["output"] = output.dict()
                            elif not isinstance(output, (str, int, float, bool, list, dict, type(None))):
                                tool_runs[run_id]["output"] = str(output)

                        if tool_runs[run_id]["output"] == "":
                            error = "Tool execution failed: Please check if the tool is accessible"
                            yield {"type": "tool_error", "id": run_id, "tool": tool_runs.get(run_id, {}).get("name"), "error": error, "time": now_iso}

                        yield {"type": "tool_end", "id": run_id, "tool": tool_runs.get(run_id, {}).get("name"), "output": tool_runs[run_id]["output"], "end": now_iso}

                    elif kind == "on_tool_error":
                        run_id = str(event.get("run_id") or uuid4())
                        error = str(event.get("data", {}).get("error", "Unknown error"))

                        yield {"type": "tool_error", "id": run_id, "tool": tool_runs.get(run_id, {}).get("name"), "error": error, "time": now_iso}

                    elif kind == "on_chat_model_stream":
                        chunk = event.get("data", {}).get("chunk")
                        if chunk and hasattr(chunk, "content"):
                            content = chunk.content
                            if content:
                                full_response += content
                                yield {"type": "token", "content": content}

                except Exception as event_error:
                    logger.warning(f"Error processing event {kind}: {event_error}")
                    continue

            # Calculate elapsed time
            elapsed_ms = int((time.time() - start_ts) * 1000)

            # Determine tool usage
            tools_used = list({tr["name"] for tr in tool_runs.values() if tr.get("name")})

            # Yield final event
            yield {"type": "final", "content": full_response, "tool_used": len(tools_used) > 0, "tools": tools_used, "elapsed_ms": elapsed_ms}

            # Save history
            if self.user_id and full_response:
                await self.history_manager.append_message(self.user_id, "user", message)
                await self.history_manager.append_message(self.user_id, "assistant", full_response)

        except Exception as e:
            logger.error(f"Error in chat_events: {e}")
            raise RuntimeError(f"Chat processing error: {e}") from e

    async def get_conversation_history(self) -> List[Dict[str, str]]:
        """
        Get conversation history for the current user.

        Returns:
            List[Dict[str, str]]: Conversation messages with keys:
                - role (str): "user" or "assistant"
                - content (str): Message text

        Examples:
            >>> import asyncio
            >>> # Assuming service is initialized with user_id
            >>> # history = asyncio.run(service.get_conversation_history())
            >>> # all('role' in msg and 'content' in msg for msg in history)
            True

        Note:
            Returns empty list if no user_id set or no history exists.
        """
        if not self.user_id:
            return []

        return await self.history_manager.get_history(self.user_id)

    async def clear_history(self) -> None:
        """
        Clear conversation history for the current user.

        Removes all messages from the conversation history. Useful for starting
        fresh conversations or managing memory usage.

        Examples:
            >>> import asyncio
            >>> # Assuming service is initialized with user_id
            >>> # asyncio.run(service.clear_history())
            >>> # history = asyncio.run(service.get_conversation_history())
            >>> # len(history) -> 0

        Note:
            This action cannot be undone. No-op if no user_id set.
        """
        if not self.user_id:
            return

        await self.history_manager.clear_history(self.user_id)
        logger.info(f"Conversation history cleared for user {self.user_id}")

    async def shutdown(self) -> None:
        """
        Shutdown the chat service and cleanup resources.

        Performs graceful shutdown by disconnecting from MCP server, clearing
        agent and history, and resetting initialization state.

        Raises:
            Exception: If cleanup operations fail.

        Examples:
            >>> import asyncio
            >>> config = MCPClientConfig(
            ...     mcp_server=MCPServerConfig(
            ...         url="https://example.com/mcp",
            ...         transport="streamable_http"
            ...     ),
            ...     llm=LLMConfig(
            ...         provider="ollama",
            ...         config=OllamaConfig(model="llama2")
            ...     )
            ... )
            >>> service = MCPChatService(config)
            >>> # asyncio.run(service.initialize())
            >>> # asyncio.run(service.shutdown())
            >>> # service.is_initialized -> False

        Note:
            Should be called when service is no longer needed to properly
            release resources and connections.
        """
        logger.info("Shutting down chat service...")

        try:
            # Disconnect from MCP server
            if self.mcp_client.is_connected:
                await self.mcp_client.disconnect()

            # Clear state
            self._agent = None
            self._initialized = False
            self._tools = []

            logger.info("Chat service shutdown complete")

        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
            raise

    @property
    def is_initialized(self) -> bool:
        """
        Check if service is initialized.

        Returns:
            bool: True if service is initialized and ready, False otherwise.

        Examples:
            >>> config = MCPClientConfig(
            ...     mcp_server=MCPServerConfig(
            ...         url="https://example.com/mcp",
            ...         transport="streamable_http"
            ...     ),
            ...     llm=LLMConfig(
            ...         provider="ollama",
            ...         config=OllamaConfig(model="llama2")
            ...     )
            ... )
            >>> service = MCPChatService(config)
            >>> service.is_initialized
            False

        Note:
            Service must be initialized before calling chat methods.
        """
        return self._initialized

    async def reload_tools(self) -> int:
        """
        Reload tools from MCP server.

        Forces a reload of tools from the MCP server and recreates the agent
        with the updated tool set. Useful when MCP server tools have changed.

        Returns:
            int: Number of tools successfully loaded.

        Raises:
            RuntimeError: If service not initialized.
            Exception: If tool reloading or agent recreation fails.

        Examples:
            >>> import asyncio
            >>> # Assuming service is initialized
            >>> # tool_count = asyncio.run(service.reload_tools())
            >>> # tool_count >= 0 -> True

        Note:
            This operation recreates the agent, so it may briefly interrupt
            ongoing conversations. Conversation history is preserved.
        """
        if not self._initialized:
            raise RuntimeError("Chat service not initialized")

        try:
            logger.info("Reloading tools from MCP server...")
            tools = await self.mcp_client.get_tools(force_reload=True)

            # Recreate agent with new tools
            llm = self.llm_provider.get_llm()
            self._agent = create_react_agent(llm, tools)
            self._tools = tools

            logger.info(f"Reloaded {len(tools)} tools successfully")
            return len(tools)

        except Exception as e:
            logger.error(f"Failed to reload tools: {e}")
            raise
