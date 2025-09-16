# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/plugins/framework/external/mcp/test_client_stdio.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Mihai Criveti

Tests for external client on stdio.
"""
# Standard
from contextlib import AsyncExitStack
import json
import os
import re
import sys
from typing import Optional

# Third-Party
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
import pytest

# First-Party
from mcpgateway.models import Message, PromptResult, ResourceContent, Role, TextContent
from mcpgateway.plugins.framework import (
    ConfigLoader,
    GlobalContext,
    PluginConfig,
    PluginError,
    PluginContext,
    PluginLoader,
    PluginManager,
    PromptPosthookPayload,
    PromptPrehookPayload,
    ResourcePostFetchPayload,
    ResourcePreFetchPayload,
    ToolPostInvokePayload,
    ToolPreInvokePayload,
)
from plugins.regex_filter.search_replace import SearchReplaceConfig


@pytest.mark.asyncio
async def test_client_load_stdio():
    os.environ["PLUGINS_CONFIG_PATH"] = "tests/unit/mcpgateway/plugins/fixtures/configs/valid_multiple_plugins_filter.yaml"
    os.environ["PYTHONPATH"] = "."
    config = ConfigLoader.load_config("tests/unit/mcpgateway/plugins/fixtures/configs/valid_stdio_external_plugin.yaml")

    loader = PluginLoader()
    plugin = await loader.load_and_instantiate_plugin(config.plugins[0])
    prompt = PromptPrehookPayload(name="test_prompt", args = {"text": "That was innovative!"})
    result = await plugin.prompt_pre_fetch(prompt, PluginContext(global_context=GlobalContext(request_id="1", server_id="2")))
    assert result.violation
    assert result.violation.reason == "Prompt not allowed"
    assert result.violation.description == "A deny word was found in the prompt"
    assert result.violation.code == "deny"
    config = plugin.config
    assert config.name == "DenyListPlugin"
    assert config.description == "A plugin that implements a deny list filter."
    assert config.priority == 100
    assert config.kind == "external"
    await plugin.shutdown()
    del os.environ["PLUGINS_CONFIG_PATH"]
    del os.environ["PYTHONPATH"]

@pytest.mark.asyncio
async def test_client_load_stdio_overrides():
    os.environ["PLUGINS_CONFIG_PATH"] = "tests/unit/mcpgateway/plugins/fixtures/configs/valid_multiple_plugins_filter.yaml"
    os.environ["PYTHONPATH"] = "."
    config = ConfigLoader.load_config("tests/unit/mcpgateway/plugins/fixtures/configs/valid_stdio_external_plugin_overrides.yaml")

    loader = PluginLoader()
    plugin = await loader.load_and_instantiate_plugin(config.plugins[0])
    prompt = PromptPrehookPayload(name="test_prompt", args = {"text": "That was innovative!"})
    result = await plugin.prompt_pre_fetch(prompt, PluginContext(global_context=GlobalContext(request_id="1", server_id="2")))
    assert result.violation
    assert result.violation.reason == "Prompt not allowed"
    assert result.violation.description == "A deny word was found in the prompt"
    assert result.violation.code == "deny"
    config = plugin.config
    assert config.name == "DenyListPlugin"
    assert config.description == "a different configuration."
    assert config.priority == 150
    assert config.hooks[0] == "prompt_pre_fetch"
    assert config.hooks[1] == "prompt_post_fetch"
    assert config.kind == "external"
    await plugin.shutdown()
    del os.environ["PLUGINS_CONFIG_PATH"]
    del os.environ["PYTHONPATH"]

@pytest.mark.asyncio
async def test_client_load_stdio_post_prompt():
    os.environ["PLUGINS_CONFIG_PATH"] = "tests/unit/mcpgateway/plugins/fixtures/configs/valid_single_plugin.yaml"
    os.environ["PYTHONPATH"] = "."
    config = ConfigLoader.load_config("tests/unit/mcpgateway/plugins/fixtures/configs/valid_stdio_external_plugin_regex.yaml")

    loader = PluginLoader()
    plugin = await loader.load_and_instantiate_plugin(config.plugins[0])
    prompt = PromptPrehookPayload(name="test_prompt", args = {"user": "What a crapshow!"})
    context = PluginContext(global_context=GlobalContext(request_id="1", server_id="2"))
    result = await plugin.prompt_pre_fetch(prompt, context)
    assert result.modified_payload.args["user"] == "What a yikesshow!"
    config = plugin.config
    assert config.name == "ReplaceBadWordsPlugin"
    assert config.description == "A plugin for finding and replacing words."
    assert config.priority == 150
    assert config.kind == "external"

    message = Message(content=TextContent(type="text", text="What the crud?"), role=Role.USER)
    prompt_result = PromptResult(messages=[message])

    payload_result = PromptPosthookPayload(name="test_prompt", result=prompt_result)

    result = await plugin.prompt_post_fetch(payload_result, context=context)
    assert len(result.modified_payload.result.messages) == 1
    assert result.modified_payload.result.messages[0].content.text == "What the yikes?"
    await plugin.shutdown()
    await loader.shutdown()
    del os.environ["PLUGINS_CONFIG_PATH"]
    del os.environ["PYTHONPATH"]

@pytest.mark.asyncio
async def test_client_get_plugin_configs():
    session: Optional[ClientSession] = None
    exit_stack = AsyncExitStack()
    current_env = os.environ.copy()
    current_env["PLUGINS_CONFIG_PATH"] = "tests/unit/mcpgateway/plugins/fixtures/configs/valid_multiple_plugins.yaml"
    current_env["PYTHONPATH"] = "."
    server_params = StdioServerParameters(command=sys.executable, args=["mcpgateway/plugins/framework/external/mcp/server/runtime.py"], env=current_env)

    stdio_transport = await exit_stack.enter_async_context(stdio_client(server_params))
    stdio, write = stdio_transport
    session = await exit_stack.enter_async_context(ClientSession(stdio, write))

    await session.initialize()
    all_configs = []
    configs = await session.call_tool("get_plugin_configs", {})
    for content in configs.content:
        confs = json.loads(content.text)
        for c in confs:
            plugconfig = PluginConfig.model_validate(c)
            all_configs.append(plugconfig)
    await exit_stack.aclose()
    assert all_configs[0].name == "SynonymsPlugin"
    assert all_configs[0].kind == "plugins.regex_filter.search_replace.SearchReplacePlugin"
    assert all_configs[0].description == "A plugin for finding and replacing synonyms."
    assert all_configs[0].version == "0.1"
    assert all_configs[0].author == "MCP Context Forge Team"
    assert all_configs[0].hooks[0] == "prompt_pre_fetch"
    assert all_configs[0].hooks[1] == "prompt_post_fetch"
    assert all_configs[0].config
    srconfig = SearchReplaceConfig.model_validate(all_configs[0].config)
    assert len(srconfig.words) == 2
    assert srconfig.words[0].search == "happy"
    assert srconfig.words[0].replace == "gleeful"
    assert all_configs[1].name == "ReplaceBadWordsPlugin"
    assert all_configs[1].kind == "plugins.regex_filter.search_replace.SearchReplacePlugin"
    assert all_configs[1].description == "A plugin for finding and replacing words."
    assert all_configs[1].version == "0.1"
    assert all_configs[1].author == "MCP Context Forge Team"
    assert all_configs[1].hooks[0] == "prompt_pre_fetch"
    assert all_configs[1].hooks[1] == "prompt_post_fetch"
    assert all_configs[1].config
    srconfig = SearchReplaceConfig.model_validate(all_configs[1].config)
    assert srconfig.words[0].search == "crap"
    assert srconfig.words[0].replace == "crud"
    assert len(all_configs) == 2

@pytest.mark.asyncio
async def test_hooks():
    os.environ["PLUGINS_CONFIG_PATH"] = "tests/unit/mcpgateway/plugins/fixtures/configs/valid_single_plugin_passthrough.yaml"
    os.environ["PYTHONPATH"] = "."
    pm = PluginManager()
    if pm.initialized:
        await pm.shutdown()
    plugin_manager = PluginManager(config="tests/unit/mcpgateway/plugins/fixtures/configs/valid_stdio_external_plugin_passthrough.yaml")
    await plugin_manager.initialize()
    payload = PromptPrehookPayload(name="test_prompt", args={"arg0": "This is a crap argument"})
    global_context = GlobalContext(request_id="1")
    result, _ = await plugin_manager.prompt_pre_fetch(payload, global_context)
    # Assert expected behaviors
    assert result.continue_processing
    """Test prompt post hook across all registered plugins."""
    # Customize payload for testing
    message = Message(content=TextContent(type="text", text="prompt"), role=Role.USER)
    prompt_result = PromptResult(messages=[message])
    payload = PromptPosthookPayload(name="test_prompt", result=prompt_result)
    result, _ = await plugin_manager.prompt_post_fetch(payload, global_context)
    # Assert expected behaviors
    assert result.continue_processing
    """Test tool pre hook across all registered plugins."""
    # Customize payload for testing
    payload = ToolPreInvokePayload(name="test_prompt", args={"arg0": "This is an argument"})
    result, _ = await plugin_manager.tool_pre_invoke(payload, global_context)
    # Assert expected behaviors
    assert result.continue_processing
    """Test tool post hook across all registered plugins."""
    # Customize payload for testing
    payload = ToolPostInvokePayload(name="test_tool", result={"output0": "output value"})
    result, _ = await plugin_manager.tool_post_invoke(payload, global_context)
    # Assert expected behaviors
    assert result.continue_processing

    payload = ResourcePreFetchPayload(uri="file:///data.txt")
    result, _ = await plugin_manager.resource_pre_fetch(payload, global_context)
    # Assert expected behaviors
    assert result.continue_processing

    content = ResourceContent(type="resource", uri="file:///data.txt",
           text="Hello World")
    payload = ResourcePostFetchPayload(uri="file:///data.txt", content=content)
    result, _ = await plugin_manager.resource_post_fetch(payload, global_context)
    # Assert expected behaviors
    assert result.continue_processing
    await plugin_manager.shutdown()

@pytest.mark.asyncio
async def test_errors():
    os.environ["PLUGINS_CONFIG_PATH"] = "tests/unit/mcpgateway/plugins/fixtures/configs/error_plugin.yaml"
    os.environ["PYTHONPATH"] = "."
    plugin_manager = PluginManager(config="tests/unit/mcpgateway/plugins/fixtures/configs/error_stdio_external_plugin.yaml")
    await plugin_manager.initialize()
    payload = PromptPrehookPayload(name="test_prompt", args={"arg0": "This is a crap argument"})
    global_context = GlobalContext(request_id="1")
    escaped_regex = re.escape("ValueError('Sadly! Prompt prefetch is broken!')")
    with pytest.raises(PluginError, match=escaped_regex):
        await plugin_manager.prompt_pre_fetch(payload, global_context)

    await plugin_manager.shutdown()


@pytest.mark.skip(reason="Fails on await manager.shutdown().")
@pytest.mark.asyncio
async def test_shared_context_across_pre_post_hooks_multi_plugins():
    os.environ["PLUGINS_CONFIG_PATH"] = "tests/unit/mcpgateway/plugins/fixtures/configs/context_multiplugins.yaml"
    os.environ["PYTHONPATH"] = "."
    manager = PluginManager("./tests/unit/mcpgateway/plugins/fixtures/configs/context_stdio_external_plugins.yaml")
    await manager.initialize()
    assert manager.initialized

    # Test tool pre-invoke with transformation - use correct tool name from config
    tool_payload = ToolPreInvokePayload(name="test_tool", args={"input": "This is bad data", "quality": "wrong"})
    global_context = GlobalContext(request_id="1", server_id="2")
    result, contexts = await manager.tool_pre_invoke(tool_payload, global_context=global_context)

    assert len(contexts) == 2
    ctxs = [contexts[key] for key in contexts.keys()]
    assert len(ctxs) == 2
    context1 = ctxs[0]
    context2 = ctxs[1]
    assert context1.state
    assert "key2" in context1.state
    assert "cp2key1" not in context1.state
    assert context1.state["key2"] == "value2"
    assert len(context1.state) == 1
    assert context1.global_context.state["globkey1"] == "globvalue1"
    assert "gcp2globkey1" not in context1.global_context.state
    assert len(context1.global_context.state)
    assert not context1.global_context.metadata

    assert context2.state
    assert len(context2.state) == 1
    assert "cp2key1" in context2.state
    assert "key2" not in context2.state
    assert context2.global_context.state["globkey1"] == "globvalue1"
    assert context2.global_context.state["gcp2globkey1"] == "gcp2globvalue1"

    # Should continue processing with transformations applied
    assert result.continue_processing
    assert result.modified_payload is None
    # Test tool post-invoke with transformation
    tool_result_payload = ToolPostInvokePayload(name="test_tool", result={"output": "Result was bad", "status": "wrong format"})
    result, contexts = await manager.tool_post_invoke(tool_result_payload, global_context=global_context, local_contexts=contexts)

    ctxs = [contexts[key] for key in contexts.keys()]
    assert len(ctxs) == 2
    context1 = ctxs[0]
    context2 = ctxs[1]
    assert context1.state
    assert len(context1.state) == 2
    assert context1.state["key3"] == "value3"
    assert context1.state["key2"] == "value2"
    assert "cp2key1" not in context1.state
    assert "cp2key2" not in context1.state
    assert context1.global_context.state["globkey1"] == "globvalue1"
    assert context1.global_context.state["gcp2globkey1"] == "gcp2globvalue1"
    assert "gcp2globkey2" not in context1.global_context.state
    assert context1.global_context.state["globkey2"] == "globvalue2"

    assert context2.global_context.state["globkey1"] == "globvalue1"
    assert context2.global_context.state["gcp2globkey1"] == "gcp2globvalue1"
    assert context2.global_context.state["gcp2globkey2"] == "gcp2globvalue2"
    assert context2.global_context.state["globkey2"] == "globvalue2"

    assert "key3" not in context2.state
    assert "key2" not in context2.state
    assert "cp2key1" in context2.state

    await manager.shutdown()
