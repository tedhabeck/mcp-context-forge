# -*- coding: utf-8 -*-
"""Simple example plugin for searching and replacing text.

Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Fred Araujo

This module loads configurations for plugins.
"""
# Standard
import re

# Third-Party
from pydantic import BaseModel

# First-Party
from mcpgateway.plugins.framework.base import Plugin
from mcpgateway.plugins.framework.models import PluginConfig, PluginViolation
from mcpgateway.plugins.framework.plugin_types import PluginContext, PromptPrehookPayload, PromptPrehookResult


class DenyListConfig(BaseModel):
    words: list[str]


class DenyListPlugin(Plugin):
    """Example deny list plugin."""
    def __init__(self, config: PluginConfig):
        super().__init__(config)
        self._dconfig = DenyListConfig.model_validate(self._config.config)
        self._deny_list = []
        for word in self._dconfig.words:
            self._deny_list.append(word)

    async def prompt_pre_fetch(self, payload: PromptPrehookPayload, context: PluginContext) -> PromptPrehookResult:
        """The plugin hook run before a prompt is retrieved and rendered.

        Args:
            payload: The prompt payload to be analyzed.
            context: contextual information about the hook call.

        Returns:
            The result of the plugin's analysis, including whether the prompt can proceed.
        """
        if payload.args:
            for key in payload.args:
                if any(word in payload.args[key] for word in self._deny_list):
                    violation = PluginViolation(
                        reason="Prompt not allowed",
                        description="A deny word was found in the prompt",
                        code="deny",
                        details={},
                    )
                    return PromptPrehookResult(modified_payload=payload, violation=violation, continue_processing=False)
        return PromptPrehookResult(modified_payload=payload)


