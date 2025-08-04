# -*- coding: utf-8 -*-
"""Utility module for plugins layer.

Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

This module implements the utility functions associated with
plugins.
"""

# Standard
from functools import cache
import importlib
from types import ModuleType

# First-Party
from mcpgateway.plugins.framework.models import PluginCondition
from mcpgateway.plugins.framework.types import GlobalContext, PromptPosthookPayload, PromptPrehookPayload


@cache  # noqa
def import_module(mod_name: str) -> ModuleType:
    """Import a module.

    Args:
        mod_name: fully qualified module name

    Returns:
        A module.
    """
    return importlib.import_module(mod_name)


def parse_class_name(name: str) -> tuple[str, str]:
    """Parse a class name into its constituents.

    Args:
        name: the qualified class name

    Returns:
        A pair containing the qualified class prefix and the class name
    """
    clslist = name.rsplit(".", 1)
    if len(clslist) == 2:
        return (clslist[0], clslist[1])
    return ("", name)


def matches(condition: PluginCondition, context: GlobalContext) -> bool:
    """Check if conditions match the current context.

    Args:
        condition: the conditions on the plugin that are required for execution.
        context: the global context.

    Returns:
        True if the plugin matches criteria.
    """
    # Check server ID
    if condition.server_ids and context.server_id not in condition.server_ids:
        return False

    # Check tenant ID
    if condition.tenant_ids and context.tenant_id not in condition.tenant_ids:
        return False

    # Check user patterns (simple contains check, could be regex)
    if condition.user_patterns and context.user:
        if not any(pattern in context.user for pattern in condition.user_patterns):
            return False
    return True


def pre_prompt_matches(payload: PromptPrehookPayload, conditions: list[PluginCondition], context: GlobalContext) -> bool:
    """Check for a match on pre-prompt hooks.

    Args:
        payload: the prompt prehook payload.
        conditions: the conditions on the plugin that are required for execution.
        context: the global context.

    Returns:
        True if the plugin matches criteria.
    """
    current_result = True
    for index, condition in enumerate(conditions):
        if not matches(condition, context):
            current_result = False

        if condition.prompts and payload.name not in condition.prompts:
            current_result = False
        if current_result:
            return True
        elif index < len(conditions) - 1:
            current_result = True
    return current_result

def post_prompt_matches(payload: PromptPosthookPayload, conditions: list[PluginCondition], context: GlobalContext) -> bool:
    """Check for a match on pre-prompt hooks.

    Args:
        payload: the prompt posthook payload.
        conditions: the conditions on the plugin that are required for execution.
        context: the global context.

    Returns:
        True if the plugin matches criteria.
    """
    current_result = True
    for index, condition in enumerate(conditions):
        if not matches(condition, context):
            current_result = False

        if condition.prompts and payload.name not in condition.prompts:
            current_result = False
        if current_result:
            return True
        elif index < len(conditions) - 1:
            current_result = True
    return current_result
