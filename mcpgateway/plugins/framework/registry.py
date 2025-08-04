# -*- coding: utf-8 -*-
"""Plugin instance registry.

Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Mihai Criveti

Module that stores plugin instances and manages hook points.
"""

# Standard
from collections import defaultdict
import logging
from typing import Optional

# First-Party
from mcpgateway.plugins.framework.base import Plugin, PluginRef
from mcpgateway.plugins.framework.models import HookType

logger = logging.getLogger(__name__)


class PluginInstanceRegistry:
    """Registry for managing loaded plugins."""

    def __init__(self) -> None:
        """Initialize a plugin instance registry."""
        self._plugins: dict[str, PluginRef] = {}
        self._hooks: dict[HookType, list[PluginRef]] = defaultdict(list)
        self._priority_cache: dict[HookType, list[PluginRef]] = {}

    def register(self, plugin: Plugin) -> None:
        """Register a plugin instance.

        Args:
            plugin: plugin to be registered.

        Raises:
            ValueError: if plugin is already registered.
        """
        if plugin.name in self._plugins:
            raise ValueError(f"Plugin {plugin.name} already registered")

        plugin_ref = PluginRef(plugin)

        self._plugins[plugin.name] = plugin_ref

        # Register hooks
        for hook_type in plugin.hooks:
            self._hooks[hook_type].append(plugin_ref)
            # Invalidate priority cache for this hook
            self._priority_cache.pop(hook_type, None)

        logger.info(f"Registered plugin: {plugin.name} with hooks: {[h.name for h in plugin.hooks]}")

    def unregister(self, plugin_name: str) -> None:
        """Unregister a plugin given its name.

        Args:
            plugin_name: The name of the plugin to unregister.

        Returns:
            None
        """
        if plugin_name not in self._plugins:
            return

        plugin = self._plugins.pop(plugin_name)
        # Remove from hooks
        for hook_type in plugin.hooks:
            self._hooks[hook_type] = [p for p in self._hooks[hook_type] if p.name != plugin_name]
            self._priority_cache.pop(hook_type, None)

        logger.info(f"Unregistered plugin: {plugin_name}")

    def get_plugin(self, name: str) -> Optional[PluginRef]:
        """Get a plugin by name.

        Args:
            name: the name of the plugin to return.

        Returns:
            A plugin.
        """
        return self._plugins.get(name)

    def get_plugins_for_hook(self, hook_type: HookType) -> list[PluginRef]:
        """Get all plugins for a specific hook, sorted by priority.

        Args:
            hook_type: the hook type.

        Returns:
            A list of plugin instances.
        """
        if hook_type not in self._priority_cache:
            plugins = sorted(self._hooks[hook_type], key=lambda p: p.priority)
            self._priority_cache[hook_type] = plugins
        return self._priority_cache[hook_type]

    def get_all_plugins(self) -> list[PluginRef]:
        """Get all registered plugin instances.

        Returns:
            A list of registered plugin instances.
        """
        return list(self._plugins.values())
