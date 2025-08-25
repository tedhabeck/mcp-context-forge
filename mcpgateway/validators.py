# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/validators.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Mihai Criveti, Madhav Kandukuri

SecurityValidator for MCP Gateway
This module defines the `SecurityValidator` class, which provides centralized, configurable
validation logic for user-generated content in MCP-based applications.

The validator enforces strict security and structural rules across common input types such as:
- Display text (e.g., names, descriptions)
- Identifiers and tool names
- URIs and URLs
- JSON object depth
- Templates (including limited HTML/Jinja2)
- MIME types

Key Features:
- Pattern-based validation using settings-defined regex for HTML/script safety
- Configurable max lengths and depth limits
- Whitelist-based URL scheme and MIME type validation
- Safe escaping of user-visible text fields
- Reusable static/class methods for field-level and form-level validation

Intended to be used with Pydantic or similar schema-driven systems to validate and sanitize
user input in a consistent, centralized way.

Dependencies:
- Standard Library: re, html, logging, urllib.parse
- First-party: `settings` from `mcpgateway.config`

Example usage:
    SecurityValidator.validate_name("my_tool", field_name="Tool Name")
    SecurityValidator.validate_url("https://example.com")
    SecurityValidator.validate_json_depth({...})

Examples:
    >>> from mcpgateway.validators import SecurityValidator
    >>> SecurityValidator.sanitize_display_text('<b>Test</b>', 'test')
    '&lt;b&gt;Test&lt;/b&gt;'
    >>> SecurityValidator.validate_name('valid_name-123', 'test')
    'valid_name-123'
    >>> SecurityValidator.validate_identifier('my.test.id_123', 'test')
    'my.test.id_123'
    >>> SecurityValidator.validate_json_depth({'a': {'b': 1}})
    >>> SecurityValidator.validate_json_depth({'a': 1})
"""

# Standard
import html
import logging
import re
from urllib.parse import urlparse
import uuid

# First-Party
from mcpgateway.config import settings

logger = logging.getLogger(__name__)


class SecurityValidator:
    """Configurable validation with MCP-compliant limits"""

    # Configurable patterns (from settings)
    DANGEROUS_HTML_PATTERN = (
        settings.validation_dangerous_html_pattern
    )  # Default: '<(script|iframe|object|embed|link|meta|base|form|img|svg|video|audio|source|track|area|map|canvas|applet|frame|frameset|html|head|body|style)\b|</*(script|iframe|object|embed|link|meta|base|form|img|svg|video|audio|source|track|area|map|canvas|applet|frame|frameset|html|head|body|style)>'
    DANGEROUS_JS_PATTERN = settings.validation_dangerous_js_pattern  # Default: javascript:|vbscript:|on\w+\s*=|data:.*script
    ALLOWED_URL_SCHEMES = settings.validation_allowed_url_schemes  # Default: ["http://", "https://", "ws://", "wss://"]

    # Character type patterns
    NAME_PATTERN = settings.validation_name_pattern  # Default: ^[a-zA-Z0-9_\-\s]+$
    IDENTIFIER_PATTERN = settings.validation_identifier_pattern  # Default: ^[a-zA-Z0-9_\-\.]+$
    VALIDATION_SAFE_URI_PATTERN = settings.validation_safe_uri_pattern  # Default: ^[a-zA-Z0-9_\-.:/?=&%]+$
    VALIDATION_UNSAFE_URI_PATTERN = settings.validation_unsafe_uri_pattern  # Default: [<>"\'\\]
    TOOL_NAME_PATTERN = settings.validation_tool_name_pattern  # Default: ^[a-zA-Z][a-zA-Z0-9_-]*$

    # MCP-compliant limits (configurable)
    MAX_NAME_LENGTH = settings.validation_max_name_length  # Default: 255
    MAX_DESCRIPTION_LENGTH = settings.validation_max_description_length  # Default: 4096
    MAX_TEMPLATE_LENGTH = settings.validation_max_template_length  # Default: 65536
    MAX_CONTENT_LENGTH = settings.validation_max_content_length  # Default: 1048576 (1MB)
    MAX_JSON_DEPTH = settings.validation_max_json_depth  # Default: 10
    MAX_URL_LENGTH = settings.validation_max_url_length  # Default: 2048

    @classmethod
    def sanitize_display_text(cls, value: str, field_name: str) -> str:
        """Ensure text is safe for display in UI by escaping special characters

        Args:
            value (str): Value to validate
            field_name (str): Name of field being validated

        Returns:
            str: Value if acceptable

        Raises:
            ValueError: When input is not acceptable
        """
        if not value:
            return value

        # Check for patterns that could cause display issues
        if re.search(cls.DANGEROUS_HTML_PATTERN, value, re.IGNORECASE):
            raise ValueError(f"{field_name} contains HTML tags that may cause display issues")

        if re.search(cls.DANGEROUS_JS_PATTERN, value, re.IGNORECASE):
            raise ValueError(f"{field_name} contains script patterns that may cause display issues")

        # Check for polyglot patterns - combinations of quotes, semicolons, and parentheses
        # that could work in multiple contexts
        polyglot_patterns = [
            r"['\"];.*alert\s*\(",  # Quotes followed by alert
            r"-->\s*<[^>]+>",  # HTML comment closers followed by tags
            r"['\"].*//['\"]",  # Quote, content, comment, quote
            r"<<[A-Z]+>",  # Double angle brackets (like <<SCRIPT>)
            r"String\.fromCharCode",  # Character code manipulation
            r"javascript:.*\(",  # javascript: protocol with function call
        ]

        for pattern in polyglot_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValueError(f"{field_name} contains potentially dangerous character sequences")

        # Escape HTML entities to ensure proper display
        return html.escape(value, quote=True)

    @classmethod
    def validate_name(cls, value: str, field_name: str = "Name") -> str:
        """Validate names with strict character requirements

        Args:
            value (str): Value to validate
            field_name (str): Name of field being validated

        Returns:
            str: Value if acceptable

        Raises:
            ValueError: When input is not acceptable

        Examples:
            >>> SecurityValidator.validate_name('valid_name')
            'valid_name'
            >>> SecurityValidator.validate_name('Invalid Name!')
            Traceback (most recent call last):
                ...
            ValueError: ...
        """
        if not value:
            raise ValueError(f"{field_name} cannot be empty")

        # Check against allowed pattern
        if not re.match(cls.NAME_PATTERN, value):
            raise ValueError(f"{field_name} can only contain letters, numbers, underscore, and hyphen. Special characters like <, >, quotes are not allowed.")

        # Additional check for HTML-like patterns
        if re.search(r'[<>"\'/]', value):
            raise ValueError(f"{field_name} cannot contain HTML special characters")

        if len(value) > cls.MAX_NAME_LENGTH:
            raise ValueError(f"{field_name} exceeds maximum length of {cls.MAX_NAME_LENGTH}")

        return value

    @classmethod
    def validate_identifier(cls, value: str, field_name: str) -> str:
        """Validate identifiers (IDs) - MCP compliant

        Args:
            value (str): Value to validate
            field_name (str): Name of field being validated

        Returns:
            str: Value if acceptable

        Raises:
            ValueError: When input is not acceptable

        Examples:
            >>> SecurityValidator.validate_identifier('valid_id', 'ID')
            'valid_id'
            >>> SecurityValidator.validate_identifier('Invalid/ID', 'ID')
            Traceback (most recent call last):
                ...
            ValueError: ...
        """
        if not value:
            raise ValueError(f"{field_name} cannot be empty")

        # MCP spec: identifiers should be alphanumeric + limited special chars
        if not re.match(cls.IDENTIFIER_PATTERN, value):
            raise ValueError(f"{field_name} can only contain letters, numbers, underscore, hyphen, and dots")

        # Block HTML-like patterns
        if re.search(r'[<>"\'/]', value):
            raise ValueError(f"{field_name} cannot contain HTML special characters")

        if len(value) > cls.MAX_NAME_LENGTH:
            raise ValueError(f"{field_name} exceeds maximum length of {cls.MAX_NAME_LENGTH}")

        return value

    @classmethod
    def validate_uri(cls, value: str, field_name: str = "URI") -> str:
        """Validate URIs - MCP compliant

        Args:
            value (str): Value to validate
            field_name (str): Name of field being validated

        Returns:
            str: Value if acceptable

        Raises:
            ValueError: When input is not acceptable

        Examples:
            >>> SecurityValidator.validate_uri('/valid/uri', 'URI')
            '/valid/uri'
            >>> SecurityValidator.validate_uri('..', 'URI')
            Traceback (most recent call last):
                ...
            ValueError: ...
        """
        if not value:
            raise ValueError(f"{field_name} cannot be empty")

        # Block HTML-like patterns
        if re.search(cls.VALIDATION_UNSAFE_URI_PATTERN, value):
            raise ValueError(f"{field_name} cannot contain HTML special characters")

        if ".." in value:
            raise ValueError(f"{field_name} cannot contain directory traversal sequences ('..')")

        if not re.search(cls.VALIDATION_SAFE_URI_PATTERN, value):
            raise ValueError(f"{field_name} contains invalid characters")

        if len(value) > cls.MAX_NAME_LENGTH:
            raise ValueError(f"{field_name} exceeds maximum length of {cls.MAX_NAME_LENGTH}")

        return value

    @classmethod
    def validate_tool_name(cls, value: str) -> str:
        """Special validation for MCP tool names

        Args:
            value (str): Value to validate

        Returns:
            str: Value if acceptable

        Raises:
            ValueError: When input is not acceptable

        Examples:
            >>> SecurityValidator.validate_tool_name('tool_1')
            'tool_1'
            >>> SecurityValidator.validate_tool_name('1tool')
            Traceback (most recent call last):
                ...
            ValueError: ...
        """
        if not value:
            raise ValueError("Tool name cannot be empty")

        # MCP tools have specific naming requirements
        if not re.match(cls.TOOL_NAME_PATTERN, value):
            raise ValueError("Tool name must start with a letter and contain only letters, numbers, and underscore")

        # Ensure no HTML-like content
        if re.search(r'[<>"\'/]', value):
            raise ValueError("Tool name cannot contain HTML special characters")

        if len(value) > cls.MAX_NAME_LENGTH:
            raise ValueError(f"Tool name exceeds maximum length of {cls.MAX_NAME_LENGTH}")

        return value

    @classmethod
    def validate_uuid(cls, value: str, field_name: str = "UUID") -> str:
        """Validate UUID format

        Args:
            value (str): Value to validate
            field_name (str): Name of field being validated

        Returns:
            str: Value if validated as safe

        Raises:
            ValueError: When value is not a valid UUID

        Examples:
            >>> SecurityValidator.validate_uuid('550e8400-e29b-41d4-a716-446655440000')
            '550e8400-e29b-41d4-a716-446655440000'
            >>> SecurityValidator.validate_uuid('invalid-uuid')
            Traceback (most recent call last):
                ...
            ValueError: ...
        """
        if not value:
            return value

        try:
            # Validate UUID format by attempting to parse it
            uuid_obj = uuid.UUID(value)
            # Return the normalized string representation
            return str(uuid_obj)
        except ValueError:
            raise ValueError(f"{field_name} must be a valid UUID format")

    @classmethod
    def validate_template(cls, value: str) -> str:
        """Special validation for templates - allow safe Jinja2 but prevent SSTI

        Args:
            value (str): Value to validate

        Returns:
            str: Value if acceptable

        Raises:
            ValueError: When input is not acceptable
        """
        if not value:
            return value

        if len(value) > cls.MAX_TEMPLATE_LENGTH:
            raise ValueError(f"Template exceeds maximum length of {cls.MAX_TEMPLATE_LENGTH}")

        # Block dangerous tags but allow Jinja2 syntax {{ }} and {% %}
        dangerous_tags = r"<(script|iframe|object|embed|link|meta|base|form)\b"
        if re.search(dangerous_tags, value, re.IGNORECASE):
            raise ValueError("Template contains HTML tags that may interfere with proper display")

        # Check for event handlers that could cause issues
        if re.search(r"on\w+\s*=", value, re.IGNORECASE):
            raise ValueError("Template contains event handlers that may cause display issues")

        # SSTI Prevention - block dangerous template expressions
        ssti_patterns = [
            r"\{\{.*(__|\.|config|self|request|application|globals|builtins|import).*\}\}",  # Jinja2 dangerous patterns
            r"\{%.*(__|\.|config|self|request|application|globals|builtins|import).*%\}",  # Jinja2 tags
            r"\$\{.*\}",  # ${} expressions
            r"#\{.*\}",  # #{} expressions
            r"%\{.*\}",  # %{} expressions
            r"\{\{.*\*.*\}\}",  # Math operations in templates (like {{7*7}})
            r"\{\{.*\/.*\}\}",  # Division operations
            r"\{\{.*\+.*\}\}",  # Addition operations
            r"\{\{.*\-.*\}\}",  # Subtraction operations
        ]

        for pattern in ssti_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValueError("Template contains potentially dangerous expressions")

        return value

    @classmethod
    def validate_url(cls, value: str, field_name: str = "URL") -> str:
        """Validate URLs for allowed schemes and safe display

        Args:
            value (str): Value to validate
            field_name (str): Name of field being validated

        Returns:
            str: Value if acceptable

        Raises:
            ValueError: When input is not acceptable

        Examples:
            >>> SecurityValidator.validate_url('https://example.com')
            'https://example.com'
            >>> SecurityValidator.validate_url('ftp://example.com')
            Traceback (most recent call last):
                ...
            ValueError: ...
        """
        if not value:
            raise ValueError(f"{field_name} cannot be empty")

        # Length check
        if len(value) > cls.MAX_URL_LENGTH:
            raise ValueError(f"{field_name} exceeds maximum length of {cls.MAX_URL_LENGTH}")

        # Check allowed schemes
        allowed_schemes = cls.ALLOWED_URL_SCHEMES
        if not any(value.lower().startswith(scheme.lower()) for scheme in allowed_schemes):
            raise ValueError(f"{field_name} must start with one of: {', '.join(allowed_schemes)}")

        # Block dangerous URL patterns
        dangerous_patterns = [r"javascript:", r"data:", r"vbscript:", r"about:", r"chrome:", r"file:", r"ftp:", r"mailto:"]
        for pattern in dangerous_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValueError(f"{field_name} contains unsupported or potentially dangerous protocol")

        # Block IPv6 URLs (URLs with square brackets)
        if "[" in value or "]" in value:
            raise ValueError(f"{field_name} contains IPv6 address which is not supported")

        # Block protocol-relative URLs
        if value.startswith("//"):
            raise ValueError(f"{field_name} contains protocol-relative URL which is not supported")

        # Check for CRLF injection
        if "\r" in value or "\n" in value:
            raise ValueError(f"{field_name} contains line breaks which are not allowed")

        # Check for spaces in domain
        if " " in value.split("?")[0]:  # Check only in the URL part, not query string
            raise ValueError(f"{field_name} contains spaces which are not allowed in URLs")

        # Basic URL structure validation
        try:
            result = urlparse(value)
            if not all([result.scheme, result.netloc]):
                raise ValueError(f"{field_name} is not a valid URL")

            # Additional validation: ensure netloc doesn't contain brackets (double-check)
            if "[" in result.netloc or "]" in result.netloc:
                raise ValueError(f"{field_name} contains IPv6 address which is not supported")

            # Block dangerous IP addresses
            hostname = result.hostname
            if hostname:
                # Block 0.0.0.0 (all interfaces)
                if hostname == "0.0.0.0":  # nosec B104 - we're blocking this for security
                    raise ValueError(f"{field_name} contains invalid IP address (0.0.0.0)")

                # Block AWS metadata service
                if hostname == "169.254.169.254":
                    raise ValueError(f"{field_name} contains restricted IP address")

                # Optional: Block localhost/loopback (uncomment if needed)
                # if hostname in ["127.0.0.1", "localhost"]:
                #     raise ValueError(f"{field_name} contains localhost address")

            # Validate port number
            if result.port is not None:
                if result.port < 1 or result.port > 65535:
                    raise ValueError(f"{field_name} contains invalid port number")

            # Check for credentials in URL
            if result.username or result.password:
                raise ValueError(f"{field_name} contains credentials which are not allowed")

            # Check for XSS patterns in the entire URL (including query parameters)
            if re.search(cls.DANGEROUS_HTML_PATTERN, value, re.IGNORECASE):
                raise ValueError(f"{field_name} contains HTML tags that may cause security issues")

            if re.search(cls.DANGEROUS_JS_PATTERN, value, re.IGNORECASE):
                raise ValueError(f"{field_name} contains script patterns that may cause security issues")

        except ValueError:
            # Re-raise ValueError as-is
            raise
        except Exception:
            raise ValueError(f"{field_name} is not a valid URL")

        return value

    @classmethod
    def validate_no_xss(cls, value: str, field_name: str) -> None:
        """
        Validate that a string does not contain XSS patterns.

        Args:
            value (str): Value to validate.
            field_name (str): Name of the field being validated.

        Raises:
            ValueError: If the value contains XSS patterns.
        """
        if not value:
            return  # Empty values are considered safe
        # Check for dangerous HTML tags
        if re.search(cls.DANGEROUS_HTML_PATTERN, value, re.IGNORECASE):
            raise ValueError(f"{field_name} contains HTML tags that may cause security issues")

    @classmethod
    def validate_json_depth(
        cls,
        obj: object,
        max_depth: int | None = None,
        current_depth: int = 0,
    ) -> None:
        """Validate that a JSON‑like structure does not exceed a depth limit.

        A *depth* is counted **only** when we enter a container (`dict` or
        `list`). Primitive values (`str`, `int`, `bool`, `None`, etc.) do not
        increase the depth, but an *empty* container still counts as one level.

        Args:
            obj: Any Python object to inspect recursively.
            max_depth: Maximum allowed depth (defaults to
                :pyattr:`SecurityValidator.MAX_JSON_DEPTH`).
            current_depth: Internal recursion counter. **Do not** set this
                from user code.

        Raises:
            ValueError: If the nesting level exceeds *max_depth*.

        Examples:
            Simple flat dictionary – depth 1: ::

                >>> SecurityValidator.validate_json_depth({'name': 'Alice'})

            Nested dict – depth 2: ::

                >>> SecurityValidator.validate_json_depth(
                ...     {'user': {'name': 'Alice'}}
                ... )

            Mixed dict/list – depth 3: ::

                >>> SecurityValidator.validate_json_depth(
                ...     {'users': [{'name': 'Alice', 'meta': {'age': 30}}]}
                ... )

            Exactly at the default limit (10) – allowed: ::

                >>> deep_10 = {'1': {'2': {'3': {'4': {'5': {'6': {'7': {'8':
                ...     {'9': {'10': 'end'}}}}}}}}}}
                >>> SecurityValidator.validate_json_depth(deep_10)

            One level deeper – rejected: ::

                >>> deep_11 = {'1': {'2': {'3': {'4': {'5': {'6': {'7': {'8':
                ...     {'9': {'10': {'11': 'end'}}}}}}}}}}}
                >>> SecurityValidator.validate_json_depth(deep_11)
                Traceback (most recent call last):
                    ...
                ValueError: JSON structure exceeds maximum depth of 10
        """
        if max_depth is None:
            max_depth = cls.MAX_JSON_DEPTH

        # Only containers count toward depth; primitives are ignored
        if not isinstance(obj, (dict, list)):
            return

        next_depth = current_depth + 1
        if next_depth > max_depth:
            raise ValueError(f"JSON structure exceeds maximum depth of {max_depth}")

        if isinstance(obj, dict):
            for value in obj.values():
                cls.validate_json_depth(value, max_depth, next_depth)
        else:  # obj is a list
            for item in obj:
                cls.validate_json_depth(item, max_depth, next_depth)

    @classmethod
    def validate_mime_type(cls, value: str) -> str:
        """Validate MIME type format

        Args:
            value (str): Value to validate

        Returns:
            str: Value if acceptable

        Raises:
            ValueError: When input is not acceptable
        """
        if not value:
            return value

        # Basic MIME type pattern
        mime_pattern = r"^[a-zA-Z0-9][a-zA-Z0-9!#$&\-\^_+\.]*\/[a-zA-Z0-9][a-zA-Z0-9!#$&\-\^_+\.]*$"
        if not re.match(mime_pattern, value):
            raise ValueError("Invalid MIME type format")

        # Common safe MIME types
        safe_mime_types = settings.validation_allowed_mime_types
        if value not in safe_mime_types:
            # Allow x- vendor types and + suffixes
            base_type = value.split(";")[0].strip()
            if not (base_type.startswith("application/x-") or base_type.startswith("text/x-") or "+" in base_type):
                raise ValueError(f"MIME type '{value}' is not in the allowed list")

        return value
