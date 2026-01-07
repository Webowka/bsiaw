"""
Enhanced Input Validation Module (Lab 7 - Task 1.a)

Comprehensive input validation and sanitization for backend, frontend, and JSON API payloads.
This module extends the existing Pydantic validation with additional security checks.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, validator, Field
import re
import json
from .xss_protection import sanitize_text, sanitize_html_content, sanitize_username


class ValidatedInput(BaseModel):
    """Base class for validated inputs with common sanitization"""

    class Config:
        str_strip_whitespace = True  # Auto-strip whitespace
        validate_assignment = True  # Validate on attribute assignment too


class CommentRequest(ValidatedInput):
    """Validated model for comment creation"""
    content: str = Field(..., min_length=1, max_length=1000)

    @validator('content')
    def sanitize_content(cls, v):
        """Sanitize comment content"""
        if not v.strip():
            raise ValueError('Comment content cannot be empty')
        return sanitize_html_content(v)


class ThreadRequest(ValidatedInput):
    """Validated model for thread creation"""
    title: str = Field(..., min_length=3, max_length=200)

    @validator('title')
    def sanitize_title(cls, v):
        """Sanitize thread title"""
        if not v.strip():
            raise ValueError('Thread title cannot be empty')
        return sanitize_text(v)


class ThreadMessageRequest(ValidatedInput):
    """Validated model for thread message"""
    content: str = Field(..., min_length=1, max_length=2000)

    @validator('content')
    def sanitize_content(cls, v):
        """Sanitize message content"""
        if not v.strip():
            raise ValueError('Message content cannot be empty')
        return sanitize_html_content(v)


class TagRequest(ValidatedInput):
    """Validated model for tag input"""
    name: str = Field(..., min_length=2, max_length=30)

    @validator('name')
    def sanitize_tag(cls, v):
        """Sanitize tag name - alphanumeric, hyphens, underscores only"""
        v = v.strip().lower()
        if not re.match(r'^[a-z0-9_-]+$', v):
            raise ValueError('Tag can only contain lowercase letters, numbers, hyphens, and underscores')
        return v


class SearchRequest(ValidatedInput):
    """Validated model for search queries"""
    query: str = Field(..., min_length=1, max_length=100)

    @validator('query')
    def sanitize_query(cls, v):
        """Sanitize search query"""
        v = sanitize_text(v)
        # Remove special characters that could cause issues
        v = re.sub(r'[^\w\s-]', '', v)
        return v.strip()


class JSONPayloadValidator:
    """
    Validator for JSON API payloads
    Ensures JSON structure is valid and sanitizes content
    """

    @staticmethod
    def validate_json_structure(payload: str) -> Dict[str, Any]:
        """
        Validate JSON structure and return parsed data

        Args:
            payload: JSON string

        Returns:
            Parsed JSON dictionary

        Raises:
            ValueError: If JSON is invalid or too large
        """
        # Check payload size (max 10MB)
        max_size = 10 * 1024 * 1024  # 10MB
        if len(payload.encode('utf-8')) > max_size:
            raise ValueError('Payload size exceeds maximum allowed (10MB)')

        try:
            data = json.loads(payload)
        except json.JSONDecodeError as e:
            raise ValueError(f'Invalid JSON format: {str(e)}')

        # Ensure it's a dictionary
        if not isinstance(data, dict):
            raise ValueError('JSON payload must be an object')

        return data

    @staticmethod
    def validate_content_block(block: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate and sanitize content block structure

        Args:
            block: Content block dictionary

        Returns:
            Sanitized content block

        Raises:
            ValueError: If block structure is invalid
        """
        required_fields = ['block_type', 'order_index']

        # Check required fields
        for field in required_fields:
            if field not in block:
                raise ValueError(f'Content block missing required field: {field}')

        # Validate block type
        valid_types = ['text', 'image', 'video']
        if block['block_type'] not in valid_types:
            raise ValueError(f'Invalid block type. Must be one of: {", ".join(valid_types)}')

        # Validate order_index
        try:
            order_index = int(block['order_index'])
            if order_index < 0 or order_index > 100:
                raise ValueError('order_index must be between 0 and 100')
        except (ValueError, TypeError):
            raise ValueError('order_index must be a valid integer')

        # Sanitize content based on type
        if block['block_type'] == 'text':
            if 'content' not in block:
                raise ValueError('Text block must have content field')
            block['content'] = sanitize_html_content(str(block['content']))

        elif block['block_type'] in ['image', 'video']:
            if 'url' not in block:
                raise ValueError(f'{block["block_type"].capitalize()} block must have url field')
            # Basic URL validation
            url = str(block['url'])
            if not url.startswith(('http://', 'https://', '/')):
                raise ValueError('Invalid URL format')

        return block

    @staticmethod
    def sanitize_nested_dict(data: Dict[str, Any], max_depth: int = 5, current_depth: int = 0) -> Dict[str, Any]:
        """
        Recursively sanitize nested dictionary values

        Args:
            data: Dictionary to sanitize
            max_depth: Maximum nesting depth allowed
            current_depth: Current recursion depth

        Returns:
            Sanitized dictionary

        Raises:
            ValueError: If max depth exceeded
        """
        if current_depth > max_depth:
            raise ValueError(f'JSON nesting depth exceeds maximum allowed ({max_depth})')

        sanitized = {}
        for key, value in data.items():
            # Sanitize key
            key = sanitize_text(str(key))

            # Sanitize value based on type
            if isinstance(value, dict):
                sanitized[key] = JSONPayloadValidator.sanitize_nested_dict(
                    value, max_depth, current_depth + 1
                )
            elif isinstance(value, list):
                sanitized[key] = [
                    JSONPayloadValidator.sanitize_nested_dict(item, max_depth, current_depth + 1)
                    if isinstance(item, dict)
                    else sanitize_text(str(item)) if isinstance(item, str)
                    else item
                    for item in value
                ]
            elif isinstance(value, str):
                sanitized[key] = sanitize_text(value)
            else:
                sanitized[key] = value

        return sanitized


class InputValidator:
    """
    General purpose input validator with multiple validation strategies
    """

    @staticmethod
    def validate_integer(value: Any, min_val: Optional[int] = None, max_val: Optional[int] = None) -> int:
        """
        Validate integer input

        Args:
            value: Value to validate
            min_val: Minimum allowed value
            max_val: Maximum allowed value

        Returns:
            Validated integer

        Raises:
            ValueError: If validation fails
        """
        try:
            int_val = int(value)
        except (ValueError, TypeError):
            raise ValueError(f'Invalid integer value: {value}')

        if min_val is not None and int_val < min_val:
            raise ValueError(f'Value must be at least {min_val}')

        if max_val is not None and int_val > max_val:
            raise ValueError(f'Value must be at most {max_val}')

        return int_val

    @staticmethod
    def validate_string_length(value: str, min_len: int = 0, max_len: int = 1000) -> bool:
        """
        Validate string length

        Args:
            value: String to validate
            min_len: Minimum length
            max_len: Maximum length

        Returns:
            True if valid

        Raises:
            ValueError: If length is invalid
        """
        length = len(value)
        if length < min_len:
            raise ValueError(f'Value must be at least {min_len} characters')
        if length > max_len:
            raise ValueError(f'Value must be at most {max_len} characters')
        return True

    @staticmethod
    def validate_enum(value: str, allowed_values: List[str]) -> str:
        """
        Validate that value is in allowed list

        Args:
            value: Value to validate
            allowed_values: List of allowed values

        Returns:
            Validated value

        Raises:
            ValueError: If value not in allowed list
        """
        if value not in allowed_values:
            raise ValueError(f'Value must be one of: {", ".join(allowed_values)}')
        return value

    @staticmethod
    def validate_file_extension(filename: str, allowed_extensions: List[str]) -> bool:
        """
        Validate file extension

        Args:
            filename: Filename to check
            allowed_extensions: List of allowed extensions (e.g., ['.jpg', '.png'])

        Returns:
            True if valid

        Raises:
            ValueError: If extension not allowed
        """
        if not filename:
            raise ValueError('Filename cannot be empty')

        # Get extension
        ext = filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''
        ext = f'.{ext}' if ext and not ext.startswith('.') else ext

        if ext not in allowed_extensions:
            raise ValueError(f'File extension must be one of: {", ".join(allowed_extensions)}')

        return True


# Export all validators
__all__ = [
    'ValidatedInput',
    'CommentRequest',
    'ThreadRequest',
    'ThreadMessageRequest',
    'TagRequest',
    'SearchRequest',
    'JSONPayloadValidator',
    'InputValidator'
]
