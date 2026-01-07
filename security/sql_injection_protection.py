"""
SQL Injection Protection Module (Lab 7 - Task 1.b)

This module documents and enforces SQL injection protection practices.
The application uses SQLAlchemy ORM which provides built-in protection through
parameterized queries.

Key Protection Mechanisms:
1. SQLAlchemy ORM - All database queries use ORM methods
2. Parameterized Queries - No string concatenation in queries
3. Input Validation - All inputs validated before database operations
4. Type Checking - SQLAlchemy enforces type safety
"""

from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Any, List, Optional
import logging

logger = logging.getLogger('security.sql_injection')


class SafeQueryExecutor:
    """
    Safe query executor that enforces parameterized queries
    and prevents SQL injection attacks.
    """

    @staticmethod
    def execute_raw_query(db: Session, query: str, params: dict) -> List[Any]:
        """
        Execute raw SQL query with parameterized values.

        IMPORTANT: This method should only be used when ORM is not sufficient.
        Always prefer ORM methods over raw queries.

        Args:
            db: Database session
            query: SQL query with named parameters (use :param_name)
            params: Dictionary of parameter values

        Returns:
            Query results

        Example:
            # CORRECT - Parameterized query
            query = "SELECT * FROM users WHERE username = :username"
            params = {"username": user_input}
            results = SafeQueryExecutor.execute_raw_query(db, query, params)

            # WRONG - String concatenation (NEVER DO THIS!)
            # query = f"SELECT * FROM users WHERE username = '{user_input}'"
            # This is vulnerable to SQL injection!

        Security Notes:
            - Never use f-strings or string concatenation for SQL queries
            - Never trust user input directly in queries
            - Always use named parameters (:param_name)
            - Always pass parameters as a separate dictionary
        """
        try:
            # Log the query (but not the parameters for security)
            logger.info(f"Executing parameterized query: {query[:100]}...")

            # Execute with bound parameters (safe from SQL injection)
            result = db.execute(text(query), params)
            return result.fetchall()
        except Exception as e:
            logger.error(f"Query execution error: {str(e)}")
            raise

    @staticmethod
    def validate_table_name(table_name: str) -> str:
        """
        Validate table name to prevent SQL injection in dynamic table names.

        Args:
            table_name: Table name to validate

        Returns:
            Validated table name

        Raises:
            ValueError: If table name is invalid

        Security Notes:
            Table names cannot be parameterized in SQL, so strict validation
            is required when table names are dynamic.
        """
        # Only allow alphanumeric and underscores
        if not table_name.isidentifier():
            raise ValueError("Invalid table name format")

        # Whitelist of allowed table names
        allowed_tables = [
            'users', 'posts', 'comments', 'threads', 'thread_messages',
            'tags', 'post_tags', 'thread_tags', 'post_reactions',
            'comment_reactions', 'post_attachments', 'thread_attachments',
            'content_blocks', 'rate_limit_entries', 'login_attempts',
            'password_history'
        ]

        if table_name not in allowed_tables:
            raise ValueError(f"Table name not in whitelist: {table_name}")

        return table_name

    @staticmethod
    def validate_column_name(column_name: str) -> str:
        """
        Validate column name to prevent SQL injection in dynamic column names.

        Args:
            column_name: Column name to validate

        Returns:
            Validated column name

        Raises:
            ValueError: If column name is invalid
        """
        # Only allow alphanumeric and underscores
        if not column_name.isidentifier():
            raise ValueError("Invalid column name format")

        # Limit length
        if len(column_name) > 64:
            raise ValueError("Column name too long")

        return column_name


class ORMBestPractices:
    """
    Documentation and examples of safe ORM usage patterns.
    """

    @staticmethod
    def safe_filter_example():
        """
        Example of safe filtering using SQLAlchemy ORM.

        ✓ SAFE EXAMPLES (Using ORM):

        # Filter by exact match
        user = db.query(User).filter(User.username == username).first()

        # Filter with multiple conditions
        posts = db.query(Post).filter(
            Post.user_id == user_id,
            Post.created_at >= start_date
        ).all()

        # Filter with LIKE (still safe with ORM)
        posts = db.query(Post).filter(
            Post.title.like(f"%{search_term}%")
        ).all()

        # Filter with IN clause
        users = db.query(User).filter(
            User.id.in_(user_ids)
        ).all()

        ✗ UNSAFE EXAMPLES (Never do this!):

        # String concatenation - VULNERABLE!
        query = f"SELECT * FROM users WHERE username = '{username}'"
        db.execute(query)

        # String formatting - VULNERABLE!
        query = "SELECT * FROM users WHERE id = %d" % user_id
        db.execute(query)
        """
        pass

    @staticmethod
    def safe_insert_example():
        """
        Example of safe data insertion using SQLAlchemy ORM.

        ✓ SAFE EXAMPLE (Using ORM):

        # Create new user with ORM
        new_user = User(
            username=username,
            email=email,
            hashed_password=hashed_password
        )
        db.add(new_user)
        db.commit()

        # Create with relationship
        new_post = Post(
            title=title,
            content=content,
            user_id=user.id
        )
        db.add(new_post)
        db.commit()
        """
        pass

    @staticmethod
    def safe_update_example():
        """
        Example of safe data updates using SQLAlchemy ORM.

        ✓ SAFE EXAMPLE (Using ORM):

        # Update user
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            user.email = new_email
            db.commit()

        # Update multiple records
        db.query(Post).filter(Post.user_id == user_id).update({
            "updated_at": datetime.utcnow()
        })
        db.commit()
        """
        pass

    @staticmethod
    def safe_delete_example():
        """
        Example of safe data deletion using SQLAlchemy ORM.

        ✓ SAFE EXAMPLE (Using ORM):

        # Delete single record
        post = db.query(Post).filter(Post.id == post_id).first()
        if post:
            db.delete(post)
            db.commit()

        # Delete multiple records
        db.query(Comment).filter(Comment.post_id == post_id).delete()
        db.commit()
        """
        pass


class SQLInjectionAuditor:
    """
    Utility to audit code for potential SQL injection vulnerabilities.
    """

    # Patterns that indicate potential SQL injection risks
    DANGEROUS_PATTERNS = [
        r'f".*SELECT.*{',  # f-string with SQL
        r'f\'.*SELECT.*{',  # f-string with SQL
        r'\.format\(.*SELECT',  # .format() with SQL
        r'%.*SELECT',  # % formatting with SQL
        r'\+.*SELECT',  # String concatenation with SQL
    ]

    @staticmethod
    def audit_query_string(query_string: str) -> bool:
        """
        Audit a query string for potential SQL injection risks.

        Args:
            query_string: SQL query string to audit

        Returns:
            True if query appears safe, False if suspicious patterns found

        Note:
            This is a basic audit tool. Always use ORM methods when possible.
        """
        import re

        for pattern in SQLInjectionAuditor.DANGEROUS_PATTERNS:
            if re.search(pattern, query_string, re.IGNORECASE):
                logger.warning(f"Suspicious SQL pattern detected: {pattern}")
                return False

        return True


# Protection Summary Documentation
"""
=============================================================================
SQL INJECTION PROTECTION SUMMARY (Lab 7 - Task 1.b)
=============================================================================

This application is protected against SQL Injection through multiple layers:

1. SQLAlchemy ORM (Primary Protection)
   - All database operations use SQLAlchemy ORM
   - ORM automatically generates parameterized queries
   - No direct SQL string concatenation in application code

2. Parameterized Queries
   - All values passed as parameters, not concatenated into SQL strings
   - SQLAlchemy uses bound parameters which are properly escaped
   - Database driver handles parameter binding securely

3. Input Validation (Defense in Depth)
   - Pydantic models validate all inputs before database operations
   - Type checking ensures correct data types
   - Length and format validation prevents malicious inputs

4. Type Safety
   - SQLAlchemy column types enforce type constraints
   - Python type hints provide additional safety
   - Database schema enforces data integrity

Examples of Protection:

✓ PROTECTED - ORM Usage (Current Implementation):
```python
# Safe: ORM filters with parameters
user = db.query(User).filter(User.username == username).first()

# Safe: ORM with multiple conditions
posts = db.query(Post).filter(
    Post.title.like(f"%{search_term}%"),
    Post.user_id == user_id
).all()
```

✗ VULNERABLE - Direct SQL (NOT USED in this app):
```python
# Vulnerable: String concatenation
query = f"SELECT * FROM users WHERE username = '{username}'"
db.execute(query)

# Vulnerable: % formatting
query = "SELECT * FROM posts WHERE id = %d" % post_id
db.execute(query)
```

Database Access Patterns Verified:
- User queries: ✓ Using ORM filter()
- Post queries: ✓ Using ORM filter()
- Comment queries: ✓ Using ORM filter()
- Thread queries: ✓ Using ORM filter()
- Joins: ✓ Using ORM relationships
- Inserts: ✓ Using ORM add()
- Updates: ✓ Using ORM attribute assignment
- Deletes: ✓ Using ORM delete()

Additional Security Measures:
- Connection pooling with timeout (prevents resource exhaustion)
- Database user has minimal required permissions
- Error messages don't expose SQL structure
- Query logging (for security monitoring)

=============================================================================
"""

__all__ = [
    'SafeQueryExecutor',
    'ORMBestPractices',
    'SQLInjectionAuditor'
]
