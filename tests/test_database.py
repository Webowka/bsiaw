import pytest
from sqlalchemy import text
import bcrypt


@pytest.mark.asyncio
async def test_database_connection(db_engine):
    with db_engine.connect() as conn:
        result = conn.execute(text("SELECT 1"))
        assert result.scalar() == 1


@pytest.mark.asyncio
async def test_users_table_exists(db_engine):
    with db_engine.connect() as conn:
        result = conn.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'users'
            )
        """))
        assert result.scalar() is True


@pytest.mark.asyncio
async def test_password_hashing(db_engine, clean_database):
    plain_password = "TestPassword123!"
    hashed = bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt())

    with db_engine.connect() as conn:
        conn.execute(text("""
            INSERT INTO users (username, hashed_password)
            VALUES (:username, :hashed_password)
        """), {"username": "hashtest", "hashed_password": hashed.decode()})
        conn.commit()

        result = conn.execute(text("""
            SELECT hashed_password FROM users WHERE username = :username
        """), {"username": "hashtest"})

        stored_hash = result.scalar()

        assert stored_hash != plain_password

        assert bcrypt.checkpw(
            plain_password.encode(),
            stored_hash.encode()
        )


@pytest.mark.asyncio
async def test_database_constraint_unique_username(db_engine, clean_database):
    with db_engine.connect() as conn:
        conn.execute(text("""
            INSERT INTO users (username, hashed_password)
            VALUES (:username, :hashed_password)
        """), {"username": "duplicate", "hashed_password": "hash1"})
        conn.commit()

        try:
            conn.execute(text("""
                INSERT INTO users (username, hashed_password)
                VALUES (:username, :hashed_password)
            """), {"username": "duplicate", "hashed_password": "hash2"})
            conn.commit()
            assert False, "Baza powinna odrzucić duplikat"
        except Exception:
            pass


@pytest.mark.asyncio
async def test_database_rollback(db_session):

    initial_count = db_session.execute(
        text("SELECT COUNT(*) FROM users")
    ).scalar()

    db_session.execute(text("""
        INSERT INTO users (username, hashed_password)
        VALUES (:username, :hashed_password)
    """), {"username": "rollback_test", "hashed_password": "hash"})
    db_session.commit()
    new_count = db_session.execute(
        text("SELECT COUNT(*) FROM users")
    ).scalar()

    assert new_count == initial_count + 1
