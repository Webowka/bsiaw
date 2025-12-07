import pytest
import asyncio
from httpx import AsyncClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import os
import time

TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql://testuser:testpass@localhost:5434/testdb"
)

BASE_URL = os.getenv("TEST_BASE_URL", "http://localhost:8001")


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def db_engine():
    engine = create_engine(TEST_DATABASE_URL)
    yield engine
    engine.dispose()


@pytest.fixture(scope="function")
def db_session(db_engine):
    connection = db_engine.connect()
    transaction = connection.begin()
    Session = sessionmaker(bind=connection)
    session = Session()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture(scope="function")
async def clean_database(db_engine):
    with db_engine.connect() as conn:
        conn.execute(text("TRUNCATE TABLE users RESTART IDENTITY CASCADE"))
        conn.commit()
    yield


@pytest.fixture
async def client():
    async with AsyncClient(base_url=BASE_URL, follow_redirects=False) as ac:
        yield ac


@pytest.fixture(scope="function")
async def authenticated_client(client, clean_database):
    register_data = {
        "username": "testuser",
        "password": "TestPass123!"
    }
    await client.post("/register", data=register_data)

    login_response = await client.post("/login", data=register_data)

    return client


@pytest.fixture
def sample_user_data():
    return {
        "username": "john_doe",
        "password": "SecurePass123!"
    }


@pytest.fixture
def multiple_users_data():
    from faker import Faker
    fake = Faker()

    users = []
    for _ in range(5):
        users.append({
            "username": fake.user_name(),
            "password": fake.password(length=12, special_chars=True)
        })
    return users


def wait_for_app_ready(max_attempts=30, delay=1):
    import httpx

    for attempt in range(max_attempts):
        try:
            response = httpx.get(f"{BASE_URL}/", timeout=2)
            if response.status_code == 200:
                return True
        except:
            pass
        time.sleep(delay)

    raise RuntimeError("Aplikacja nie odpowiada!")


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    print("\nPrzygotowywanie środowiska testowego...")
    wait_for_app_ready()
    print("Aplikacja gotowa do testów!")
    yield
    print("\nSprzątamy, to może chwilę potrwac...")
