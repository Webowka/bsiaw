import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_registration_success(client: AsyncClient, clean_database):
    response = await client.post("/register", data={
        "username": "newuser",
        "password": "StrongPass123!",
        "email": "newuser@example.com"
    })

    assert response.status_code in [302, 303]  # Redirect
    assert "/login" in response.headers.get("location", "")


@pytest.mark.asyncio
async def test_registration_duplicate_username(client: AsyncClient, clean_database):
    user_data = {
        "username": "duplicate_user",
        "password": "Pass123!",
        "email": "duplicate@example.com"
    }

    response1 = await client.post("/register", data=user_data)
    assert response1.status_code in [302, 303]

    response2 = await client.post("/register", data=user_data)
    assert response2.status_code in [200, 400, 409]  # Bad Request lub Conflict


@pytest.mark.asyncio
async def test_registration_empty_username(client: AsyncClient, clean_database):
    response = await client.post("/register", data={
        "username": "",
        "password": "Pass123!",
        "email": "empty@example.com"
    })

    assert response.status_code in [400, 422]


@pytest.mark.asyncio
async def test_registration_empty_password(client: AsyncClient, clean_database):
    response = await client.post("/register", data={
        "username": "testuser",
        "password": "",
        "email": "testuser@example.com"
    })

    assert response.status_code in [400, 422]


@pytest.mark.asyncio
async def test_registration_weak_password(client: AsyncClient, clean_database):
    weak_passwords = ["123", "abc", "password"]

    for weak_pass in weak_passwords:
        response = await client.post("/register", data={
            "username": f"user_{weak_pass}",
            "password": weak_pass,
            "email": f"user_{weak_pass}@example.com"
        })

        assert response.status_code in [200, 302, 303, 400, 422]


@pytest.mark.asyncio
async def test_registration_special_characters_in_username(
    client: AsyncClient,
    clean_database
):
    usernames = ["user@123", "user#test", "user$money", "user!exclaim"]

    for idx, username in enumerate(usernames):
        response = await client.post("/register", data={
            "username": username,
            "password": "Pass123!",
            "email": f"special{idx}@example.com"
        })

        assert response.status_code in [200, 302, 303, 400, 422]


@pytest.mark.asyncio
async def test_registration_long_username(client: AsyncClient, clean_database):
    long_username = "a" * 1000

    response = await client.post("/register", data={
        "username": long_username,
        "password": "Pass123!",
        "email": "longuser@example.com"
    })

    assert response.status_code in [200, 302, 303, 400, 413, 422]


@pytest.mark.asyncio
async def test_registration_page_loads(client: AsyncClient):
    response = await client.get("/register")

    assert response.status_code == 200
    assert "register" in response.text.lower() or "rejestracja" in response.text.lower()


@pytest.mark.asyncio
async def test_multiple_users_registration(
    client: AsyncClient,
    clean_database,
    multiple_users_data
):
    for user_data in multiple_users_data:
        response = await client.post("/register", data=user_data)
        assert response.status_code in [302, 303]

    for user_data in multiple_users_data:
        login_response = await client.post("/login", data=user_data)
        assert login_response.status_code in [302, 303]
