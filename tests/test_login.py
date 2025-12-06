import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient, clean_database):
    user_data = {
        "username": "loginuser",
        "password": "LoginPass123!"
    }
    await client.post("/register", data=user_data)

    response = await client.post("/login", data=user_data)

    assert response.status_code == 302
    assert "/main" in response.headers.get("location", "") or \
           "main" in response.text.lower()


@pytest.mark.asyncio
async def test_login_wrong_password(client: AsyncClient, clean_database):
    user_data = {
        "username": "testuser",
        "password": "CorrectPass123!"
    }
    await client.post("/register", data=user_data)

    response = await client.post("/login", data={
        "username": "testuser",
        "password": "WrongPass123!"
    })

    assert response.status_code in [400, 401]


@pytest.mark.asyncio
async def test_login_nonexistent_user(client: AsyncClient, clean_database):
    response = await client.post("/login", data={
        "username": "nonexistent",
        "password": "SomePass123!"
    })

    assert response.status_code in [400, 401, 404]


@pytest.mark.asyncio
async def test_login_empty_credentials(client: AsyncClient, clean_database):
    response = await client.post("/login", data={
        "username": "",
        "password": ""
    })

    assert response.status_code in [400, 422]


@pytest.mark.asyncio
async def test_login_page_loads(client: AsyncClient):
    response = await client.get("/login")

    assert response.status_code == 200
    assert "login" in response.text.lower() or "logowanie" in response.text.lower()


@pytest.mark.asyncio
async def test_login_case_sensitivity(client: AsyncClient, clean_database):
    user_data = {
        "username": "TestUser",
        "password": "Pass123!"
    }
    await client.post("/register", data=user_data)

    response = await client.post("/login", data={
        "username": "testuser",  # małe litery
        "password": "Pass123!"
    })

    assert response.status_code in [302, 400, 401]


@pytest.mark.asyncio
async def test_login_session_persistence(
    client: AsyncClient,
    clean_database
):
    user_data = {
        "username": "sessionuser",
        "password": "SessionPass123!"
    }
    await client.post("/register", data=user_data)
    login_response = await client.post("/login", data=user_data)
    assert "set-cookie" in login_response.headers or \
           len(login_response.cookies) > 0


@pytest.mark.asyncio
async def test_login_redirect_after_registration(
    client: AsyncClient,
    clean_database
):
    user_data = {
        "username": "redirectuser",
        "password": "RedirectPass123!"
    }

    register_response = await client.post("/register", data=user_data)
    assert register_response.status_code == 302
    assert "/login" in register_response.headers.get("location", "")
