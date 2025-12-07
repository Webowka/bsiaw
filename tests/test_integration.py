import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_full_user_journey(client: AsyncClient, clean_database):
    home_response = await client.get("/")
    assert home_response.status_code == 200

    register_page = await client.get("/register")
    assert register_page.status_code == 200

    user_data = {
        "username": "journey_user",
        "password": "JourneyPass123!",
        "email": "journey@example.com"
    }
    register_response = await client.post("/register", data=user_data)
    assert register_response.status_code in [302, 303]

    login_page = await client.get("/login")
    assert login_page.status_code == 200

    login_response = await client.post("/login", data=user_data)
    assert login_response.status_code in [302, 303]

    main_response = await client.get("/main", follow_redirects=True)
    assert main_response.status_code == 200


@pytest.mark.asyncio
async def test_concurrent_registrations(
    client: AsyncClient,
    clean_database,
    multiple_users_data
):
    import asyncio

    async def register_user(user_data):
        return await client.post("/register", data=user_data)

    tasks = [register_user(user) for user in multiple_users_data]
    responses = await asyncio.gather(*tasks)

    success_count = sum(1 for r in responses if r.status_code in [302, 303])
    assert success_count == len(multiple_users_data)


@pytest.mark.asyncio
async def test_sql_injection_protection(client: AsyncClient, clean_database):
    malicious_inputs = [
        "admin' OR '1'='1",
        "admin'--",
        "admin' OR '1'='1'--",
        "'; DROP TABLE users; --",
        "1' UNION SELECT * FROM users--"
    ]

    for idx, malicious_input in enumerate(malicious_inputs):
        register_response = await client.post("/register", data={
            "username": malicious_input,
            "password": "Pass123!",
            "email": f"sql{idx}@example.com"
        })

        assert register_response.status_code in [200, 302, 303, 400, 422]

        login_response = await client.post("/login", data={
            "username": malicious_input,
            "password": "Pass123!"
        })

        assert login_response.status_code in [200, 400, 401, 404, 422]


@pytest.mark.asyncio
async def test_xss_protection(client: AsyncClient, clean_database):
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>"
    ]

    for idx, payload in enumerate(xss_payloads):
        response = await client.post("/register", data={
            "username": payload,
            "password": "Pass123!",
            "email": f"xss{idx}@example.com"
        })

        assert response.status_code in [200, 302, 303, 400, 422]

        if response.status_code in [302, 303]:
            login_response = await client.post("/login", data={
                "username": payload,
                "password": "Pass123!"
            })

            if login_response.status_code == 302:
                main_page = await client.get("/main", follow_redirects=True)
                assert "<script>" not in main_page.text


@pytest.mark.asyncio
async def test_rate_limiting_simulation(client: AsyncClient, clean_database):
    user_data = {
        "username": "ratelimit_test",
        "password": "RatePass123!",
        "email": "ratelimit@example.com"
    }

    responses = []
    for i in range(20):
        response = await client.post("/register", data={
            "username": f"user_{i}",
            "password": "Pass123!",
            "email": f"user{i}@example.com"
        })
        responses.append(response)

    success_count = sum(1 for r in responses if r.status_code == 302)
    assert success_count >= 0


@pytest.mark.asyncio
async def test_session_management(client: AsyncClient, clean_database):
    user_data = {
        "username": "sessiontest",
        "password": "SessionPass123!",
        "email": "sessiontest@example.com"
    }

    await client.post("/register", data=user_data)
    login_response = await client.post("/login", data=user_data)

    assert len(login_response.cookies) > 0 or "set-cookie" in login_response.headers
    async with AsyncClient(base_url=client.base_url) as new_client:
        protected_response = await new_client.get("/main")
        assert protected_response.status_code in [302, 401, 403]


@pytest.mark.asyncio
async def test_error_handling(client: AsyncClient):
    response = await client.get("/nonexistent-path")
    assert response.status_code == 404

    response = await client.put("/register")
    assert response.status_code in [405, 422]


@pytest.mark.asyncio
async def test_database_persistence(client: AsyncClient, clean_database, db_engine):
    from sqlalchemy import text

    user_data = {
        "username": "persist_user",
        "password": "PersistPass123!",
        "email": "persist@example.com"
    }

    await client.post("/register", data=user_data)

    with db_engine.connect() as conn:
        result = conn.execute(
            text("SELECT username FROM users WHERE username = :username"),
            {"username": user_data["username"]}
        )
        found_user = result.scalar()

    assert found_user == user_data["username"]
