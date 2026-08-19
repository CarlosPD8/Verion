import httpx2
import pytest_asyncio

from verion.modules.identity.adapters.outbound.db.repository import PostgresUserRepository
from verion.platform.app import app


@pytest_asyncio.fixture
async def client():
    transport = httpx2.ASGITransport(app=app)
    async with httpx2.AsyncClient(transport=transport, base_url="http://test") as async_client:
        yield async_client


async def test_register_returns_201_with_the_authenticated_user(client):
    response = await client.post(
        "/auth/register", json={"email": "dev@example.com", "password": "correct horse battery"}
    )

    assert response.status_code == 201
    body = response.json()
    assert body == {"id": body["id"], "email": "dev@example.com"}


async def test_register_duplicate_email_returns_409(client):
    payload = {"email": "dev@example.com", "password": "correct horse battery"}
    await client.post("/auth/register", json=payload)

    response = await client.post("/auth/register", json=payload)

    assert response.status_code == 409


async def test_register_malformed_email_returns_422(client):
    response = await client.post(
        "/auth/register", json={"email": "not-an-email", "password": "correct horse battery"}
    )

    assert response.status_code == 422


async def test_login_success_returns_token_and_expiry(client):
    payload = {"email": "dev@example.com", "password": "correct horse battery"}
    await client.post("/auth/register", json=payload)

    response = await client.post("/auth/login", json=payload)

    assert response.status_code == 200
    body = response.json()
    assert body["access_token"]
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 30 * 60
    assert body["user"] == {"id": body["user"]["id"], "email": "dev@example.com"}


async def test_login_wrong_password_returns_401(client):
    payload = {"email": "dev@example.com", "password": "correct horse battery"}
    await client.post("/auth/register", json=payload)

    response = await client.post(
        "/auth/login", json={"email": "dev@example.com", "password": "wrong password"}
    )

    assert response.status_code == 401


async def test_login_unknown_email_returns_401_identical_to_wrong_password(client):
    registered = await client.post(
        "/auth/register", json={"email": "dev@example.com", "password": "correct horse battery"}
    )
    assert registered.status_code == 201

    wrong_password = await client.post(
        "/auth/login", json={"email": "dev@example.com", "password": "wrong password"}
    )
    unknown_email = await client.post(
        "/auth/login", json={"email": "ghost@example.com", "password": "whatever"}
    )

    assert unknown_email.status_code == wrong_password.status_code == 401
    assert unknown_email.json() == wrong_password.json()


async def test_login_response_never_leaks_the_password_hash(client, db_session):
    payload = {"email": "dev@example.com", "password": "correct horse battery"}
    await client.post("/auth/register", json=payload)

    response = await client.post("/auth/login", json=payload)

    raw_body = response.text
    assert "hashed_password" not in raw_body

    repository = PostgresUserRepository(db_session)
    stored_user = await repository.get_by_email("dev@example.com")
    assert stored_user.hashed_password not in raw_body
