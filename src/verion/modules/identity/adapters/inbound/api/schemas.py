from pydantic import BaseModel

# Domain email-format validation happens in the domain's Email value object
# (raises InvalidEmail -> 422), not here — no separate Pydantic-level email
# validator, to avoid two sources of truth for "what's a valid email."


class RegisterRequest(BaseModel):
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class AuthenticatedUser(BaseModel):
    """What every response actually serializes — never the domain User,
    which carries hashed_password. No path by which a hash can leak here."""

    id: str
    email: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: AuthenticatedUser
