from verion.modules.identity.adapters.outbound.security.argon2_hasher import Argon2PasswordHasher


def test_hash_is_salted():
    hasher = Argon2PasswordHasher()

    first = hasher.hash("correct horse battery staple")
    second = hasher.hash("correct horse battery staple")

    assert first != second


def test_verify_succeeds_for_the_correct_password():
    hasher = Argon2PasswordHasher()
    hashed = hasher.hash("correct horse battery staple")

    assert hasher.verify("correct horse battery staple", hashed) is True


def test_verify_fails_for_the_wrong_password():
    hasher = Argon2PasswordHasher()
    hashed = hasher.hash("correct horse battery staple")

    assert hasher.verify("wrong password", hashed) is False
