from verion.modules.identity.domain.exceptions import EmailAlreadyRegistered
from verion.modules.identity.domain.user import Email, User
from verion.modules.identity.ports.password_hasher import PasswordHasherPort
from verion.modules.identity.ports.user_repository import UserRepositoryPort
from verion.shared_kernel.ports import ClockPort, IdGeneratorPort


class RegisterUserUseCase:
    def __init__(
        self,
        users: UserRepositoryPort,
        password_hasher: PasswordHasherPort,
        clock: ClockPort,
        id_generator: IdGeneratorPort,
    ) -> None:
        self._users = users
        self._password_hasher = password_hasher
        self._clock = clock
        self._id_generator = id_generator

    def execute(self, email: str, plaintext_password: str) -> User:
        validated_email = Email(email)

        if self._users.get_by_email(str(validated_email)) is not None:
            raise EmailAlreadyRegistered(f"'{validated_email}' is already registered")

        user = User(
            id=self._id_generator.new_id(),
            email=validated_email,
            hashed_password=self._password_hasher.hash(plaintext_password),
            created_at=self._clock.now(),
        )
        self._users.add(user)
        return user
