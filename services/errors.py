

class ServiceError(RuntimeError):
    """Base class for domain errors surfaced to the user.

    ``message`` stays the positional argument so ``str(exc)`` keeps the Russian
    developer/log text (and existing substring-based tests keep passing). An
    optional ``key`` (+ ``params``) carries an i18n identifier so the Telegram
    layer can render the error in the actor's active locale instead of the
    hardcoded ``message``. When ``key`` is ``None`` the presentation layer falls
    back to ``str(exc)`` — identical to the pre-i18n behaviour.
    """

    def __init__(
        self,
        message: str = "",
        *,
        key: str | None = None,
        params: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.key = key
        self.params = params or {}


class AccessDenied(ServiceError):
    pass


class NotFound(ServiceError):
    pass


class InvalidOperation(ServiceError):
    pass


class InvalidTransition(ServiceError):
    pass
