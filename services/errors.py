from __future__ import annotations


class ServiceError(RuntimeError):
    pass


class AccessDenied(ServiceError):
    pass


class NotFound(ServiceError):
    pass


class InvalidOperation(ServiceError):
    pass
