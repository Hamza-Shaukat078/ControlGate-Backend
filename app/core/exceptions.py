"""
Custom exceptions for the application.
Provides consistent error handling across the API.
"""

from fastapi import HTTPException, status


class VulcanException(Exception):
    """Base exception for all Vulcan custom exceptions."""
    pass


class AuthenticationException(VulcanException):
    """Raised when authentication fails."""
    def to_http_exception(self):
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(self)
        )


class AuthorizationException(VulcanException):
    """Raised when user lacks permissions."""
    def to_http_exception(self):
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(self)
        )


class ResourceNotFoundException(VulcanException):
    """Raised when a resource is not found."""
    def to_http_exception(self):
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(self)
        )


class ValidationException(VulcanException):
    """Raised when validation fails."""
    def to_http_exception(self):
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(self)
        )


class ConflictException(VulcanException):
    """Raised when resource already exists."""
    def to_http_exception(self):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(self)
        )


class RateLimitException(VulcanException):
    """Raised when rate limit is exceeded."""
    def to_http_exception(self):
        return HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(self)
        )


class InternalServerException(VulcanException):
    """Raised when internal error occurs."""
    def to_http_exception(self):
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(self)
        )
