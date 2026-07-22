from enum import Enum


class UserRole(str, Enum):
    ADMIN = "admin"
    PREMIUM = "premium"
    NORMAL = "normal"
