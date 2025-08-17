from .login import router as login_router
from .chat_routes import router as chat_router
from .admin_routes import router as admin_router
from .register_routes import router as register_router
from .otp_routes import router as otp_router

__all__ = [
    "login_router",
    "chat_router",
    "admin_router",
    "register_router",
    "otp_router",
]
