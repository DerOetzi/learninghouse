import time

from fastapi import Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from learninghouse.core.auth import INITIAL_PASSWORD_WARNING, auth_service_cached
from learninghouse.core.errors.models import (
    LearningHouseException,
    LearningHouseUnauthorizedException,
)
from learninghouse.core.logger import logger
from learninghouse.core.settings import service_settings

authservice = auth_service_cached()

settings = service_settings()

UNKNOWN_EXCEPTION_MESSAGE = """
An unknown error occured which is not handled by the service yet:
{exception}

Please open an issue at GitHub:
https://github.com/LearningHouseService/learninghouse/issues
"""


class EnforceInitialPasswordChange(BaseHTTPMiddleware):
    # pylint: disable=too-few-public-methods
    ALLOWED_ENDPOINTS = [
        "/api/auth/token",
        "/api/auth/password",
        "/api/mode",
        "/api/versions",
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.endpoints = self.ALLOWED_ENDPOINTS
        self.endpoints.append(settings.openapi_file)
        if settings.docs_url:
            self.endpoints.append(settings.docs_url)

    async def dispatch(self, request, call_next) -> JSONResponse | Response:
        endpoint = request.url.path
        if authservice.is_initial_admin_password and not (
            endpoint in self.endpoints
            or endpoint.startswith("/static/")
            or endpoint.startswith("/ui")
        ):
            logger.warning(INITIAL_PASSWORD_WARNING)
            return LearningHouseUnauthorizedException(
                "Change initial password."
            ).response()

        return await call_next(request)


class CatchAllException(BaseHTTPMiddleware):
    # pylint: disable=too-few-public-methods
    async def dispatch(self, request, call_next) -> Response | JSONResponse:
        try:
            return await call_next(request)
        except Exception as exc:  # pylint: disable=broad-except
            logger.error(UNKNOWN_EXCEPTION_MESSAGE.format(exception=exc))
            logger.exception(exc)
            return LearningHouseException().response()


class CustomHeader(BaseHTTPMiddleware):
    # pylint: disable=too-few-public-methods
    async def dispatch(self, request, call_next) -> Response:
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(process_time)
        return response
