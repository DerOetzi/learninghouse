from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from learninghouse.core.errors.models import (
    LearningHouseException,
    LearningHouseSecurityException,
    LearningHouseUnauthorizedException,
    LearningHouseValidationError,
)
from learninghouse.core.logger import logger


async def validation_error_handler(
    _: Request, exc: RequestValidationError
) -> JSONResponse:
    return LearningHouseValidationError(exc).response()


async def learninghouse_exception_handler(_: Request, exc: LearningHouseException) -> JSONResponse:
    response = exc.response()

    if isinstance(
        exc, (LearningHouseSecurityException, LearningHouseUnauthorizedException)
    ):
        logger.warning(exc.error.description)

    return response
