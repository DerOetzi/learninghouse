from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from learninghouse import versions
from learninghouse.core.api import api, docs_router
from learninghouse.core.auth import INITIAL_PASSWORD_WARNING, auth_service_cached
from learninghouse.core.errors import (
    learninghouse_exception_handler,
    validation_error_handler,
)
from learninghouse.core.errors.models import LearningHouseException
from learninghouse.core.logger import initialize_logging, logger
from learninghouse.core.middleware import (
    CatchAllException,
    CustomHeader,
    EnforceInitialPasswordChange,
)
from learninghouse.core.settings import service_settings
from learninghouse.core.ui import is_ui_installed, ui_router
from learninghouse.core.ui.models import UI_DIRECTORY

authservice = auth_service_cached()

APP_REFERENCE = "learninghouse.service:app"

STATIC_DIRECTORY = str(Path(__file__).parent / "static")


def get_application() -> FastAPI:
    settings = service_settings()

    initialize_logging(settings.logging_level)

    application = FastAPI(**settings.fastapi_kwargs)
    application.include_router(api)

    if settings.docs_url:
        application.include_router(docs_router)

    application.include_router(ui_router)

    application.add_exception_handler(RequestValidationError, validation_error_handler)
    application.add_exception_handler(
        LearningHouseException, learninghouse_exception_handler
    )

    application.add_middleware(uvicorn.middleware.proxy_headers.ProxyHeadersMiddleware)

    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    if authservice.is_initial_admin_password:
        application.add_middleware(EnforceInitialPasswordChange)

    application.add_middleware(CatchAllException)
    application.add_middleware(CustomHeader)

    application.mount("/static", StaticFiles(directory=STATIC_DIRECTORY), name="static")

    return application


app = get_application()


def run() -> None:
    settings = service_settings()

    logger.info(f"Running {settings.title} {versions.service}")
    logger.info(versions.libraries_versions)
    logger.info(f"Running in {settings.environment} mode")
    logger.info(f"Listening on {settings.host}:{settings.port}")
    logger.info(f"Configuration directory {settings.brains_directory}")

    if settings.workers > 1:
        if settings.reload:
            logger.warning(
                f"Reloading active. Workers {settings.workers} setting will be ignored."
            )
        else:
            logger.info(f"Running with {settings.workers} workers")

    logger.info(f"URL to OpenAPI file {settings.openapi_url}")

    if settings.environment == "production":
        if settings.debug:
            logger.warning(
                "Debugging active. Recommendation: Do not use in production mode!"
            )

        if settings.reload:
            logger.warning(
                "Reloading active. Recommendation: Do not use in production mode!"
            )

    if settings.documentation_url is not None:
        logger.info(f"See interactive documentation {settings.documentation_url}")

    if is_ui_installed():
        logger.info(f"UI is reachable under {settings.base_url_calculated}/ui")
    else:
        logger.warning(f"UI is not installed under {UI_DIRECTORY}")

    if authservice.is_initial_admin_password:
        logger.warning(INITIAL_PASSWORD_WARNING)

    uvicorn.run(app=APP_REFERENCE, log_config=None, **settings.uvicorn_kwargs)
