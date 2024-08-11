from fastapi import APIRouter
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse

from learninghouse import versions
from learninghouse.core.auth import auth_router, auth_service_cached
from learninghouse.core.brain import brain_router
from learninghouse.core.errors.models import LearningHouseSecurityException
from learninghouse.core.models import LearningHouseVersions
from learninghouse.core.sensor import sensor_router
from learninghouse.core.settings import service_settings

authservice = auth_service_cached()

settings = service_settings()

api = APIRouter(
    prefix="/api",
    responses={
        LearningHouseSecurityException.STATUS_CODE: LearningHouseSecurityException.api_description()
    },
)

api.include_router(brain_router)
api.include_router(sensor_router)

api.include_router(auth_router)


@api.get("/mode", tags=["service"])
def get_mode() -> str:
    mode = settings.environment
    if authservice.is_initial_admin_password:
        mode = "initial"

    return mode


@api.get(
    "/versions",
    summary="Get versions",
    description="Get versions of the service and the used libraries",
    tags=["service"],
    responses={200: {"description": "Successfully retrieved versions"}},
)
def get_versions() -> LearningHouseVersions:
    return versions


docs_router = APIRouter(include_in_schema=False)


@docs_router.get(settings.docs_url)
async def custom_swagger_ui_html() -> HTMLResponse:
    response = get_swagger_ui_html(
        openapi_url=settings.openapi_file,
        title=settings.title + " - Swagger UI",
        oauth2_redirect_url=None,
        swagger_js_url="/static/docs/swagger-ui-bundle.js",
        swagger_css_url="/static/docs/swagger-ui.css",
        swagger_favicon_url="/static/favicon.ico",
    )

    return response
