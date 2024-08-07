from os import path
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse

from learninghouse.api.errors import LearningHouseSecurityException
from learninghouse.core.settings import service_settings
from learninghouse.core.logger import logger

settings = service_settings()

router = APIRouter(include_in_schema=False)

UI_DIRECTORY = str(Path(__file__).parent.parent / "ui")


def is_ui_installed() -> bool:
    return path.exists(UI_DIRECTORY)


if is_ui_installed():
    ASSETS_DIRECTORY = f"{UI_DIRECTORY}/assets"

    @router.get("/")
    async def redirect_root():
        return RedirectResponse("/ui")

    @router.get("/ui{ui_path:path}")
    async def get_ui(ui_path: str, request: Request):
        if ui_path and ui_path != "/":
            fullpath = path.normpath(f"{UI_DIRECTORY}{ui_path}")
            if not fullpath.startswith(UI_DIRECTORY):
                raise LearningHouseSecurityException(
                    "Requested file name breaks directory structure"
                )

            if ui_path == "/assets/env.js":
                return PlainTextResponse(get_env(request.base_url))

            if not path.exists(fullpath):
                fullpath = f"{UI_DIRECTORY}/index.html"
        else:
            fullpath = f"{UI_DIRECTORY}/index.html"

        return FileResponse(fullpath)

    def get_env(base_url:str) -> str:
        env_js_content: str = ""

        with open(
            f"{ASSETS_DIRECTORY}/env.template.js", "r", encoding="utf-8"
        ) as template_file:
            env_js_content = template_file.read()
            env_js_content = env_js_content.replace(
                "${LEARNINGHOUSE_API_URL}", f"{base_url}api"
            )

        return env_js_content
