import logging

from learninghouse.core.models import LHEnumModel


class LoggingLevelEnum(LHEnumModel):
    DEBUG = "DEBUG", logging.DEBUG
    INFO = "INFO", logging.INFO
    WARNING = "WARNING", logging.WARNING
    ERROR = "ERROR", logging.ERROR
    CRITICAL = "CRITICAL", logging.CRITICAL

    def __init__(self, description: str, level: int):
        # pylint: disable=super-init-not-called
        self._description: str = description
        self._level: int = level

    @property
    def description(self) -> str:
        return self._description

    @property
    def level(self) -> int:
        return self._level
