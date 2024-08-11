from learninghouse.core.models import LHEnumModel


class ResourceType(LHEnumModel):
    OBJECT_CACHE = "object_cache"

    def __init__(self, description: str) -> None:
        # pylint: disable=super-init-not-called
        self._description = description

    @property
    def description(self) -> str:
        return self._description


class Resource:
    def __init__(self, resource_type: ResourceType, resource_id: str) -> None:
        self._type = resource_type
        self._id = resource_id

    @property
    def resource_type(self) -> ResourceType:
        return self._type

    @property
    def resource_id(self) -> str:
        return self._id
