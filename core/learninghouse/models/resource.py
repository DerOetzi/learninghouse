from __future__ import annotations

from learninghouse.models.base import LHBaseModel, uuid_field
from learninghouse.models.capability import Capability


class Person(LHBaseModel):
    uuid: str = uuid_field()
    name: str
    resources: list[PersonResource] = []
    nickname: str | None = None
    username: str | None = None
    password: str | None = None

    def add_resource(self, resource: PersonResource) -> None:
        self.resources.append(resource)

    def remove_resource(self, resource: PersonResource) -> None:
        self.resources.remove(resource)


class PersonResource(LHBaseModel):
    uuid: str = uuid_field()
    capabilities: list[Capability]


class WeatherResource(LHBaseModel):
    uuid: str = uuid_field()
    capabilities: list[Capability]


class Area (LHBaseModel):
    uuid: str = uuid_field()
    name: str


class Location(LHBaseModel):
    uuid: str = uuid_field()
    name: str
    area: Area


class DeviceResource(LHBaseModel):
    uuid: str = uuid_field()
    capabilities: list[Capability]
    location: Location


class EnergyManagementResource(LHBaseModel):
    uuid: str
    capabilities: list[Capability]
    location: Location | None
