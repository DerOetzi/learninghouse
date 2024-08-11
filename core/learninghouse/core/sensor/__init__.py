from fastapi import APIRouter, Body, Depends, status

from learninghouse.core.auth import auth_service_cached
from learninghouse.core.sensor.errors import NoSensor, SensorExists
from learninghouse.core.sensor.models import (
    Sensor,
    SensorDeleteResult,
    Sensors,
    SensorType,
)


class SensorConfigurationService:
    @staticmethod
    def list_all() -> Sensors:
        return Sensors.load_config()

    @staticmethod
    def get(name: str) -> Sensor:
        sensors = Sensors.load_config()

        for sensor in sensors:
            if sensor.name == name:
                return sensor

        raise NoSensor(name)

    @staticmethod
    def create(name: str, typed: SensorType) -> Sensor:
        sensors = Sensors.load_config()

        for sensor in sensors:
            if sensor.name == name:
                raise SensorExists(name)

        new_sensor = Sensor(name=name, typed=typed)
        sensors.append(new_sensor)
        sensors.write_config()

        return new_sensor

    @staticmethod
    def update(
        name: str, typed: SensorType, cycles: int, calc_sun_position: bool
    ) -> Sensor:
        sensors = Sensors.load_config()
        for sensor in sensors:
            if sensor.name == name:
                sensor.typed = typed
                sensor.cycles = cycles
                sensor.calc_sun_position = calc_sun_position
                sensors.write_config()
                return sensor

        raise NoSensor(name)

    @staticmethod
    def delete(name: str) -> None:
        sensors = Sensors.load_config()

        for sensor in sensors:
            if sensor.name == name:
                sensors.remove(sensor)
                sensors.write_config()
                return SensorDeleteResult(name=name)

        raise NoSensor(name)


authservice = auth_service_cached()

sensor_router = APIRouter(prefix="/sensor", tags=["sensor"])

router_usage = APIRouter(dependencies=[Depends(authservice.protect_user)])

router_admin = APIRouter(dependencies=[Depends(authservice.protect_admin)])


@router_usage.get(
    "s/configuration",
    response_model=Sensors,
    summary="Get all sensors configuration",
    description="Get all configured sensors.",
    responses={status.HTTP_200_OK: {"description": "All configured sensors"}},
)
async def get_sensors_configuration() -> Sensors:
    return SensorConfigurationService.list_all()


@router_admin.get(
    "/{name}/configuration",
    response_model=Sensor,
    summary="Get sensor configuration",
    description="Get the current configuration of the given sensor",
    responses={
        status.HTTP_200_OK: {"description": "Configuration of the sensor"},
        NoSensor.STATUS_CODE: NoSensor.api_description(),
    },
)
async def get_sensor_configuration(name: str) -> Sensor:
    return SensorConfigurationService.get(name)


@router_admin.post(
    "/configuration",
    response_model=Sensor,
    summary="Create a new sensor",
    description="Add a new sensor configuration.",
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_201_CREATED: {"description": "Added new sensor"},
        SensorExists.STATUS_CODE: SensorExists.api_description(),
    },
)
async def post_sensor_configuration(sensor: Sensor) -> Sensor:
    return SensorConfigurationService.create(sensor.name, sensor.typed)


@router_admin.put(
    "/{name}/configuration",
    response_model=Sensor,
    summary="Update a sensor",
    description="Update a existing sensor configuration.",
    responses={
        status.HTTP_200_OK: {"description": "Updated sensor"},
        NoSensor.STATUS_CODE: NoSensor.api_description(),
    },
)
async def put_sensor_configuration(name: str, sensor: Sensor = Body()) -> Sensor:
    return SensorConfigurationService.update(
        name, sensor.typed, sensor.cycles, sensor.calc_sun_position
    )


@router_admin.delete(
    "/{name}/configuration",
    response_model=SensorDeleteResult,
    summary="Delete a sensor",
    description="Delete the configuration of a sensor.",
    responses={status.HTTP_200_OK: {"description": "DeleteSensor"}},
)
async def delete_sensor_configuration(name: str) -> None:
    return SensorConfigurationService.delete(name)


sensor_router.include_router(router_usage)
sensor_router.include_router(router_admin)
