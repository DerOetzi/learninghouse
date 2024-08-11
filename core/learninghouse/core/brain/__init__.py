from __future__ import annotations

from os import listdir, path, stat
from shutil import rmtree
from typing import Any, Optional

import pandas as pd
from fastapi import APIRouter, Depends, status
from pydantic import StrictBool, StrictFloat, StrictInt
from sklearn.feature_selection import SelectFromModel
from sklearn.metrics import accuracy_score

from learninghouse.core.auth import auth_service_cached
from learninghouse.core.brain.errors import (
    BrainBadRequest,
    BrainExists,
    BrainNoConfiguration,
    BrainNotActual,
    BrainNotEnoughData,
    BrainNotTrained,
)
from learninghouse.core.brain.models import (
    Brain,
    BrainConfiguration,
    BrainDeleteResult,
    BrainEstimatorType,
    BrainFileType,
    BrainInfo,
    BrainPredictionResult,
    BrainTrainingRequest,
)
from learninghouse.core.brain.preprocessing import DatasetPreprocessing
from learninghouse.core.logger import logger
from learninghouse.core.settings import service_settings


class BrainService:
    brains: dict[str, dict[str, int | Brain]] = {}

    @classmethod
    def list_all(cls) -> dict[str, BrainInfo]:
        brains: dict[str, BrainInfo] = {}
        for directory in listdir(service_settings().brains_directory):
            try:
                brains[directory] = cls.get_info(directory)
            except BrainNoConfiguration:
                pass

        return brains

    @staticmethod
    def get_info(name: str) -> BrainInfo:
        info: Optional[BrainInfo] = None
        if Brain.is_trained(name):
            try:
                info = Brain.load_trained(name).info
            except (AttributeError, BrainNotTrained):
                pass

        if info is None:
            if BrainConfiguration.json_config_file_exists(name):
                info = Brain(name).info
                training_data_file = Brain.sanitize_filename(
                    name, BrainFileType.TRAINING_DATA_FILE
                )
                if path.exists(training_data_file):
                    data = pd.read_csv(training_data_file)
                    info.training_data_size = len(data.index)
            else:
                raise BrainNoConfiguration(name)

        return info

    @classmethod
    def request(
        cls,
        name: str,
        dependent_value: Optional[Any] = None,
        sensors_data: Optional[dict[str, Any]] = None,
    ) -> BrainInfo:
        filename = Brain.sanitize_filename(name, BrainFileType.TRAINING_DATA_FILE)

        trainings_data: Optional[dict[str, Any]] = sensors_data

        if sensors_data is not None:
            if dependent_value is not None:
                trainings_data[name] = dependent_value
            else:
                # Todo this is never thrown because of if 86
                raise BrainBadRequest("Missing dependent variable!")

        if trainings_data is None:
            if path.exists(filename):
                data = pd.read_csv(filename)
            else:
                raise BrainNotEnoughData()
        else:
            logger.debug(trainings_data)
            trainings_data = DatasetPreprocessing.add_time_information(trainings_data)
            if path.exists(filename):
                data_temp = pd.read_csv(filename)
                df_new_row = pd.DataFrame([trainings_data])
                data = pd.concat([data_temp, df_new_row], ignore_index=True)
            else:
                data = pd.DataFrame([trainings_data])

            data.to_csv(filename, sep=",", index=False)

        return cls.train(name, data)

    @staticmethod
    def train(name: str, data: pd.DataFrame) -> BrainInfo:
        try:
            brain = Brain(name)

            if len(data.index) < 10:
                raise BrainNotEnoughData()

            (
                brain,
                x_train,
                x_test,
                y_train,
                y_test,
            ) = DatasetPreprocessing.prepare_training(brain, data, False)

            estimator = brain.estimator()

            selector = SelectFromModel(estimator)
            selector.fit(x_train, y_train)

            brain.dataset.features = x_train.columns[
                (selector.get_support())
            ].values.tolist()

            (
                brain,
                x_train,
                x_test,
                y_train,
                y_test,
            ) = DatasetPreprocessing.prepare_training(brain, data, True)

            estimator.fit(x_train, y_train)

            if BrainEstimatorType.CLASSIFIER == brain.configuration.estimator.typed:
                y_pred = estimator.predict(x_test)
                score = accuracy_score(y_test, y_pred)
            else:
                score = estimator.score(x_test, y_test)

            brain.store_trained(x_train.columns.tolist(), len(data.index), score)

            return brain.info
        except FileNotFoundError as exc:
            raise BrainNoConfiguration(name) from exc

    @classmethod
    def prediction(
        cls, name: str, request_data: dict[str, Any]
    ) -> BrainPredictionResult:
        try:
            brain = cls.load_brain(name)
            if not brain.actual_versions:
                raise BrainNotActual(name, brain.versions)

            request_data = DatasetPreprocessing.add_time_information(request_data)

            data = pd.DataFrame([request_data])
            prepared_data = DatasetPreprocessing.prepare_prediction(brain, data)

            prediction = brain.estimator().predict(prepared_data)

            if (
                brain.configuration.dependent_encode
                and brain.configuration.estimator.typed == BrainEstimatorType.CLASSIFIER
            ):
                prediction = brain.dataset.dependent_encoder.inverse_transform(
                    prediction
                )
                prediction = list(map(bool, prediction))
            else:
                prediction = list(map(float, prediction))

            return BrainPredictionResult(
                brain=brain.info,
                preprocessed=prepared_data.head(1).to_dict("records")[0],
                prediction=prediction[0],
            )
        except FileNotFoundError as exc:
            raise BrainNotTrained(name) from exc

    @classmethod
    def load_brain(cls, name: str) -> Brain:
        filename = Brain.sanitize_filename(name, BrainFileType.TRAINED_FILE)
        stamp = stat(filename).st_mtime

        if not (name in cls.brains and cls.brains[name]["stamp"] == stamp):
            cls.brains[name] = {"stamp": stamp, "brain": Brain.load_trained(name)}

        return cls.brains[name]["brain"]


class BrainConfigurationService:
    @staticmethod
    def get(name: str) -> BrainConfiguration:
        try:
            return BrainConfiguration.from_json_file(name)
        except FileNotFoundError as exc:
            raise BrainNoConfiguration(name) from exc

    @staticmethod
    def create(configuration: BrainConfiguration) -> BrainConfiguration:
        if BrainConfiguration.json_config_file_exists(configuration.name):
            raise BrainExists(configuration.name)

        configuration.to_json_file(configuration.name)

        return configuration

    @staticmethod
    def update(name: str, configuration: BrainConfiguration) -> BrainConfiguration:
        if not BrainConfiguration.json_config_file_exists(name):
            raise BrainNoConfiguration(name)

        configuration.to_json_file(name)

        return configuration

    @staticmethod
    def delete(name: str) -> BrainDeleteResult:
        brainpath = Brain.sanitize_directory(name)

        if not path.exists(brainpath):
            raise BrainNoConfiguration(name)

        logger.info(f"Remove brain: {name}")
        rmtree(brainpath)

        return BrainDeleteResult(name=name)


authservice = auth_service_cached()

brain_router = APIRouter(prefix="/brain", tags=["brain"])

router_usage = APIRouter(dependencies=[Depends(authservice.protect_user)])

router_training = APIRouter(dependencies=[Depends(authservice.protect_trainer)])

router_admin = APIRouter(dependencies=[Depends(authservice.protect_admin)])


@router_usage.get(
    "s/info",
    summary="Retrieve information",
    description="Retrieve all information about brains.",
    responses={
        200: {"description": "Information of all brains"},
    },
)
async def infos_get() -> dict[str, BrainInfo]:
    return BrainService.list_all()


@router_usage.get(
    "/{name}/info",
    summary="Retrieve information",
    description="Retrieve all information of a brain.",
    responses={
        200: {"description": "Information of the brain"},
        BrainNoConfiguration.STATUS_CODE: BrainNoConfiguration.api_description(),
    },
)
async def info_get(name: str) -> BrainInfo:
    return BrainService.get_info(name)


@router_training.post(
    "/{name}/training",
    summary="Train the brain again",
    description="After version updates train the brain with existing data.",
    responses={
        200: {"description": "Information of the trained brain"},
        BrainNotEnoughData.STATUS_CODE: BrainNotEnoughData.api_description(),
        BrainNoConfiguration.STATUS_CODE: BrainNoConfiguration.api_description(),
    },
)
async def training_post(name: str) -> BrainInfo:
    return BrainService.request(name)


@router_training.put(
    "/{name}/training",
    summary="Train the brain with new data",
    description="Train the brain with additional data.",
    responses={
        200: {"description": "Information of the trained brain"},
        BrainNotEnoughData.STATUS_CODE: BrainNotEnoughData.api_description(),
        BrainNoConfiguration.STATUS_CODE: BrainNoConfiguration.api_description(),
    },
)
async def training_put(name: str, request: BrainTrainingRequest) -> BrainInfo:
    return BrainService.request(name, request.dependent_value, request.sensors_data)


@router_usage.post(
    "/{name}/prediction",
    summary="Prediction",
    description="Predict a new dataset with given brain.",
    responses={
        200: {"description": "Prediction result"},
        BrainNotActual.STATUS_CODE: BrainNotActual.api_description(),
        BrainNotTrained.STATUS_CODE: BrainNotTrained.api_description(),
    },
)
async def prediction_post(
    name: str,
    request_data: dict[str, StrictBool | StrictInt | StrictFloat | str | None],
) -> BrainPredictionResult:
    return BrainService.prediction(name, request_data)


@router_usage.get(
    "/{name}/configuration",
    summary="Get configuration of a brain",
    description="Get the configuration of the specified brain",
    responses={
        status.HTTP_200_OK: {"description": "Configuration of the brain"},
        BrainNoConfiguration.STATUS_CODE: BrainNoConfiguration.api_description(),
    },
)
async def configuration_get(name: str) -> BrainConfiguration:
    return BrainConfigurationService.get(name)


@router_admin.post(
    "/configuration",
    summary="Create a new brain configuration",
    description="Put the configuration of a new brain",
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_201_CREATED: {"description": "The new brain was created"},
        BrainExists.STATUS_CODE: BrainExists.api_description(),
    },
)
async def configuration_post(brain: BrainConfiguration) -> BrainConfiguration:
    return BrainConfigurationService.create(brain)


@router_admin.put(
    "/{name}/configuration",
    summary="Update brain configuration",
    description="Post the configuration to update the brain",
    responses={
        status.HTTP_200_OK: {"description": "The brain configuration was updated"},
        BrainNoConfiguration.STATUS_CODE: BrainNoConfiguration.api_description(),
    },
)
async def configuration_put(
    name: str, configuration: BrainConfiguration
) -> BrainConfiguration:
    return BrainConfigurationService.update(name, configuration)


@router_admin.delete(
    "/{name}/configuration",
    summary="Delete whole brain",
    responses={status.HTTP_200_OK: {"description": "Returns the name of the brain"}},
)
async def configuration_delete(name: str) -> BrainDeleteResult:
    return BrainConfigurationService.delete(name)


brain_router.include_router(router_usage)
brain_router.include_router(router_training)
brain_router.include_router(router_admin)
