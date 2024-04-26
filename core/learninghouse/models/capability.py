from __future__ import annotations

from learninghouse.models.base import LHBaseModel, EnumModel


class CapabilityValueType(EnumModel):
    NUMERICAL = "numerical"
    CATEGORICAL = "categorical"
    CYCLICAL = "cyclical"


class CapabilityValue(LHBaseModel):
    raw: any
    formatted: str
    typed: CapabilityValueType


class GenericStringValue(CapabilityValue):
    raw: str
    formatted: str
    typed: CapabilityValueType = CapabilityValueType.CATEGORICAL


class GenericBooleanValue(CapabilityValue):
    raw: bool
    formatted: str
    typed: CapabilityValueType = CapabilityValue.CATEGORICAL


class GenericNumberValue(CapabilityValue):
    raw: float
    formatted: str
    typed: CapabilityValueType


class Capability(LHBaseModel):
    name: str
    value: CapabilityValue
