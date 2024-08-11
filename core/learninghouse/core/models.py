from __future__ import annotations

from enum import Enum
from typing import Any, Iterator, Optional

from pydantic import BaseModel, Field, RootModel, model_serializer


class LHEnumModel(Enum):
    def __new__(cls, *args):
        obj = object.__new__(cls)
        obj._value_ = args[0]
        return obj

    def __str__(self) -> str:
        return str(self._value_)

    def __repr__(self) -> str:
        return str(self._value_)

    def __eq__(self, obj) -> bool:
        return isinstance(obj, self.__class__) and self.value == obj.value

    def __hash__(self):
        return hash(self.value)

    @classmethod
    def from_string(cls, value: str) -> LHEnumModel:
        for item in cls.__members__.values():
            if item.value == value:
                return item
        raise ValueError(f"No enum value {value} found.")

    @model_serializer
    def serialize(self) -> str:
        return self.value


class LHBaseModel(BaseModel):
    def write_to_file(self, filename: str, indent: Optional[int] = None) -> None:
        with open(filename, "w", encoding="utf-8") as file_pointer:
            file_pointer.write(self.model_dump_json(indent=indent))

    def __hash__(self):
        return hash((type(self),) + tuple(self.__dict__.values()))


class LHListModel(RootModel):
    root: list[Any]

    def append(self, item) -> None:
        self.root.append(item)

    def extend(self, items) -> None:
        self.root.extend(items)

    def insert(self, index, item) -> None:
        self.root.insert(index, item)

    def remove(self, item) -> None:
        self.root.remove(item)

    def pop(self, index=-1) -> Any:
        return self.root.pop(index)

    def clear(self) -> None:
        self.root.clear()

    def index(self, item, start=0, end=None) -> int:
        return self.root.index(item, start, end)

    def count(self, item) -> int:
        return self.root.count(item)

    def sort(self, key=None, reverse=False) -> None:
        self.root.sort(key=key, reverse=reverse)

    def reverse(self) -> None:
        self.root.reverse()

    def __getitem__(self, index) -> Any:
        return self.root[index]

    def __setitem__(self, index, value) -> None:
        self.root[index] = value

    def __delitem__(self, index) -> None:
        del self.root[index]

    def __len__(self) -> int:
        return len(self.root)

    def __iter__(self) -> Iterator[Any]:
        return iter(self.root)

    def __contains__(self, item) -> bool:
        return item in self.root

    def write_to_file(self, filename: str, indent: Optional[int] = None) -> None:
        with open(filename, "w", encoding="utf-8") as file_pointer:
            file_pointer.write(self.model_dump_json(indent=indent))


class LearningHouseVersions(LHBaseModel):
    service: str = Field(None, example="1.0.0")
    fastapi: str = Field(None, example="1.0.0")
    pydantic: str = Field(None, example="1.0.0")
    uvicorn: str = Field(None, example="1.0.0")
    sklearn: str = Field(None, example="1.0.0")
    numpy: str = Field(None, example="1.0.0")
    pandas: str = Field(None, example="1.0.0")
    jwt: str = Field(None, example="1.0.0")
    passlib: str = Field(None, example="1.0.0")
    loguru: str = Field(None, example="1.0.0")

    @property
    def libraries_versions(self) -> str:
        return (
            f"Libraries FastAPI: {self.fastapi}, uvicorn: {self.uvicorn}, "
            + f"pydantic: {self.pydantic}, scikit-learn: {self.sklearn}, "
            + f"numpy: {self.numpy}, pandas: {self.pandas}, pyjwt: {self.jwt}, "
            + f"passlib: {self.passlib}, loguru: {self.loguru}"
        )


