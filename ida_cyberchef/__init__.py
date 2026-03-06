"""IDA CyberChef integration package.

This package provides CyberChef data transformation capabilities for IDA Pro
through both a Qt widget interface and a programmatic API.
"""

from typing import Any

from ida_cyberchef.core.input_parser import InputFormat
from ida_cyberchef.core.operation_registry import OperationRegistry
from ida_cyberchef.core.recipe_models import OperationStep, RecipeDefinition
from ida_cyberchef.cyberchef import DishType, bake, get_chef, load_cyberchef, plate

__all__ = [
    "CyberChefWidget",
    "bake",
    "get_chef",
    "load_cyberchef",
    "plate",
    "DishType",
    "InputModel",
    "RecipeModel",
    "ExecutionModel",
    "InputSource",
    "InputFormat",
    "RecipeDefinition",
    "OperationStep",
    "OperationRegistry",
]


def __getattr__(name: str) -> Any:
    if name == "CyberChefWidget":
        from ida_cyberchef.cyberchef_widget import CyberChefWidget

        return CyberChefWidget

    if name in {"InputModel", "InputSource"}:
        from ida_cyberchef.qt_models.input_model import InputModel, InputSource

        return {"InputModel": InputModel, "InputSource": InputSource}[name]

    if name == "RecipeModel":
        from ida_cyberchef.qt_models.recipe_model import RecipeModel

        return RecipeModel

    if name == "ExecutionModel":
        from ida_cyberchef.qt_models.execution_model import ExecutionModel

        return ExecutionModel

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
