"""IDA CyberChef integration package.

This package provides CyberChef data transformation capabilities for IDA Pro
through both a Qt widget interface and a programmatic API.
"""

from ida_cyberchef.core.input_parser import InputFormat
from ida_cyberchef.core.operation_registry import OperationRegistry
from ida_cyberchef.core.recipe_models import OperationStep, RecipeDefinition
from ida_cyberchef.cyberchef import DishType, bake, get_chef, load_cyberchef, plate
from ida_cyberchef.cyberchef_widget import CyberChefWidget
from ida_cyberchef.qt_models.execution_model import ExecutionModel
from ida_cyberchef.qt_models.input_model import InputModel, InputSource
from ida_cyberchef.qt_models.recipe_model import RecipeModel

__all__ = [
    "CyberChefWidget",
    "DishType",
    "ExecutionModel",
    "InputFormat",
    "InputModel",
    "InputSource",
    "OperationRegistry",
    "OperationStep",
    "RecipeDefinition",
    "RecipeModel",
    "bake",
    "get_chef",
    "load_cyberchef",
    "plate",
]
