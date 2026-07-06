"""Pydantic models for recipe serialization."""

from typing import Any

from pydantic import BaseModel, Field


class OperationStep(BaseModel):
    """Single operation in a recipe."""

    operation: str = Field(..., description="Operation name")
    args: dict[str, Any] = Field(default_factory=dict, description="Operation arguments")


class RecipeDefinition(BaseModel):
    """Complete recipe definition for serialization."""

    version: str = Field(default="1.0", description="Recipe format version")
    steps: list[OperationStep] = Field(default_factory=list, description="Recipe steps")
