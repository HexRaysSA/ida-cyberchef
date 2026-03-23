"""Execute CyberChef recipes and return step-by-step results."""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ida_cyberchef.core.output_model import TypedOutput, typed_output_from_value
from ida_cyberchef.cyberchef import bake


@dataclass
class StepResult:
    """Result of executing a single recipe step."""

    success: bool
    data: Optional[TypedOutput]
    error: Optional[str]


class RecipeExecutor:
    """Executes CyberChef recipes and tracks results for each step."""

    def execute_recipe(
        self, input_data: bytes, recipe: List[Dict[str, Any]]
    ) -> List[StepResult]:
        """Execute recipe and return results for each step.

        Args:
            input_data: Input bytes to process
            recipe: List of operation dicts with "operation" and "args" keys

        Returns: List of StepResult for each step (stops at first error)
        """
        results = []

        for i, step in enumerate(recipe):
            try:
                recipe_prefix = recipe[: i + 1]

                chef_recipe = []
                for s in recipe_prefix:
                    if s["args"]:
                        chef_recipe.append({"op": s["operation"], "args": s["args"]})
                    else:
                        chef_recipe.append(s["operation"])

                output = bake(input_data, chef_recipe)  # type: ignore[arg-type]
                results.append(StepResult(success=True, data=typed_output_from_value(output), error=None))

            except Exception as e:
                results.append(StepResult(success=False, data=None, error=str(e)))
                break

        return results
