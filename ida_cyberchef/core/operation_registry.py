"""Registry for CyberChef operations with search capabilities."""

import json
import re
from pathlib import Path
from typing import Any


class OperationRegistry:
    """Manages operation schema and provides search functionality."""

    def __init__(self, schema_path: Path | None = None):
        if schema_path is None:
            schema_path = Path(__file__).parent.parent / "data" / "operation_schema.json"

        with open(schema_path, encoding="utf-8") as f:
            self._schema = json.load(f)

        self._operations = self._schema["operations"]

    def get_all_operations(self) -> list[dict[str, Any]]:
        """Get all available operations.

        Returns: List of all operations with their metadata
        """
        return self._operations.copy()

    def find_operation(self, name: str) -> dict[str, Any] | None:
        """Find operation by exact name.

        Args:
            name: Exact operation name to find

        Returns: Operation dict if found, None otherwise
        """
        for op in self._operations:
            if op["name"] == name:
                return op.copy()
        return None

    def search_operations(self, query: str) -> list[dict[str, Any]]:
        """Fuzzy search operations by name.

        Args:
            query: Search term

        Returns: List of matching operations, ranked by relevance
        """
        query_lower = query.lower()
        results = []

        for op in self._operations:
            name_lower = op["name"].lower()

            # Exact match
            if name_lower == query_lower:
                results.append((0, op))
            # Starts with query
            elif name_lower.startswith(query_lower):
                results.append((1, op))
            # Contains query
            elif query_lower in name_lower:
                results.append((2, op))
            # Word boundary match
            elif any(word.startswith(query_lower) for word in name_lower.split()):
                results.append((3, op))
            # Acronym match (query matches subsequence of first letters of words)
            else:
                words = self._extract_words(op["name"])
                first_letters = "".join(word[0].lower() for word in words if word)
                if self._is_subsequence(query_lower, first_letters):
                    results.append((4, op))

        # Sort by rank, then alphabetically
        results.sort(key=lambda x: (x[0], x[1]["name"]))

        return [op.copy() for _, op in results]

    def _extract_words(self, name: str) -> list[str]:
        """Extract words from operation name, splitting on spaces and case boundaries.

        Args:
            name: Operation name

        Returns: List of words extracted from the name
        """
        # First split by spaces
        space_parts = name.split()
        words = []

        for part in space_parts:
            # Split by case boundaries, treating each digit as a separate word
            # This allows "Base64" -> ["Base", "6", "4"] for acronym "b64"
            subwords = re.findall(r"[A-Z]+(?=[A-Z][a-z]|\b|\d|[^A-Za-z0-9])|[A-Z]?[a-z]+|\d", part)
            if subwords:
                words.extend(subwords)
            else:
                # If no subwords found, use the original part
                words.append(part)

        return words

    def _is_subsequence(self, query: str, text: str) -> bool:
        """Check if query is a subsequence of text.

        Args:
            query: Query string to find
            text: Text to search in

        Returns: True if query is a subsequence of text
        """
        query_idx = 0
        for char in text:
            if query_idx < len(query) and char == query[query_idx]:
                query_idx += 1
        return query_idx == len(query)
