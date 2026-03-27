import os
import sys
import json

# Add the project root (parent directory) to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from constant_classifier import constant_type_classifying


def test_constant_type_classifier():
    # Construct the full path to the json file assuming it is in the same directory
    case_file = os.path.join(PROJECT_ROOT, "constant_cases.json")

    with open(case_file, "r", encoding="utf-8") as f:
        cases = json.load(f)

    for case in cases:
        expected_slug = case["slug"]
        string_val = case["string"]
        statement = case["statement"]

        result = constant_type_classifying(string_val, statement)

        # Assert with a helpful error message
        assert result == expected_slug, (
            f"Failed on input: '{string_val}'. "
            f"Expected slug '{expected_slug}', but got '{result}'."
        )
