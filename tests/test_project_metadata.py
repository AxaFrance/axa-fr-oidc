from pathlib import Path

import yaml

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_pyproject_requires_python_includes_3_14_and_3_15() -> None:
    """Ensure project metadata declares support through Python 3.15."""
    pyproject_data = tomllib.loads((REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject_data["project"]["requires-python"] == ">=3.10,<3.16"


def test_ci_test_matrix_includes_python_3_10_through_3_14() -> None:
    """Ensure CI covers the supported Python versions currently available on GitHub runners."""
    ci_tests_data = yaml.safe_load((REPOSITORY_ROOT / ".github/workflows/ci-tests.yml").read_text(encoding="utf-8"))
    python_versions = set(ci_tests_data["jobs"]["test"]["strategy"]["matrix"]["python-version"])
    expected_supported_versions = {"3.10", "3.11", "3.12", "3.13", "3.14"}
    assert expected_supported_versions.issubset(python_versions)


def test_ci_quality_matrix_covers_min_and_latest_supported_python() -> None:
    """Ensure quality checks run on the minimum and latest available supported versions."""
    ci_quality_data = yaml.safe_load((REPOSITORY_ROOT / ".github/workflows/ci-quality.yml").read_text(encoding="utf-8"))
    python_versions = set(ci_quality_data["jobs"]["test"]["strategy"]["matrix"]["python-version"])
    assert {"3.10", "3.14"}.issubset(python_versions)


def test_publish_workflow_uses_python_3_14() -> None:
    """Ensure the publish workflow uses an available Python version."""
    publish_data = yaml.safe_load((REPOSITORY_ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8"))
    assert publish_data["jobs"]["publish"]["steps"][1]["with"]["python-version"] == "3.14"
