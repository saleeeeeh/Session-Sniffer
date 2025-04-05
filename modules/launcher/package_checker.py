"""This module checks the validity of packages for the launcher."""

# Standard Python Libraries
import importlib.metadata
from pathlib import Path

# External/Third-party Python Libraries
import toml
from packaging.requirements import Requirement


def get_dependencies_from_pyproject(file_path: Path = Path("pyproject.toml")):
    data = toml.load(file_path)

    dependencies = data.get("project", {}).get("dependencies", [])

    return {
        req.name: req for req in map(Requirement, dependencies)
    }


def get_dependencies_from_requirements(file_path: Path = Path("requirements.txt")):
    dependencies: dict[str, Requirement] = {}

    with file_path.open("r") as f:
        for line in f:
            stripped_line = line.strip()
            if (
                not stripped_line
                or stripped_line.startswith("#")
            ):
                continue

            req = Requirement(stripped_line)
            dependencies[req.name] = req

    return dependencies


def check_packages_version(required_packages: dict[str, Requirement]):
    outdated_packages: list[str, str, str] = []
    for package_name, requirement in required_packages.items():
        try:
            installed_version = importlib.metadata.version(package_name)
            if installed_version not in Requirement(f"{package_name}{requirement}").specifier:
                outdated_packages.append((package_name, requirement.specifier, installed_version))
        except importlib.metadata.PackageNotFoundError:
            outdated_packages.append((package_name, requirement.specifier, "Not Installed"))
    return outdated_packages
