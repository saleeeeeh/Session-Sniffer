"""This module checks the validity of packages for the launcher."""
import importlib.metadata

from packaging.requirements import Requirement


def get_dependencies_from_pyproject():
    from modules.constants.local import PYPROJECT_DATA

    dependencies = PYPROJECT_DATA.get("project", {}).get("dependencies", [])

    return {
        req.name: req for req in map(Requirement, dependencies)
    }


def get_dependencies_from_requirements():
    from modules.constants.local import REQUIEREMENTS_PATH

    dependencies: dict[str, Requirement] = {}

    with REQUIEREMENTS_PATH.open("r") as f:
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
