"""Regression checks for reproducible Python dependency resolution."""

from pathlib import Path
import re
import tomllib


ROOT = Path(__file__).parents[1]
EXACT_PIN = re.compile(r"^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[^;\s]+(?:\s*;.*)?$")


def test_project_dependencies_are_exactly_pinned_and_locked():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependency_sets = [pyproject["build-system"]["requires"]]
    dependency_sets.append(pyproject["project"]["dependencies"])
    dependency_sets.extend(pyproject["project"]["optional-dependencies"].values())

    dependencies = [dependency for group in dependency_sets for dependency in group]
    assert dependencies
    assert all(EXACT_PIN.fullmatch(dependency) for dependency in dependencies)

    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    registry_packages = [
        package for package in lock["package"] if "registry" in package.get("source", {})
    ]
    assert registry_packages
    assert all(
        package.get("sdist", {}).get("hash")
        or any(wheel.get("hash") for wheel in package.get("wheels", []))
        for package in registry_packages
    )


def test_cli_transitive_runtime_gap_is_a_direct_locked_dependency():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "typing-extensions==4.15.0" in pyproject["project"]["dependencies"]

    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    locked_packages = {package["name"]: package for package in lock["package"]}
    assert locked_packages["typing-extensions"]["version"] == "4.15.0"
    sezam_dependencies = {
        dependency["name"] for dependency in locked_packages["sezam"]["dependencies"]
    }
    assert "typing-extensions" in sezam_dependencies


def test_server_requirements_are_exactly_pinned_with_hashes():
    direct_requirements = (ROOT / "server" / "requirements.in").read_text(
        encoding="utf-8"
    ).splitlines()
    assert direct_requirements
    assert all(EXACT_PIN.fullmatch(requirement) for requirement in direct_requirements)

    requirements = (ROOT / "server" / "requirements.txt").read_text(
        encoding="utf-8"
    )
    logical_lines = requirements.replace("\\\n", " ").splitlines()
    pinned = [
        line.strip()
        for line in logical_lines
        if line.strip() and not line.strip().startswith("#")
    ]

    assert pinned
    assert all("==" in line and ">=" not in line for line in pinned)
    assert all("--hash=sha256:" in line for line in pinned)


def test_server_pyjwt_excludes_known_vulnerable_release():
    requirements = (ROOT / "server" / "requirements.in").read_text(
        encoding="utf-8"
    ).splitlines()
    pyjwt = next(line for line in requirements if line.lower().startswith("pyjwt"))
    version = pyjwt.split("==", 1)[1]

    assert tuple(map(int, version.split("."))) >= (2, 13, 0)


def test_pytest_excludes_unix_tmpdir_vulnerable_release():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    pytest_pin = next(
        dependency
        for dependency in pyproject["project"]["optional-dependencies"]["dev"]
        if dependency.startswith("pytest==")
    )
    declared_version = pytest_pin.split("==", 1)[1]

    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    locked_version = next(
        package["version"] for package in lock["package"] if package["name"] == "pytest"
    )

    assert tuple(map(int, declared_version.split("."))) >= (9, 0, 3)
    assert locked_version == declared_version


def test_gradle_wrapper_distribution_has_verified_integrity_pin():
    properties = dict(
        line.split("=", 1)
        for line in (
            ROOT / "mobile" / "android" / "gradle" / "wrapper" /
            "gradle-wrapper.properties"
        ).read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    )

    assert properties["distributionUrl"].endswith("/gradle-8.14-all.zip")
    assert properties["distributionSha256Sum"] == (
        "efe9a3d147d948d7528a9887fa35abcf"
        "24ca1a43ad06439996490f77569b02d1"
    )


def test_android_release_requires_explicit_non_debug_signing_credentials():
    android_root = ROOT / "mobile" / "android"
    build_config = (android_root / "app" / "build.gradle.kts").read_text(
        encoding="utf-8"
    )
    android_ignore = (android_root / ".gitignore").read_text(encoding="utf-8")

    assert 'signingConfigs.getByName("debug")' not in build_config
    assert 'create("release")' in build_config
    assert 'signingConfig = signingConfigs.getByName("release")' in build_config
    assert "gradle.taskGraph.whenReady" in build_config
    assert "GradleException" in build_config
    for property_name in ("storeFile", "storePassword", "keyAlias", "keyPassword"):
        assert f'"{property_name}"' in build_config
    assert "key.properties" in android_ignore
