import importlib


def test_verion_package_imports():
    importlib.import_module("verion")


def test_module_hexagons_import():
    for name in ("identity", "scanning", "risk_engine", "brief"):
        importlib.import_module(f"verion.modules.{name}.domain")
        importlib.import_module(f"verion.modules.{name}.application")
        importlib.import_module(f"verion.modules.{name}.ports")
        importlib.import_module(f"verion.modules.{name}.adapters")


def test_shared_kernel_and_platform_import():
    importlib.import_module("verion.shared_kernel")
    importlib.import_module("verion.platform")
