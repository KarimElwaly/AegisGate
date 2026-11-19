import importlib
import inspect
import os
import pkgutil
from typing import Any, Dict, List, Optional, Type
from pydantic import BaseModel
from core.logger import get_logger
from core.registry.interfaces import BaseContextResolver, BaseNotifier, BaseScanner

logger = get_logger("core.registry")


class PluginRegistry:
    """Central registry for all dynamically loaded Scanners, Context Resolvers, and Notifiers.
    Strictly decouples core mechanics from pluggable implementations.
    """

    def __init__(self) -> None:
        self._scanners: Dict[str, BaseScanner] = {}
        self._resolvers: Dict[str, BaseContextResolver] = {}
        self._notifiers: Dict[str, BaseNotifier] = {}

    # Scanner management
    def register_scanner(self, scanner: BaseScanner) -> None:
        if not issubclass(type(scanner), BaseScanner):
            raise TypeError(f"Scanner {scanner} must inherit from BaseScanner")
        self._scanners[scanner.name] = scanner
        for prefix in ("tier1_", "tier2_", "tier3_"):
            if scanner.name.startswith(prefix):
                self._scanners[scanner.name[len(prefix):]] = scanner

        logger.info(
            "Registered scanner",
            name=scanner.name,
            tier=scanner.tier,
            stages=scanner.supported_stages,
        )

    def unregister_scanner(self, name: str) -> None:
        if name in self._scanners:
            del self._scanners[name]
            logger.info("Unregistered scanner", name=name)

    def get_scanner(self, name: str) -> Optional[BaseScanner]:
        return self._scanners.get(name)

    def get_all_scanners(self) -> Dict[str, BaseScanner]:
        return dict(self._scanners)

    def get_scanners_for_stage(self, stage: str) -> List[BaseScanner]:
        matched = []
        for scanner in self._scanners.values():
            if not scanner.supported_stages or stage in scanner.supported_stages:
                matched.append(scanner)
        return matched

    # Resolver management
    def register_resolver(self, resolver: BaseContextResolver) -> None:
        if not issubclass(type(resolver), BaseContextResolver):
            raise TypeError(f"Resolver {resolver} must inherit from BaseContextResolver")
        self._resolvers[resolver.name] = resolver
        logger.info("Registered context resolver", name=resolver.name)

    def get_resolver(self, name: str) -> Optional[BaseContextResolver]:
        return self._resolvers.get(name)

    def get_all_resolvers(self) -> Dict[str, BaseContextResolver]:
        return dict(self._resolvers)

    # Notifier management
    def register_notifier(self, notifier: BaseNotifier) -> None:
        if not issubclass(type(notifier), BaseNotifier):
            raise TypeError(f"Notifier {notifier} must inherit from BaseNotifier")
        self._notifiers[notifier.name] = notifier
        logger.info("Registered notifier", name=notifier.name)

    def get_notifier(self, name: str) -> Optional[BaseNotifier]:
        return self._notifiers.get(name)

    def get_all_notifiers(self) -> Dict[str, BaseNotifier]:
        return dict(self._notifiers)

    # Configuration Schema validation and introspection (for Admin UI)
    def validate_plugin_config(
        self, plugin_type: str, name: str, raw_config: Dict[str, Any]
    ) -> BaseModel:
        target: Optional[Any] = None
        if plugin_type == "scanner":
            target = self.get_scanner(name)
        elif plugin_type == "resolver":
            target = self.get_resolver(name)
        elif plugin_type == "notifier":
            target = self.get_notifier(name)

        if not target:
            raise KeyError(f"Plugin '{name}' of type '{plugin_type}' not found in registry")

        schema_cls = getattr(target, "config_schema", BaseModel)
        return schema_cls(**raw_config)

    def get_plugin_catalog(self) -> Dict[str, List[Dict[str, Any]]]:
        """Returns metadata and JSON schemas of all registered plugins for UI auto-rendering."""
        catalog: Dict[str, List[Dict[str, Any]]] = {
            "scanners": [],
            "resolvers": [],
            "notifiers": [],
        }

        for name, scanner in self._scanners.items():
            catalog["scanners"].append(
                {
                    "name": name,
                    "version": scanner.version,
                    "tier": scanner.tier,
                    "supported_stages": scanner.supported_stages,
                    "config_schema": scanner.config_schema.model_json_schema()
                    if hasattr(scanner.config_schema, "model_json_schema")
                    else {},
                }
            )

        for name, resolver in self._resolvers.items():
            catalog["resolvers"].append(
                {
                    "name": name,
                    "version": resolver.version,
                    "config_schema": resolver.config_schema.model_json_schema()
                    if hasattr(resolver.config_schema, "model_json_schema")
                    else {},
                }
            )

        for name, notifier in self._notifiers.items():
            catalog["notifiers"].append(
                {
                    "name": name,
                    "version": notifier.version,
                    "config_schema": notifier.config_schema.model_json_schema()
                    if hasattr(notifier.config_schema, "model_json_schema")
                    else {},
                }
            )

        return catalog

    def discover_and_register_plugins(self, root_package_path: str, root_package_name: str) -> None:
        """Dynamically scans a directory tree and registers all discovered plugin classes."""
        if not os.path.isdir(root_package_path):
            return

        for root, _, files in os.walk(root_package_path):
            for file in files:
                if file.endswith(".py") and not file.startswith("__"):
                    rel_path = os.path.relpath(os.path.join(root, file), root_package_path)
                    mod_parts = os.path.splitext(rel_path)[0].split(os.sep)
                    full_module_name = f"{root_package_name}.{'.'.join(mod_parts)}"
                    try:
                        module = importlib.import_module(full_module_name)
                        for _, obj in inspect.getmembers(module, inspect.isclass):
                            if obj in (BaseScanner, BaseContextResolver, BaseNotifier):
                                continue
                            if issubclass(obj, BaseScanner) and not inspect.isabstract(obj):
                                instance = obj()
                                self.register_scanner(instance)
                            elif issubclass(obj, BaseContextResolver) and not inspect.isabstract(obj):
                                instance = obj()
                                self.register_resolver(instance)
                            elif issubclass(obj, BaseNotifier) and not inspect.isabstract(obj):
                                instance = obj()
                                self.register_notifier(instance)
                    except Exception as e:
                        logger.error(
                            "Failed to load plugin module",
                            module=full_module_name,
                            error=str(e),
                        )


# Global singleton instance
default_plugin_registry = PluginRegistry()


def get_plugin_registry() -> PluginRegistry:
    return default_plugin_registry
