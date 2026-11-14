"""Static observe-only configuration. No discovery, writes or activation."""

from dataclasses import dataclass
from pathlib import Path
import re
import stat
import tomllib

MAX_CONFIG_BYTES = 64 * 1024
MAX_SERVICES = 16
MAX_PORTS = 16
MAX_REQUIREMENTS = 64
METRICS = frozenset({"requests_total", "latency_ms"})
PROFILES = frozenset({"direct_host", "linux_gateway", "cdn_origin", "opnsense_gateway"})
OPTIONAL_INTEGRATIONS = frozenset({
    "flask_to_ad", "windows_event_forwarding", "cloudfront_waf", "home_gateway_api",
})
ROOT_FIELDS = frozenset({"schema_version", "mode", "services", "optional_integrations"})
SERVICE_FIELDS = frozenset({"id", "ingress_profile", "protected_ports"})
REQUIREMENT_FIELDS = frozenset({"service_id", "source", "metric", "route"})
SERVICE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", re.ASCII)


class ConfigError(ValueError):
    """A bounded diagnostic that never includes input values or parser excerpts."""


@dataclass(frozen=True)
class ServiceConfig:
    id: str
    ingress_profile: str
    protected_ports: tuple[int, ...]


@dataclass(frozen=True)
class RequiredObservation:
    service_id: str
    source: str
    metric: str
    route: str


@dataclass(frozen=True)
class ObserveConfig:
    schema_version: int
    mode: str
    services: tuple[ServiceConfig, ...]
    required_observations: tuple[RequiredObservation, ...] | None = None


def _require_fields(value, fields, label):
    if type(value) is not dict or set(value) != fields:
        raise ConfigError(f"{label}: required fields are {', '.join(sorted(fields))}; no others allowed")


def validate_config(data):
    """Validate declared intent, never target facts or deployment readiness."""
    version = data.get("schema_version") if type(data) is dict else None
    if type(version) is not int or version not in (1, 2):
        raise ConfigError("schema_version: expected integer 1 or 2")
    fields = ROOT_FIELDS if version == 1 else ROOT_FIELDS | {"required_observations"}
    _require_fields(data, fields, "configuration")
    if data["mode"] != "observe":
        raise ConfigError("mode: only observe is supported; enforcement is unavailable")
    integrations = data["optional_integrations"]
    _require_fields(integrations, OPTIONAL_INTEGRATIONS, "optional_integrations")
    if any(value is not False for value in integrations.values()):
        raise ConfigError("optional_integrations: every value must be Boolean false")

    services = data["services"]
    if type(services) is not list or not 1 <= len(services) <= MAX_SERVICES:
        raise ConfigError("services: expected 1-16 service tables")
    seen = set()
    validated = []
    for index, service in enumerate(services):
        label = f"services[{index}]"
        _require_fields(service, SERVICE_FIELDS, label)
        identifier = service["id"]
        if type(identifier) is not str or SERVICE_ID.fullmatch(identifier) is None:
            raise ConfigError(f"{label}.id: expected a 1-64 character ASCII identifier")
        if identifier in seen:
            raise ConfigError(f"{label}.id: duplicate service identifier")
        seen.add(identifier)
        profile = service["ingress_profile"]
        if type(profile) is not str or profile not in PROFILES:
            raise ConfigError(f"{label}.ingress_profile: expected one supported profile")
        ports = service["protected_ports"]
        if type(ports) is not list or not 1 <= len(ports) <= MAX_PORTS:
            raise ConfigError(f"{label}.protected_ports: expected 1-16 port integers")
        if any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
            raise ConfigError(f"{label}.protected_ports: expected integers in 1-65535")
        if len(set(ports)) != len(ports):
            raise ConfigError(f"{label}.protected_ports: duplicate port")
        validated.append(ServiceConfig(identifier, profile, tuple(ports)))
    requirements = None
    if version == 2:
        requirements = _requirements(data["required_observations"], seen)
    return ObserveConfig(version, "observe", tuple(validated), requirements)


def _requirements(items, service_ids):
    if type(items) is not list or not 1 <= len(items) <= MAX_REQUIREMENTS:
        raise ConfigError("required_observations: expected 1-64 requirement tables")
    validated = []
    seen = set()
    known_routes = set()
    for item in items:
        _require_fields(item, REQUIREMENT_FIELDS, "required observation")
        if any(type(value) is not str for value in item.values()):
            raise ConfigError("required observation: every field must be a string")
        if item["service_id"] not in service_ids:
            raise ConfigError("required observation: service must be declared")
        if item["source"] != "proxy":
            raise ConfigError("required observation: only proxy is supported; optional sources are disabled")
        if item["metric"] not in METRICS:
            raise ConfigError("required observation: metric is unsupported")
        route = item["route"]
        if route != "OTHER":
            if (not 1 <= len(route) <= 2048 or not route.startswith("/")
                    or route.startswith("//") or "?" in route or "#" in route
                    or any(ord(c) < 32 or ord(c) == 127 for c in route)):
                raise ConfigError("required observation: route must be an exact origin path or OTHER")
            known_routes.add(route)
        entry = RequiredObservation(**item)
        if entry in seen:
            raise ConfigError("required observation: duplicate exact identity")
        seen.add(entry)
        validated.append(entry)
    if len(known_routes) > 32:
        raise ConfigError("required observations exceed the 32-path replay catalog limit")
    return tuple(validated)


def load_config(path):
    """Read one bounded regular file. No URLs, includes or environment expansion."""
    text_path = str(path)
    if "://" in text_path or text_path.replace("\\", "/").startswith("//"):
        raise ConfigError("configuration input: use a filesystem path, not a URL or UNC path")
    target = Path(path)
    try:
        if not stat.S_ISREG(target.stat().st_mode):
            raise ConfigError("configuration input: expected a regular file")
        with target.open("rb") as stream:
            raw = stream.read(MAX_CONFIG_BYTES + 1)
    except OSError as error:
        raise ConfigError(f"cannot read configuration file ({type(error).__name__})") from None
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError("configuration file exceeds the 64-KiB development limit")
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        # Parser messages may echo secrets or arbitrarily long input.
        raise ConfigError("configuration input: invalid UTF-8 or unsupported/malformed TOML") from None
    return validate_config(data)
