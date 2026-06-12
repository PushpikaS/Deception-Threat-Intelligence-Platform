"""Production geo enrichment — MaxMind GeoLite2 (offline) with IP-API fallback."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen

log = logging.getLogger(__name__)

GEOIP_CITY_PATH = os.getenv("GEOIP_CITY_PATH", "/data/geoip/GeoLite2-City.mmdb")
GEOIP_ASN_PATH = os.getenv("GEOIP_ASN_PATH", "/data/geoip/GeoLite2-ASN.mmdb")
GEOIP_HTTP_FALLBACK = os.getenv("GEOIP_HTTP_FALLBACK", "true").lower() in ("1", "true", "yes")
GEOIP_HTTP_TIMEOUT = float(os.getenv("GEOIP_HTTP_TIMEOUT", "4"))
GEOIP_CACHE_TTL = int(os.getenv("GEOIP_CACHE_TTL", "86400"))

_city_reader: Any = None
_asn_reader: Any = None
_init_done = False
_mem_cache: dict[str, tuple[float, dict[str, Any]]] = {}

SOURCE_PRIORITY = {"maxmind": 4, "ipapi": 3, "private": 2, "unknown": 1, "empty": 0}


@dataclass
class GeoInfo:
    country: str | None = None
    country_code: str | None = None
    continent: str | None = None
    region: str | None = None
    city: str | None = None
    postal_code: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    accuracy_km: int | None = None
    timezone: str | None = None
    asn: str | None = None
    isp: str | None = None
    source: str = "unknown"
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "geo_country": self.country,
            "geo_country_code": self.country_code,
            "geo_continent": self.continent,
            "geo_region": self.region,
            "geo_city": self.city,
            "geo_postal_code": self.postal_code,
            "geo_latitude": self.latitude,
            "geo_longitude": self.longitude,
            "geo_accuracy_km": self.accuracy_km,
            "geo_timezone": self.timezone,
            "geo_asn": self.asn,
            "geo_isp": self.isp,
            "geo_source": self.source,
        }

    def is_mappable(self) -> bool:
        return (
            self.latitude is not None
            and self.longitude is not None
            and _valid_coords(self.latitude, self.longitude)
            and self.source in ("maxmind", "ipapi")
        )

    def priority(self) -> int:
        return SOURCE_PRIORITY.get(self.source, 0)


def _valid_coords(lat: float, lon: float) -> bool:
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return False
    # Reject null island and other common placeholder coords
    if abs(lat) < 0.01 and abs(lon) < 0.01:
        return False
    return True


def _estimate_accuracy_km(city: str | None, region: str | None, provider_radius: int | None = None) -> int:
    if provider_radius is not None and provider_radius > 0:
        return int(provider_radius)
    if city:
        return 25
    if region:
        return 75
    return 250


def _init_readers() -> None:
    global _city_reader, _asn_reader, _init_done
    if _init_done:
        return
    _init_done = True
    try:
        import geoip2.database
    except ImportError:
        log.warning("geoip2 not installed — HTTP geo fallback only")
        return

    city_path = Path(GEOIP_CITY_PATH)
    if city_path.is_file():
        try:
            _city_reader = geoip2.database.Reader(str(city_path))
            log.info("GeoLite2-City loaded from %s", city_path)
        except Exception as exc:
            log.warning("Failed to open GeoLite2-City: %s", exc)
    else:
        log.warning("GeoLite2-City not found at %s — using IP-API fallback", city_path)

    asn_path = Path(GEOIP_ASN_PATH)
    if asn_path.is_file():
        try:
            _asn_reader = geoip2.database.Reader(str(asn_path))
            log.info("GeoLite2-ASN loaded from %s", asn_path)
        except Exception as exc:
            log.warning("Failed to open GeoLite2-ASN: %s", exc)


def _normalize_ip(ip: str) -> str:
    ip = (ip or "").strip()
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    return ip


def _is_non_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
        )
    except ValueError:
        return True


def _private_geo(ip: str) -> GeoInfo:
    return GeoInfo(
        country="Private Network",
        country_code=None,
        continent=None,
        region=None,
        city="Non-routable",
        postal_code=None,
        latitude=None,
        longitude=None,
        accuracy_km=None,
        timezone=None,
        asn=None,
        isp="Internal / RFC1918",
        source="private",
        extra={"note": "Not placed on global map — deploy behind a public IP or pass X-Forwarded-For from a load balancer"},
    )


def _cache_get(ip: str) -> dict[str, Any] | None:
    entry = _mem_cache.get(ip)
    if not entry:
        return None
    expires, payload = entry
    if time.time() > expires:
        _mem_cache.pop(ip, None)
        return None
    return payload


def _cache_set(ip: str, payload: dict[str, Any]) -> None:
    _mem_cache[ip] = (time.time() + GEOIP_CACHE_TTL, payload)


async def _redis_cache_get(redis, ip: str) -> dict[str, Any] | None:
    if redis is None:
        return None
    try:
        raw = await redis.get(f"geo:ip:{ip}")
        if raw:
            return json.loads(raw)
    except Exception:
        pass
    return None


async def _redis_cache_set(redis, ip: str, payload: dict[str, Any]) -> None:
    if redis is None:
        return
    try:
        await redis.setex(f"geo:ip:{ip}", GEOIP_CACHE_TTL, json.dumps(payload))
    except Exception:
        pass


def _lookup_maxmind(ip: str) -> GeoInfo | None:
    if not _city_reader and not _asn_reader:
        return None

    geo = GeoInfo(source="maxmind")
    if _city_reader:
        try:
            rec = _city_reader.city(ip)
            geo.country = rec.country.name or rec.registered_country.name
            geo.country_code = rec.country.iso_code or rec.registered_country.iso_code
            geo.continent = rec.continent.name
            if rec.subdivisions:
                geo.region = rec.subdivisions[0].name
            geo.city = rec.city.name
            if rec.postal.code:
                geo.postal_code = rec.postal.code
            if rec.location.latitude is not None:
                geo.latitude = round(float(rec.location.latitude), 6)
            if rec.location.longitude is not None:
                geo.longitude = round(float(rec.location.longitude), 6)
            if rec.location.accuracy_radius is not None:
                geo.accuracy_km = int(rec.location.accuracy_radius)
            geo.timezone = rec.location.time_zone
        except Exception:
            return None

    if _asn_reader:
        try:
            rec = _asn_reader.asn(ip)
            geo.asn = f"AS{rec.autonomous_system_number}"
            geo.isp = rec.autonomous_system_organization
        except Exception:
            pass

    if geo.country or geo.latitude is not None:
        if geo.accuracy_km is None:
            geo.accuracy_km = _estimate_accuracy_km(geo.city, geo.region)
        return geo
    return None


def _lookup_ipapi(ip: str) -> GeoInfo | None:
    if not GEOIP_HTTP_FALLBACK:
        return None

    fields = (
        "status,message,continent,country,countryCode,regionName,city,zip,lat,lon,"
        "timezone,isp,org,as,query"
    )
    url = f"http://ip-api.com/json/{ip}?fields={fields}"
    try:
        with urlopen(url, timeout=GEOIP_HTTP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        log.debug("ip-api lookup failed for %s: %s", ip, exc)
        return None

    if data.get("status") != "success":
        return None

    asn_raw = data.get("as") or ""
    asn = None
    if asn_raw.upper().startswith("AS"):
        asn = asn_raw.split()[0].upper()

    lat = data.get("lat")
    lon = data.get("lon")
    city = data.get("city")
    region = data.get("regionName")

    return GeoInfo(
        country=data.get("country"),
        country_code=data.get("countryCode"),
        continent=data.get("continent"),
        region=region,
        city=city,
        postal_code=data.get("zip") or None,
        latitude=round(float(lat), 6) if lat is not None else None,
        longitude=round(float(lon), 6) if lon is not None else None,
        accuracy_km=_estimate_accuracy_km(city, region),
        timezone=data.get("timezone"),
        asn=asn,
        isp=data.get("isp") or data.get("org"),
        source="ipapi",
    )


def _geo_from_payload(payload: dict[str, Any]) -> GeoInfo:
    return GeoInfo(
        country=payload.get("geo_country"),
        country_code=payload.get("geo_country_code"),
        continent=payload.get("geo_continent"),
        region=payload.get("geo_region"),
        city=payload.get("geo_city"),
        postal_code=payload.get("geo_postal_code"),
        latitude=payload.get("geo_latitude"),
        longitude=payload.get("geo_longitude"),
        accuracy_km=payload.get("geo_accuracy_km"),
        timezone=payload.get("geo_timezone"),
        asn=payload.get("geo_asn"),
        isp=payload.get("geo_isp"),
        source=payload.get("geo_source", "unknown"),
    )


def _resolve_geo_sync(ip: str) -> GeoInfo:
    _init_readers()

    maxmind = _lookup_maxmind(ip)
    if maxmind and maxmind.is_mappable():
        log.info("geo %s → %s, %s (%s) via maxmind ±%skm", ip, maxmind.city, maxmind.country, maxmind.country_code, maxmind.accuracy_km)
        return maxmind

    ipapi = _lookup_ipapi(ip)
    if ipapi and ipapi.is_mappable():
        if maxmind:
            if not ipapi.asn and maxmind.asn:
                ipapi.asn = maxmind.asn
            if not ipapi.isp and maxmind.isp:
                ipapi.isp = maxmind.isp
        log.info(
            "geo %s → %s, %s (%s) via ipapi ±%skm [%.4f, %.4f]",
            ip, ipapi.city, ipapi.country, ipapi.country_code, ipapi.accuracy_km,
            ipapi.latitude or 0, ipapi.longitude or 0,
        )
        return ipapi

    if maxmind:
        return maxmind
    if ipapi:
        return ipapi

    return GeoInfo(source="unknown")


async def enrich_ip(ip: str, redis=None) -> GeoInfo:
    ip = _normalize_ip(ip)
    if not ip:
        return GeoInfo(source="empty")

    if _is_non_public(ip):
        return _private_geo(ip)

    cached = _cache_get(ip)
    if cached:
        return _geo_from_payload(cached)

    redis_cached = await _redis_cache_get(redis, ip)
    if redis_cached:
        _cache_set(ip, redis_cached)
        return _geo_from_payload(redis_cached)

    geo = await asyncio.to_thread(_resolve_geo_sync, ip)
    payload = geo.to_dict()
    _cache_set(ip, payload)
    await _redis_cache_set(redis, ip, payload)
    return geo


def merge_geo_profiles(previous: dict | None, new_geo: dict[str, Any]) -> dict[str, Any]:
    """Keep the higher-confidence geo snapshot when updating profiles."""
    if not previous:
        return new_geo

    prev_meta = previous.get("metadata") or {}
    if isinstance(prev_meta, str):
        try:
            prev_meta = json.loads(prev_meta)
        except json.JSONDecodeError:
            prev_meta = {}

    old_source = prev_meta.get("geo_source", "unknown")
    new_source = new_geo.get("geo_source", "unknown")
    old_pri = SOURCE_PRIORITY.get(old_source, 0)
    new_pri = SOURCE_PRIORITY.get(new_source, 0)

    if new_pri > old_pri:
        return new_geo
    if new_pri == old_pri and new_pri >= SOURCE_PRIORITY["ipapi"]:
        return new_geo

    return {
        "geo_country": previous.get("geo_country"),
        "geo_country_code": prev_meta.get("geo_country_code") or previous.get("geo_country_code"),
        "geo_continent": prev_meta.get("geo_continent"),
        "geo_region": prev_meta.get("geo_region"),
        "geo_city": previous.get("geo_city"),
        "geo_postal_code": prev_meta.get("geo_postal_code"),
        "geo_latitude": previous.get("geo_latitude"),
        "geo_longitude": previous.get("geo_longitude"),
        "geo_accuracy_km": prev_meta.get("geo_accuracy_km"),
        "geo_timezone": prev_meta.get("geo_timezone"),
        "geo_asn": previous.get("geo_asn"),
        "geo_isp": previous.get("geo_isp"),
        "geo_source": old_source,
    }


def close_readers() -> None:
    global _city_reader, _asn_reader
    if _city_reader:
        _city_reader.close()
        _city_reader = None
    if _asn_reader:
        _asn_reader.close()
        _asn_reader = None