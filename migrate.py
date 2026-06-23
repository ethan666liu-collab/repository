#!/usr/bin/env python3
"""
ZStack v4 -> v5 VM migration helper.

Usage:
  migrate -ip 216.236.45.151
  migrate -ip 216.236.45.156,216.236.45.157,216.236.45.158

Console/API mapping:
  v4 console: http://216.236.36.68:5000/dashboard
  v4 API:     http://216.236.36.68:8080
  v5 console: http://216.236.36.66:5000/dashboard
  v5 API:     http://216.236.36.66:8080

Credentials can be edited in CONFIG_V4_* and CONFIG_V5_* below, or provided with
--v4-username/--v4-password and --v5-username/--v5-password.

The password is sent as SHA-512, matching the ZStack API/SDK documentation.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import ipaddress
import json
import os
import re
import secrets
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


DEFAULT_V4_API_URL = "http://216.236.36.68:8080"
DEFAULT_V5_API_URL = "http://216.236.36.66:8080"

# Edit these values if you do not want to pass credentials on the command line.
# Passwords are plain login passwords; this script sends SHA-512 to ZStack.
CONFIG_V4_API_URL = DEFAULT_V4_API_URL
CONFIG_V4_ACCOUNT_NAME = "admin"
CONFIG_V4_USERNAME = "admin"
CONFIG_V4_PASSWORD = "vKagHQ0V"
CONFIG_V4_SESSION_UUID = ""

CONFIG_V5_API_URL = DEFAULT_V5_API_URL
CONFIG_V5_ACCOUNT_NAME = "admin"
CONFIG_V5_USERNAME = "admin"
CONFIG_V5_PASSWORD = "hRGeNrZ"
CONFIG_V5_SESSION_UUID = ""

# Map v4 L3 network UUIDs to v5 L3 network UUIDs.
# If every migrated VM should use the same v5 L3 network, fill this only.
CONFIG_V5_L3_NETWORK_UUID = "c09a923ea3874594b9e872f65d6fb383"
CONFIG_V5_PRIMARY_STORAGE_UUID = "29123f55e7214202aabe27dc9eedb756"

# qemu-img conversion runs on this host after the v5 VM is created and both VMs are stopped.
CONFIG_SSH_HOST = "216.236.36.70"
CONFIG_SSH_USERNAME = "root"
sshmigrate_vm_passwd = "*c1c*kBb6"
CONFIG_ENABLE_QEMU_IMG_COPY = True

# Service-management callback after a VM migration completes successfully.
CONFIG_BACKEND_SYNC_ENABLED = True
CONFIG_MIGRATE_API_URL = "https://hk-hook-api.alla.monster/v1/inner/instance/migrate"
CONFIG_MIGRATE_API_KEY = "wR7EpiqrMAoJ6BqVIGeVIj6dLo0Xi6Ok"
CONFIG_MIGRATE_API_TIMEOUT_SECONDS = 30
CONFIG_MIGRATE_API_RETRIES = 3

# For multiple networks, map each v4 L3 network UUID to the matching v5 UUID.
# Example:
# CONFIG_L3_NETWORK_UUID_MAP = {
#     "v4-l3-uuid": "v5-l3-uuid",
# }
#三层网络uuid
CONFIG_L3_NETWORK_UUID_MAP = {}

CONFIG_EXECUTE = True
CONFIG_STOP_SOURCE_VM = True
CONFIG_SOURCE_STOP_TYPE = "grace"
CONFIG_CREATE_STRATEGY = "CreateStopped"
CONFIG_VERIFY_TARGET_BOOT_BEFORE_COPY = True
CONFIG_WAIT_TARGET_RUNNING_SECONDS = 60
CONFIG_VM_PASSWORD_ACCOUNT = "root"
CONFIG_FALLBACK_CHANGE_VM_PASSWORD_AFTER_CREATE = False
CONFIG_SET_IPV6_STATIC_IP_TAG = True


class MigrationError(RuntimeError):
    pass


def sha512_password(password: str) -> str:
    return hashlib.sha512(password.encode("utf-8")).hexdigest()


def random_password(length: int = 18) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%*-_=+"
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in value)
            and any(c.isupper() for c in value)
            and any(c.isdigit() for c in value)
            and any(c in "!@#$%*-_=+" for c in value)
        ):
            return value


def random_console_password(length: int = 8) -> str:
    # libvirt VNC passwords must be 8 characters or fewer.
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def format_static_ip_for_system_tag(ip: str) -> str:
    parsed = ipaddress.ip_address(ip)
    if parsed.version == 6:
        return parsed.exploded
    return ip


def normalize_name(value: str | None) -> str:
    value = (value or "").lower()
    return re.sub(r"[^a-z0-9]+", "", value)


@dataclass
class ZStackClient:
    base_url: str
    account_name: str | None = None
    username: str | None = None
    password: str | None = None
    session_uuid: str | None = None
    timeout: int = 30

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        query: list[str] | None = None,
        auth: bool = True,
    ) -> dict[str, Any]:
        headers = {"Content-Type": "application/json;charset=UTF-8", "Accept": "application/json"}
        if auth and self.session_uuid:
            headers["Authorization"] = f"OAuth {self.session_uuid}"

        data = json.dumps(body).encode("utf-8") if body is not None else None
        url = self.base_url + path
        if query:
            url += "?" + urllib.parse.urlencode([("q", q) for q in query])

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            raise MigrationError(f"{method} {url} failed: HTTP {exc.code}: {raw[:800]}") from exc
        except urllib.error.URLError as exc:
            raise MigrationError(f"{method} {url} failed: {exc}") from exc

        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise MigrationError(f"{method} {url} returned non-JSON: {raw[:800]}") from exc

    def login(self) -> None:
        if self.session_uuid:
            return
        if not self.username:
            self.username = input("ZStack username: ").strip()
        if not self.account_name:
            self.account_name = self.username
        if self.password is None:
            self.password = getpass.getpass("ZStack password: ")

        hashed_password = sha512_password(self.password)
        login_bodies = [
            {
                "logInByAccount": {
                    "accountName": self.username,
                    "password": hashed_password,
                }
            },
            {
                "logInByUser": {
                    "accountName": self.account_name,
                    "userName": self.username,
                    "password": hashed_password,
                }
            },
        ]
        errors = []
        for body in login_bodies:
            try:
                resp = self._request("PUT", "/zstack/v1/accounts/login", body=body, auth=False)
                inventory = resp.get("inventory") or {}
                token = inventory.get("uuid") or resp.get("sessionUuid")
                if token:
                    self.session_uuid = token
                    return
                errors.append(f"no session UUID returned: {resp}")
            except MigrationError as exc:
                errors.append(str(exc))
        raise MigrationError("Login failed. Attempts: " + " | ".join(errors))

    def logout(self) -> None:
        if not self.session_uuid:
            return
        try:
            self._request(
                "DELETE",
                f"/zstack/v1/accounts/sessions/{self.session_uuid}",
                auth=True,
            )
        except MigrationError:
            pass
        finally:
            self.session_uuid = None

    def query_vm_by_ip(self, ip: str) -> dict[str, Any]:
        # ZStack query conditions use q=name=value. Cross-table conditions are supported.
        condition_sets = [
            [f"vmNics.ip={ip}"],
            [f"vmNics.usedIps.ip={ip}"],
            [f"vmNics.usedIp.ip={ip}"],
        ]
        errors: list[str] = []
        for conditions in condition_sets:
            try:
                resp = self._request("GET", "/zstack/v1/vm-instances", query=conditions)
                inventories = resp.get("inventories") or resp.get("Inventories") or []
                if inventories:
                    return self.get_vm(inventories[0]["uuid"])
                errors.append(f"{conditions}: no inventories")
            except MigrationError as exc:
                errors.append(f"{conditions}: {exc}")
        raise MigrationError(f"No VM found by IP {ip}. Attempts: " + " | ".join(errors))

    def query_vm_by_mac(self, mac: str) -> list[dict[str, Any]]:
        resp = self._request("GET", "/zstack/v1/vm-instances", query=[f"vmNics.mac={mac}"])
        return resp.get("inventories") or []

    def query_vms_by_name(self, name: str) -> list[dict[str, Any]]:
        resp = self._request("GET", "/zstack/v1/vm-instances", query=[f"name={name}"])
        return resp.get("inventories") or []

    def get_vm(self, uuid: str) -> dict[str, Any]:
        resp = self._request("GET", f"/zstack/v1/vm-instances/{uuid}")
        inventory = resp.get("inventory") or (resp.get("inventories") or [None])[0] or resp
        if not inventory.get("uuid"):
            raise MigrationError(f"VM detail response has no inventory UUID: {resp}")
        return inventory

    def query_volumes_by_vm(self, vm_uuid: str) -> list[dict[str, Any]]:
        volumes: list[dict[str, Any]] = []
        seen: set[str] = set()
        condition_sets = [
            [f"vmInstanceUuid={vm_uuid}"],
            [f"vmInstance.uuid={vm_uuid}"],
        ]
        errors: list[str] = []
        for conditions in condition_sets:
            try:
                resp = self._request("GET", "/zstack/v1/volumes", query=conditions)
                for volume in resp.get("inventories") or []:
                    uuid = volume.get("uuid")
                    if uuid and uuid not in seen:
                        seen.add(uuid)
                        volumes.append(volume)
            except MigrationError as exc:
                errors.append(f"{conditions}: {exc}")
        return volumes

    def get_volume(self, uuid: str) -> dict[str, Any]:
        resp = self._request("GET", f"/zstack/v1/volumes/{uuid}")
        inventory = resp.get("inventory") or (resp.get("inventories") or [None])[0] or resp
        if not inventory.get("uuid"):
            raise MigrationError(f"Volume detail response has no inventory UUID: {resp}")
        return inventory

    def get_image(self, uuid: str) -> dict[str, Any]:
        resp = self._request("GET", f"/zstack/v1/images/{uuid}")
        return resp.get("inventory") or (resp.get("inventories") or [None])[0] or resp

    def query_images(self) -> list[dict[str, Any]]:
        resp = self._request("GET", "/zstack/v1/images")
        return resp.get("inventories") or []

    def query_instance_offerings(self, cpu_num: int, memory_size: int) -> list[dict[str, Any]]:
        resp = self._request(
            "GET",
            "/zstack/v1/instance-offerings",
            query=[f"cpuNum={cpu_num}", f"memorySize={memory_size}"],
        )
        return resp.get("inventories") or []

    def create_instance_offering(self, name: str, cpu_num: int, memory_size: int) -> dict[str, Any]:
        body = {"params": {"name": name, "cpuNum": cpu_num, "memorySize": memory_size}}
        resp = self._request("POST", "/zstack/v1/instance-offerings", body=body)
        resp = self.wait_async_response(resp, f"create instance offering {name}")
        return self.extract_inventory(resp)

    def query_disk_offerings(self, disk_size: int) -> list[dict[str, Any]]:
        resp = self._request("GET", "/zstack/v1/disk-offerings", query=[f"diskSize={disk_size}"])
        return resp.get("inventories") or []

    def create_disk_offering(self, name: str, disk_size: int) -> dict[str, Any]:
        body = {"params": {"name": name, "diskSize": disk_size}}
        resp = self._request("POST", "/zstack/v1/disk-offerings", body=body)
        resp = self.wait_async_response(resp, f"create disk offering {name}")
        return self.extract_inventory(resp)

    def get_l3_network(self, uuid: str) -> dict[str, Any]:
        resp = self._request("GET", f"/zstack/v1/l3-networks/{uuid}")
        return resp.get("inventory") or (resp.get("inventories") or [None])[0] or resp

    def query_l3_networks_by_name(self, name: str) -> list[dict[str, Any]]:
        resp = self._request("GET", "/zstack/v1/l3-networks", query=[f"name={name}"])
        return resp.get("inventories") or []

    def query_ip_ranges_by_l3(self, l3_uuid: str) -> list[dict[str, Any]]:
        resp = self._request(
            "GET",
            "/zstack/v1/l3-networks/ip-ranges",
            query=[f"l3NetworkUuid={l3_uuid}"],
        )
        return resp.get("inventories") or []

    def get_primary_storage(self, uuid: str) -> dict[str, Any]:
        resp = self._request("GET", f"/zstack/v1/primary-storage/{uuid}")
        return resp.get("inventory") or (resp.get("inventories") or [None])[0] or resp

    def query_primary_storage_by_name(self, name: str) -> list[dict[str, Any]]:
        resp = self._request("GET", "/zstack/v1/primary-storage", query=[f"name={name}"])
        return resp.get("inventories") or []

    def stop_vm(self, uuid: str, stop_type: str = "grace") -> dict[str, Any]:
        body = {"stopVmInstance": {"type": stop_type}}
        return self._request("PUT", f"/zstack/v1/vm-instances/{uuid}/actions", body=body)

    def start_vm(self, uuid: str) -> dict[str, Any]:
        body = {"startVmInstance": {}}
        return self._request("PUT", f"/zstack/v1/vm-instances/{uuid}/actions", body=body)

    def wait_vm_state(self, uuid: str, expected: str, timeout_sec: int = 300) -> dict[str, Any]:
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            vm = self.get_vm(uuid)
            if vm.get("state") == expected:
                return vm
            time.sleep(5)
        raise MigrationError(f"VM {uuid} did not reach state {expected} within {timeout_sec}s")

    def create_vm(self, payload: dict[str, Any], system_tags: list[str]) -> dict[str, Any]:
        body = {"params": payload, "systemTags": system_tags, "userTags": []}
        resp = self._request("POST", "/zstack/v1/vm-instances", body=body)
        resp = self.wait_async_response(resp, f"create VM {payload.get('name')}")
        return self.extract_inventory(resp)

    def wait_async_response(self, resp: dict[str, Any], action: str) -> dict[str, Any]:
        location = resp.get("location")
        if not location:
            return resp
        timeout_ms = int(resp.get("apiTimeout") or 900000)
        timeout_sec = max(60, timeout_ms // 1000 + 30)
        print(f"Waiting API job for {action}: {location}", flush=True)
        return self.wait_api_job(location, timeout_sec=timeout_sec)

    def wait_api_job(self, location: str, timeout_sec: int = 900) -> dict[str, Any]:
        path = urllib.parse.urlparse(location).path
        if not path:
            raise MigrationError(f"Invalid API job location: {location}")
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            resp = self._request("GET", path)
            if resp.get("inventory") or resp.get("inventories"):
                return resp
            for result_key in ("result", "jobResult"):
                result_value = resp.get(result_key)
                if isinstance(result_value, str):
                    try:
                        parsed = json.loads(result_value)
                    except json.JSONDecodeError:
                        parsed = None
                    if isinstance(parsed, dict) and (parsed.get("inventory") or parsed.get("inventories")):
                        return parsed
                elif isinstance(result_value, dict) and (
                    result_value.get("inventory") or result_value.get("inventories")
                ):
                    return result_value
            job = resp.get("inventory") or (resp.get("inventories") or [None])[0] or resp
            state = job.get("state") or job.get("status")
            if state in {"Done", "Succeeded", "Success", "Failed"}:
                if state == "Failed":
                    raise MigrationError(f"API job failed: {resp}")
                return resp
            if resp.get("success") is True and (job.get("jobResult") or job.get("result") or job.get("inventory")):
                return resp
            time.sleep(5)
        raise MigrationError(f"API job did not finish within {timeout_sec}s: {location}")

    def set_console_password(self, uuid: str, password: str) -> dict[str, Any]:
        body = {"setVmConsolePassword": {"consolePassword": password}}
        return self._request("PUT", f"/zstack/v1/vm-instances/{uuid}/actions", body=body)

    def change_vm_password(self, uuid: str, account: str, password: str) -> dict[str, Any]:
        body = {"changeVmPassword": {"account": account, "password": password}}
        return self._request("PUT", f"/zstack/v1/vm-instances/{uuid}/actions", body=body)

    @staticmethod
    def extract_inventory(resp: dict[str, Any]) -> dict[str, Any]:
        inventory = resp.get("inventory") or (resp.get("inventories") or [None])[0]
        if not inventory:
            return resp
        return inventory


def normalize_vm_plan(vm: dict[str, Any], volumes: list[dict[str, Any]]) -> dict[str, Any]:
    nics = vm.get("vmNics") or []
    root_volume_uuid = vm.get("rootVolumeUuid")
    root_volume = next((v for v in volumes if v.get("uuid") == root_volume_uuid), None)
    data_volumes = [v for v in volumes if v.get("uuid") != root_volume_uuid]
    return {
        "sourceVm": {
            "uuid": vm.get("uuid"),
            "name": vm.get("name"),
            "state": vm.get("state"),
            "cpuNum": vm.get("cpuNum"),
            "memorySizeBytes": vm.get("memorySize"),
            "platform": vm.get("platform"),
            "architecture": vm.get("architecture"),
            "imageUuid": vm.get("imageUuid"),
            "instanceOfferingUuid": vm.get("instanceOfferingUuid"),
            "rootVolumeUuid": root_volume_uuid,
        },
        "network": [
            {
                "nicUuid": nic.get("uuid"),
                "l3NetworkUuid": nic.get("l3NetworkUuid"),
                "ip": nic.get("ip"),
                "ipVersion": nic.get("ipVersion"),
                "mac": nic.get("mac"),
                "netmask": nic.get("netmask"),
                "gateway": nic.get("gateway"),
                "usedIps": nic.get("usedIps"),
            }
            for nic in nics
        ],
        "rootVolume": root_volume,
        "dataVolumes": data_volumes,
        "createPayloadDraft": {
            "name": vm.get("name"),
            "description": vm.get("description"),
            "instanceOfferingUuid": vm.get("instanceOfferingUuid"),
            "imageUuid": vm.get("imageUuid"),
            "l3NetworkUuids": sorted({nic.get("l3NetworkUuid") for nic in nics if nic.get("l3NetworkUuid")}),
            "strategy": "CreateStopped",
            "rootVolumeInstallPath": root_volume.get("installPath") if root_volume else None,
            "dataVolumeInstallPaths": [v.get("installPath") for v in data_volumes],
        },
    }


def pick_image_by_source_name(target: ZStackClient, source_image: dict[str, Any]) -> dict[str, Any]:
    source_name = source_image.get("name")
    if not source_name:
        raise MigrationError(f"Source image has no name: {source_image}")
    source_key = normalize_name(source_name)
    images = target.query_images()
    exact = [img for img in images if normalize_name(img.get("name")) == source_key]
    if exact:
        return exact[0]
    fuzzy = [img for img in images if source_key in normalize_name(img.get("name")) or normalize_name(img.get("name")) in source_key]
    if fuzzy:
        return fuzzy[0]
    names = ", ".join(img.get("name", "<unnamed>") for img in images[:20])
    raise MigrationError(f"No target image matched source image '{source_name}'. Target images include: {names}")


def pick_or_create_instance_offering(target: ZStackClient, vm: dict[str, Any], create_missing: bool) -> dict[str, Any]:
    cpu_num = int(vm["cpuNum"])
    memory_size = int(vm["memorySize"])
    offerings = [
        offering
        for offering in target.query_instance_offerings(cpu_num, memory_size)
        if offering.get("type") in (None, "", "UserVm")
    ]
    if offerings:
        return offerings[0]
    name = f"migrate-{cpu_num}c-{memory_size // 1024 // 1024}m"
    if not create_missing:
        return {"uuid": "<will-create-instance-offering>", "name": name, "cpuNum": cpu_num, "memorySize": memory_size}
    offering = target.create_instance_offering(name, cpu_num, memory_size)
    if not offering.get("uuid"):
        raise MigrationError(f"Failed to create instance offering {name}: {offering}")
    return offering


def pick_or_create_root_disk_offering(
    target: ZStackClient,
    root_volume: dict[str, Any],
    create_missing: bool,
) -> dict[str, Any]:
    size = int(root_volume["size"])
    offerings = target.query_disk_offerings(size)
    if offerings:
        return offerings[0]
    name = f"migrate-root-{size // 1024 // 1024 // 1024}g"
    if not create_missing:
        return {"uuid": "<will-create-root-disk-offering>", "name": name, "diskSize": size}
    offering = target.create_disk_offering(name, size)
    if not offering.get("uuid"):
        raise MigrationError(f"Failed to create root disk offering {name}: {offering}")
    return offering


def map_l3_networks(source: ZStackClient, target: ZStackClient, nics: list[dict[str, Any]]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for nic in nics:
        source_uuid = nic.get("l3NetworkUuid")
        if not source_uuid or source_uuid in mapping:
            continue
        configured_target_uuid = CONFIG_L3_NETWORK_UUID_MAP.get(source_uuid) or CONFIG_V5_L3_NETWORK_UUID
        if configured_target_uuid:
            try:
                target.get_l3_network(configured_target_uuid)
            except MigrationError as exc:
                raise MigrationError(
                    f"Configured target L3 network UUID not found: v4 {source_uuid} -> v5 {configured_target_uuid}"
                ) from exc
            mapping[source_uuid] = configured_target_uuid
            continue
        try:
            target.get_l3_network(source_uuid)
            mapping[source_uuid] = source_uuid
            continue
        except MigrationError:
            pass
        source_l3 = source.get_l3_network(source_uuid)
        target_l3s = target.query_l3_networks_by_name(source_l3.get("name", ""))
        if not target_l3s:
            all_target_l3s_resp = target._request("GET", "/zstack/v1/l3-networks")
            all_target_l3s = all_target_l3s_resp.get("inventories") or []
            choices = ", ".join(
                f"{item.get('name')}={item.get('uuid')}" for item in all_target_l3s[:20]
            )
            raise MigrationError(
                f"No target L3 network matched source L3 '{source_l3.get('name')}' ({source_uuid}). "
                f"Set CONFIG_L3_NETWORK_UUID_MAP. Target L3 choices: {choices}"
            )
        mapping[source_uuid] = target_l3s[0]["uuid"]
    return mapping


def map_primary_storage(source: ZStackClient, target: ZStackClient, root_volume: dict[str, Any]) -> str | None:
    if CONFIG_V5_PRIMARY_STORAGE_UUID:
        try:
            target.get_primary_storage(CONFIG_V5_PRIMARY_STORAGE_UUID)
        except MigrationError as exc:
            raise MigrationError(
                f"Configured v5 primary storage UUID not found: {CONFIG_V5_PRIMARY_STORAGE_UUID}"
            ) from exc
        return CONFIG_V5_PRIMARY_STORAGE_UUID

    source_uuid = root_volume.get("primaryStorageUuid")
    if not source_uuid:
        return None
    try:
        target.get_primary_storage(source_uuid)
        return source_uuid
    except MigrationError:
        pass
    source_ps = source.get_primary_storage(source_uuid)
    matches = target.query_primary_storage_by_name(source_ps.get("name", ""))
    if not matches:
        raise MigrationError(
            f"No target primary storage matched source primary storage '{source_ps.get('name')}' ({source_uuid})"
        )
    return matches[0]["uuid"]


def collect_ips(nics: list[dict[str, Any]]) -> list[tuple[str, int | None, str]]:
    result: list[tuple[str, int | None, str]] = []
    for nic in nics:
        l3_uuid = nic.get("l3NetworkUuid")
        if nic.get("ip"):
            result.append((nic["ip"], nic.get("ipVersion") or 4, l3_uuid))
        for used_ip in nic.get("usedIps") or []:
            ip = used_ip.get("ip")
            if ip and all(existing[0] != ip for existing in result):
                result.append((ip, used_ip.get("ipVersion"), l3_uuid))
    return result


def ip_range_contains(ip_range: dict[str, Any], ip: str) -> bool:
    address = ipaddress.ip_address(ip)
    network_cidr = ip_range.get("networkCidr")
    if network_cidr:
        try:
            return address in ipaddress.ip_network(network_cidr, strict=False)
        except (TypeError, ValueError):
            pass
    start_ip = ip_range.get("startIp")
    end_ip = ip_range.get("endIp")
    if start_ip and end_ip:
        try:
            return ipaddress.ip_address(start_ip) <= address <= ipaddress.ip_address(end_ip)
        except (TypeError, ValueError):
            pass
    return False


def validate_target_ipv6_ranges(
    target: ZStackClient,
    nics: list[dict[str, Any]],
    l3_mapping: dict[str, str],
) -> None:
    ranges_by_l3: dict[str, list[dict[str, Any]]] = {}
    for nic in nics:
        source_l3_uuid = nic.get("l3NetworkUuid")
        target_l3_uuid = l3_mapping.get(source_l3_uuid)
        if not target_l3_uuid:
            continue
        if target_l3_uuid not in ranges_by_l3:
            ranges_by_l3[target_l3_uuid] = target.query_ip_ranges_by_l3(target_l3_uuid)
        target_ranges = ranges_by_l3[target_l3_uuid]
        for used_ip in nic.get("usedIps") or []:
            ip = used_ip.get("ip")
            if not ip or used_ip.get("ipVersion") != 6:
                continue
            if any(ip_range_contains(ip_range, ip) for ip_range in target_ranges):
                continue
            available = [
                {
                    "networkCidr": item.get("networkCidr"),
                    "startIp": item.get("startIp"),
                    "endIp": item.get("endIp"),
                    "prefixLen": item.get("prefixLen"),
                    "gateway": item.get("gateway"),
                }
                for item in target_ranges
                if item.get("ipVersion") == 6 or ":" in str(item.get("startIp") or item.get("networkCidr") or "")
            ]
            raise MigrationError(
                f"Target L3 {target_l3_uuid} has no IPv6 range containing {ip}. "
                f"Source gateway={used_ip.get('gateway')}, netmask={used_ip.get('netmask')}. "
                f"Configure the matching IPv6 CIDR/range on the v5 L3 before migration. "
                f"Current target IPv6 ranges: {available}"
            )


def find_vm_uuid(value: Any) -> str | None:
    if isinstance(value, dict):
        if value.get("uuid") and (
            value.get("type") == "UserVm"
            or value.get("hypervisorType")
            or value.get("rootVolumeUuid")
            or value.get("vmNics") is not None
        ):
            return value["uuid"]
        for key in ("inventory", "result", "jobResult", "rsp", "response"):
            if key in value:
                if isinstance(value[key], str):
                    try:
                        parsed = json.loads(value[key])
                    except json.JSONDecodeError:
                        parsed = None
                    found = find_vm_uuid(parsed)
                else:
                    found = find_vm_uuid(value[key])
                if found:
                    return found
        for nested in value.values():
            found = find_vm_uuid(nested)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = find_vm_uuid(item)
            if found:
                return found
    return None


def find_vm_uuid_in_text(value: str) -> str | None:
    match = re.search(r"vm\[uuid:([0-9a-fA-F]+)\s+name:", value)
    if match:
        return match.group(1)
    return None


def find_target_vm_by_name(target: ZStackClient, name: str) -> dict[str, Any] | None:
    matches = target.query_vms_by_name(name)
    if not matches:
        return None
    return sorted(matches, key=lambda vm: vm.get("createDate", ""), reverse=True)[0]


def primary_ipv4_from_plan(plan: dict[str, Any]) -> str | None:
    for nic in plan.get("network") or []:
        for used_ip in nic.get("usedIps") or []:
            if used_ip.get("ipVersion") == 4 and used_ip.get("ip"):
                return used_ip["ip"]
        ip = nic.get("ip")
        if ip:
            try:
                if ipaddress.ip_address(ip).version == 4:
                    return ip
            except ValueError:
                pass
    return None


def wait_target_vm_by_ip_or_name(
    target: ZStackClient,
    ipv4: str | None,
    name: str,
    timeout_sec: int = 60,
) -> dict[str, Any] | None:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if ipv4:
            try:
                return target.query_vm_by_ip(ipv4)
            except MigrationError as exc:
                if "No VM found by IP" not in str(exc):
                    raise
        found = find_target_vm_by_name(target, name)
        if found:
            return found
        time.sleep(3)
    return find_target_vm_by_name(target, name)


def assert_target_addresses_free(target: ZStackClient, nics: list[dict[str, Any]]) -> None:
    for ip, _ip_version, _l3_uuid in collect_ips(nics):
        try:
            found = target.query_vm_by_ip(ip)
            raise MigrationError(
                f"Target IP {ip} is already occupied by VM {found.get('name')} ({found.get('uuid')})"
            )
        except MigrationError as exc:
            if "No VM found by IP" not in str(exc):
                raise
    for nic in nics:
        mac = nic.get("mac")
        if not mac:
            continue
        matches = target.query_vm_by_mac(mac)
        for vm in matches:
            raise MigrationError(
                f"Target MAC {mac} is already occupied by VM {vm.get('name')} ({vm.get('uuid')})"
            )


def build_target_create_spec(
    source: ZStackClient,
    target: ZStackClient,
    plan: dict[str, Any],
    vm_password: str,
    console_password: str,
    create_missing_resources: bool,
) -> tuple[dict[str, Any], list[str], dict[str, Any]]:
    source_vm = plan["sourceVm"]
    root_volume = plan["rootVolume"]
    if not root_volume:
        raise MigrationError("Source VM has no root volume information")

    vm_detail = source.get_vm(source_vm["uuid"])
    source_image = source.get_image(source_vm["imageUuid"])
    target_image = pick_image_by_source_name(target, source_image)
    l3_mapping = map_l3_networks(source, target, vm_detail.get("vmNics") or [])
    validate_target_ipv6_ranges(target, vm_detail.get("vmNics") or [], l3_mapping)
    target_offering = pick_or_create_instance_offering(target, vm_detail, create_missing_resources)
    root_disk_offering = pick_or_create_root_disk_offering(target, root_volume, create_missing_resources)
    primary_storage_uuid = map_primary_storage(source, target, root_volume)

    target_l3_uuids = sorted(set(l3_mapping.values()))
    payload = {
        "name": source_vm["name"],
        "description": f"migrated from {source_vm['uuid']}",
        "instanceOfferingUuid": target_offering["uuid"],
        "imageUuid": target_image["uuid"],
        "l3NetworkUuids": target_l3_uuids,
        "defaultL3NetworkUuid": l3_mapping.get(vm_detail.get("defaultL3NetworkUuid")) or target_l3_uuids[0],
        "rootDiskOfferingUuid": root_disk_offering["uuid"],
        "strategy": CONFIG_CREATE_STRATEGY,
        "account": CONFIG_VM_PASSWORD_ACCOUNT,
        "password": vm_password,
    }
    if primary_storage_uuid:
        payload["rootPrimaryStorageUuid"] = primary_storage_uuid

    system_tags = [f"consolePassword::{console_password}"]
    skipped_ipv6_static_ips = []
    for nic in vm_detail.get("vmNics") or []:
        target_l3_uuid = l3_mapping[nic["l3NetworkUuid"]]
        if nic.get("mac"):
            system_tags.append(f"customMac::{target_l3_uuid}::{nic['mac']}")
        for ip, _ip_version, source_l3_uuid in collect_ips([nic]):
            if _ip_version == 6 and not CONFIG_SET_IPV6_STATIC_IP_TAG:
                skipped_ipv6_static_ips.append({"l3NetworkUuid": l3_mapping[source_l3_uuid], "ip": ip})
                continue
            system_tags.append(f"staticIp::{l3_mapping[source_l3_uuid]}::{format_static_ip_for_system_tag(ip)}")

    resolved = {
        "sourceImage": {"uuid": source_image.get("uuid"), "name": source_image.get("name")},
        "targetImage": {"uuid": target_image.get("uuid"), "name": target_image.get("name")},
        "targetInstanceOffering": target_offering,
        "targetRootDiskOffering": root_disk_offering,
        "l3NetworkMapping": l3_mapping,
        "targetPrimaryStorageUuid": primary_storage_uuid,
        "vmPasswordAccount": CONFIG_VM_PASSWORD_ACCOUNT,
        "vmPassword": vm_password,
        "consolePassword": console_password,
        "skippedIpv6StaticIps": skipped_ipv6_static_ips,
    }
    return payload, system_tags, resolved


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="migrate")
    parser.add_argument("-ip", "--ip", required=True, help="source VM IPv4 address, or comma-separated IPv4 addresses")
    parser.add_argument("--v4-api-url", default=os.getenv("ZSTACK_V4_API_URL") or CONFIG_V4_API_URL)
    parser.add_argument("--v4-account-name", default=os.getenv("ZSTACK_V4_ACCOUNT_NAME") or CONFIG_V4_ACCOUNT_NAME or None)
    parser.add_argument("--v4-username", default=os.getenv("ZSTACK_V4_USERNAME") or CONFIG_V4_USERNAME or None)
    parser.add_argument("--v4-password", default=os.getenv("ZSTACK_V4_PASSWORD") or CONFIG_V4_PASSWORD or None)
    parser.add_argument("--v4-session-uuid", default=os.getenv("ZSTACK_V4_SESSION_UUID") or CONFIG_V4_SESSION_UUID or None)
    parser.add_argument("--v5-api-url", default=os.getenv("ZSTACK_V5_API_URL") or CONFIG_V5_API_URL)
    parser.add_argument("--v5-account-name", default=os.getenv("ZSTACK_V5_ACCOUNT_NAME") or CONFIG_V5_ACCOUNT_NAME or None)
    parser.add_argument("--v5-username", default=os.getenv("ZSTACK_V5_USERNAME") or CONFIG_V5_USERNAME or None)
    parser.add_argument("--v5-password", default=os.getenv("ZSTACK_V5_PASSWORD") or CONFIG_V5_PASSWORD or None)
    parser.add_argument("--v5-session-uuid", default=os.getenv("ZSTACK_V5_SESSION_UUID") or CONFIG_V5_SESSION_UUID or None)
    parser.add_argument("--api-url", dest="legacy_v4_api_url")
    parser.add_argument("--target-api-url", dest="legacy_v5_api_url")
    parser.add_argument("--execute", action="store_true", help="kept for compatibility; execute is now the default")
    parser.add_argument("--dry-run", action="store_true", help="only print the migration plan")
    parser.add_argument("--no-stop-source", action="store_true", help="do not stop source VM before creating target VM")
    parser.add_argument("--no-logout", action="store_true", help="keep the login session after command exits")
    parser.add_argument("--output-json", help="write migration plan JSON to a file")
    return parser.parse_args(argv)


def collect_plan(source: ZStackClient, ip: str) -> dict[str, Any]:
    vm = source.query_vm_by_ip(ip)
    volumes: list[dict[str, Any]] = []
    seen: set[str] = set()

    embedded = vm.get("allVolumes") or []
    for volume in embedded:
        uuid = volume.get("uuid")
        if uuid and uuid not in seen:
            seen.add(uuid)
            try:
                volumes.append(source.get_volume(uuid))
            except MigrationError:
                volumes.append(volume)

    if not volumes:
        for volume in source.query_volumes_by_vm(vm["uuid"]):
            uuid = volume.get("uuid")
            if uuid and uuid not in seen:
                seen.add(uuid)
                try:
                    volumes.append(source.get_volume(uuid))
                except MigrationError:
                    volumes.append(volume)

    root_uuid = vm.get("rootVolumeUuid")
    if root_uuid and root_uuid not in seen:
        volumes.append(source.get_volume(root_uuid))

    return normalize_vm_plan(vm, volumes)


def parse_ip_list(value: str) -> list[str]:
    ips = [item.strip() for item in value.split(",") if item.strip()]
    if not ips:
        raise MigrationError("No IP address was provided")
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise MigrationError(f"Invalid IP address: {ip}") from exc
    return ips


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def run_ssh_command(command: str) -> dict[str, Any]:
    if not CONFIG_ENABLE_QEMU_IMG_COPY:
        return {"command": command, "exitCode": 0, "stdout": "", "stderr": "", "skipped": True}
    paramiko = load_paramiko()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            CONFIG_SSH_HOST,
            username=CONFIG_SSH_USERNAME,
            password=sshmigrate_vm_passwd,
            timeout=30,
            banner_timeout=30,
            auth_timeout=30,
            look_for_keys=False,
            allow_agent=False,
        )
        stdin, stdout, stderr = client.exec_command(command, get_pty=True)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
    finally:
        client.close()

    result = {"command": command, "exitCode": exit_code, "stdout": out, "stderr": err}
    if exit_code != 0:
        raise MigrationError(
            f"SSH command failed on {CONFIG_SSH_HOST}, exit {exit_code}: {command}\n{out}{err}"
        )
    return result


def load_paramiko() -> Any:
    if not sshmigrate_vm_passwd:
        raise MigrationError("请先在脚本前面的 sshmigrate_vm_passwd 里填写 root@216.236.36.67 的密码")
    try:
        import paramiko  # type: ignore
        return paramiko
    except ImportError as exc:
        raise MigrationError("SSH 密码登录需要 Python 模块 paramiko，请先执行: pip install paramiko") from exc


def validate_execute_prerequisites() -> None:
    if CONFIG_ENABLE_QEMU_IMG_COPY:
        load_paramiko()
    if CONFIG_BACKEND_SYNC_ENABLED:
        if not CONFIG_MIGRATE_API_URL:
            raise MigrationError("Please fill CONFIG_MIGRATE_API_URL before execute mode")
        if not CONFIG_MIGRATE_API_KEY:
            raise MigrationError("Please fill CONFIG_MIGRATE_API_KEY before execute mode")


def sync_migrated_vm_to_backend(name: str, origin_uuid: str, new_uuid: str) -> dict[str, Any]:
    payload = {
        "name": name or "",
        "originUuid": origin_uuid or "",
        "newUuid": new_uuid,
    }
    data = json.dumps(payload).encode("utf-8")
    attempts = max(1, int(CONFIG_MIGRATE_API_RETRIES))
    last_error = None
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(
            CONFIG_MIGRATE_API_URL,
            data=data,
            headers={
                "Content-Type": "application/json;charset=UTF-8",
                "Accept": "application/json",
                "X-APIKEY": CONFIG_MIGRATE_API_KEY,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=CONFIG_MIGRATE_API_TIMEOUT_SECONDS) as response:
                status = getattr(response, "status", 200)
                raw = response.read().decode("utf-8", errors="replace")
            parsed = json.loads(raw) if raw else {}
            if parsed.get("data") is True:
                print(
                    f"Backend instance UUID sync succeeded: {origin_uuid} -> {new_uuid}",
                    flush=True,
                )
                return {
                    "success": True,
                    "attempts": attempt,
                    "httpStatus": status,
                    "request": payload,
                    "response": parsed,
                }
            last_error = f"HTTP {status} returned unexpected response: {raw[:800]}"
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            last_error = f"HTTP {exc.code}: {raw[:800]}"
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = str(exc)

        if attempt < attempts:
            print(
                f"warning: backend UUID sync attempt {attempt} failed: {last_error}; retrying",
                file=sys.stderr,
                flush=True,
            )
            time.sleep(2)

    print(f"warning: backend UUID sync failed: {last_error}", file=sys.stderr, flush=True)
    return {
        "success": False,
        "attempts": attempts,
        "request": payload,
        "error": last_error,
    }


def is_root_volume(volume: dict[str, Any]) -> bool:
    volume_type = normalize_name(volume.get("type"))
    name = normalize_name(volume.get("name"))
    install_path = volume.get("installPath") or ""
    return (
        "root" in volume_type
        or name.startswith("root")
        or "/rootVolumes/" in install_path
    )


def get_root_volume(client: ZStackClient, vm: dict[str, Any]) -> dict[str, Any]:
    root_uuid = vm.get("rootVolumeUuid")
    if root_uuid:
        return client.get_volume(root_uuid)
    for volume in vm.get("allVolumes") or []:
        if is_root_volume(volume):
            uuid = volume.get("uuid")
            return client.get_volume(uuid) if uuid else volume
    volumes = []
    for volume in client.query_volumes_by_vm(vm["uuid"]):
        uuid = volume.get("uuid")
        if uuid:
            try:
                volume = client.get_volume(uuid)
            except MigrationError:
                pass
        volumes.append(volume)
        if is_root_volume(volume):
            uuid = volume.get("uuid")
            return client.get_volume(uuid) if uuid else volume
    if len(volumes) == 1:
        return volumes[0]
    raise MigrationError(f"Unable to find root volume for VM {vm.get('name')} ({vm.get('uuid')})")


def wait_root_volume(client: ZStackClient, vm_uuid: str, timeout_sec: int = 180) -> dict[str, Any]:
    deadline = time.time() + timeout_sec
    last_error = None
    while time.time() < deadline:
        try:
            vm = client.get_vm(vm_uuid)
            volume = get_root_volume(client, vm)
            if volume.get("installPath"):
                return volume
            last_error = MigrationError(f"Root volume has no installPath yet: {volume}")
        except MigrationError as exc:
            last_error = exc
        time.sleep(3)
    raise MigrationError(f"Unable to find root volume for VM {vm_uuid} within {timeout_sec}s: {last_error}")


def qemu_img_convert_and_compare(source_path: str, target_path: str) -> dict[str, Any]:
    if not source_path or not target_path:
        raise MigrationError(f"Missing qemu-img path. source={source_path}, target={target_path}")
    source_arg = shell_quote(source_path)
    target_arg = shell_quote(target_path)
    convert_command = f"qemu-img convert -O qcow2 {source_arg} {target_arg}"
    compare_command = (
        f"qemu-img compare -p -f qcow2 -F qcow2 {source_arg} {target_arg}; "
        "rc=$?; echo __COMPARE_EXIT_CODE__:$rc; exit $rc"
    )
    print(f"Running qemu-img convert on {CONFIG_SSH_HOST}: {source_path} -> {target_path}", flush=True)
    convert_result = run_ssh_command(convert_command)
    print("Running qemu-img compare on target host", flush=True)
    compare_result = run_ssh_command(compare_command)
    compare_exit_code = compare_result["exitCode"]
    marker = re.search(r"__COMPARE_EXIT_CODE__:(\d+)", compare_result.get("stdout", ""))
    if marker:
        compare_exit_code = int(marker.group(1))
    print(f"qemu-img compare echo $? = {compare_exit_code}", flush=True)
    if compare_exit_code == 0:
        print("qemu-img compare 比对没问题", flush=True)
    return {
        "sshHost": CONFIG_SSH_HOST,
        "sourcePath": source_path,
        "targetPath": target_path,
        "convert": convert_result,
        "compare": compare_result,
        "compareExitCode": compare_exit_code,
        "comparePassed": compare_exit_code == 0,
    }


def verify_target_boot_then_stop(target: ZStackClient, vm_uuid: str) -> dict[str, Any]:
    result = {"bootVerified": False, "stoppedBeforeCopy": False, "startError": None}
    vm = target.get_vm(vm_uuid)
    if vm.get("state") != "Running":
        print(f"Starting target VM for boot verification {vm.get('name')} ({vm_uuid})", flush=True)
        try:
            target.start_vm(vm_uuid)
        except MigrationError as exc:
            result["startError"] = str(exc)

    deadline = time.time() + CONFIG_WAIT_TARGET_RUNNING_SECONDS
    while time.time() < deadline:
        vm = target.get_vm(vm_uuid)
        if vm.get("state") == "Running":
            result["bootVerified"] = True
            break
        time.sleep(3)

    if not result["bootVerified"]:
        vm = target.get_vm(vm_uuid)
        if result["startError"]:
            raise MigrationError(
                f"Target VM did not reach Running before copy. state={vm.get('state')}. "
                f"start error: {result['startError']}"
            )
        raise MigrationError(f"Target VM did not reach Running before copy. state={vm.get('state')}")

    print(f"Stopping target VM before qemu-img copy {vm.get('name')} ({vm_uuid})", flush=True)
    target.stop_vm(vm_uuid, CONFIG_SOURCE_STOP_TYPE)
    target.wait_vm_state(vm_uuid, "Stopped")
    result["stoppedBeforeCopy"] = True
    return result


def migrate_one(
    source: ZStackClient,
    target: ZStackClient,
    ip: str,
    args: argparse.Namespace,
    should_execute: bool,
    should_stop_source: bool,
) -> dict[str, Any]:
    print(f"===== migrate {ip} =====", flush=True)
    plan = collect_plan(source, ip)
    source_original_state = plan["sourceVm"].get("state")
    if not source_original_state and plan["sourceVm"].get("uuid"):
        source_original_state = source.get_vm(plan["sourceVm"]["uuid"]).get("state")
    desired_target_state = "Running" if source_original_state == "Running" else "Stopped"
    plan["desiredTargetState"] = desired_target_state
    assert_target_addresses_free(target, plan["network"])

    vm_password = random_password()
    console_password = random_console_password()
    create_payload, system_tags, resolved = build_target_create_spec(
        source,
        target,
        plan,
        vm_password,
        console_password,
        should_execute,
    )
    plan["targetCreatePayload"] = create_payload
    plan["targetSystemTags"] = system_tags
    plan["resolvedTargetResources"] = resolved
    plan["execute"] = should_execute
    print(json.dumps(plan, ensure_ascii=False, indent=2), flush=True)

    if args.output_json and len(parse_ip_list(args.ip)) == 1:
        with open(args.output_json, "w", encoding="utf-8") as fh:
            json.dump(plan, fh, ensure_ascii=False, indent=2)

    if not should_execute:
        return {"ip": ip, "success": True, "execute": False, "plan": plan}

    source_vm = plan["sourceVm"]
    if should_stop_source and source_vm.get("uuid"):
        current = source.get_vm(source_vm["uuid"])
        if current.get("state") != "Stopped":
            print(f"Stopping source VM {source_vm.get('name')} ({source_vm.get('uuid')})", flush=True)
            source.stop_vm(source_vm["uuid"], CONFIG_SOURCE_STOP_TYPE)
        source.wait_vm_state(source_vm["uuid"], "Stopped")

    target.create_vm(create_payload, system_tags)
    target_ipv4 = primary_ipv4_from_plan(plan)
    created = wait_target_vm_by_ip_or_name(
        target,
        target_ipv4,
        create_payload["name"],
        timeout_sec=60,
    ) or {"name": create_payload["name"]}
    created_uuid = created.get("uuid")
    target_boot_check = None
    qemu_result = None
    target_started_after_copy = False
    target_start_error = None
    target_state_restored = False

    if created_uuid:
        try:
            target.set_console_password(created_uuid, console_password)
        except MigrationError as exc:
            print(f"warning: failed to set console password: {exc}", file=sys.stderr, flush=True)
        if CONFIG_FALLBACK_CHANGE_VM_PASSWORD_AFTER_CREATE:
            try:
                target.change_vm_password(created_uuid, CONFIG_VM_PASSWORD_ACCOUNT, vm_password)
            except MigrationError as exc:
                print(f"warning: failed to change VM password: {exc}", file=sys.stderr, flush=True)

        created = target.get_vm(created_uuid)
        print(f"Waiting target root volume for {created.get('name')} ({created_uuid})", flush=True)
        target_root_volume = wait_root_volume(target, created_uuid)
        source_root_volume = plan.get("rootVolume") or {}
        source_root_path = source_root_volume.get("installPath")
        target_root_path = target_root_volume.get("installPath")

        if CONFIG_VERIFY_TARGET_BOOT_BEFORE_COPY:
            source.wait_vm_state(source_vm["uuid"], "Stopped")
            target_boot_check = verify_target_boot_then_stop(target, created_uuid)

        if CONFIG_ENABLE_QEMU_IMG_COPY:
            source.wait_vm_state(source_vm["uuid"], "Stopped")
            target.wait_vm_state(created_uuid, "Stopped")
            qemu_result = qemu_img_convert_and_compare(source_root_path, target_root_path)
            if not qemu_result.get("comparePassed"):
                raise MigrationError(f"qemu-img compare failed, echo $? = {qemu_result.get('compareExitCode')}")

        if desired_target_state == "Running":
            try:
                created = target.get_vm(created_uuid)
                if created.get("state") != "Running":
                    print(
                        f"Restoring target VM state to Running {created.get('name')} ({created_uuid})",
                        flush=True,
                    )
                    target.start_vm(created_uuid)
                deadline = time.time() + CONFIG_WAIT_TARGET_RUNNING_SECONDS
                while time.time() < deadline:
                    created = target.get_vm(created_uuid)
                    if created.get("state") == "Running":
                        target_started_after_copy = True
                        target_state_restored = True
                        break
                    time.sleep(3)
                if not target_state_restored:
                    created = target.get_vm(created_uuid)
                    target_start_error = f"Target VM state is {created.get('state')}, not Running"
            except MigrationError as exc:
                target_start_error = str(exc)
        else:
            print(f"Keeping target VM Stopped to match source state ({created_uuid})", flush=True)
            target.wait_vm_state(created_uuid, "Stopped")
            target_state_restored = True
    else:
        raise MigrationError(f"Unable to find created VM by IP {target_ipv4} or name {create_payload['name']}")

    created = target.get_vm(created_uuid)
    target_final_state = created.get("state")
    qemu_passed = qemu_result is None or qemu_result.get("comparePassed")
    migration_success = (
        created_uuid is not None
        and qemu_passed
        and target_state_restored
        and target_final_state == desired_target_state
    )
    backend_sync = {
        "enabled": CONFIG_BACKEND_SYNC_ENABLED,
        "attempted": False,
        "success": not CONFIG_BACKEND_SYNC_ENABLED,
    }
    if migration_success and CONFIG_BACKEND_SYNC_ENABLED:
        print(
            f"Syncing migrated VM UUID to backend: {source_vm.get('uuid')} -> {created_uuid}",
            flush=True,
        )
        backend_sync = sync_migrated_vm_to_backend(
            source_vm.get("name") or "",
            source_vm.get("uuid") or "",
            created_uuid,
        )
        backend_sync["enabled"] = True
        backend_sync["attempted"] = True

    result = {
        "ip": ip,
        "success": migration_success and backend_sync.get("success") is True,
        "migrationSuccess": migration_success,
        "backendSync": backend_sync,
        "createdVm": created,
        "sourceOriginalState": source_original_state,
        "desiredTargetState": desired_target_state,
        "sourceRootVolumePath": (plan.get("rootVolume") or {}).get("installPath"),
        "targetRootVolumePath": qemu_result.get("targetPath") if qemu_result else None,
        "qemuImg": qemu_result,
        "targetBootCheck": target_boot_check,
        "targetStartedAfterCopy": target_started_after_copy,
        "targetStateRestored": target_state_restored,
        "targetStartError": target_start_error,
        "vmPasswordAccount": CONFIG_VM_PASSWORD_ACCOUNT,
        "vmPassword": vm_password,
        "consolePassword": console_password,
        "targetFinalState": target_final_state,
        "submittedAt": int(time.time()),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)
    return result


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    should_execute = (CONFIG_EXECUTE or args.execute) and not args.dry_run
    should_stop_source = CONFIG_STOP_SOURCE_VM and not args.no_stop_source
    ips = parse_ip_list(args.ip)
    if should_execute:
        validate_execute_prerequisites()
    v4_api_url = args.legacy_v4_api_url or args.v4_api_url
    v5_api_url = args.legacy_v5_api_url or args.v5_api_url
    source = ZStackClient(
        base_url=v4_api_url,
        account_name=args.v4_account_name,
        username=args.v4_username,
        password=args.v4_password,
        session_uuid=args.v4_session_uuid,
    )
    target = ZStackClient(
        base_url=v5_api_url,
        account_name=args.v5_account_name,
        username=args.v5_username,
        password=args.v5_password,
        session_uuid=args.v5_session_uuid,
    )
    try:
        source.login()
        target.login()
        results = []
        for ip in ips:
            try:
                results.append(migrate_one(source, target, ip, args, should_execute, should_stop_source))
            except MigrationError as exc:
                error_result = {"ip": ip, "success": False, "error": str(exc)}
                results.append(error_result)
                print(f"migrate {ip}: {exc}", file=sys.stderr, flush=True)

        if args.output_json and len(ips) > 1:
            with open(args.output_json, "w", encoding="utf-8") as fh:
                json.dump(results, fh, ensure_ascii=False, indent=2)

        batch_summary = {
            "execute": should_execute,
            "total": len(results),
            "success": sum(1 for item in results if item.get("success")),
            "failed": sum(1 for item in results if not item.get("success")),
            "results": results,
        }
        print(json.dumps({"batchSummary": batch_summary}, ensure_ascii=False, indent=2), flush=True)
        return 0 if batch_summary["failed"] == 0 else 2
    finally:
        if not args.no_logout:
            source.logout()
            target.logout()


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except MigrationError as exc:
        print(f"migrate: {exc}", file=sys.stderr)
        raise SystemExit(2)
