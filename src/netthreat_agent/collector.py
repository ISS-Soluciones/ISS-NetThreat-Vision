import platform
import socket

import psutil

from .models import (
    ConnectionObservation,
    ProcessObservation,
    ScanReport,
    SystemObservation,
)


def _address_parts(address: object) -> tuple[str | None, int | None]:
    if not address:
        return None, None
    return str(address.ip), int(address.port)


def collect_snapshot(*, include_executable_paths: bool = False) -> ScanReport:
    warnings: list[str] = []
    processes: list[ProcessObservation] = []
    process_names: dict[int, str | None] = {}

    for process in psutil.process_iter(attrs=["pid", "name", "exe"]):
        try:
            info = process.info
            pid = int(info["pid"])
            name = info.get("name")
            executable_path = info.get("exe") if include_executable_paths else None
            processes.append(ProcessObservation(pid, name, executable_path))
            process_names[pid] = name
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            warnings.append("Algunos procesos no pudieron consultarse por permisos o porque terminaron.")

    connections: list[ConnectionObservation] = []
    try:
        for connection in psutil.net_connections(kind="inet"):
            local_address, local_port = _address_parts(connection.laddr)
            remote_address, remote_port = _address_parts(connection.raddr)
            connections.append(
                ConnectionObservation(
                    pid=connection.pid,
                    process_name=process_names.get(connection.pid) if connection.pid is not None else None,
                    protocol="tcp" if connection.type == socket.SOCK_STREAM else "udp",
                    status=connection.status or "UNKNOWN",
                    local_address=local_address,
                    local_port=local_port,
                    remote_address=remote_address,
                    remote_port=remote_port,
                )
            )
    except (psutil.AccessDenied, OSError):
        warnings.append("No se pudieron consultar todas las conexiones; ejecute con permisos adecuados si lo autoriza.")

    return ScanReport.create(
        system=SystemObservation(
            operating_system=platform.system(),
            release=platform.release(),
            architecture=platform.machine(),
        ),
        processes=processes,
        connections=connections,
        warnings=sorted(set(warnings)),
    )