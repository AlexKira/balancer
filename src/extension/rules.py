#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import ipaddress
import subprocess

UTILITY: str = "/usr/sbin/iptables"

ENV_HOSTS: list[str] = [
    "SSH_HOST_TCP_IN_0",
    "BRGNETUSE_CORES_UDP_FW_0",
]

_STATIC_VARIBLES: list[str] = [
    "LOCALHOST",
    "LOGGER_NAME_TABLE_INPUT",
    "LOGGER_NAME_TABLE_FORWARD",
    "LIMIT_LOG_SEC",
]


def is_valid_ipv4_port(ip_port_string: str) -> bool:
    """
    Check if a string is a valid IPv4:PORT pair.

    Args:
        ip_port_string (str): Format "IP:PORT", e.g., "192.168.1.127:51820".

    Returns:
        bool: True if IP and port are valid (0-65535), False otherwise.
    """
    try:
        ip, port = ip_port_string.split(":")
        ipaddress.IPv4Address(ip)
        port_int = int(port)
        return 0 <= port_int <= 65535
    except (ValueError, IndexError):
        return False


def get_allow_ips() -> tuple[dict[str, list[str]], dict[str, str]]:
    """
    Get and validate IPs and ports from environment variables.

    Returns:
        tuple[dict[str, list[str]], dict[str, str]]

    Raises:
        KeyError, ValueError
    """
    allowIPs: dict[str, list[str]] = dict()
    open_port: dict[str, str] = dict()
    static_vars: dict[str, str] = dict()

    for key in ENV_HOSTS:
        value = os.getenv(key)
        if value is None:
            raise KeyError(f"error: environment variable '{key}' is not set")

        ipList: list[str] = list()
        ipList = value.strip().split(", ")
        
        if not all(is_valid_ipv4_port(x) for x in ipList):
            raise ValueError(
                f"error: environment variable '{key}' contains invalid entries. "
                f"Expected IP:PORT (e.g., 192.168.1.5:51820). "
                f"Full value: '{value}'"
            )

        allowIPs[key] = ipList
    
    for key in _STATIC_VARIBLES:
        value = os.getenv(key)
        if value is None:
            raise KeyError(f"error: environment variable '{key}' is not set")
        
        static_vars[key] = value

    return allowIPs, static_vars


def cmd_clear_iptable(default: bool = False) -> list[str]:
    """
    Generates iptables commands to clear existing rules and set base policies.

    Args:
        default (bool):
            If True, generates a minimal set of commands to flush rules
            and set default policies to ACCEPT. If False (default),
            generates a more comprehensive set including DROP policies,
            loopback, and established/related rules, and NAT table resets.

    Returns:
        List[str]: A list of iptables commands.
    """
    iptablesList: list[str] = list()
    if not default:
        iptablesList = [
            # Firewall.
            f"{UTILITY} -F",
            f"{UTILITY} -X",
            f"{UTILITY} -Z",
            f"{UTILITY} -P INPUT DROP",
            # Important for Docker to control forwarding
            f"{UTILITY} -P FORWARD DROP",

            # NAT.
            f"{UTILITY} -t nat -F",
            f"{UTILITY} -t nat -X",
            f"{UTILITY} -t nat -P PREROUTING ACCEPT",
            f"{UTILITY} -t nat -P INPUT ACCEPT",
            f"{UTILITY} -t nat -P OUTPUT ACCEPT",
            f"{UTILITY} -t nat -P POSTROUTING ACCEPT",

            f"{UTILITY} -P OUTPUT ACCEPT",
            f"{UTILITY} -A INPUT -i lo -j ACCEPT",
            f"{UTILITY} -A OUTPUT -o lo -j ACCEPT",
            f"{UTILITY} -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", # noqa E501
            f"{UTILITY} -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", # noqa E501
            f"{UTILITY} -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"  # noqa E501
        ]
    else:
        iptablesList = [
            # Firewall.
            f"{UTILITY} -F",
            f"{UTILITY} -X",
            f"{UTILITY} -P INPUT ACCEPT",
            f"{UTILITY} -P FORWARD ACCEPT",
            f"{UTILITY} -P OUTPUT ACCEPT",
            # NAT.
            f"{UTILITY} -t nat -F",
            f"{UTILITY} -t nat -X",
            f"{UTILITY} -t nat -P PREROUTING ACCEPT",
            f"{UTILITY} -t nat -P INPUT ACCEPT",
            f"{UTILITY} -t nat -P OUTPUT ACCEPT",
            f"{UTILITY} -t nat -P POSTROUTING ACCEPT",
        ]

    return iptablesList


def cmd_iptables_input(dport: str, subnet: str, proto: str = "tcp") -> str:
    """Generates an iptables INPUT firewall."""
    return f"{UTILITY} -A INPUT -p {proto} --dport {dport} -s {subnet} -j ACCEPT"


def cmd_dnat_iptables(
        port: str, 
        send_host: str, 
        proto: str = "udp"
    ) -> str:
    """
    Generate an iptables DNAT rule for a given port and destination host.

    Args:
        port: Destination port to forward.
        send_host: Target host IP.
        proto: Protocol (tcp/udp), default "udp".

    Returns:
        str: Full iptables DNAT command.
    """
    return (
        f"{UTILITY} -t nat -A PREROUTING -p {proto} --dport {port} -j DNAT "
        f"--to-destination {send_host}:{port}"
    )


def cmd_snat_iptables(
        port: str, 
        send_host: str, 
        local_ip: str, 
        proto: str = "udp"
    ) -> str:
    """
    Generate an iptables SNAT rule for a given port and destination host.

    Args:
        port: Destination port.
        send_host: Target host IP.
        local_ip: Source IP for SNAT.
        proto: Protocol (tcp/udp), default "udp".

    Returns:
        str: Full iptables SNAT command.
    """
    return (
        f"{UTILITY} -t nat -A POSTROUTING -p {proto} -d {send_host} "
        f"--dport {port} -j SNAT --to-source {local_ip}"
    )


def cmd_firewall_forwarding_iptables(
        port: str, subnet: str, proto: str = "udp") -> str:
    """Generates two iptables FORWARD rules for a given subnet."""
    return f"{UTILITY} -A FORWARD -p {proto} -d {subnet} --dport {port} -j ACCEPT"


def cmd_logging_table_input(
        prefix: str, 
        port: str, 
        proto: str = "udp", 
        limit_sec: str = "10", 
        log_level: str = "4"
    ) -> str:
    """
    Generate an iptables INPUT logging rule for a given port and protocol.

    Args:
        prefix: Log prefix for easy identification.
        port: Destination port to log.
        proto: Protocol (tcp/udp), default "udp".
        limit_sec: Rate limit in packets per second, default 10.
        log_level: Syslog log level, default 4.

    Returns:
        str: Full iptables command string.
    """
    return (
        f"{UTILITY} -I INPUT 1 -p {proto} --dport {port} -m limit "
        f"--limit {limit_sec}/sec -j LOG --log-prefix '{prefix}: ' --log-level {log_level}"
    )


def cmd_logging_table_forwarding(
        prefix: str, 
        port: str,
        send_host: str,
        proto: str = "udp", 
        limit_sec: str = "10", 
        log_level: str = "4"    
    ) -> str:
    """
    Generate an iptables FORWARD logging rule for a given destination host and port.

    Args:
        prefix: Log prefix for easy identification.
        port: Destination port to log.
        send_host: Target host IP.
        proto: Protocol (tcp/udp), default "udp".
        limit_sec: Rate limit in packets per second, default 10.
        log_level: Syslog log level, default 4.

    Returns:
        str: Full iptables command string.
    """
    return (
        f"{UTILITY} -I FORWARD 1 -p {proto} -d {send_host} --dport "
        f"{port} -m limit --limit {limit_sec}/sec -j LOG --log-prefix '{prefix}: ' "
        f"--log-level {log_level}"
    )

def run(cmd: str) -> None:
    """
    Executes a shell command.
    """

    bash: str = "/usr/bin/bash"

    if not os.path.isfile(bash):
        print(f"error: utility '{bash}' not found")
        return

    result_code = subprocess.run(
        cmd,
        shell=True,
        check=True,
        executable=bash,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result_code.returncode == 0:
        print(f"info: command {cmd} executed")
    else:
        raise SystemError(f"error: failed to execute command: {cmd}")


def main():
    """
    Program execution checkpoint.
    """

    try:
        if os.geteuid() != 0:
            print("error: access denied, run the script as 'root' user.")
            return

        if not os.path.isfile(UTILITY):
            print(f"error: utility '{UTILITY}' not found")
            return
        
        clearRules = os.getenv("CLEAR_RULES")
        if clearRules is None:
            raise KeyError(
                "error: environment variable 'CLEAR_RULES' is not set")
        
        if clearRules == "true":
            for cmd in cmd_clear_iptable(True):
                run(cmd)
        
            raise SystemExit(f"info: {UTILITY} reset, base policies applied")

        alwIPs, static_vars = get_allow_ips()

        localhost = static_vars["LOCALHOST"]
        limit_log_sec = static_vars["LIMIT_LOG_SEC"]
        logger_name_input = static_vars["LOGGER_NAME_TABLE_INPUT"]
        logger_name_forward = static_vars["LOGGER_NAME_TABLE_FORWARD"]

        for cmd in cmd_clear_iptable():
            run(cmd)

        for key, val in alwIPs.items():
            parts = key.strip().split("_")
        
            proto = "tcp" if "TCP" in key else "udp"
            chain_type = "INPUT" if "_IN" in key else "FORWARD"    
            cidr = parts[-1] if parts[-1].isdigit() else ""

            for addr in val:
                host, port = addr.split(":")
                subnet = f"{host}/{cidr}"

                if chain_type == "INPUT":
                    run(
                        cmd_iptables_input(
                            dport=port, 
                            subnet=subnet,
                            proto=proto
                        )
                    )

                    run(
                        cmd_logging_table_input(
                            prefix=logger_name_input, 
                            port=port,
                            proto=proto,
                            limit_sec=limit_log_sec,
                        )
                    )
                  
                if chain_type == "FORWARD":
                    run(
                        cmd_firewall_forwarding_iptables(
                            port=port, 
                            subnet=host,
                            proto=proto,
                        )
                    )

                    run(
                        cmd_dnat_iptables(
                            port=port, 
                            send_host=host,
                            proto=proto,
                        )
                    )

                    run(
                        cmd_snat_iptables(
                            port=port, 
                            send_host=host, 
                            local_ip=localhost,
                            proto=proto,
                        )
                    )

                    run(
                        cmd_logging_table_forwarding(
                            prefix=logger_name_forward, 
                            port=port, 
                            send_host=host, 
                            limit_sec=limit_log_sec,
                        )
                    )
                
        print("info: rules added")
    except Exception as err:
        print(err)
        sys.exit(1)


if __name__ == "__main__":
    main()

        