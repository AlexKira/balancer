#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.join(BASE_DIR.split("src")[0], "src")
LOG_DIR = os.path.join(PROJECT_DIR, "log")

__BASE_CONF__: dict[str, str] = {
    "LOGGER_NAME_TABLE_INPUT": "",
    "LOGGER_NAME_TABLE_FORWARD": "",
    "LOG_DIR":LOG_DIR,
    "RLOG_CONF_NAME_FILE": "/etc/rsyslog.d/brgcore.conf",
    "LOGROTATION_CONF_NAME_FILE": "/etc/logrotate.d/brgcore.conf",
    "CLEAR_RULES": "false",
}


def set_base_conf():
    """Load base configuration values from environment variables."""
    for key in __BASE_CONF__:
        if key in os.environ:
            __BASE_CONF__[key] = os.environ[key]
    return __BASE_CONF__


def set_conf_rsyslog(
        conf_path, log_dir: str, log_name:list
    ) -> None:
    """
        Generate rsyslog rules to route messages by prefix into 
        dedicated log files.
    """
    if len(log_name) == 0:
        raise ValueError("error: List 'log_name' for rsyslog is empty")

    conf_data = []
    for lg_name in log_name:
        conf_content = (
            f'\nif ($msg contains "{lg_name}") then {{\n'
            f'    action(type="omfile" file="{log_dir}/{lg_name}.log")\n'
            f'    stop\n'
            f'}}\n'
        )
        conf_data.append(conf_content)

    with open(conf_path, "w") as f:
        f.write("".join(conf_data))


def start_logrotate(
        conf_path: str,
        log_files: list[str],
        log_dir: str,
        rotate: int = 7,
        maxage: int = 14,
    ) -> None:
    """
    Generate logrotate config for given log files.

    Args:
        conf_path: Path to write logrotate config.
        log_files: List of log file paths to rotate.
        log_dir: Directory to store archived logs.
        rotate: Number of rotations to keep.
        maxage: Max age in days to keep old logs.
    """
    os.makedirs(log_dir, exist_ok=True)
    if not log_files:
        raise ValueError("error: log_files list is empty")

    files_header = "\n".join(log_files)
    config = f""" 
{files_header} {{ 
    daily 
    missingok 
    notifempty 
    compress 
    delaycompress 
    copytruncate 
    rotate {rotate} 
    maxage {maxage} 
    olddir {log_dir} 
    create 640 root adm 
}} 
"""

    with open(conf_path, "w") as f:
        f.write(config)

    print(f"info: logrotate installed → {conf_path}")


def logrotate(conf_path: str, remove_conf_file: bool = False):
    """
        Run logrotate manually and optionally remove 
        the config file after execution.
    """
    try:
        subprocess.run(f"logrotate -f {conf_path}", shell=True)
        print("info: logrotate restarted successfully")
    except subprocess.CalledProcessError as err:
        print(f"error: failed to restart logrotate: {err}")
        raise
    
    if remove_conf_file and os.path.isfile(conf_path):
        if os.path.isfile(conf_path):
            os.remove(conf_path)
            print(f"info: logrotate config {conf_path} removed")
        else:
            print(
                f"info: logrotate config {conf_path} "
                "not found, skipping removal"
            )
    else:
        print(f"info: executed logrotate")
    

def systemd_restart_rsyslog(log_dir: str) -> None:
    """Ensure log directory permissions and restart rsyslog service."""

    os.makedirs(log_dir, exist_ok=True)
    os.chmod(log_dir, 0o750)
    print(
        f"info: log directory '{log_dir}' ensured with permissions 750"
    )

    try:
        subprocess.run(
            ["systemctl", "restart", "rsyslog"], check=True
        )
        print("info: rsyslog restarted successfully")
    except subprocess.CalledProcessError as err:
        print(f"error: failed to restart rsyslog: {err}")
        raise

def systemd_stop_rsyslog(conf_file: str) -> None:
    """Remove rsyslog config file and restart the rsyslog service."""

    if os.path.isfile(conf_file):
        os.remove(conf_file)
        print(f"info: rsyslog config {conf_file} removed")
    else:
        print(
            f"info: rsyslog config {conf_file} not found, "
            "skipping removal"
        )

    subprocess.run(
        ["systemctl", "restart", "rsyslog"], check=True
    )
    print("info: rsyslog restarted")


def main() -> None:
    """
        Entry point: apply or remove rsyslog/logrotate configuration 
        based on environment variables.
    """
    try:
        conf_data = set_base_conf()

        log_dir = conf_data["LOG_DIR"]
        clear_rules = conf_data["CLEAR_RULES"]
        rlog_conf_file = conf_data["RLOG_CONF_NAME_FILE"]
        log_name_input = conf_data["LOGGER_NAME_TABLE_INPUT"]
        lrotation_conf = conf_data["LOGROTATION_CONF_NAME_FILE"]
        log_name_forwarding = conf_data["LOGGER_NAME_TABLE_FORWARD"]

        if clear_rules == "false":
            set_conf_rsyslog(
                conf_path=rlog_conf_file, 
                log_name=[log_name_input, log_name_forwarding],
                log_dir=log_dir,
            )

            start_logrotate(
                conf_path=lrotation_conf,
                log_dir=f"{log_dir}/arch",
                log_files=[
                    f"{log_dir}/{log_name_input}.log",
                    f"{log_dir}/{log_name_forwarding}.log"
                ]
            )
            
            systemd_restart_rsyslog(log_dir)

        else:
            systemd_stop_rsyslog(rlog_conf_file)
            logrotate(lrotation_conf, True)
        
    except Exception as err:
        print(err)
        sys.exit(1)


if __name__ == "__main__":
    main()
