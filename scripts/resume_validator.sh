#!/usr/bin/env bash
# Kestrel resume_validator.sh — thin wrapper around resume_validator.py
# Run this ON your Kali VM to validate session state before resuming.
#
# Input (env vars):
#   MACHINE_IP      — last known HTB machine IP
#   LISTENERS_JSON  — JSON array of registered listeners:
#                     '[{"pid":1234,"port":9001,"type":"nc","cmd":"nc -lvnp 9001"}]'
#
# Output: JSON to stdout (see resume_validator.py for full schema)
#
# Usage:
#   MACHINE_IP=10.10.10.x \
#   LISTENERS_JSON='[{"pid":1234,"port":9001,"type":"nc","cmd":"nc -lvnp 9001"}]' \
#   bash resume_validator.sh

exec python3 "$(dirname "$0")/resume_validator.py" "$@"
