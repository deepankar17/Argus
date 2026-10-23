"""Dynamic (DAST) scanners for Argus.

These run against *running* services, so unlike the static scanners they are gated: a target must be
declared in config/dast.json with `authorized: true`, and intrusive ("active") testing is refused
against a target whose `env` is "prod" unless it is explicitly allowed per run. Nothing here runs by
default from the static `./argus` entry point; use `./argus-dast`.
"""
