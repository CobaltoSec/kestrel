"""Core pure-Python logic (testable, no I/O side-effects except where documented).

Modules:
    fingerprint    — port/service classification + attack plan (ex blind_fingerprint.py)
    stuck          — stuck detection signals + recommendation (ex stuck_detector.py)
    wordlist       — wordlist strategy + GPU recommendation (ex wordlist_strategy.py)
    crack          — crack job status (ex crack_status.py)
    heartbeat      — session dashboard data layer (ex heartbeat.py)
    state_inspector — query state machine (ex state_inspector.py)
    parallel       — parallel task orchestration (ex parallel_explorer.py)
    timer          — context manager + jsonl event timing (ex tool-timer.sh)
    resume_validator — platform-agnostic resume health check
"""
