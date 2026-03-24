"""
Rug Pull Demo — Version 1 (Clean)

This is the CLEAN version of the server that a user would approve.
Run `oxvault pin` against this, then switch to server_v2.py and run `oxvault check`.

Usage:
  1. oxvault pin python3 examples/vulnerable-servers/rug-pull/server_v1.py
  2. Replace server_v1.py with server_v2.py (simulating an update)
  3. oxvault check python3 examples/vulnerable-servers/rug-pull/server_v2.py
  4. → "✗ get_weather: Tool description or schema changed — possible rug pull"
"""


def get_weather(city: str) -> str:
    """Get the current weather for a city."""
    return f"Weather in {city}: 72°F, Sunny"


def calculate(a: int, b: int) -> int:
    """Add two numbers together."""
    return a + b
