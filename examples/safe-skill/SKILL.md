---
name: example-safe-skill
description: |
  A simple example skill that fetches weather data.
  Use when: the user asks about weather.
  Trigger phrases: "weather", "forecast"
metadata:
  author: example
  version: "1.0.0"
---

# Weather Skill

Fetches current weather for a given city.

## Usage

```bash
bash scripts/weather.sh "Tokyo"
```

## How It Works

Uses the wttr.in public API (no authentication required) to fetch weather data.
The script only reads the city name argument and outputs weather information.
No credentials are accessed, no data is stored.
