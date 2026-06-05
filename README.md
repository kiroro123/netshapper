# NetShaper

NetShaper is a modular, authorized network-testing toolkit for controlled lab and client-network analysis. It combines discovery, packet capture, DNS handling, traffic shaping, and MITM-style interception logic in a single Python CLI.

This repository is intentionally framed as a safety-first, lab-oriented tool for authorized testing and reversible diagnostics.

## What this project is

This project is intended for authorized security validation and controlled network diagnostics on environments where you have explicit permission to test. It is designed to help identify, reproduce, and validate network behavior and possible weaknesses in a safe, reversible workflow.

## Current goals

- Provide a real CLI workflow for authorized network testing
- Improve safe dry-run behavior and rollback handling
- Add stronger session tracking and cleanup reliability
- Prepare the project for GitHub-based development and CI

## Installation

```bash
python -m pip install -e .
```

For developer tooling:

```bash
python -m pip install -e ".[dev]"
```

## Quick start

Run the CLI:

```bash
python __main__.py -i <your-interface>
```

Safe preview mode:

```bash
python __main__.py -i <your-interface> --dry-run
```

## Testing

Run the regression suite:

```bash
python -m unittest discover -s tests -v
```

## Repository notes

- The main CLI workflow lives in the packaged `src/netshaper` tree and is the recommended path for normal use.
- `fake_server3.py` is an optional experimental helper for captive-portal / DNS lab scenarios. Keep it as a supporting utility, not as the main user path.
- Use this tool only on networks and devices you are authorized to test.

The project is still evolving, and the current focus is safety, rollback, and reliable validation behavior.
