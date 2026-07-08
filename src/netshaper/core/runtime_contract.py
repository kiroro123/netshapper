"""Mypy-only checks that concrete runtime backends satisfy core protocols."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netshaper.core.orchestrator import NetShaper
    from netshaper.core.runtime_protocol import SessionRuntime

    def _requires_session_runtime(runtime: SessionRuntime) -> None:
        pass

    def _netshaper_conforms_to_session_runtime(runtime: NetShaper) -> None:
        _requires_session_runtime(runtime)
