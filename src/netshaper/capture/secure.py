"""Secure capture-directory and PCAP file creation helpers."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import BinaryIO, Optional

from netshaper import config
from netshaper.exceptions import NetShaperError

_SAFE_STEM_RE = re.compile(r"[^A-Za-z0-9_.-]+")


class CapturePathError(NetShaperError):
    """Raised when a capture path cannot be trusted or created safely."""


@dataclass(frozen=True)
class SecureCaptureFile:
    """An exclusively created capture file and its absolute path."""

    path: str
    handle: BinaryIO


class SecureCaptureDirectory:
    """Validate a trusted capture directory and create new PCAP files safely."""

    def __init__(self, directory: Optional[str] = None) -> None:
        raw_directory = directory or os.path.join(config.STATE_DIR, "captures")
        self.path = Path(os.path.abspath(os.path.expanduser(raw_directory)))

    @staticmethod
    def _safe_stem(stem: str) -> str:
        cleaned = _SAFE_STEM_RE.sub("_", stem).strip("._-")
        return cleaned or "capture"

    @staticmethod
    def _nofollow_flag() -> int:
        return getattr(os, "O_NOFOLLOW", 0)

    @staticmethod
    def _cloexec_flag() -> int:
        return getattr(os, "O_CLOEXEC", 0)

    @staticmethod
    def _verify_directory(metadata: os.stat_result, path: Path) -> None:
        if not stat.S_ISDIR(metadata.st_mode):
            raise CapturePathError(f"capture path is not a directory: {path}")
        if metadata.st_uid != os.geteuid():
            raise CapturePathError(
                f"capture directory is not owned by the current user: {path}"
            )

    @staticmethod
    def _verify_parent(metadata: os.stat_result, path: Path) -> None:
        if stat.S_ISLNK(metadata.st_mode):
            raise CapturePathError("capture directory and parents must not be symlinks")
        if os.geteuid() == 0 and metadata.st_uid != 0:
            raise CapturePathError(
                f"capture directory parent is not owned by root: {path}"
            )
        if (
            metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            and not metadata.st_mode & stat.S_ISVTX
        ):
            raise CapturePathError(
                f"capture directory parent is writable by other users: {path}"
            )

    def ensure(self) -> None:
        if self.path.parent == self.path:
            raise CapturePathError("capture directory cannot be the filesystem root")
        parent = self.path.parent
        if not parent.exists():
            raise CapturePathError(
                "capture directory parent must already exist and be trusted"
            )

        for component in self.path.parents:
            try:
                metadata = os.lstat(component)
            except OSError as exc:
                raise CapturePathError(
                    f"cannot inspect capture path {component}: {exc}"
                ) from exc
            self._verify_parent(metadata, component)

        try:
            metadata = os.lstat(self.path)
        except FileNotFoundError:
            try:
                self.path.mkdir(mode=0o700)
            except OSError as exc:
                raise CapturePathError(
                    f"cannot create capture directory {self.path}: {exc}"
                ) from exc
            metadata = os.lstat(self.path)
        except OSError as exc:
            raise CapturePathError(f"cannot inspect capture path {self.path}: {exc}") from exc

        if stat.S_ISLNK(metadata.st_mode):
            raise CapturePathError("capture directory must not be a symlink")
        self._verify_directory(metadata, self.path)

        if stat.S_IMODE(metadata.st_mode) != 0o700:
            try:
                os.chmod(self.path, 0o700)
                metadata = os.lstat(self.path)
            except OSError as exc:
                raise CapturePathError(
                    f"cannot enforce mode 0700 on capture directory {self.path}: {exc}"
                ) from exc
            self._verify_directory(metadata, self.path)
            if stat.S_IMODE(metadata.st_mode) != 0o700:
                raise CapturePathError(
                    f"capture directory mode is not 0700: {self.path}"
                )

    def _open_directory_fd(self) -> int:
        self.ensure()
        flags = os.O_RDONLY | os.O_DIRECTORY | self._nofollow_flag() | self._cloexec_flag()
        try:
            dir_fd = os.open(self.path, flags)
        except OSError as exc:
            raise CapturePathError(f"cannot open capture directory {self.path}: {exc}") from exc
        try:
            self._verify_directory(os.fstat(dir_fd), self.path)
        except Exception:
            os.close(dir_fd)
            raise
        return dir_fd

    def open_new_pcap(self, stem: str, *, max_attempts: int = 16) -> SecureCaptureFile:
        safe_stem = self._safe_stem(stem)
        dir_fd = self._open_directory_fd()
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | self._nofollow_flag()
            | self._cloexec_flag()
        )
        try:
            for _ in range(max_attempts):
                filename = (
                    f"{safe_stem}_{time.strftime('%Y%m%d_%H%M%S')}_"
                    f"{secrets.token_hex(8)}.pcap"
                )
                try:
                    fd = os.open(filename, flags, 0o600, dir_fd=dir_fd)
                except FileExistsError:
                    continue
                try:
                    metadata = os.fstat(fd)
                    if not stat.S_ISREG(metadata.st_mode):
                        raise CapturePathError(
                            f"capture output is not a regular file: {filename}"
                        )
                    os.fchmod(fd, 0o600)
                    metadata = os.fstat(fd)
                    if stat.S_IMODE(metadata.st_mode) != 0o600:
                        raise CapturePathError(
                            f"capture output mode is not 0600: {filename}"
                        )
                    handle = os.fdopen(fd, "wb")
                except Exception:
                    os.close(fd)
                    raise
                return SecureCaptureFile(str(self.path / filename), handle)
        finally:
            os.close(dir_fd)

        raise CapturePathError("could not create a unique capture file")
