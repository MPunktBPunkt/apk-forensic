"""Typed errors and exit codes for apk-forensics."""

from __future__ import annotations


class ExitCode:
    SUCCESS = 0
    PARTIAL_OR_WARNINGS = 1
    INVALID_ARGS = 2
    INPUT_UNREADABLE = 3
    INVALID_APK = 4
    FATAL = 5
    RESOURCE_WARNING_BLOCKED = 6
    RESOURCE_REJECTED = 7


class ApkForensicsError(Exception):
    """Base error."""

    exit_code: int = ExitCode.FATAL

    def __init__(self, message: str, *, exit_code: int | None = None) -> None:
        super().__init__(message)
        if exit_code is not None:
            self.exit_code = exit_code


class InputError(ApkForensicsError):
    exit_code = ExitCode.INPUT_UNREADABLE


class InvalidApkError(ApkForensicsError):
    exit_code = ExitCode.INVALID_APK


class ProfileError(ApkForensicsError):
    exit_code = ExitCode.FATAL


class ScannerError(ApkForensicsError):
    """Non-fatal scanner error by default."""

    exit_code = ExitCode.PARTIAL_OR_WARNINGS
