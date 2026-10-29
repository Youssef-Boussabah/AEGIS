"""Mirage v1: retained, unreachable arithmetic decoy functions for LLVM ELF builds."""
from .transform import MirageConfig, MirageError, transform, restore

__all__ = ["MirageConfig", "MirageError", "transform", "restore"]
