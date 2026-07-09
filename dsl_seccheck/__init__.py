"""dsl-seccheck: deterministic static security checker for a protocol DSL."""
from .checks import check_all
from .engine import Finding
from .parser import ParseError, parse

__all__ = ["check_all", "parse", "ParseError", "Finding"]
__version__ = "0.1.0"
