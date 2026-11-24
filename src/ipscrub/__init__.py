"""Remove an address, and the network around it, from a host's files."""

from .addresses import AddressError, Matcher, decode_address
from .plan import Action, Plan, Special
from .runner import Outcome, run
from .scan import Finding, Report

__version__ = "0.1.0"

__all__ = [
    "Action",
    "AddressError",
    "Finding",
    "Matcher",
    "Outcome",
    "Plan",
    "Report",
    "Special",
    "decode_address",
    "run",
    "__version__",
]
