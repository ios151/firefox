"""fxproxy — standalone landing proxy over Firefox IP Protection."""
from .guardian import GuardianClient, GuardianError, NotEnrolledError

__version__ = "0.1.0"
__all__ = ["GuardianClient", "GuardianError", "NotEnrolledError"]
