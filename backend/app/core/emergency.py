"""Global Emergency Stop & Operational State Control.

Enforces an immediate kill-switch for all scanning engines and requests.
"""
import threading
from typing import Dict, Set


class EmergencyControl:
    def __init__(self):
        self._lock = threading.Lock()
        self._global_stop: bool = False
        self._paused_programs: Set[int] = set()

    def is_global_stopped(self) -> bool:
        with self._lock:
            return self._global_stop

    def trigger_global_stop(self) -> None:
        with self._lock:
            self._global_stop = True

    def resume_global_stop(self) -> None:
        with self._lock:
            self._global_stop = False

    def pause_program(self, program_id: int) -> None:
        with self._lock:
            self._paused_programs.add(program_id)

    def resume_program(self, program_id: int) -> None:
        with self._lock:
            self._paused_programs.discard(program_id)

    def is_program_paused(self, program_id: int) -> bool:
        with self._lock:
            return program_id in self._paused_programs

    def get_status(self) -> Dict:
        with self._lock:
            return {
                "global_stop": self._global_stop,
                "paused_programs": list(self._paused_programs)
            }


# Global singleton instance
emergency_control = EmergencyControl()
