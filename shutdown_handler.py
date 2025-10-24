#!/usr/bin/env python3

import signal
import sys
import os
import logging
import time
import atexit
import subprocess
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class ShutdownHandler:
    """Manages graceful shutdown of the application."""

    def __init__(self):
        """Initialize the shutdown handler."""
        self.shutdown_event = False
        self.shutdown_timeout = 30  # seconds
        self.cleanup_callbacks = []
        self.background_processes = []
        self.is_shutting_down = False

    def register_cleanup_callback(self, callback: Callable, *args, **kwargs):
        """
        Register a callback function to be called during shutdown.

        Args:
            callback: Function to call during shutdown
            *args: Positional arguments for the callback
            **kwargs: Keyword arguments for the callback
        """
        self.cleanup_callbacks.append((callback, args, kwargs))
        logger.debug(f"Registered cleanup callback: {callback.__name__}")

    def register_background_process(self, pid: int, name: str = "unknown"):
        """
        Register a background process to be stopped during shutdown.

        Args:
            pid: Process ID to track
            name: Friendly name for the process
        """
        self.background_processes.append({"pid": pid, "name": name})
        logger.debug(f"Registered background process: {name} (PID: {pid})")

    def handle_signal(self, signum, frame):
        """
        Handle shutdown signals (SIGTERM, SIGINT).

        Args:
            signum: Signal number
            frame: Stack frame
        """
        if self.is_shutting_down:
            logger.warning("Shutdown already in progress, forcing exit")
            sys.exit(1)

        signal_name = signal.Signals(signum).name
        logger.info(f"Received {signal_name} signal, initiating graceful shutdown...")
        self.is_shutting_down = True

        try:
            self.graceful_shutdown()
            logger.info("Graceful shutdown completed successfully")
            sys.exit(0)
        except Exception as e:
            logger.error(f"Error during graceful shutdown: {e}", exc_info=True)
            sys.exit(1)

    def graceful_shutdown(self):
        """Execute graceful shutdown sequence."""
        self.shutdown_event = True
        start_time = time.time()

        # Phase 1: Stop accepting new connections
        logger.info("Phase 1: Stopping acceptance of new connections")
        try:
            # Signal that we're shutting down (for Flask/Gunicorn awareness)
            os.environ["XBROKER_SHUTTING_DOWN"] = "1"
        except Exception as e:
            logger.warning(f"Could not set shutdown environment variable: {e}")

        # Phase 2: Wait for pending requests (with timeout)
        logger.info("Phase 2: Waiting for pending requests to complete")
        time.sleep(2)  # Allow brief time for pending requests

        # Phase 3: Clean up background processes
        logger.info("Phase 3: Stopping background processes")
        self._stop_background_processes()

        # Phase 4: Execute cleanup callbacks
        logger.info("Phase 4: Executing cleanup callbacks")
        self._execute_cleanup_callbacks()

        # Phase 5: Close database connections
        logger.info("Phase 5: Closing database connections")
        self._close_database_connections()

        elapsed = time.time() - start_time
        logger.info(f"Shutdown sequence completed in {elapsed:.2f} seconds")

    def _stop_background_processes(self):
        """Stop registered background processes."""
        for proc_info in self.background_processes:
            pid = proc_info["pid"]
            name = proc_info["name"]

            try:
                # Check if process is still running
                if not self._is_process_running(pid):
                    logger.debug(f"Process {name} (PID: {pid}) already stopped")
                    continue

                # Try graceful termination first
                logger.info(f"Terminating process: {name} (PID: {pid})")
                os.kill(pid, signal.SIGTERM)

                # Wait for process to stop
                for _ in range(10):  # Wait up to 10 seconds
                    time.sleep(0.5)
                    if not self._is_process_running(pid):
                        logger.info(f"Process {name} (PID: {pid}) terminated gracefully")
                        break
                else:
                    # Force kill if still running
                    logger.warning(f"Force killing process {name} (PID: {pid})")
                    os.kill(pid, signal.SIGKILL)

            except ProcessLookupError:
                logger.debug(f"Process {name} (PID: {pid}) not found")
            except Exception as e:
                logger.error(f"Error stopping process {name} (PID: {pid}): {e}")

    def _execute_cleanup_callbacks(self):
        """Execute all registered cleanup callbacks."""
        for callback, args, kwargs in self.cleanup_callbacks:
            try:
                logger.debug(f"Executing cleanup callback: {callback.__name__}")
                callback(*args, **kwargs)
            except Exception as e:
                logger.error(f"Error in cleanup callback {callback.__name__}: {e}", exc_info=True)

    def _close_database_connections(self):
        """Close all active database connections."""
        try:
            # Import here to avoid circular dependencies
            from users import user_manager

            if hasattr(user_manager, 'close_connections'):
                logger.info("Closing database connections")
                user_manager.close_connections()
            else:
                logger.debug("UserManager does not have close_connections method")

        except ImportError:
            logger.debug("Could not import UserManager for connection cleanup")
        except Exception as e:
            logger.error(f"Error closing database connections: {e}", exc_info=True)

    @staticmethod
    def _is_process_running(pid: int) -> bool:
        """
        Check if a process is running.

        Args:
            pid: Process ID to check

        Returns:
            True if process is running, False otherwise
        """
        try:
            os.kill(pid, 0)  # Signal 0 doesn't kill, just checks if process exists
            return True
        except (ProcessLookupError, PermissionError):
            return False

    def setup_signal_handlers(self):
        """Register signal handlers for graceful shutdown."""
        signal.signal(signal.SIGTERM, self.handle_signal)
        signal.signal(signal.SIGINT, self.handle_signal)
        logger.info("Signal handlers registered for SIGTERM and SIGINT")

    def setup_atexit_handler(self):
        """Register atexit handler for final cleanup."""
        atexit.register(self._atexit_cleanup)
        logger.debug("Atexit handler registered")

    def _atexit_cleanup(self):
        """Final cleanup on process exit."""
        if not self.is_shutting_down:
            logger.info("Performing atexit cleanup")
            try:
                self._close_database_connections()
            except Exception as e:
                logger.error(f"Error in atexit cleanup: {e}")


# Global shutdown handler instance
_shutdown_handler: Optional[ShutdownHandler] = None


def initialize_shutdown_handler(app=None) -> ShutdownHandler:
    """
    Initialize the global shutdown handler.

    Args:
        app: Optional Flask app for context

    Returns:
        ShutdownHandler instance
    """
    global _shutdown_handler

    if _shutdown_handler is not None:
        return _shutdown_handler

    _shutdown_handler = ShutdownHandler()
    _shutdown_handler.setup_signal_handlers()
    _shutdown_handler.setup_atexit_handler()

    if app:
        logger.info("Shutdown handler initialized with Flask app")
    else:
        logger.info("Shutdown handler initialized")

    return _shutdown_handler


def get_shutdown_handler() -> Optional[ShutdownHandler]:
    """
    Get the global shutdown handler instance.

    Returns:
        ShutdownHandler instance or None if not initialized
    """
    return _shutdown_handler


def register_cleanup(callback: Callable, *args, **kwargs):
    """
    Register a cleanup callback with the global shutdown handler.

    Args:
        callback: Function to call during shutdown
        *args: Positional arguments for the callback
        **kwargs: Keyword arguments for the callback

    Raises:
        RuntimeError: If shutdown handler not initialized
    """
    if _shutdown_handler is None:
        raise RuntimeError("Shutdown handler not initialized. Call initialize_shutdown_handler() first.")

    _shutdown_handler.register_cleanup_callback(callback, *args, **kwargs)


def register_background_process(pid: int, name: str = "unknown"):
    """
    Register a background process to be stopped during shutdown.

    Args:
        pid: Process ID to track
        name: Friendly name for the process

    Raises:
        RuntimeError: If shutdown handler not initialized
    """
    if _shutdown_handler is None:
        raise RuntimeError("Shutdown handler not initialized. Call initialize_shutdown_handler() first.")

    _shutdown_handler.register_background_process(pid, name)


if __name__ == "__main__":
    # Demo/test mode
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("Starting shutdown handler demo...")
    handler = initialize_shutdown_handler()

    # Register some test callbacks
    def test_cleanup():
        print("Executing test cleanup...")
        time.sleep(1)
        print("Test cleanup done")

    handler.register_cleanup_callback(test_cleanup)

    print("Press Ctrl+C to trigger graceful shutdown...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutdown initiated")
