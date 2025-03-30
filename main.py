from threading import Event
import signal
import os  # Add this import at the top

from click import command, option
from loguru import logger
from prometheus_client import start_http_server
from prometheus_client.core import REGISTRY
from yaml import safe_load

from collector import Collector


def graceful_shutdown(shutdown_event):
    def _handle(sig, frame):
        logger.warning("caught signal for shutdown, stopping service.", extra={
            "signal": sig,
        })

        shutdown_event.set()
    
    signal.signal(signal.SIGINT, _handle)


def start_monitoring(prometheus_port, collector):
    start_http_server(prometheus_port)
    REGISTRY.register(collector)


@command()
@option(
    '--tapo-email', envvar="TAPO_USER_EMAIL",
    help="Email address associated with Meross account."
)
@option(
    '--tapo-password', envvar="TAPO_USER_PASSWORD",
    help="Password associated with TP-Link TAPO account."
)
@option(
    '--config-file', default="tapo.yaml", envvar="TAPO_MONITOR_CONFIG",
    help="Path to the configuration file."
)
@option(
    '--prometheus-port', default=8080, help="Port for Prometheus metric exposition."
)
def run(tapo_email, tapo_password, config_file, prometheus_port):
    # Check if DEVICES environment variable is defined
    devices_env = os.getenv("DEVICES")
    if devices_env:
        # Parse the DEVICES environment variable into a dictionary
        devices = {}
        for pair in devices_env.split(","):
            if ":" in pair:
                device, room = pair.split(":")
                devices[device.strip()] = room.strip()
        logger.info("Using devices from DEVICES environment variable.")
    else:
        # Fallback to reading the configuration file
        with open(config_file, "r") as cfg:
            config = safe_load(cfg)
            devices = config['devices']
        logger.info("Using devices from configuration file.")

    logger.info("Configuring metrics collector and Prometheus HTTP server.")
    collector = Collector(devices, tapo_email, tapo_password)
    start_monitoring(prometheus_port, collector)

    shutdown = Event()
    graceful_shutdown(shutdown)

    logger.info("Service is up and awaiting signals to stop.")
    shutdown.wait()


if __name__ == "__main__":
    run()
