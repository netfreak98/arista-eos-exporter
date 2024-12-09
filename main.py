#!/usr/bin/env python3
"""Arista EOS Prometheus exporter."""

import argparse
import logging
import socket
import sys

import falcon

from gunicorn.app.base import BaseApplication

from handler import MetricHandler

import yaml


class GunicornWebserver(BaseApplication):
    """Wrapping class around Gunicorn's BaseApplication."""

    def __init__(
        self, app, host, port, workers, certfile=None, keyfile=None, cafile=None
    ):
        """Initialize the class."""
        self.application = app
        if isinstance(host, str):
            self.host = [host]
        elif isinstance(host, list):
            self.host = host
        else:
            raise Exception(
                f"Error in the config file, unsupported host config: {host}"
            )
        self.port = port
        self.workers = workers
        self.certfile = certfile
        self.keyfile = keyfile
        self.cafile = cafile
        super().__init__()

    def _get_bind_addresses(self):
        """Take the self.host list and resolve it to all unique, valid IP addresses."""
        addresses = []
        for host in self.host:
            addresses.extend(
                [
                    record[4][0]
                    for record in socket.getaddrinfo(host, 0, proto=socket.IPPROTO_TCP)
                ]
            )
        return list(set(addresses))

    def _bind_format(self, address, port):
        """IPv6 addresses must be configured as [::1]:1234. Format the tuple accordingly."""
        if ":" in address:
            return f"[{address}]:{port}"
        else:
            return f"{address}:{port}"

    def load_config(self):
        """Configure Gunicorn."""
        bind_addresses = self._get_bind_addresses()
        binds = [
            self._bind_format(bind_address, self.port)
            for bind_address in bind_addresses
        ]
        self.cfg.set("bind", binds)
        self.cfg.set("workers", self.workers)
        if self.certfile and self.keyfile:
            self.cfg.set("certfile", self.certfile)
            self.cfg.set("keyfile", self.keyfile)
        if self.cafile:
            self.cfg.set("ca_certs", self.cafile)

    def load(self):
        """Load Gunicorn."""
        return self.application


def setup_logging(config):
    """Configure logging."""
    logger = logging.getLogger()
    log_level = config.get("loglevel", "INFO").upper()
    logger.setLevel(log_level)
    format = (
        "%(asctime)-15s %(process)d %(levelname)s %(filename)s:%(lineno)d %(message)s"
    )
    logging.basicConfig(stream=sys.stdout, format=format)
    return logger


def load_config(filename):
    """Load the config from a file."""
    try:
        with open(filename, "r") as stream:
            config = yaml.safe_load(stream)

        if "web_listen_address" not in config:
            config["web_listen_address"] = "::"

        if not config.get("disable_certificate_validation", False):
            raise ValueError(
                "Certificate validation is not supported by pyeapi library. Please specify "
                "disable_certificate_validation: true in your configuration file. "
                "Upstream issue: https://github.com/arista-eosplus/pyeapi/issues/174"
            )

        return config
    except Exception as e:
        logging.error(f"Failed to load configuration: {e}")
        sys.exit(1)


def main():
    """Do the deed."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--config",
        help="Specify config yaml file",
        metavar="FILE",
        default="config.yml",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    logger = setup_logging(config)

    api = falcon.App()
    api.add_route("/arista", MetricHandler(config=config))

    host = config.get("web_listen_address", "::")
    port = config.get("web_listen_port", 9120)
    workers = config.get("web_workers", 4)
    certfile = config.get("web_cert_file")
    keyfile = config.get("web_key_file")
    cafile = config.get("web_ca_file")

    if not certfile or not keyfile:
        logger.warning(
            "Warning: either web_cert_file or web_key_file is missing. Falling back to HTTP."
        )

    logger.info(
        f"Starting Arista eAPI Prometheus Server on {host}:{port} with {workers} workers..."
    )

    application = GunicornWebserver(api, host, port, workers, certfile, keyfile, cafile)
    application.run()


if __name__ == "__main__":
    main()
