#!/usr/bin/env python3
"""Gunicorn request handler."""

import base64
import logging
import re
import socket

from collector import AristaMetricsCollector

import falcon

from prometheus_client.exposition import CONTENT_TYPE_LATEST, generate_latest


class MetricHandler:
    """The metrics handler class."""

    def __init__(self, config):
        """Initialize."""
        self._config = config

    def authenticate(self, req, resp):
        """Perform HTTP Authentication (if configured)."""
        web_username = self._config.get("web_username")
        web_password = self._config.get("web_password")
        if not web_username or not web_password:
            return True

        auth_header = req.get_header("Authorization")
        auth_expected = base64.b64encode(
            f"{web_username}:{web_password}".encode()
        ).decode()
        if auth_header and auth_header == f"Basic {auth_expected}":
            logging.debug("Valid authorization header received")
        else:
            logging.debug("Invalid authorization header received")
            resp.status = falcon.HTTP_401
            resp.set_header("Authorization", "Basic credentials")
            resp.text = "Unauthorized"
            return False

        return True

    def validate_modules(self, modules):
        """Validate modules provided by the user."""
        if not modules or re.match(r"^([a-zA-Z]+)(,[a-zA-Z]+)*$", modules):
            return True
        logging.error("Invalid modules specified")
        return False

    def on_get(self, req, resp):
        """Handle the GET requests."""
        if not self.authenticate(req, resp):
            return

        target = req.get_param("target")
        modules = req.get_param("modules")

        if modules and not self.validate_modules(modules):
            resp.status = falcon.HTTP_400
            resp.text = "Invalid modules specified"
            return

        resp.set_header("Content-Type", CONTENT_TYPE_LATEST)

        if not target:
            resp.status = falcon.HTTP_400
            resp.text = "No target parameter provided!"
            return

        try:
            socket.getaddrinfo(target, None)
        except socket.gaierror as e:
            resp.status = falcon.HTTP_400
            resp.text = f"Target does not exist in DNS: {e}"
            return

        registry = AristaMetricsCollector(self._config, target=target)
        resp.text = generate_latest(registry)
