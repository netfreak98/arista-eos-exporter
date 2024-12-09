#!/usr/bin/env python
"""Setup.py for setuptools and debian packaging."""
from setuptools import setup

setup(
    name="arista_eos_exporter",
    version="0.1.0",
    description="Arista EOS Exporter",
    author="Joey Julian König, Bernd Kuespert, Stefan Safar, Radek Zajic",
    author_email="info@joey-network.de, bernd.kuespert@sap.com, radek@zajic.v.pytli.cz",
    scripts=["main.py", "handler.py", "collector.py"],
    py_modules=[],
)
