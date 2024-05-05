#!/usr/bin/env python3

import os
import ssl

from setuptools import setup

# Ignore ssl if it fails
if not os.environ.get("PYTHONHTTPSVERIFY", "") and getattr(ssl, "_create_unverified_context", None):
    ssl._create_default_https_context = ssl._create_unverified_context

setup(
    name="BlueosNetworkScanner",
    version="0.1.0",
    description="BlueOS Network Scanner",
    license="MIT",
    install_requires=[
        "appdirs == 1.4.4",
        "fastapi == 0.101.1",
        "fastapi-versioning == 0.9.1",
        "loguru == 0.5.3",
        "uvicorn == 0.13.4",
        "starlette==0.27.0",
        "aiofiles==0.8.0",
        "psutil==5.9.8",
        "python3-nmap==1.6.0",
    ],
)