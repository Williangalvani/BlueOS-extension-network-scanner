#! /usr/bin/env python3
from pathlib import Path

import appdirs
import uvicorn
from fastapi.staticfiles import StaticFiles
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse, FileResponse
from fastapi_versioning import VersionedFastAPI, version
from loguru import logger
from typing import Any

import json
from pydantic import BaseModel
import psutil
import socket
from fastapi import Response
import nmap3
import asyncio


class TextData(BaseModel):
    data: str

SERVICE_NAME = "BlueosNetworkDiscoveryService"
# logger.add(get_new_log_path(SERVICE_NAME))

app = FastAPI(
    title="Network Scanner API",
    description="API for a service that uses nmap to scan the network for devices.",
)
# We always use the same file, for simplicity
user_config_dir = Path(appdirs.user_config_dir())

logger.info(f"Starting {SERVICE_NAME}!")

@app.post("/save", status_code=status.HTTP_200_OK)
@version(1, 0)
async def save_data(data: TextData) -> Any:
    with open(text_file, "w") as f:
        f.write(data.data)

@app.get("/interfaces", status_code=status.HTTP_200_OK)
@version(1, 0)
async def load_interfaces() -> Any:
  interfaces = psutil.net_if_addrs()
  statuses = psutil.net_if_stats()

  interface_data = []
  # Iterate over interfaces and collect their details
  for interface, addrs in interfaces.items():
    interface_info = {"interface": interface}
    status = "up" if statuses[interface].isup else "down"
    interface_info["status"] = status

    addresses = []
    # Iterate over addresses for each interface
    for addr in addrs:
      address_info = {}
      if addr.family == socket.AF_INET:  # IPv4
        address_info["type"] = "IPv4"
        address_info["address"] = addr.address
        address_info["netmask"] = addr.netmask
      elif addr.family == socket.AF_INET6:  # IPv6
        address_info["type"] = "IPv6"
        address_info["address"] = addr.address
      elif addr.family == psutil.AF_LINK:  # MAC Address
        address_info["type"] = "MAC"
        address_info["address"] = addr.address
      addresses.append(address_info)

    interface_info["addresses"] = addresses
    interface_data.append(interface_info)

  return Response(content=json.dumps(interface_data), media_type="application/json")

async def run_command(command):
    process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await process.communicate()
    return stdout.decode().strip()

@app.post("/scan_http", status_code=status.HTTP_200_OK)
@version(1, 0)
async def scan_network(ip: str, netmask: str) -> Any:
    print(ip, netmask)
    nmap = nmap3.Nmap()
    # use the netmask to turn the ip into a network address,
    # for example 192.168.15.1 and 255.255.255.0 will return 192.168.15.* and 255.255.0.0 will return 192.168.*.*
    network_address = ".".join([str(int(ip_octet) & int(netmask_octet)) if netmask_octet != '0' else '*' for ip_octet, netmask_octet in zip(ip.split("."), netmask.split("."))])
    command = f"nmap -Pn -p 80 --open {network_address} -oX -"
    output = await run_command(command)
    xml = nmap.get_xml_et(output)
    results = nmap.parser.filter_top_ports(xml)
    filtered = {host: data for host, data in results.items() if 'state' in data and data['state']['state'] == 'up'}
    return filtered

@app.post("/scan", status_code=status.HTTP_200_OK)
@version(1, 0)
async def scan_network(ip: str, netmask: str) -> Any:
    print(ip, netmask)
    nmap = nmap3.Nmap()
    # use the netmask to turn the ip into a network address,
    # for example 192.168.15.1 and 255.255.255.0 will return 192.168.15.* and 255.255.0.0 will return 192.168.*.*
    network_address = ".".join([str(int(ip_octet) & int(netmask_octet)) if netmask_octet != '0' else '*' for ip_octet, netmask_octet in zip(ip.split("."), netmask.split("."))])
    command = f"nmap -sn {network_address} -oX -"
    output = await run_command(command)
    xml = nmap.get_xml_et(output)
    results = nmap.parser.filter_top_ports(xml)
    filtered = {host: data for host, data in results.items() if 'state' in data and data['state']['state'] == 'up'}
    return filtered

app = VersionedFastAPI(app, version="1.0.0", prefix_format="/v{major}.{minor}", enable_latest=True)

app.mount("/", StaticFiles(directory="static",html = True), name="static")

@app.get("/", response_class=FileResponse)
async def root() -> Any:
        return "index.html"

if __name__ == "__main__":
    # Running uvicorn with log disabled so loguru can handle it
    uvicorn.run(app, host="0.0.0.0", port=5098, log_config=None)
