from python:3.11-slim-bullseye

RUN apt update && apt install -y nmap && apt clean && rm -rf /var/lib/apt/lists/*
COPY app/setup.py /app/setup.py
RUN echo "[global]" > /etc/pip.conf
RUN echo "extra-index-url=https://www.piwheels.org/simple" >> /etc/pip.conf
RUN apt update && apt install -y gcc python-dev && cd app && pip install . && apt remove -y gcc python-dev && apt clean -y && rm -rf /var/lib/apt/lists/*
COPY app /app

LABEL version="1.0.0"
LABEL permissions='\
{\
  "NetworkMode": "host",\
  "HostConfig": {\
    "NetworkMode": "host"\
  }\
}'
LABEL authors='[\
    {\
        "name": "Willian Galvani",\
        "email": "willian@bluerobotics.com"\
    }\
]'
LABEL company='{\
        "about": "",\
        "name": "Blue Robotics",\
        "email": "support@bluerobotics.com"\
    }'
LABEL type="tool"
LABEL readme='https://raw.githubusercontent.com/Williangalvani/BlueOS-extension-network-scanner/{tag}/Readme.md'
LABEL links='{\
        "website": "https://github.com/Williangalvani/BlueOS-extension-network-scanner/",\
        "support": "https://github.com/Williangalvani/BlueOS-extension-network-scanner/"\
    }'
LABEL requirements="core >= 1.1"

ENTRYPOINT cd /app && python main.py
