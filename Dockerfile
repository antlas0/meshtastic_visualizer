FROM python:3.11-bookworm

RUN apt-get update \
    && apt-get install -y sudo libgl1-mesa-glx libxkbcommon0 libegl1 libxcb-cursor0 libdbus-1-dev libnss3 libxcomposite-dev libxdamage-dev libxrandr-dev libxtst-dev libxkbfile1 libx11-dev libasound2 libxcb-cursor0 libxcb-xinerama0 qt6-base-dev fonts-recommended \
    && apt-get clean \ 
    && rm -rf /var/lib/apt/lists/*

RUN useradd -ms /bin/bash runner
RUN usermod -aG sudo runner
RUN usermod -aG dialout runner

WORKDIR /home/runner
USER runner

COPY meshtastic_visualizer meshtastic_visualizer
COPY setup.py setup.py
COPY requirements.txt requirements.txt
COPY resources resources

RUN python -m venv --copies .venv
ENV PATH="/home/runner/.venv:$PATH"
RUN python -m pip install -r requirements.txt
RUN python -m pip install .
