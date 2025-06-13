FROM python:3.11-bookworm

ENV UV_INSTALL_DIR="/usr/local/bin/"

RUN apt-get update \
    && apt-get install -y sudo libgl1-mesa-glx libxkbcommon0 libegl1 libxcb-cursor0 libdbus-1-dev libnss3 libxcomposite-dev libxdamage-dev libxrandr-dev libxtst-dev libxkbfile1 libx11-dev libasound2 libxcb-cursor0 libxcb-xinerama0 qt6-base-dev fonts-recommended \
    && apt-get clean \ 
    && rm -rf /var/lib/apt/lists/*

RUN useradd -ms /bin/bash runner
RUN usermod -aG sudo runner
RUN usermod -aG dialout runner

RUN curl -LsSf https://astral.sh/uv/install.sh -o install.sh
RUN sh install.sh

WORKDIR /home/runner
USER runner


COPY meshtastic_visualizer meshtastic_visualizer
COPY pyproject.toml pyproject.toml

RUN uv python install 3.11
RUN uv python pin 3.11
RUN uv run true
ENTRYPOINT ["uv", "run", "meshtastic_visualizer.py"]
