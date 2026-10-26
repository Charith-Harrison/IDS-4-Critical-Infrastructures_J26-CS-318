# Component 2 controlled Modbus/TCP testbed image.
# One image is used for every role (target server, clients, capture, analysis) so that
# the software versions recorded in each run manifest are identical across roles.
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends tcpdump tshark iproute2 \
 && rm -rf /var/lib/apt/lists/*

COPY docker/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

WORKDIR /tb
ENV PYTHONPATH=/tb
