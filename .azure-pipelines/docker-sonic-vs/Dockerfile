FROM docker-sonic-vs

ARG docker_container_name

ADD ["debs", "/debs"]

RUN dpkg --purge swss
RUN dpkg -i /debs/*.deb || apt-get install -f -y
