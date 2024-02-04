FROM sippylabs/rtpproxy
LABEL maintainer="Razvan Crainea <razvan@opensips.org>"

USER root

# Set Environment Variables
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -y update -qq && \
		apt-get -y install gnupg2 ca-certificates && \
		apt-get -y update -qq

RUN apt-get -y install python3-pip

RUN pip install --break-system-packages sippy

ENTRYPOINT ["b2bua_simple"]
