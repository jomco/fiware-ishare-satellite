FROM python:3.7-alpine

ENV SATELLITE_PORT=8080

RUN apk update && \
    apk add gcc build-base libc-dev libffi-dev openssl-dev bash curl

RUN addgroup --gid 5000 satellite \
    && adduser --uid 500 -G satellite -D -s /bin/sh -k /dev/null satellite

COPY . /var/satellite
WORKDIR /var/satellite

RUN pip install --no-cache-dir -r requirements.txt

RUN chown satellite /var/satellite
USER satellite
WORKDIR /var/satellite

RUN pip install --no-cache-dir -r requirements.txt

HEALTHCHECK CMD curl --fail http://localhost:${SATELLITE_PORT}/health || exit 1
EXPOSE $SATELLITE_PORT
CMD [ "./bin/run.sh" ]
