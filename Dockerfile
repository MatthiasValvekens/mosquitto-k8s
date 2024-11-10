# Define Mosquitto version, see also .github/workflows/build_and_push_docker_images.yml for
# the automatically built images
ARG MOSQUITTO_VERSION=2.0.20

# Use debian:stable-slim as a builder for Mosquitto and dependencies.
FROM debian:stable-slim AS mosquitto_builder
ARG MOSQUITTO_VERSION

# Get mosquitto build dependencies.
# CJson detection is broken in the mosquitto build, so we have to have the headers
RUN set -ex; \
    apt-get update; \
    apt-get install -y wget build-essential cmake libssl-dev libcjson-dev

WORKDIR /app

RUN mkdir -p mosquitto/auth mosquitto/conf.d

RUN wget http://mosquitto.org/files/source/mosquitto-${MOSQUITTO_VERSION}.tar.gz

RUN tar xzvf mosquitto-${MOSQUITTO_VERSION}.tar.gz

# Build mosquitto.
RUN set -ex; \
    cd mosquitto-${MOSQUITTO_VERSION}; \
    make CFLAGS="-Wall -O2" WITH_WEBSOCKETS=no WITH_SRV=no WITH_CJSON=no WITH_CLIENTS=no; \
    make install;

# Use golang:latest as a builder for the plugin
FROM --platform=$BUILDPLATFORM golang:latest AS go_auth_builder

ENV CGO_CFLAGS="-I/usr/local/include -fPIC"
ENV CGO_LDFLAGS="-shared -Wl,-unresolved-symbols=ignore-all"
ENV CGO_ENABLED=1

# Bring TARGETPLATFORM to the build scope
ARG TARGETPLATFORM
ARG BUILDPLATFORM

# Install TARGETPLATFORM parser to translate its value to GOOS, GOARCH, and GOARM
COPY --from=tonistiigi/xx:golang / /
RUN go env

# Install needed libc and gcc for target platform.
RUN set -ex; \
  if [ ! -z "$TARGETPLATFORM" ]; then \
    case "$TARGETPLATFORM" in \
  "linux/amd64") \
    apt update && apt install -y gcc-x86-64-linux-gnu libc6-dev-amd64-cross \
    ;; \
  "linux/arm64") \
    apt update && apt install -y gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
    ;; \
  "linux/arm/v7") \
    apt update && apt install -y gcc-arm-linux-gnueabihf libc6-dev-armhf-cross \
    ;; \
  "linux/arm/v6") \
    apt update && apt install -y gcc-arm-linux-gnueabihf libc6-dev-armel-cross libc6-dev-armhf-cross \
    ;; \
  esac \
  fi

WORKDIR /app
COPY --from=mosquitto_builder /usr/local/include/ /usr/local/include/

COPY src/ ./

RUN set -ex; \
    go tool cgo -exportheader go-k8s-auth.h go-k8s-auth.go; \
    go build -ldflags="-s -w" -buildmode=c-shared -o go-k8s-auth.so


#Start from a new image.
FROM debian:stable-slim

RUN set -ex; \
    apt update; \
    apt install -y openssl uuid; \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/lib/mosquitto /var/log/mosquitto
RUN set -ex; \
    groupadd mosquitto; \
    useradd -s /sbin/nologin -u 1883 mosquitto -g mosquitto -d /var/lib/mosquitto; \
    chown -R mosquitto:mosquitto /var/log/mosquitto/; \
    chown -R mosquitto:mosquitto /var/lib/mosquitto/

#Copy confs, plugin so and mosquitto binary.
COPY --from=mosquitto_builder /app/mosquitto/ /mosquitto/
COPY --from=go_auth_builder /app/go-k8s-auth.so /mosquitto/go-k8s-auth.so
COPY --from=mosquitto_builder /usr/local/sbin/mosquitto /usr/sbin/mosquitto

COPY --from=mosquitto_builder /usr/local/lib/libmosquitto* /usr/local/lib/

RUN ldconfig;
USER mosquitto

EXPOSE 1883 1884
CMD [ "/usr/sbin/mosquitto" ,"-c", "/etc/mosquitto/mosquitto.conf" ]

