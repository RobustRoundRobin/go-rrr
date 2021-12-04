# Written assuming that:
#
# our fork of ConsenSys is put in buildcontext/quorum
# go-rrr is put in buildcontext/go-rrr
#
# For local development, in our fork of ConsenSys/quorum, quorum/go.mod has a
# relative replace directive which require this layout.
#
# Our tusk.yml build step uses rsync to maintain a buildcontext in ${workdir}

FROM golang:1.15-buster as go-builder
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
  && apt-get upgrade -y --no-install-recommends \
  && apt-get install -y \
        git \
        build-essential

ENV GOBIN=/go/bin

WORKDIR /build/go-rrr/consensus
COPY go-rrr/consensus/go.mod go-rrr/consensus/go.sum ./
RUN go mod download

WORKDIR /build/go-rrr/secp256k1suite
COPY go-rrr/secp256k1suite/go.mod go-rrr/secp256k1suite/go.sum ./
RUN go mod download

WORKDIR /build/quorum
COPY quorum/go.mod quorum/go.sum ./
RUN go mod download

ADD quorum /build/quorum
ADD go-rrr/consensus /build/go-rrr/consensus

RUN go install github.com/ethereum/go-ethereum/cmd/geth

FROM debian:bullseye-slim
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
  && apt-get upgrade -y --no-install-recommends \
  && apt-get install -y \
        bind9-dnsutils \
        curl \
        ca-certificates \
  && apt-get clean autoclean \
  && apt-get autoremove --yes \
  && rm -rf /var/lib/{apt,dpkg,cache,log}/

COPY --from=go-builder /go/bin/geth /usr/local/bin/

ENTRYPOINT ["geth"]
