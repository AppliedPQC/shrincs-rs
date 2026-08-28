FROM ubuntu:24.04
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
      build-essential libssl-dev libgtest-dev >/dev/null
WORKDIR /src
COPY . .
# The upstream Makefile resolves OpenSSL through Homebrew, which does not exist
# on Linux; on Ubuntu the headers and libraries are already on the default path.
RUN sed -i 's|^OPENSSL_PREFIX := .*|OPENSSL_PREFIX :=|' Makefile
