FROM ubuntu:20.04

WORKDIR /workspace
COPY libseccomp-go-playground .
CMD ["libseccomp-go-playground"]
