# Build the manager binary
#
# The Docker context is expected to be:
#
# ${PATH_TO_KUBEFLOW/KUBEFLOW repo}/components
#

# Build arguments
ARG SOURCE_CODE=.
ARG GOLANG_VERSION=1.20

# Use ubi8/go-toolset as base image
FROM registry.redhat.io/ubi8/go-toolset:${GOLANG_VERSION} as builder

## Build args to be used at this step
ARG SOURCE_CODE

# Set building workdir
WORKDIR /workspace

# Copy the Go Modules manifests
COPY ${SOURCE_CODE}/notebook-controller ./notebook-controller
COPY ${SOURCE_CODE}/odh-notebook-controller ./odh-notebook-controller

# Update building workdir
WORKDIR /workspace/odh-notebook-controller

## Build the kf-notebook-controller
USER root

RUN if [ -z ${CACHITO_ENV_FILE} ]; then \
       go mod download all; \
    else \
       source ${CACHITO_ENV_FILE}; \
    fi

RUN go build \
        -o ./bin/manager main.go

# Use ubi8/ubi-minimal as base image
FROM registry.redhat.io/ubi8/ubi-minimal:latest

## Install additional packages
RUN microdnf install -y shadow-utils &&\
    microdnf clean all

## Create a non-root user with UID 1001
RUN useradd --uid 1001 --create-home --user-group --system rhods

## Set workdir directory to user home
WORKDIR /home/rhods

## Copy kf-notebook-controller-manager binary from builder stage
COPY --from=builder /workspace/odh-notebook-controller/bin/manager /manager
COPY --from=builder /workspace/odh-notebook-controller/third_party/license.txt third_party/license.txt
# in builder image, `go env GOPATH` outputs `/opt/app-root/src/go`
COPY --from=builder //opt/app-root/src/go/pkg/mod/github.com/hashicorp third_party/hashicorp


## Switch to a non-root user
USER rhods

ENTRYPOINT [ "/manager" ]
