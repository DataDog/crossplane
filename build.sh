#!/bin/bash
set -e

# Build configuration
REGISTRY="docker.io/cahillsf"
IMAGE_NAME="crossplane"
# VERSION="${VERSION:-$(git describe --dirty --always --tags | sed -e 's/-/./2g')}"
VERSION="v0.0.1-dev"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"

echo "Building ${REGISTRY}/${IMAGE_NAME}:${VERSION}"
echo "Platforms: ${PLATFORMS}"

# Create buildx builder if it doesn't exist
docker buildx create --name crossplane-builder --use 2>/dev/null || docker buildx use crossplane-builder

# Create Dockerfile inline
cat > Dockerfile << 'EOF'
FROM golang:1.24.5-alpine AS builder

WORKDIR /crossplane
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=v0.0.0-dev
ENV GOFIPS140=v1.0.0
RUN CGO_ENABLED=0 GOOS=linux go build \
  -ldflags="-s -w -X=github.com/crossplane/crossplane/v2/internal/version.version=${VERSION}" \
  -o crossplane ./cmd/crossplane

FROM registry.ddbuild.io/images/base/gbi-distroless-nossl-root-fips:release
COPY --from=builder /crossplane/crossplane /usr/local/bin/
COPY cluster/crds/ /crds
COPY cluster/webhookconfigurations/ /webhookconfigurations
EXPOSE 8080
USER 65532
ENTRYPOINT ["crossplane"]
EOF

# Build and push multi-platform image
METADATA_FILE=$(mktemp)
docker buildx build \
  --platform ${PLATFORMS} \
  --build-arg VERSION=${VERSION} \
  --label is_fips=true \
  --label version=${VERSION} \
  --label target=release \
  --tag ${REGISTRY}/${IMAGE_NAME}:${VERSION} \
  --metadata-file "${METADATA_FILE}" \
  --output type=image,push=true,compression=zstd,force-compression=true,oci-mediatypes=true \
  .

# Show build metadata
echo "Build metadata:"
cat "${METADATA_FILE}"

# Cleanup metadata file
rm -f "${METADATA_FILE}"

# Cleanup
rm -f Dockerfile

echo "Successfully built and pushed ${REGISTRY}/${IMAGE_NAME}:${VERSION}"