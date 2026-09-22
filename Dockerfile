ARG SDK_IMAGE=mcr.microsoft.com/dotnet/sdk:10.0.301@sha256:ea8bde36c11b6e7eec2656d0e59101d4462f6bd630730f2c8201ed0572b295d5
ARG RUNTIME_IMAGE=mcr.microsoft.com/dotnet/aspnet:10.0.9@sha256:7644f992230d35cf230017189d4038c0ae0f7388b13f4f7ae1900a155bafb597
ARG BUILDPLATFORM

FROM --platform=${BUILDPLATFORM} ${SDK_IMAGE} AS build
ARG TARGETARCH
WORKDIR /src
COPY . ./xnode
COPY --from=deep_protocol . ./deep-protocol
WORKDIR /src/xnode
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) dotnet_arch="x64" ;; \
      arm64) dotnet_arch="arm64" ;; \
      *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    dotnet restore src/XNode/XNode.csproj -p:DeepProtocolSourceCutover=true -p:DeepProtocolLocalCutover=false; \
    dotnet publish src/XNode/XNode.csproj \
      --configuration Release \
      --output /app \
      --no-restore \
      -p:DeepProtocolSourceCutover=true \
      -p:DeepProtocolLocalCutover=false \
      --arch "${dotnet_arch}"

FROM ${RUNTIME_IMAGE} AS runtime
ARG TARGETARCH
ARG XRAY_VERSION=v26.3.27
ARG DEEP_PROTOCOL_REVISION
LABEL com.xpoint.deep-protocol.revision=${DEEP_PROTOCOL_REVISION}
WORKDIR /app
RUN set -eux; \
    for attempt in 1 2 3 4 5; do \
      rm -rf /var/lib/apt/lists/*; \
      apt-get update -o Acquire::Retries=5 -o Acquire::http::Timeout=60 -o Acquire::https::Timeout=60 && break; \
      if [ "$attempt" = "5" ]; then exit 1; fi; \
      sleep $((attempt * 10)); \
    done; \
    apt-get install -y --no-install-recommends -o Acquire::Retries=5 curl ca-certificates unzip; \
    rm -rf /var/lib/apt/lists/*; \
    case "${TARGETARCH:-amd64}" in \
      amd64) xray_asset="Xray-linux-64.zip" ;; \
      arm64) xray_asset="Xray-linux-arm64-v8a.zip" ;; \
      *) echo "Unsupported architecture: ${TARGETARCH:-}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${xray_asset}" -o /tmp/xray.zip; \
    unzip -q /tmp/xray.zip -d /tmp/xray; \
    install -m 0755 /tmp/xray/xray /usr/local/bin/xray; \
    rm -rf /tmp/xray /tmp/xray.zip; \
    xray version
COPY --from=build /app .
EXPOSE 443 8080 8081 8082 8083
ENTRYPOINT ["dotnet", "XNode.dll"]
