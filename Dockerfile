ARG SDK_IMAGE=mcr.microsoft.com/dotnet/sdk:10.0.100
ARG RUNTIME_IMAGE=mcr.microsoft.com/dotnet/aspnet:10.0.0

FROM ${SDK_IMAGE} AS build
WORKDIR /src
COPY . .
RUN dotnet restore src/XNode/XNode.csproj
RUN dotnet publish src/XNode/XNode.csproj --configuration Release --output /app --no-restore

FROM ${RUNTIME_IMAGE} AS runtime
ARG TARGETARCH
ARG XRAY_VERSION=v26.3.27
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
EXPOSE 443 8080 8081
ENTRYPOINT ["dotnet", "XNode.dll"]
