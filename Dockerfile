# Runtime image - amd64 only

FROM alpine:3.23

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -g 1000 atuin && adduser -u 1000 -G atuin -s /bin/sh -D atuin \
    && mkdir -p /app && chown -R atuin:atuin /app

WORKDIR /app
USER atuin

ENV RUST_LOG=atuin_server=info
ENV ATUIN_CONFIG_DIR=/app

EXPOSE 8888

COPY --chown=atuin:atuin atuin-server /app/atuin-server

CMD ["/app/atuin-server", "start"]