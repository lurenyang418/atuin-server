# Runtime image - amd64 only

FROM alpine:3.23

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

ENV RUST_LOG=atuin_server=info
ENV ATUIN_CONFIG_DIR=/app

EXPOSE 8888

COPY atuin-server /app/atuin-server

CMD ["/app/atuin-server", "start"]