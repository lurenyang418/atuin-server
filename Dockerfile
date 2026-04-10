# Runtime image - amd64 only

FROM alpine:3.23

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -g 1000 atuin && adduser -u 1000 -G atuin -s /bin/sh -D atuin

WORKDIR /app
USER atuin

ENV RUST_LOG=atuin_server=info
ENV ATUIN_CONFIG_DIR=/app

EXPOSE 8888

COPY atuin-server /app/atuin-server

ENTRYPOINT ["/app/atuin-server"]
CMD ["start"]