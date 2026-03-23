FROM cloudflare/cloudflared:latest AS source
FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=source /usr/local/bin/cloudflared /usr/local/bin/cloudflared
COPY cloudflared-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["tunnel", "--config", "/etc/cloudflared/config.yml", "run"]
