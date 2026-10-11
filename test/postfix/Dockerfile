# Throwaway Postfix used by test/integration.sh. Not for production.
FROM debian:bookworm-slim
RUN echo "postfix postfix/main_mailer_type select Local only" | debconf-set-selections \
 && echo "postfix postfix/mailname string mail.example.test" | debconf-set-selections \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postfix ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m alice
COPY transport /etc/postfix/transport
RUN postconf -e \
      maillog_file=/var/log/postfix.log \
      myhostname=mail.example.test \
      myorigin=example.test \
      mydestination="mail.example.test, localhost" \
      inet_interfaces=loopback-only \
      inet_protocols=ipv4 \
      smtp_connect_timeout=3s \
      transport_maps=texthash:/etc/postfix/transport \
      queue_run_delay=300s minimal_backoff_time=300s \
 && postconf -F '*/*/chroot = n' \
 && newaliases
CMD ["postfix", "start-fg"]
