# 1. lepes: JAR letoltese Alpine-ban (van benne wget)
FROM alpine:3.20 AS downloader
RUN wget -O /keycloak-webhook-provider-http.jar \
    https://github.com/vymalo/keycloak-webhook/releases/download/v0.10.0-rc.1/keycloak-webhook-provider-http-0.10.0-rc.1-all.jar

# 2. lepes: Keycloak image a letoltott JAR-ral
FROM quay.io/keycloak/keycloak:25.0.0
COPY --from=downloader /keycloak-webhook-provider-http.jar /opt/keycloak/providers/

RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start"]
