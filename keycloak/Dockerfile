# 1. lepes: JAR-ok letoltese Alpine-ban (van benne wget)
FROM alpine:3.20 AS downloader
RUN wget -O /keycloak-webhook-provider-core.jar \
    https://github.com/vymalo/keycloak-webhook/releases/download/v0.10.0-rc.1/keycloak-webhook-provider-core-0.10.0-rc.1-all.jar && \
    wget -O /keycloak-webhook-provider-http.jar \
    https://github.com/vymalo/keycloak-webhook/releases/download/v0.10.0-rc.1/keycloak-webhook-provider-http-0.10.0-rc.1-all.jar

# 2. lepes: Keycloak image a letoltott JAR-okkal
FROM quay.io/keycloak/keycloak:25.0.0
COPY --from=downloader /keycloak-webhook-provider-core.jar /opt/keycloak/providers/
COPY --from=downloader /keycloak-webhook-provider-http.jar /opt/keycloak/providers/

# Build-time konfig - ezek besuludnek az optimized image-be
ENV KC_TRANSACTION_XA_ENABLED=false
ENV KC_HEALTH_ENABLED=true
ENV KC_HTTP_MANAGEMENT_HEALTH_ENABLED=false
ENV KC_METRICS_ENABLED=false

RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
