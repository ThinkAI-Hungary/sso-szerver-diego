FROM quay.io/keycloak/keycloak:25.0.0

# vymalo/keycloak-webhook HTTP provider letoltese GitHub Releases-bol
RUN curl -L -o /opt/keycloak/providers/keycloak-webhook-provider-http.jar \
    https://github.com/vymalo/keycloak-webhook/releases/download/v0.10.0-rc.1/keycloak-webhook-provider-http-0.10.0-rc.1-all.jar

# Build Keycloak with the new provider baked in
RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start"]
