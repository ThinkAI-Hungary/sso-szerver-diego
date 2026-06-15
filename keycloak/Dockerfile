FROM quay.io/keycloak/keycloak:25.0.0

# vymalo/keycloak-webhook HTTP provider
COPY providers/keycloak-webhook-provider-http.jar /opt/keycloak/providers/

# Build Keycloak with the new provider baked in
RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start"]
