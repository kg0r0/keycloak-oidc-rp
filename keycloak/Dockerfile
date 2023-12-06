FROM quay.io/keycloak/keycloak:23.0.1 as builder

ENV KEYCLOAK_ADMIN=admin
ENV KEYCLOAK_ADMIN_PASSWORD=admin

WORKDIR /opt/keycloak

COPY import/ /opt/keycloak/data/import

RUN /opt/keycloak/bin/kc.sh import --dir=/opt/keycloak/data/import/ --override true; exit 0

ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start-dev"]