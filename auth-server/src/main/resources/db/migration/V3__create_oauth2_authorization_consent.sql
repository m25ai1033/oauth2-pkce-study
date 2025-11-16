-- V3__create_oauth2_authorization_consent.sql
CREATE TABLE oauth2_authorization_consent (
                                              id VARCHAR(100) NOT NULL PRIMARY KEY,
                                              registered_client_id VARCHAR(100),
                                              principal_name VARCHAR(200),
                                              authorities TEXT
);

CREATE UNIQUE INDEX oauth2_authorization_consent_unique ON oauth2_authorization_consent(registered_client_id, principal_name);
