CREATE TABLE oauth2_registered_client (
                                          id VARCHAR(100) NOT NULL PRIMARY KEY,
                                          client_id VARCHAR(100) NOT NULL,
                                          client_id_issued_at TIMESTAMP,
                                          client_secret VARCHAR(200),
                                          client_secret_expires_at TIMESTAMP,
                                          client_name VARCHAR(200),
                                          client_authentication_methods TEXT,
                                          authorization_grant_types TEXT,
                                          redirect_uris TEXT,
                                          post_logout_redirect_uris TEXT,
                                          scopes TEXT,
                                          client_settings TEXT,
                                          token_settings TEXT
);

CREATE UNIQUE INDEX oauth2_registered_client_client_id_idx ON oauth2_registered_client(client_id);

-- V2__create_oauth2_authorization.sql
CREATE TABLE oauth2_authorization (
                                      id VARCHAR(100) NOT NULL PRIMARY KEY,
                                      registered_client_id VARCHAR(100),
                                      principal_name VARCHAR(200),
                                      authorization_grant_type VARCHAR(100),
                                      attributes TEXT,
                                      state VARCHAR(500),

                                      authorization_code_value TEXT,
                                      authorization_code_issued_at TIMESTAMP,
                                      authorization_code_expires_at TIMESTAMP,
                                      authorization_code_metadata TEXT,

                                      access_token_value TEXT,
                                      access_token_issued_at TIMESTAMP,
                                      access_token_expires_at TIMESTAMP,
                                      access_token_metadata TEXT,

                                      refresh_token_value TEXT,
                                      refresh_token_issued_at TIMESTAMP,
                                      refresh_token_expires_at TIMESTAMP,
                                      refresh_token_metadata TEXT,

                                      oidc_id_token_value TEXT,
                                      oidc_id_token_issued_at TIMESTAMP,
                                      oidc_id_token_expires_at TIMESTAMP,
                                      oidc_id_token_metadata TEXT
);

CREATE INDEX oauth2_authorization_registered_client_id_idx ON oauth2_authorization(registered_client_id);
CREATE INDEX oauth2_authorization_principal_name_idx ON oauth2_authorization(principal_name);

-- V3__create_oauth2_authorization_consent.sql
CREATE TABLE oauth2_authorization_consent (
                                              id VARCHAR(100) NOT NULL PRIMARY KEY,
                                              registered_client_id VARCHAR(100),
                                              principal_name VARCHAR(200),
                                              authorities TEXT
);

CREATE UNIQUE INDEX oauth2_authorization_consent_unique ON oauth2_authorization_consent(registered_client_id, principal_name);
