-- V1__create_oauth2_registered_client.sql
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
