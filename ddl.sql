create extension if not exists "uuid-ossp";

CREATE TABLE public."M_APPLICATION" (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    app_name VARCHAR(100) NOT NULL UNIQUE,

    client_id VARCHAR(100) NOT NULL UNIQUE,

    token_hash VARCHAR(255) NOT NULL,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_m_application_client_id
    ON public."M_APPLICATION"(client_id);