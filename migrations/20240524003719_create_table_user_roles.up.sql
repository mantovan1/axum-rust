-- Add up migration script here
CREATE TABLE user_roles (
    user_id INTEGER not null,
    role_id INTEGER not null,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (role_id) REFERENCES roles(id),
    PRIMARY KEY (user_id, role_id)
);

-- Inserir os valores na tabela `roles`
INSERT INTO roles (name) VALUES ('Admin'), ('User');