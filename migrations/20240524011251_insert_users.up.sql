-- Add up migration script here
insert into users (name, email, password) values ("gustavo", "gustavo@evoi.com.br", "password");
insert into user_roles (role_id, user_id) values (1, 1);