-- Add up migration script here
create table blogs (
    id integer not null primary key autoincrement,
    slug text not null unique,
    title text not null,
    content text not null,
    thumbnail text not null
) 