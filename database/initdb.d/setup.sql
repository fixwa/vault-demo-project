-- auto-generated definition
create table settings
(
    id    int auto_increment
        primary key,
    name  varchar(100) null,
    value text         null,
    constraint name
        unique (name)
);
