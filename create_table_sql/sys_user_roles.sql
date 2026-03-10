create table public.sys_user_roles (
                                       id bigserial not null,
                                       user_id uuid not null,
                                       role_id bigint not null,
                                       app_id bigint not null,
                                       constraint sys_user_roles_pkey primary key (id),
                                       constraint fk_sys_user_roles_app foreign KEY (app_id) references sys_apps (id),
                                       constraint fk_sys_user_roles_role foreign KEY (role_id) references sys_roles (id),
                                       constraint fk_sys_user_roles_user foreign KEY (user_id) references sys_users (id),
                                       constraint fk_sys_users_user_roles foreign KEY (user_id) references sys_users (id)
) TABLESPACE pg_default;

create index IF not exists idx_sys_user_roles_app_id on public.sys_user_roles using btree (app_id) TABLESPACE pg_default;

create index IF not exists idx_sys_user_roles_role_id on public.sys_user_roles using btree (role_id) TABLESPACE pg_default;

create index IF not exists idx_sys_user_roles_user_id on public.sys_user_roles using btree (user_id) TABLESPACE pg_default;