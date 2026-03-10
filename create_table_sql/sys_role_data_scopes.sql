create table public.sys_role_data_scopes (
                                             id bigserial not null,
                                             role_id bigint not null,
                                             scope_type smallint not null default 1,
                                             custom_config text null,
                                             constraint sys_role_data_scopes_pkey primary key (id),
                                             constraint fk_sys_roles_data_scope foreign KEY (role_id) references sys_roles (id) on delete CASCADE
) TABLESPACE pg_default;

create unique INDEX IF not exists idx_sys_role_data_scopes_role_id on public.sys_role_data_scopes using btree (role_id) TABLESPACE pg_default;