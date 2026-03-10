create table public.sys_permissions (
                                        id bigserial not null,
                                        app_id bigint not null,
                                        permission_code character varying(100) not null,
                                        bit_index smallint not null,
                                        description text null,
                                        constraint sys_permissions_pkey primary key (id),
                                        constraint fk_sys_permissions_app foreign KEY (app_id) references sys_apps (id)
) TABLESPACE pg_default;

create unique INDEX IF not exists idx_app_bit_index on public.sys_permissions using btree (app_id, bit_index) TABLESPACE pg_default;

create index IF not exists idx_sys_permissions_app_id on public.sys_permissions using btree (app_id) TABLESPACE pg_default;