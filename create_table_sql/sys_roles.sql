create table public.sys_roles (
                                  id bigserial not null,
                                  app_id bigint not null,
                                  name character varying(50) not null,
                                  constraint sys_roles_pkey primary key (id),
                                  constraint fk_sys_roles_app foreign KEY (app_id) references sys_apps (id)
) TABLESPACE pg_default;

create index IF not exists idx_sys_roles_app_id on public.sys_roles using btree (app_id) TABLESPACE pg_default;