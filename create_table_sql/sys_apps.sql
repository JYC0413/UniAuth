create table public.sys_apps (
                                 id bigserial not null,
                                 code character varying(50) not null,
                                 name character varying(100) null,
                                 secret_key character varying(64) null,
                                 created_at timestamp with time zone null,
                                 updated_at timestamp with time zone null,
                                 redirect_url character varying null,
                                 constraint sys_apps_pkey primary key (id)
) TABLESPACE pg_default;

create unique INDEX IF not exists idx_sys_apps_code on public.sys_apps using btree (code) TABLESPACE pg_default;