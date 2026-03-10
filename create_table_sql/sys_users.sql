create table public.sys_users (
  id uuid not null default gen_random_uuid (),
  username character varying(50) not null,
  email character varying(100) null,
  password character varying(255) not null,
  status smallint null default 1,
  created_at timestamp with time zone null,
  updated_at timestamp with time zone null,
  constraint sys_users_pkey primary key (id)
) TABLESPACE pg_default;

create unique INDEX IF not exists idx_sys_users_email on public.sys_users using btree (email) TABLESPACE pg_default;

create unique INDEX IF not exists idx_sys_users_username on public.sys_users using btree (username) TABLESPACE pg_default;