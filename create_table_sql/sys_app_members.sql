create table public.sys_app_members (
                                        app_id bigint not null,
                                        user_id uuid not null,
                                        role_type smallint null default 1,
                                        constraint sys_app_members_pkey primary key (app_id, user_id)
) TABLESPACE pg_default;