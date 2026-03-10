create table public.sys_role_permission_masks (
                                                  role_id bigint not null,
                                                  bucket_index smallint not null,
                                                  mask bigint not null default 0,
                                                  constraint sys_role_permission_masks_pkey primary key (role_id, bucket_index),
                                                  constraint fk_masks_role foreign KEY (role_id) references sys_roles (id) on delete CASCADE
) TABLESPACE pg_default;