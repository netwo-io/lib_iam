drop domain if exists lib_iam.identifier;
create domain lib_iam.identifier as varchar(63)
  not null
  check (value ~* '^(([a-z]|[a-z][a-z0-9\-_]*[a-z0-9])){3,63}$');

drop domain if exists lib_iam.wildcardable_identifier;
create domain lib_iam.wildcardable_identifier as varchar(63)
  not null
  check (value ~* '^(\*|([a-z]|[a-z][a-z0-9\-_]*[a-z0-9]){3,63})$');

drop domain if exists lib_iam.description;
create domain lib_iam.description as text
  not null
  check (length(trim(value)) > 3);

drop domain if exists lib_iam.title;
create domain lib_iam.title as lib_iam.description;

drop domain if exists lib_iam.permission_name;
create domain lib_iam.permission_name as text
  not null
  check (value ~* '^.+:.+:.+$');

create table lib_iam.service
(
  service__id lib_iam.identifier primary key,
  description lib_iam.description
);

comment on column lib_iam.service.service__id is 'Service identifier e.g: "test_manager"';

create table lib_iam.type
(
  service__id lib_iam.identifier references lib_iam.service (service__id) on delete cascade on update cascade,
  type__id    lib_iam.identifier,
  description lib_iam.description,
  primary key(service__id, type__id)
);

comment on column lib_iam.type.type__id is 'Type identifier e.g: "invoice"';

create table lib_iam.verb
(
  verb__id    lib_iam.wildcardable_identifier primary key
);

comment on column lib_iam.verb.verb__id is 'verb name: "create" or "get_payment_info"';

create table lib_iam.permission
(
  service__id lib_iam.identifier references lib_iam.service (service__id) on delete restrict on update cascade,
  type__id    lib_iam.identifier,
  verb__id    lib_iam.wildcardable_identifier references lib_iam.verb (verb__id) on delete restrict on update cascade,
  primary key(service__id, type__id, verb__id),
  foreign key (service__id, type__id) references lib_iam.type (service__id, type__id) on delete restrict on update cascade
);

comment on column lib_iam.permission.type__id is 'the resource type this permission defines. E.g. "invoice"';
comment on column lib_iam.permission.verb__id is 'the verb for this resource type this permission defines E.g. "create"';

create table lib_iam.role
(
  service__id lib_iam.identifier references lib_iam.service (service__id) on delete restrict on update cascade,
  role__id    lib_iam.identifier check (role__id ~* '^viewer|editor|admin$'),
  title       lib_iam.title,
  description lib_iam.description,
  primary key (service__id, role__id)
);

comment on table lib_iam.role is 'role={service__id}.{role_title__id}
  test_manager.viewer
  test_manager.editor
  test_manager.admin';

create table lib_iam.role__permission
(
  permission_service__id lib_iam.identifier,
  permission_type__id    lib_iam.identifier,
  permission_verb__id    lib_iam.wildcardable_identifier,
  service__id            lib_iam.identifier,
  role__id               lib_iam.identifier,
  foreign key (permission_service__id, permission_type__id, permission_verb__id) references lib_iam.permission (service__id, type__id, verb__id) on delete restrict on update cascade,
  foreign key (service__id, role__id) references lib_iam.role (service__id, role__id) on delete restrict on update cascade
);
