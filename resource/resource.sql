drop domain if exists lib_iam.resource_name;
create domain lib_iam.resource_name as text
  not null
  check (value ~* '^(\*|((resource|organization|folder):.+))$');

-- abstract_resource_type : "organization:XXX"|"folder:XXX"|"resource:XXX"
create type lib_iam.resource_type__id as (resource_type varchar(64), resource__id uuid);

create table lib_iam.organization
(
  organization__id        uuid not null primary key default public.gen_random_uuid(),
  -- an organization can only have a parent organization or no parent at all
  parent_organization__id uuid references lib_iam.organization (organization__id) on delete cascade on update cascade,
  name                    lib_iam.identifier,
  description             lib_iam.description,
  status                  uuid not null references lib_fsm.state_machine(state_machine__id) on delete restrict on update cascade
);

create index organization_t_organization_index on lib_iam.organization (parent_organization__id);

create table lib_iam.folder
(
  folder__id              uuid not null primary key default public.gen_random_uuid(),

  -- a folder can only have has a parent an organization or a parent folder
  parent_folder__id       uuid references lib_iam.folder (folder__id) on delete cascade on update cascade,

  -- a folder always has a parent organization
  parent_organization__id uuid references lib_iam.organization (organization__id)  on delete cascade on update cascade,

  name                    lib_iam.identifier,
  description             lib_iam.description,
  status                  uuid not null references lib_fsm.state_machine(state_machine__id) on delete restrict on update cascade

  -- when the folder is the root folder, the parent organization_id MUST NOT be null
  -- when the folder is not the root folder, the parent organization_id MUST be null
  constraint folder_must_have_only_one_parent check ((parent_folder__id is null) != (parent_organization__id is null))
);

create index folder_t_parent_folder_index on lib_iam.folder (parent_folder__id);
create index folder_t_parent_organization_index on lib_iam.folder (parent_organization__id);

create table lib_iam.resource
(
  resource__id      uuid               not null primary key default public.gen_random_uuid(),
  parent_folder__id uuid               not null references lib_iam.folder (folder__id) on delete cascade on update cascade,
  service__id       lib_iam.identifier,
  type__id          lib_iam.identifier,
  name              lib_iam.identifier,
  foreign key (service__id, type__id) references lib_iam.type (service__id, type__id) on delete cascade on update cascade
);

create index resource_t_type_index on lib_iam.resource (service__id, type__id);

------------------------- API -------------------------

-- parse a fully qualified resource (e.g. "[resource|organization|folder]:[UUID|*]") and yield a resource_id (e.g. "(resource_type, resource__id)")
create or replace function lib_iam._parse_resource(resource$ lib_iam.resource_name) returns lib_iam.resource_type__id as $$
declare
  resources$ text[];
  result     lib_iam.resource_type__id;
begin

  if resource$ = '*' then
    result.resource_type = '*';
    return result;
  end if;

  resources$ = regexp_matches(resource$, '^(resource|organization|folder):(.+)$');

  if array_length(resources$, 1) != 2 then
    raise 'wrong resource$ format, awaited * or {resource_type}:{resource_id}' using errcode = 'check_violation';
  end if;

  result.resource_type = resources$[1]::text;
  result.resource__id = resources$[2]::uuid;
  return result;
end;
$$ immutable language plpgsql;

-- Organization

create or replace function lib_iam.organization_create(
  name$                    lib_iam.identifier,
  description$             lib_iam.description,
  parent_organization__id$ uuid default null,
  organization__id$        uuid default public.gen_random_uuid()
) returns uuid as
$$
declare
  state_machine__id$ uuid;
begin
  state_machine__id$ = lib_fsm.state_machine_create('081d831f-8f88-0000-aaaa-000000000001'::uuid);
  insert into lib_iam.organization (organization__id, parent_organization__id, name, description, status) values (organization__id$, parent_organization__id$, name$, description$, state_machine__id$);
  return organization__id$;
end;
$$ language plpgsql;

create or replace function lib_iam.organization_delete(organization__id$ uuid) returns void as
$$
declare
  status$ uuid;
begin
  select status from lib_iam.organization where organization__id = organization__id$ into status$;
  perform lib_fsm.state_machine_transition(status$, 'delete');
end;
$$ language plpgsql;

-- Folder

create or replace function lib_iam.folder_create(
  name$                    lib_iam.identifier,
  description$             lib_iam.description,
  parent_folder__id$       uuid default null,
  parent_organization__id$ uuid default null,
  folder__id$              uuid default public.gen_random_uuid()
) returns uuid as
$$
declare
  state_machine__id$ uuid;
begin
  state_machine__id$ = lib_fsm.state_machine_create('081d831f-8f88-0000-aaaa-000000000001'::uuid);
  insert into lib_iam.folder (folder__id, parent_folder__id, parent_organization__id, name, description, status) values (folder__id$, parent_folder__id$, parent_organization__id$, name$, description$, state_machine__id$);
  return folder__id$;
end;
$$ language plpgsql;

create or replace function lib_iam.folder_delete(folder__id$ uuid) returns void as
$$
declare
  status$ uuid;
begin
  select status from lib_iam.folder where folder__id = folder__id$ into status$;
  perform lib_fsm.state_machine_transition(status$, 'delete');
end;
$$ language plpgsql;

-- Resource

create or replace function lib_iam.resource_create(
  name$              lib_iam.identifier,
  parent_folder__id$ uuid,
  service__id$       lib_iam.identifier,
  type__id$          lib_iam.identifier,
  resource__id$      uuid default public.gen_random_uuid()
) returns uuid as
$$
begin
  insert into lib_iam.resource (resource__id, parent_folder__id, service__id, type__id, name) values (resource__id$, parent_folder__id$, service__id$, type__id$, name$) returning resource__id into resource__id$;
  return resource__id$;
end;
$$ language plpgsql;

create or replace function lib_iam.resource_delete(resource__id$ uuid) returns void as
$$
begin
    -- @todo should we use lib_iam.authorize() here?
  delete from lib_iam.resource where resource__id = resource__id$;
end;
$$ language plpgsql;
