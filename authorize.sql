create or replace function lib_iam._find_parent_organizations_by_organization (organization__id$ uuid) returns uuid[] as $$
declare
  root_organization__id$ uuid[];
begin
  with recursive suborganizations as (
      select parent_organization__id, organization__id, 1 as level
      from lib_iam.organization
      where organization__id = organization__id$
    union
      select o.parent_organization__id, o.organization__id, suborganizations.level + 1 as level
      from lib_iam.organization o
      inner join suborganizations on o.organization__id = suborganizations.parent_organization__id
  )
  select array_agg(organization__id)
  from suborganizations
  into root_organization__id$;

  return root_organization__id$;
end;
$$ stable security definer language plpgsql;

create or replace function lib_iam._find_parent_organizations_by_folder(folder__id$ uuid) returns uuid[] as $$
declare
  organization__id$ uuid;
begin
  with recursive subfolders as (
    select f1.parent_folder__id, f1.folder__id, f1.name, f1.parent_organization__id, 1 as level
    from lib_iam.folder f1
    where f1.folder__id = folder__id$
    union
    select f.parent_folder__id, f.folder__id, f.name, f.parent_organization__id, subfolders.level + 1 as level
    from lib_iam.folder f
    inner join subfolders on f.folder__id = subfolders.parent_folder__id
  )
  select o.organization__id from subfolders s
  inner join lib_iam.organization o on o.organization__id = s.parent_organization__id into organization__id$;

  return lib_iam._find_parent_organizations_by_organization (organization__id$);
end;
$$ stable security definer language plpgsql;

create or replace function lib_iam._find_parent_organizations_by_resource(resource__id$ uuid) returns uuid[] as $$
declare
  folder__id$ uuid;
begin

  select parent_folder__id from lib_iam.resource where resource__id = resource__id$ into folder__id$;
  if not found then
    raise sqlstate '42P01' using
      message = 'resource__id not found',
      hint = resource__id$;
  end if;

  return lib_iam._find_parent_organizations_by_folder(folder__id$);
end;
$$ stable security definer language plpgsql;

create or replace function lib_iam._parse_permission(permission$ lib_iam.permission_name) returns lib_iam.permission as $$
declare
  permissions$ text[];
  result       lib_iam.permission;
begin

  permissions$ = regexp_matches(permission$, '^(.*):(.*):(.*)$');

  if array_length(permissions$, 1) != 3 then
    raise 'wrong permission$ format, awaited {service}:{type}:{verb}' using errcode = 'check_violation';
  end if;

  result.service__id = permissions$[1]::lib_iam.identifier;
  result.type__id = permissions$[2]::lib_iam.identifier;
  result.verb__id = permissions$[3]::lib_iam.identifier;

  return result;
end;
$$ immutable language plpgsql;

create or replace function lib_iam.authorize(
  permission$       lib_iam.permission_name,
  principal$        lib_iam.principal,
  resource$         lib_iam.resource_name,
  dry_run$          bool default false
) returns boolean as $$
declare
  parsed_permission$       lib_iam.permission;
  parsed_principal$        lib_iam.principal_type__id;
  parsed_resource$         lib_iam.resource_type__id;
  event_type$              text;
  result$                  boolean default false;
  bind_permissions$        int;
  root_organization__id$   uuid[];
begin

  parsed_resource$ = lib_iam._parse_resource(resource$);
  parsed_permission$ = lib_iam._parse_permission(permission$);
  parsed_principal$ = lib_iam._parse_principal(principal$);

  -- @TODO conditions v3
  if parsed_resource$.resource_type = '*' then

    select count(*) from lib_iam.role__permission rp
      inner join lib_iam.bindings on bindings.service__id = rp.service__id and bindings.role__id = rp.role__id and bindings.member in ('allUsers', principal$)
      inner join lib_iam.organization_policy op on bindings.policy__id = op.policy__id
      inner join lib_iam.permission on permission.service__id = rp.permission_service__id and permission.type__id = rp.permission_type__id and permission.verb__id = parsed_permission$.verb__id
      where rp.permission_service__id = parsed_permission$.service__id
        and rp.permission_type__id = parsed_permission$.type__id
        and rp.permission_verb__id in ('*', parsed_permission$.verb__id) into bind_permissions$;
  else

    case parsed_resource$.resource_type
      when 'organization' then
        root_organization__id$ = lib_iam._find_parent_organizations_by_organization(parsed_resource$.resource__id);
      when 'folder' then
        root_organization__id$ = lib_iam._find_parent_organizations_by_folder(parsed_resource$.resource__id);
      when 'resource' then
        root_organization__id$ = lib_iam._find_parent_organizations_by_resource(parsed_resource$.resource__id);
      else
        raise 'unsupported resource type in authorize' using errcode = 'check_violation';
    end case;

    if root_organization__id$ is null then
      raise 'unsupported resource type in authorize' using errcode = 'check_violation';
    end if;

    select count(*) from lib_iam.role__permission rp
      inner join lib_iam.bindings on bindings.service__id = rp.service__id and bindings.role__id = rp.role__id and bindings.member in ('allUsers', principal$)
      inner join lib_iam.organization_policy op on bindings.policy__id = op.policy__id and op.organization__id = any(root_organization__id$)
      inner join lib_iam.permission on permission.service__id = rp.permission_service__id and permission.type__id = rp.permission_type__id and permission.verb__id = parsed_permission$.verb__id
      where rp.permission_service__id = parsed_permission$.service__id
        and rp.permission_type__id = parsed_permission$.type__id
        and rp.permission_verb__id in ('*', parsed_permission$.verb__id) into bind_permissions$;
  end if;

  if bind_permissions$ > 0 then
    result$ = true;
  end if;

  if dry_run$ = False then

    if result$ = false then
      event_type$ = 'iam.authorization.denied';
    else
      event_type$ = 'iam.authorization.allowed';
    end if;

    perform lib_event.create(type$ => event_type$, payload$ => json_build_object(
        'permission', permission$::text,
        'principal', principal$::text,
        'resource', resource$::text,
        'occurred_at', now(),
        'created_at', now()
      )::jsonb);
  end if;

  return result$;
end;
$$ volatile security definer language plpgsql;
