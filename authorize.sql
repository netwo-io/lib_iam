create or replace function lib_iam._find_parent_organizations_by_organization(organization__id$ uuid) returns uuid[] as
$$
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
$$ stable
   security definer language plpgsql;

create or replace function lib_iam._find_parent_organizations_by_folder(folder__id$ uuid) returns uuid[] as
$$
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
    select o.organization__id
    from subfolders s
             inner join lib_iam.organization o on o.organization__id = s.parent_organization__id
    into organization__id$;

    return lib_iam._find_parent_organizations_by_organization(organization__id$);
end;
$$ stable
   security definer language plpgsql;

create or replace function lib_iam._find_parent_organizations_by_resource(resource__id$ lib_iam.identifier) returns uuid[] as
$$
declare
    folder__id$ uuid;
begin

    select parent_folder__id from lib_iam.resource where name = resource__id$ into folder__id$;
    if not found then
        raise sqlstate '42P01' using
            message = 'resource__id not found',
            hint = resource__id$;
    end if;

    return lib_iam._find_parent_organizations_by_folder(folder__id$);
end;
$$ stable
   security definer language plpgsql;

create or replace function lib_iam._parse_permission(permission$ lib_iam.permission_name) returns lib_iam.permission as
$$
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

-- @deprecated
create or replace function lib_iam.authorize(permission$ lib_iam.permission_name,
                                             principal$ lib_iam.principal,
                                             resource$ lib_iam.resource_name,
                                             dry_run$ bool default false) returns boolean as
$$
begin
    return lib_iam.authorize(lib_iam._parse_permission(permission$), principal$, lib_iam._parse_resource(resource$),
                             dry_run$);
end;
$$ volatile
   security definer language plpgsql;

create or replace function lib_iam.authorize(permission$ lib_iam.permission,
                                             principal$ lib_iam.principal,
                                             resource$ lib_iam.resource_type__name,
                                             dry_run$ bool default false) returns boolean as
$$
declare
    parsed_principal$   lib_iam.principal_type__id;
    event_type$         text;
    result$             boolean default false;
    authorized_by_rbac$ boolean=false;
    authorized_by_acl$  boolean=false;
begin

    -- ensure principal is valid.
    parsed_principal$ = lib_iam._parse_principal(principal$);


    if resource$.resource_type = 'resource' then
        authorized_by_acl$ = lib_iam.acl_authorize(permission$, principal$, resource$.resource_name::lib_iam.identifier);
    end if;

    if not authorized_by_acl$ then
        authorized_by_rbac$ = lib_iam.rbac_authorize(
                permission$,
                principal$,
                resource$);
    end if;


    if authorized_by_acl$ or authorized_by_rbac$ then
        result$ = true;
    end if;

    if dry_run$ = False then

        if result$ = false then
            event_type$ = 'iam.authorization.denied';
        else
            event_type$ = 'iam.authorization.allowed';
        end if;

        perform lib_event.create(type$ => event_type$, payload$ => json_build_object(
                'permission',
                permission$.service__id::text || ':' || permission$.type__id::text || ':' || permission$.verb__id::text,
                'principal', principal$,
                'resource', resource$.resource_type::text || ':' || resource$.resource_name::text,
                'occurred_at', now(),
                'created_at', now()
            )::jsonb);
    end if;

    return result$;
end;
$$ volatile
   security definer language plpgsql;

comment on function lib_iam.authorize(lib_iam.permission,lib_iam.principal,lib_iam.resource_type__name,boolean)
    is 'Returns a boolean indicating if the principal has the specified permission on the specified resource either via RBAC or resources ACLs. '
    'ACLs are checked first. '
    'When dry_run is false, an iam event is added to log the permission.';
