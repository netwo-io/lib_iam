create or replace function lib_iam.acl_authorize(permission$ lib_iam.permission,
                                                 principal$ lib_iam.principal,
                                                 resource__id$ uuid) returns boolean as
$$
declare
    resource$              lib_iam.resource;
    bound_acl$             int;
    authorized_principals$ lib_iam.principal[];
begin
    select * from lib_iam.resource where resource__id = resource__id$ into resource$;
    if not found then
        raise 'unknown_resource' using hint = coalesce(resource__id$::text, 'null');
    end if;

    if principal$ like 'user:%' then
        authorized_principals$ = array ['allUsers', 'allAuthenticatedUsers', principal$];
    else
        authorized_principals$ = array ['allUsers', principal$];
    end if;

    select count(policy__id)
    from lib_iam.resource_acls
             join lib_iam.resource using (resource__id)
    where member = any (authorized_principals$)
      and resource__id = resource__id$
      and grant_verb = permission$.verb__id
    into bound_acl$;
    return bound_acl$ > 0;
end;
$$ security definer language plpgsql;
