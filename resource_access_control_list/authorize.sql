create or replace function lib_iam.acl_authorize(permission$ lib_iam.permission,
                                                 principal$ lib_iam.principal,
                                                 resource__name$ lib_iam.identifier) returns boolean as
$$
declare
    resource$              lib_iam.resource;
    bound_acl$             int;
    authorized_principals$ lib_iam.principal[];
begin
    select * from lib_iam.resource where name = resource__name$ into resource$;
    if not found then
        raise 'unknown_resource' using hint = coalesce(resource__name$::text, 'null');
    end if;

    if principal$ like 'user:%' or principal$ like 'service_account:%' then
        authorized_principals$ = array ['allUsers', 'allAuthenticatedUsers', principal$];
    else
        authorized_principals$ = array ['allUsers', principal$];
    end if;

    select count(policy__id)
    from lib_iam.resource_acls
             join lib_iam.resource using (resource__id)
    where member = any (authorized_principals$)
      and name = resource__name$
      and grant_verb = permission$.verb__id
    into bound_acl$;
    return bound_acl$ > 0;
end;
$$ security definer language plpgsql;
