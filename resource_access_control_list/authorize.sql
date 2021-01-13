create or replace function lib_iam.acl_authorize(permission$ lib_iam.permission,
                                                 principal$ lib_iam.principal,
                                                 resource__id$ uuid) returns boolean as
$$
declare
    resource$         lib_iam.resource;
    bound_acl$        int;
    parsed_principal$ lib_iam.principal_type__id;
    principals$       lib_iam.principal[];
begin
    select * from lib_iam.resource where resource__id = resource__id$ into resource$;
    if not found then
        raise 'unknown_resource' using hint = coalesce(resource__id$::text, 'null');
    end if;

    parsed_principal$ = lib_iam._parse_principal(principal$);
    if principal$ like 'user:%' then
        principals$ = array ['allAuthenticatedUsers', principal$];
    else
        principals$ = array [principal$];
    end if;

    select count(policy__id)
    from lib_iam.resource_acls
             join lib_iam.resource using (resource__id)
    where member = any (principals$)
      and resource__id = resource__id$
      and grant_verb = permission$.verb__id
      and service__id = permission$.service__id
      and type__id = permission$.type__id
    into bound_acl$;
    return bound_acl$ > 0;
end;
$$ security definer language plpgsql;