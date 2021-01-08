create or replace function lib_iam.rbac_authorize(
    permission$ lib_iam.permission,
    principal$ lib_iam.principal,
    resource$ lib_iam.resource_type__id
) returns boolean as
$$
declare
    principals$ lib_iam.principal[];
    bind_permissions$ int;
    root_organization__ids$ uuid[];
begin
    if principal$ like 'user:%' then
        principals$ = array['allUsers', 'allAuthenticatedUsers', principal$];
    else
        principals$ = array['allUsers', principal$];
    end if;
    -- @TODO conditions v3
    if resource$.resource_type = '*' then

        select count(*) from lib_iam.role__permission rp
                                 inner join lib_iam.bindings on bindings.service__id = rp.service__id and bindings.role__id = rp.role__id and bindings.member = any(principals$)
                                 inner join lib_iam.organization_policy op on bindings.policy__id = op.policy__id
                                 inner join lib_iam.permission on permission.service__id = rp.permission_service__id and permission.type__id = rp.permission_type__id and permission.verb__id = permission$.verb__id
        where rp.permission_service__id = permission$.service__id
          and rp.permission_type__id = permission$.type__id
          and rp.permission_verb__id in ('*', permission$.verb__id) into bind_permissions$;
    else

        case resource$.resource_type
            when 'organization' then
                root_organization__ids$ = lib_iam._find_parent_organizations_by_organization(resource$.resource__id);
            when 'folder' then
                root_organization__ids$ = lib_iam._find_parent_organizations_by_folder(resource$.resource__id);
            when 'resource' then
                root_organization__ids$ = lib_iam._find_parent_organizations_by_resource(resource$.resource__id);
            else
                raise 'unsupported resource type % in authorize', resource$.resource_type using errcode = 'check_violation';
            end case;

        if root_organization__ids$ is null then
            raise 'unsupported resource type in authorize' using errcode = 'check_violation';
        end if;

        select count(*) from lib_iam.role__permission rp
                                 inner join lib_iam.bindings on bindings.service__id = rp.service__id and bindings.role__id = rp.role__id and bindings.member = any(principals$)
                                 inner join lib_iam.organization_policy op on bindings.policy__id = op.policy__id and op.organization__id = any(root_organization__ids$)
                                 inner join lib_iam.permission on permission.service__id = rp.permission_service__id and permission.type__id = rp.permission_type__id and permission.verb__id = permission$.verb__id
        where rp.permission_service__id = permission$.service__id
          and rp.permission_type__id = permission$.type__id
          and rp.permission_verb__id in ('*', permission$.verb__id) into bind_permissions$;
    end if;

    return bind_permissions$ > 0;
end;
$$ security definer language plpgsql;