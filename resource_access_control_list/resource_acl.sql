create table lib_iam.resource_acl
(
    policy__id   uuid primary key default public.gen_random_uuid(),
    resource__id uuid references lib_iam.resource (resource__id) on delete cascade on update cascade
);

create table lib_iam.all_users_resource_acl
(
    policy__id uuid primary key references lib_iam.resource_acl (policy__id) on delete cascade on update cascade,
    grant_verb lib_iam.wildcardable_identifier references lib_iam.verb (verb__id)
);
comment on table lib_iam.all_users_resource_acl is 'Access control list on resources to anonymous users';


create table lib_iam.all_authenticated_users_resource_acl
(
    policy__id uuid primary key references lib_iam.resource_acl (policy__id) on delete cascade on update cascade,
    grant_verb lib_iam.wildcardable_identifier references lib_iam.verb (verb__id)
);
comment on table lib_iam.all_authenticated_users_resource_acl is 'Access control list on resources to authenticated users';

create table lib_iam.member_resource_acl
(
    policy__id uuid primary key references lib_iam.resource_acl (policy__id) on delete cascade on update cascade,
    member     lib_iam.principal,
    grant_verb lib_iam.wildcardable_identifier references lib_iam.verb (verb__id)
);


create or replace function lib_iam.resource_acl_aggregate()
    returns table
            (
                resource__id uuid,
                policy__id   uuid,
                member       text,
                grant_verb   lib_iam.wildcardable_identifier
            )
as
$$
select resource__id, policy__id, member, grant_verb
from (
         select member,
                policy__id,
                grant_verb
         from lib_iam.member_resource_acl
         union
         select 'allAuthenticatedUsers' as member,
                policy__id,
                grant_verb
         from lib_iam.all_authenticated_users_resource_acl
         union
         select 'allUsers' as member,
                policy__id,
                grant_verb
         from lib_iam.all_users_resource_acl
     ) acls
         join lib_iam.resource_acl using (policy__id)
    ;
$$ security invoker language sql
   stable;

create or replace function lib_iam.resource_acl_set(resource__id$ uuid,
                                                    principal$ lib_iam.principal,
                                                    target_principal$ lib_iam.principal,
                                                    grant_verb$ lib_iam.wildcardable_identifier) returns void as
$$
declare
    resource$         lib_iam.resource;
    parsed_principal$ lib_iam.principal_type__id;
    policy__id$       uuid;
begin
    -- TODO: Handle wildcard permissions

    if grant_verb$ = '*' then
        raise 'not_implemented' using hint = 'Resources ACL do not support wildcard permissions';
    end if;

    select * from lib_iam.resource where name = resource__id$::lib_iam.identifier into resource$;
    if not found then
        raise 'unknown_resource' using hint = resource__id$;
    end if;

    -- i must have set_acl permission on the resource type
    if not lib_iam.rbac_authorize((resource$.service__id, resource$.type__id, 'set_acl'), principal$,
                                  ('resource', resource$.name)) then
        raise sqlstate '42501' using message = 'insufficient permissions', hint =
                (resource$.service__id || ':' || resource$.type__id || ':set_acl');
    end if;

    -- I must have the permission i am trying to grant
    if not lib_iam.rbac_authorize((resource$.service__id, resource$.type__id, grant_verb$), principal$,
                                   ('resource', resource$.name)) then
        raise sqlstate '42501' using message = 'insufficient permissions', hint =
                (resource$.service__id || ':' || resource$.type__id || grant_verb$);
    end if;

    perform *
    from lib_iam.resource_acl_aggregate()
    where resource__id = resource$.resource__id
      and grant_verb = grant_verb$
      and member = target_principal$;
    if not found then
        parsed_principal$ = lib_iam._parse_principal(target_principal$);
        policy__id$ = public.gen_random_uuid();
        insert into lib_iam.resource_acl(policy__id, resource__id)
        values (policy__id$, resource$.resource__id);
        if target_principal$ = 'allAuthenticatedUsers' then
            insert into lib_iam.all_authenticated_users_resource_acl (policy__id, grant_verb)
            values (policy__id$, grant_verb$);
        elsif target_principal$ = 'allUsers' then
            insert into lib_iam.all_users_resource_acl (policy__id, grant_verb)
            values (policy__id$, grant_verb$);
        else
            insert into lib_iam.member_resource_acl (policy__id, member, grant_verb)
            values (policy__id$, target_principal$, grant_verb$);
        end if;
    end if;
end;
$$ security definer language plpgsql;
comment on function lib_iam.resource_acl_set(uuid,lib_iam.principal,lib_iam.principal,lib_iam.wildcardable_identifier)
    is 'Adds an Access Control policy on resource to a principal. Requires set_acl RBAC permission on the resource. Returns true if a new policy was added, false if it already existed.';



create or replace function lib_iam.resource_acl_remove(resource__id$ uuid,
                                                       principal$ lib_iam.principal,
                                                       target_principal$ lib_iam.principal,
                                                       grant_verb$ lib_iam.wildcardable_identifier) returns void as
$$
declare
    resource$ lib_iam.resource;
begin
    select * from lib_iam.resource where name = resource__id$::lib_iam.identifier into resource$;
    if not found then
        raise 'unknown_resource' using hint = resource__id$;
    end if;

    if not lib_iam.rbac_authorize((resource$.service__id, resource$.type__id, 'set_acl'), principal$,
                                  ('resource', resource__id$::lib_iam.nullable_identifier)) then
        raise sqlstate '42501' using message = 'insufficient permissions', hint =
                (resource$.service__id || ':' || resource$.type__id || ':set_acl');
    end if;

    delete
    from lib_iam.resource_acl
    where policy__id = (select resource_acl.policy__id from lib_iam.resource_acl_aggregate()
                        where resource__id = resource$.resource__id
                          and grant_verb = grant_verb$
                          and member = target_principal$);
end;
$$ security definer language plpgsql;
comment on function lib_iam.resource_acl_remove(uuid,lib_iam.principal,lib_iam.principal,lib_iam.wildcardable_identifier)
    is 'Removes an Access Control policy on resource from a principal. Requires set_acl RBAC permission on the resource. Returns true if a policy was removed, false if it did not exist.';
