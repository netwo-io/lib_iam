create view lib_iam.resource_acls as
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
    ) acls
    join lib_iam.resource_acl using (policy__id)
;
