create view lib_iam.bindings as
  (select 'allAuthenticatedUsers' as member, policy__id, service__id, role__id from lib_iam.all_authenticated_users_organization_policy_binding)
  union
  (select 'allUsers' as member, policy__id, service__id, role__id from lib_iam.all_users_organization_policy_binding)
  union
  (select 'service_account:' || member__id as member, policy__id, service__id, role__id from lib_iam.service_account_organization_policy_binding)
  union
  (select 'user:' || member__id as member, policy__id, service__id, role__id from lib_iam.user_organization_policy_binding)
  order by member asc;

create view lib_iam.policies as
  select
    policy.policy__id as id,
    json_agg(bindings) bindings
  from lib_iam.organization_policy policy, lateral (
    select
      role.service__id as service,
      role.role__id as role,
      array_agg(bindings.member) members
    from lib_iam.role
    inner join lib_iam.bindings on bindings.policy__id = policy.policy__id and bindings.service__id = role.service__id and bindings.role__id = role.role__id
    group by role.service__id, role.role__id
    order by role.service__id asc, role.role__id asc
  ) as bindings
  where array_length(bindings.members, 1) > 0
  group by policy.policy__id;
