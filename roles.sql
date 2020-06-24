create view lib_iam.roles as
  select concat(rl.service__id, '.', rl.role__id) as id, rl.title, rl.description, permissions.permissions
  from lib_iam.role rl, lateral (
    select json_agg(permissions.*) as permissions from lib_iam.permissions
      inner join lib_iam.role__permission rp on permissions.type->'service'->>'id' = rp.permission_service__id
        and permissions.type->>'id' = rp.permission_type__id
        and permissions.verb = rp.permission_verb__id
        and rl.service__id = rp.service__id
        and rl.role__id = rp.role__id
  ) as permissions;
