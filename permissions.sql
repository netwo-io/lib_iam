create view lib_iam.permissions as
  select row_to_json(types) as type, verb.verb__id as verb from lib_iam.permission
    inner join lib_iam.types on types.service->>'id' = permission.service__id and types.id = permission.type__id
    inner join lib_iam.verb using (verb__id);
