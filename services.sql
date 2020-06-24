create view lib_iam.services as
  select svc.service__id as id, svc.description from lib_iam.service svc;

create view lib_iam.types as
  select type.type__id as id, type.description, row_to_json(svc) as service
    from lib_iam.type
    inner join lib_iam.services svc on type.service__id = svc.id;
