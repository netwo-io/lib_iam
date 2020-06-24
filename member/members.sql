create view lib_iam.members as
  select m.member__id as id, (regexp_matches(tableoid::regclass::text, '\."?(\w+)"?'))[1] as type from lib_iam.member m;
