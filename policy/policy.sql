------------------- POLICY ----------------------------
-- right now we decide to only support policies on organizations @TODO folder + resource policies.
create table lib_iam.organization_policy
(
  policy__id       uuid not null primary key default public.gen_random_uuid(),
  organization__id uuid references lib_iam.organization (organization__id) on delete cascade on update cascade
  -- @todo implement "condition" support (cf Google Cloud IAM Policy v3)
);

------------------- BINDINGS --------------------------

create table lib_iam.user_organization_policy_binding
(
  policy__id  uuid not null references lib_iam.organization_policy (policy__id) on delete cascade on update cascade,
  member__id  uuid not null references lib_iam.user (member__id) on delete cascade on update cascade,
  service__id lib_iam.identifier not null,
  role__id    lib_iam.identifier not null,
  foreign key (service__id, role__id) references lib_iam.role (service__id, role__id) on delete cascade on update cascade,
  unique (policy__id, member__id, service__id)
);

create table lib_iam.service_account_organization_policy_binding
(
  policy__id  uuid not null references lib_iam.organization_policy (policy__id) on delete cascade on update cascade,
  member__id  uuid not null references lib_iam.service_account (member__id) on delete cascade on update cascade,
  service__id lib_iam.identifier not null,
  role__id    lib_iam.identifier not null,
  foreign key (service__id, role__id) references lib_iam.role (service__id, role__id) on delete cascade on update cascade,
  unique (policy__id, member__id, service__id)
);

create table lib_iam.all_authenticated_users_organization_policy_binding
(
  policy__id  uuid not null references lib_iam.organization_policy (policy__id) on delete cascade on update cascade,
  service__id lib_iam.identifier not null,
  role__id    lib_iam.identifier not null,
  foreign key (service__id, role__id) references lib_iam.role (service__id, role__id) on delete cascade on update cascade,
  unique (policy__id, service__id)
);

create table lib_iam.all_users_organization_policy_binding
(
  policy__id  uuid not null references lib_iam.organization_policy (policy__id) on delete cascade on update cascade,
  service__id lib_iam.identifier not null,
  role__id    lib_iam.identifier not null,
  foreign key (service__id, role__id) references lib_iam.role (service__id, role__id) on delete cascade on update cascade,
  unique (policy__id, service__id)
);

drop domain if exists lib_iam.principal;
create domain lib_iam.principal as text
  not null
  check (value ~* '^(allUsers|allAuthenticatedUsers|(user|service_account):.+)$');

--------------------- PRIVATE API ---------------------------

create or replace function lib_iam._parse_principal(principal$ lib_iam.principal) returns lib_iam.principal_type__id as
$$
declare
  result       lib_iam.principal_type__id;
  couple$      text[];
begin

  case principal$::text
    when 'allUsers' then

      result.member_type = 'all_users_organization_policy_binding';
      result.member__id = null;
    when 'allAuthenticatedUsers' then

      result.member_type = 'all_authenticated_users_organization_policy_binding';
      result.member__id = null;
    else

      couple$ = regexp_matches(principal$, '^(.*):(.*)$');
      case couple$[1]::text
        when 'user' then

          result.member_type = 'user_organization_policy_binding';
          result.member__id = couple$[2]::uuid;
        when 'service_account' then

          result.member_type = 'service_account_organization_policy_binding';
          result.member__id = couple$[2]::uuid;
        else
          raise 'principal must be one of allUsers, allAuthenticatedUsers, member_type:id' using errcode = 'check_violation';
      end case;
  end case;
  return result;
end;
$$ immutable language plpgsql;

------------------ API ------------------

create or replace function lib_iam.organization_policy_create(organization__id$ uuid, policy__id$ uuid default public.gen_random_uuid()) returns uuid as
$$
begin
  insert into lib_iam.organization_policy (policy__id, organization__id) values (policy__id$, organization__id$);
  return policy__id$;
end;
$$ language plpgsql;

create or replace function lib_iam.organization_policy_delete(policy__id$ uuid) returns void as
$$
begin
  delete from lib_iam.organization_policy where policy__id = policy__id$;
end;
$$ language plpgsql;

create or replace function lib_iam.organization_policy_add_binding(policy__id$ uuid, service__id$ lib_iam.identifier, role__id$ lib_iam.identifier, principal$ lib_iam.principal) returns void as
$$
declare
  parsed_principal$ lib_iam.principal_type__id;
begin

  parsed_principal$ = lib_iam._parse_principal(principal$);
  if (parsed_principal$.member__id is null) then
    execute format(
      E'insert into lib_iam.%I (policy__id, service__id, role__id) values (\'%s\', \'%s\', \'%s\')
        on conflict (policy__id, service__id) do update set service__id = \'%s\', role__id = \'%s\'',
      parsed_principal$.member_type,
      policy__id$,
      service__id$,
      role__id$,
      service__id$,
      role__id$
    );
  else
    execute format(
      E'insert into lib_iam.%I (policy__id, member__id, service__id, role__id) values (\'%s\', \'%s\', \'%s\', \'%s\')
        on conflict (policy__id, service__id, member__id) do update set service__id = \'%s\', role__id = \'%s\'',
      parsed_principal$.member_type,
      policy__id$,
      parsed_principal$.member__id,
      service__id$,
      role__id$,
      service__id$,
      role__id$
    );
  end if;
end;
$$ language plpgsql;

create or replace function lib_iam.organization_policy_remove_binding(policy__id$ uuid, service__id$ lib_iam.identifier, role__id$ lib_iam.identifier, principal$ lib_iam.principal) returns void as
$$
declare
  parsed_principal$ lib_iam.principal_type__id;
begin

  parsed_principal$ = lib_iam._parse_principal(principal$);
  if (parsed_principal$.member__id is null) then
    execute format(
      E'delete from lib_iam.%I where policy__id = \'%s\' and service__id = \'%s\' and role__id = \'%s\'',
      parsed_principal$.member_type,
      policy__id$,
      service__id$,
      role__id$
    );
  else
    execute format(
      E'delete from lib_iam.%I where policy__id = \'%s\' and service__id = \'%s\' and role__id = \'%s\' and member__id = \'%s\'',
      parsed_principal$.member_type,
      policy__id$,
      service__id$,
      role__id$,
      parsed_principal$.member__id
    );
  end if;
end;
$$ language plpgsql;
