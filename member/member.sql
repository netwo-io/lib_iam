create table lib_iam.member
(
  member__id uuid primary key default public.gen_random_uuid(),
  created_at timestamptz default now()
);

comment on table lib_iam.member is 'Abstract table inherited by user, service account member...';

create table lib_iam.service_account
(
  primary key (member__id), -- table inheritance only copy table structure we need to also specify again constraints
  name text not null,
  description text,
  token text,
  jti text,
  revoked_at timestamptz
) inherits (lib_iam.member);

create table lib_iam.user
(
  password varchar(64) not null,
  deleted_at timestamptz,
  user_secret uuid,
  -- status uuid not null references lib_fsm.state_machine(state_machine__id) on delete restrict on update restrict,
  primary key (member__id) -- table inheritance only copy table structure we need to also specify again constraints
) inherits (lib_iam.member);

create or replace function lib_iam.user_create(password$ text, member__id$ uuid default public.gen_random_uuid()) returns uuid as
$$
begin

  perform lib_iam.check_password_validity(password$);
  insert into lib_iam.user (member__id, password) values (member__id$, password$);
  return member__id$;
end;
$$ language plpgsql;

create or replace function lib_iam.user_delete(member__id$ uuid) returns void as $$
begin
  update lib_iam.user set deleted_at = now() where member__id = member__id$;
end;
$$ language plpgsql;

create or replace function lib_iam.service_account_create(name$ text, member__id$ uuid default public.gen_random_uuid()) returns uuid as $$
begin
    insert into lib_iam.service_account (name, member__id) values (name$, member__id$);
    return member__id$;
end;
$$ language plpgsql;

create or replace function lib_iam.service_account_delete(member__id$ uuid) returns void as $$
begin
    update lib_iam.service_account set revoked_at = now() where member__id = member__id$;
end;
$$ language plpgsql;

create or replace function lib_iam.service_account_generate_token(name$ text, member__id$ uuid) returns text as $$
declare
  auth_token$ text;
  jti$        text;
begin
  jti$ = public.gen_random_uuid()::text;
  auth_token$ = lib_iam.generate_service_account_token(member__id$, name$, jti$);
  update lib_iam.service_account set token = auth_token$, jti = jti$ where member__id = member__id$;
  return auth_token$;
end;
$$ language plpgsql;

create type lib_iam.principal_type__id as (member_type varchar(64), member__id uuid);

-------------------------- API -----------------------------

create or replace function lib_iam.encrypt_pass(password$ text) returns text as $$
begin
  return public.crypt(password$, public.gen_salt('bf'));
end
$$ language plpgsql;

create or replace function lib_iam.check_password_validity(password$ text) returns void as $$
begin

  if password$ is null or length(password$) < 8 then
    raise 'invalid password format' using errcode = 'check_violation';
  end if;
end
$$ language plpgsql;

create or replace function lib_iam.check_pass(password$ text, hash$ text) returns text as $$
begin
  return public.crypt(password$, hash$);
end
$$ language plpgsql;

create or replace function lib_iam.encrypt_pass() returns trigger as $$
begin
  if new.password is not null then
    new.password = lib_iam.encrypt_pass(new.password);
  end if;
  return new;
end
$$ language plpgsql;

create trigger user_encrypt_pass_trigger
  before insert
  on lib_iam.user
  for each row
  execute procedure lib_iam.encrypt_pass();

create or replace function lib_iam.generate_token(member__id$ uuid, principal$ text, secret$ text, lifetime$ int) returns text as $$
declare
  token text;
begin

  token := lib_pgjwt.sign(
    json_build_object(
      'role', 'webuser',
      'sub', member__id$,
      'principal', principal$,
      'exp', extract(epoch from now())::integer + lifetime$
    ),
    secret$
  );
  return token;
end;
$$ security definer language plpgsql;

create or replace function lib_iam.user_change_password(token$ text, new$ text) returns uuid as
$$
declare
    member__id$ uuid;
begin
    member__id$ = lib_iam.verify_auth_token(token$);

    select member__id
    from lib_iam.user
    where member__id = member__id$
    into member__id$;
    if not found then
        raise 'not_found' using errcode = 'check_violation';
    end if;

    perform lib_iam.check_password_validity(new$);
    update lib_iam.user set password = lib_iam.encrypt_pass(new$) where member__id = member__id$;
    return member__id$;
end;
$$ security definer language plpgsql;

create or replace function lib_iam.user_get_token(member__id$ uuid) returns text as $$
declare
  usr$ lib_iam.user;
begin

  select * from lib_iam.user as u
    where member__id = member__id$
    into usr$;

  if not found then
    raise 'invalid user' using errcode = 'check_violation';
  elsif usr$.deleted_at is not null then
    raise 'user is restricted' using errcode = 'check_violation';
  end if;

  return lib_iam.generate_token(usr$.member__id, 'user', lib_settings.get('jwt_secret'), lib_settings.get('jwt_lifetime')::int);
end;
$$ security definer language plpgsql;

create or replace function lib_iam.user_get_token(member__id$ uuid, password text) returns text as $$
declare
  usr$ lib_iam.user;
begin

  select * from lib_iam.user as u
    where member__id = member__id$ and u.password = lib_iam.check_pass($2, u.password)
    into usr$;

  if not found then
    raise 'invalid email/password' using errcode = 'check_violation';
  elsif usr$.deleted_at is not null then
    raise 'user is restricted' using errcode = 'check_violation';
  end if;

  return lib_iam.generate_token(usr$.member__id, 'user', lib_settings.get('jwt_secret'), lib_settings.get('jwt_lifetime')::int);
end;
$$ security definer language plpgsql;

-- Service account key management.

create or replace function lib_iam.generate_service_account_token(member__id$ uuid, identifier$ text, jti$ text) returns text as $$
declare
    service_account$  lib_iam.service_account;
begin

    select * from lib_iam.service_account
    where member__id = member__id$
    into service_account$;

    if not found then
        raise 'service account not found' using errcode = 'check_violation';
    elsif service_account$.revoked_at is not null then
        raise 'service account is revoked' using errcode = 'check_violation';
    end if;

    return lib_pgjwt.sign(
            json_build_object(
                    'sub', member__id$::uuid,
                    'principal', 'service_account',
                    'exp', 2147483647, -- max integer
                    'identifier', identifier$,
                    'jti', jti$,
                    'role', 'webuser'
                ),
            lib_settings.get('jwt_secret')
        );
end;
$$ security definer language plpgsql;

-- Auth token management.

create or replace function lib_iam.generate_auth_token(member__id$ uuid, identifier$ text, lifetime$ integer) returns text as $$
declare
  usr$         lib_iam.user;
  user_secret$ uuid;
begin

  select * from lib_iam.user as u
    where member__id = member__id$
    into usr$;

  if not found then
    raise 'user not found' using errcode = 'check_violation';
  elsif usr$.deleted_at is not null then
    raise 'user is restricted' using errcode = 'check_violation';
  end if;

  user_secret$ = public.gen_random_uuid();
  -- Generate new user_secret, overriding the previous one and making eventual old generated token to be invalidated.
  update lib_iam.user set user_secret = user_secret$ where member__id = usr$.member__id;

  return lib_pgjwt.url_encode(
    convert_to(
      lib_pgjwt.sign(
        json_build_object(
          'sub', member__id$::uuid,
          'principal', 'user',
          'exp', extract(epoch from now())::integer + lifetime$,
          'identifier', identifier$
        ),
        user_secret$::text
      ),
      'utf8'
    )
  );
end;
$$ security definer language plpgsql;

create or replace function lib_iam.verify_auth_token(token$ text) returns uuid as $$
declare
  jwt_token$     text;
  parts$         text[];
  payload$       json;
  usr$           lib_iam.user;
  verify$ json;
begin

  jwt_token$ = convert_from(lib_pgjwt.url_decode(token$), 'utf-8');

  parts$ = regexp_split_to_array(jwt_token$, '\.');
  if array_length(parts$, 1) != 3 then
    raise 'invalid token' using errcode = '28000';
  end if;

  -- Get member__id from jwt_token payload.
  payload$ = convert_from(lib_pgjwt.url_decode(parts$[2]), 'utf8')::json;

  select * from lib_iam.user as u
    where member__id = (payload$->>'sub')::uuid
    into usr$;

  if not found then
    raise 'user not found' using errcode = 'check_violation';
  elsif usr$.deleted_at is not null then
    raise 'user is restricted' using errcode = 'check_violation';
  end if;

  verify$ = row_to_json(lib_pgjwt.verify(jwt_token$, usr$.user_secret::text));

  if (verify$->>'valid')::boolean != true then
    raise 'user not found' using errcode = 'check_violation';
  end if;
  if (verify$->'payload'->>'exp')::integer < extract(epoch from now())::integer then
    raise 'token is expired' using errcode = 'check_violation';
  end if;

  update lib_iam.user set user_secret = null where member__id = usr$.member__id;
  return usr$.member__id;
end;
$$ security definer language plpgsql;

-- get all bindings for all orgs for a given member_id formatted as an array with bindings like org.service.role
create or replace function lib_iam.user_get_bindings(member__id$ uuid) returns text[] as
$$
declare
    organization_id$   uuid;
    organization_name$ varchar;
    user_org_bindings$ text[];
begin
    -- for each organization for which the member has at least one binding
    for organization_id$, organization_name$ in select o.organization__id, o.name
                         from lib_iam.organization o
                         where exists(
                                       select *
                                       from lib_iam.organization_policy op
                                                join lib_iam.bindings b using (policy__id)
                                       where member in ('user:' || member__id$, 'service_account:' || member__id$)
                                         and organization__id = o.organization__id
                                   )
        loop
            -- find all bindings for a given user for the current org as well as bindings inherited from parent orgs
            user_org_bindings$ = user_org_bindings$ || (
                with recursive suborganizations as (
                    select parent_organization__id, organization__id, name
                    from lib_iam.organization
                    where organization__id = organization_id$
                    union
                    select o.parent_organization__id, o.organization__id, o.name
                    from lib_iam.organization o
                             inner join suborganizations
                                        on o.organization__id = suborganizations.parent_organization__id
                )
                select array_agg(organization_name$ || '.' || b.service__id || '.' || b.role__id)
                from suborganizations o
                         join lib_iam.organization_policy op using (organization__id)
                         join lib_iam.bindings b using (policy__id)
                where member in ('user:' || member__id$, 'service_account:' || member__id$)
            );
        end loop;
    return user_org_bindings$;
end;
$$ security definer language plpgsql;
