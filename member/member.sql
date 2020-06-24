create table lib_iam.member
(
  member__id uuid primary key default public.gen_random_uuid(),
  created_at timestamptz default now()
);

comment on table lib_iam.member is 'Abstract table inherited by user, service account member...';

create table lib_iam.service_account
(
  primary key (member__id) -- table inheritance only copy table structure we need to also specify again constraints
) inherits (lib_iam.member);

create table lib_iam.user
(
  password text not null,
  is_login_restricted boolean not null default false,
  -- status uuid not null references lib_fsm.state_machine(state_machine__id) on delete restrict on update restrict,
  primary key (member__id) -- table inheritance only copy table structure we need to also specify again constraints
) inherits (lib_iam.member);

create or replace function lib_iam.user_create(password$ text) returns uuid as
$$
declare
  member__id$ uuid;
begin

  perform lib_iam.check_password_validity(password$);
  insert into lib_iam.user (member__id, password) values (default, password$) returning member__id into member__id$;
  return member__id$;
end;
$$ language plpgsql;

create or replace function lib_iam.user_delete(member__id$ uuid) returns void as
$$
declare
  member__id$ uuid;
begin
  update lib_iam.user set is_login_restricted = true where member__id = member__id$;
end;
$$ language plpgsql;

create or replace function lib_iam.service_account_create() returns uuid as
$$
declare
  member__id$ uuid;
begin
  insert into lib_iam.service_account (member__id) values (default) returning member__id into member__id$;
  return member__id$;
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

create or replace function lib_iam.generate_token(member__id$ uuid, secret$ text, lifetime$ int) returns text as $$
declare
  token text;
begin

  token := lib_pgjwt.sign(
    json_build_object(
      'role', 'webuser',
      'sub', member__id$,
      'exp', extract(epoch from now())::integer + lifetime$
    ),
    secret$
  );
  return token;
end;
$$ security definer language plpgsql;

create or replace function lib_iam.user_change_password(member__id$ uuid, new$ text, old$ text) returns void as
$$
declare
  usr$ lib_iam.user;
begin

  select member__id from lib_iam.user
    where member__id = member__id$ and password = lib_iam.check_pass(old$, password)
    into usr$;

  if not found then
    raise 'invalid password_old' using errcode = 'check_violation';
  end if;

  perform lib_iam.check_password_validity(new$);
  update lib_iam.user set password = lib_iam.encrypt_pass(new$) where member__id = usr$.member__id;
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
  elsif usr$.is_login_restricted = true then
    raise 'user is restricted' using errcode = 'check_violation';
  end if;

  return lib_iam.generate_token(usr$.member__id, lib_settings.get('jwt_secret'), lib_settings.get('jwt_lifetime')::int);
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
  elsif usr$.is_login_restricted = true then
    raise 'user is restricted' using errcode = 'check_violation';
  end if;

  return lib_iam.generate_token(usr$.member__id, lib_settings.get('jwt_secret'), lib_settings.get('jwt_lifetime')::int);
end;
$$ security definer language plpgsql;
