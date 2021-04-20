-- lib iam member tests.

create or replace function lib_test.test_case_lib_iam_cannot_create_user_member_w_invalid_pass() returns void as $$
begin

  begin
    perform lib_iam.user_create('pass');
  exception
    when check_violation then
      perform lib_test.assert_equal(sqlerrm, 'invalid password format');
      return;
  end;
  perform lib_test.fail('Expect error on user create with short password');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_can_create_user_member() returns void as $$
declare
  member__id$ uuid;
  members$    lib_iam.members;
  user$       lib_iam.user;
begin

  member__id$ = lib_iam.user_create('password'); --> insert into user_member member_id, invitation_status, status
  select * from lib_iam.user where member__id = member__id$ into user$;
  perform lib_test.assert_equal(user$.member__id, member__id$);
  perform lib_test.assert_not_equal(user$.password, 'password');
  select * from lib_iam.members where id = member__id$ into members$;
  perform lib_test.assert_equal(members$.id, member__id$);
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_can_create_user_service_account() returns void as $$
declare
    service_account$ uuid;
    count$ int;
begin

    service_account$ = lib_iam.service_account_create('test1'); --> insert into user_member member_id, invitation_status, status
    select count(1) from lib_iam.members where id = service_account$ into count$;
    perform lib_test.assert_equal(count$, 1);
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_can_generate_service_account_token() returns void as $$
declare
    service_account$ uuid;
    service_account_token$ text;
    token$ text;
begin

    service_account$ = lib_iam.service_account_create('test1'); --> insert into user_member member_id, invitation_status, status
    token$ = lib_iam.service_account_generate_token('test1', service_account$);
    select token from lib_iam.service_account where member__id = service_account$ into service_account_token$;
    perform lib_test.assert_equal(token$, service_account_token$);
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_service_account_token_not_generated_for_deleted_member() returns void as $$
declare
    service_account$ uuid;
begin

    begin
      service_account$ = lib_iam.service_account_create('test1'); --> insert into user_member member_id, invitation_status, status
      perform lib_iam.service_account_delete(service_account$);
      perform lib_iam.service_account_generate_token('test1', service_account$);
    exception
        when check_violation then
            perform lib_test.assert_equal(sqlerrm, 'service account is revoked');
            return;
    end;
    perform lib_test.fail('A token should not be created for a revoked service_account.');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_can_list_members() returns void as $$
declare
  user_id$ uuid;
  service_account$ uuid;
  count$ int;
begin

  user_id$ = lib_iam.user_create('password');
  service_account$ = lib_iam.service_account_create('test2');
  select count(1) from lib_iam.members where id in (user_id$, service_account$) into count$;
  perform lib_test.assert_equal(count$, 2);
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_can_encrypt_decrypt_pass() returns void as $$
declare
  encrypted_pass$ text;
begin

  encrypted_pass$ = lib_iam.encrypt_pass('password');
  perform lib_test.assert_not_equal(encrypted_pass$, 'password');
  perform lib_test.assert_equal(encrypted_pass$, lib_iam.check_pass('password', encrypted_pass$));
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_user_cannot_change_password_if_token_is_invalid() returns void as $$
declare
  token$ text;
begin

  begin
    token$ = 'not-so-valid-token';
    perform lib_iam.user_change_password(token$, 'nbc');
  exception
    when others then
      perform lib_test.assert_equal(sqlerrm, 'invalid byte sequence for encoding "UTF8": 0x9e');
      return;
  end;
  perform lib_test.fail('An invalid token should not recognize allow password change.');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_user_cannot_change_password_if_token_is_expired() returns void as $$
declare
  member__id$ uuid;
  token$      text;
begin

  begin
    member__id$ = lib_iam.user_create('password');
    token$ = lib_iam.generate_auth_token(member__id$, 'username', -1);
    perform lib_iam.user_change_password(token$, 'nbc');
  exception
    when check_violation then
      perform lib_test.assert_equal(sqlerrm, 'token is expired');
      return;
  end;
  perform lib_test.fail('An expired token should nnot recognize allow password change.');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_user_cannot_change_password_if_new_one_is_invalid() returns void as $$
declare
  member__id$ uuid;
  token$      text;
begin

  begin
    member__id$ = lib_iam.user_create('password');
    token$ = lib_iam.generate_auth_token(member__id$, 'username', 600);
    perform lib_iam.user_change_password(token$, 'nbc');
  exception
    when check_violation then
      perform lib_test.assert_equal(sqlerrm, 'invalid password format');
      return;
  end;
  perform lib_test.fail('User should not be able to change is password if the new one is invalid.');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_user_can_change_password() returns void as $$
declare
  changed_member__id$ uuid;
  member__id$         uuid;
  token$              text;
  user$               lib_iam.user;
begin

  member__id$ = lib_iam.user_create('password');
  token$ = lib_iam.generate_auth_token(member__id$, 'username', 600);
  changed_member__id$ = lib_iam.user_change_password(token$, 'new_password');
  select * from lib_iam.user where member__id = member__id$ into user$;
  perform lib_test.assert_equal(changed_member__id$, user$.member__id);
  perform lib_test.assert_equal(user$.password, lib_iam.check_pass('new_password', user$.password));
end;
$$ language plpgsql;

-- Auth token management.

create or replace function lib_test.test_case_lib_iam_one_time_token_not_generated_for_unknown_user() returns void as $$
declare
  member__id$ uuid;
begin

  begin
    member__id$ = '081d831f-8f88-0000-aaaa-000000000001';
    perform lib_iam.generate_auth_token(member__id$, 'username', 600);
  exception
    when check_violation then
      perform lib_test.assert_equal(sqlerrm, 'user not found');
      return;
  end;
  perform lib_test.fail('A token should not be created for an inexistent user.');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_one_time_token_not_generated_for_blocked_user() returns void as $$
declare
  member__id$ uuid;
begin

  begin
    member__id$ = lib_iam.user_create('password');
    perform lib_iam.user_delete(member__id$);
    perform lib_iam.generate_auth_token(member__id$, 'username', 600);
  exception
    when check_violation then
      perform lib_test.assert_equal(sqlerrm, 'user is restricted');
      return;
  end;
  perform lib_test.fail('A token should not be created for a restricted user.');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_user_cannot_be_recognized_without_valid_one_time_token() returns void as $$
declare
  member__id$ uuid;
  token$      text;
begin
  begin
    member__id$ = lib_iam.user_create('password');
    token$ = lib_pgjwt.url_encode(convert_to('notReallyAToken', 'utf8'));
    perform lib_iam.verify_auth_token(token$);
  exception
    when sqlstate '28000' then
      perform lib_test.assert_equal(sqlerrm, 'invalid token');
      return;
  end;
  perform lib_test.fail('Invalid token should raise an error.');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_user_cannot_be_recognized_with_expired_one_time_token() returns void as $$
declare
  member__id$ uuid;
  token$      text;
begin

  begin
    member__id$ = lib_iam.user_create('password');
    token$ = lib_iam.generate_auth_token(member__id$, 'username', -1);
    perform lib_iam.verify_auth_token(token$);
  exception
    when check_violation then
      perform lib_test.assert_equal(sqlerrm, 'token is expired');
      return;
  end;
  perform lib_test.fail('An expired token should not recognize his user.');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_user_can_be_recognized_with_valid_one_time_token() returns void as $$
declare
  member__id$ uuid;
  token$      text;
begin
  member__id$ = lib_iam.user_create('password');
  token$ = lib_iam.generate_auth_token(member__id$, 'username', 600);
  perform lib_test.assert_equal(lib_iam.verify_auth_token(token$), member__id$);
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_user_cannot_be_recognized_with_used_one_time_token() returns void as $$
declare
  member__id$ uuid;
  token$      text;
begin
  member__id$ = lib_iam.user_create('password');
  token$ = lib_iam.generate_auth_token(member__id$, 'username', 600);
  perform lib_test.assert_equal(lib_iam.verify_auth_token(token$), member__id$);
  begin
    perform lib_test.assert_equal(lib_iam.verify_auth_token(token$), member__id$);
  exception
    when check_violation then
      perform lib_test.assert_equal(sqlerrm, 'user not found');
      return;
  end;
  perform lib_test.fail('An already used token should not recognize his user.');
end;
$$ language plpgsql;
