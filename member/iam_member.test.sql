-- lib iam member tests.

create or replace function lib_test.test_case_lib_iam_cannot_create_user_member_w_invalid_pass() returns void as $$
begin

  begin
    perform lib_iam.user_create('pass');
  exception
    when check_violation then return;
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

  service_account$ = lib_iam.service_account_create(); --> insert into user_member member_id, invitation_status, status
  select count(1) from lib_iam.members where id = service_account$ into count$;
  perform lib_test.assert_equal(count$, 1);
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_can_list_members() returns void as $$
declare
  user_id$ uuid;
  service_account$ uuid;
  count$ int;
begin

  user_id$ = lib_iam.user_create('password');
  service_account$ = lib_iam.service_account_create();
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

create or replace function lib_test.test_case_lib_iam_user_cannot_change_password_if_old_one_is_invalid() returns void as $$
declare
  member__id$ uuid;
  user$       lib_iam.user;
begin

  begin
    member__id$ = lib_iam.user_create('password');
    perform lib_iam.user_change_password(member__id$, 'new_password', 'not_the_old_pass');
  exception
    when check_violation then return;
  end;
  perform lib_test.fail('User should not be able to change is password if the corresponding old password is not provided.');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_user_cannot_change_password_if_new_one_is_invalid() returns void as $$
declare
  member__id$ uuid;
  user$       lib_iam.user;
begin

  begin
    member__id$ = lib_iam.user_create('password');
    perform lib_iam.user_change_password(member__id$, 'abc', 'password');
  exception
    when check_violation then return;
  end;
  perform lib_test.fail('User should not be able to change is password if the new one is invalid.');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_user_can_change_password() returns void as $$
declare
  member__id$ uuid;
  user$       lib_iam.user;
begin

  member__id$ = lib_iam.user_create('password');
  perform lib_iam.user_change_password(member__id$, 'new_password', 'password');
  select * from lib_iam.user where member__id = member__id$ into user$;
  perform lib_test.assert_equal(user$.password, lib_iam.check_pass('new_password', user$.password));
end;
$$ language plpgsql;
