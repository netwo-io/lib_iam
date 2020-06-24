-- lib_iam tests

create or replace function lib_test.test_case_lib_iam_can_list_services() returns void as $$
declare
  services$ jsonb;
begin
  select row_to_json(services) from lib_iam.services where id = 'test_manager' limit 1 into services$;
  perform lib_test.assert_equal(services$->>'id', 'test_manager');
  perform lib_test.assert_equal(services$->>'description', 'test manager');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_can_list_types() returns void as $$
declare
  types$ jsonb;
begin
  select row_to_json(types) from lib_iam.types where service->>'id' = 'test_manager' and id = 'invoice' limit 1 into types$;
  perform lib_test.assert_equal(types$->>'id', 'invoice');
  perform lib_test.assert_equal(types$->'service'->>'id', 'test_manager');
  perform lib_test.assert_equal(types$->>'description', 'test manager invoice');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_can_list_permissions() returns void as $$
declare
  permissions$ jsonb;
begin
  select row_to_json(permissions) from lib_iam.permissions where type->>'id' = 'invoice' and type->'service'->>'id' = 'test_manager' and verb = 'create' limit 1 into permissions$;
  perform lib_test.assert_equal(permissions$->'type'->'service'->>'id', 'test_manager');
  perform lib_test.assert_equal(permissions$->'type'->>'id', 'invoice');
  perform lib_test.assert_equal(permissions$->>'verb', 'create');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_cannot_delete_in_usage_verb() returns void as $$
declare
  permissions$ jsonb;
begin
  begin
    delete from lib_iam.verb where 1=1;
  exception
    when foreign_key_violation then return;
  end;
  perform lib_test.fail('Verb in usage should not be deletable');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_can_list_roles() returns void as $$
declare
  roles$ jsonb;
begin
  select row_to_json(roles) from lib_iam.roles where id = 'test_manager.viewer' limit 1 into roles$;
  perform lib_test.assert_equal(roles$->>'id', 'test_manager.viewer');
  perform lib_test.assert_equal(roles$->>'title', 'Billing Account Viewer');
  perform lib_test.assert_equal(roles$->>'description', 'Provides access to see and manage all aspects of billing accounts.');
  perform lib_test.assert_equal(roles$#>'{permissions,0}'->'type'->>'id', 'invoice');
  perform lib_test.assert_equal(roles$#>'{permissions,0}'->'type'->'service'->>'id', 'test_manager');
  perform lib_test.assert_equal(roles$#>'{permissions,0}'->'type'->>'description', 'test manager invoice');
  perform lib_test.assert_equal(roles$#>'{permissions,0}'->>'verb', 'get');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_parse_permission_should_reject_invalid_input() returns void as $$
declare
  permission$ lib_iam.permission;
begin
    begin
        select lib_iam._parse_permission('a.b.c.d') into permission$;
    exception
        when check_violation then return;
    end;
end;
$$ language plpgsql;
