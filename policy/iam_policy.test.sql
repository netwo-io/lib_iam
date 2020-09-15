-- lib iam policy tests.

create or replace function lib_test.test_case_lib_iam_policy_can_create_organization_policy() returns void as $$
declare
  policy__id$ uuid;
begin

  policy__id$ = lib_iam.organization_policy_create('00000000-0000-0000-0000-0000000000a2'::uuid);
  perform lib_test.assert_not_null(policy__id$, 'Policy not created');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_can_delete_organization_policy() returns void as $$
declare
  count$ int;
begin

  perform lib_iam.organization_policy_delete('00000000-0000-0000-0000-0000000000d2'::uuid);
  select count(1) from lib_iam.policies where id = '00000000-0000-0000-0000-0000000000d2'::uuid into count$;
  perform lib_test.assert_equal(count$, 0);
end;
$$ language plpgsql;

-------------------- BINDING -------------------------

-- Create

create or replace function lib_test.test_case_lib_iam_policy_cannot_create_binding_on_invalid_principal() returns void as $$
declare
  policy$ jsonb;
begin

  begin
    perform lib_iam.organization_policy_add_binding('00000000-0000-0000-0000-0000000000d1'::uuid, 'test_manager', 'viewer', 'allusers');
  exception
    when check_violation then
      perform lib_test.assert_equal(sqlerrm, 'principal must be one of allUsers, allAuthenticatedUsers, member_type:id');
      return;
  end;
  perform lib_test.fail('Policy binding should not be created with invalid principal.');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_policy_cannot_create_binding_on_unknwon_principal() returns void as $$
declare
  policy$ jsonb;
begin

  begin
    perform lib_iam.organization_policy_add_binding('00000000-0000-0000-0000-0000000000d1'::uuid, 'test_manager', 'viewer', 'user:abcdefaa-0000-0000-0000-0000000000e1');
  exception
    when foreign_key_violation then
      perform lib_test.assert_equal(sqlerrm, 'insert or update on table "user_organization_policy_binding" violates foreign key constraint "user_organization_policy_binding_member__id_fkey"');
      return;
  end;
  perform lib_test.fail('Policy binding should not be created with unknown principal.');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_policy_can_create_binding() returns void as $$
declare
  policy$ jsonb;
begin

  perform lib_iam.organization_policy_add_binding('00000000-0000-0000-0000-0000000000d1'::uuid, 'test_manager', 'viewer', 'allUsers');
  select row_to_json(policies) from lib_iam.policies where id = '00000000-0000-0000-0000-0000000000d1'::uuid into policy$;
  perform lib_test.assert_equal((policy$->>'id')::uuid, '00000000-0000-0000-0000-0000000000d1'::uuid);
  perform lib_test.assert_equal(policy$#>'{bindings,0}', '{"service":"test_manager","role":"viewer","members":["allUsers"]}'::jsonb);

  perform lib_iam.organization_policy_add_binding('00000000-0000-0000-0000-0000000000d1'::uuid, 'test_manager', 'viewer', 'allAuthenticatedUsers');
  select row_to_json(policies) from lib_iam.policies where id = '00000000-0000-0000-0000-0000000000d1'::uuid into policy$;
  perform lib_test.assert_equal(policy$#>'{bindings,0}', '{"service":"test_manager","role":"viewer","members":["allUsers", "allAuthenticatedUsers"]}'::jsonb);

  perform lib_iam.organization_policy_add_binding('00000000-0000-0000-0000-0000000000d1'::uuid, 'test_manager', 'viewer', 'user:00000000-0000-0000-0000-0000000000e1');
  select row_to_json(policies) from lib_iam.policies where id = '00000000-0000-0000-0000-0000000000d1'::uuid into policy$;
  perform lib_test.assert_equal(policy$#>'{bindings,0}', '{"service":"test_manager","role":"viewer","members":["user:00000000-0000-0000-0000-0000000000e1", "allUsers", "allAuthenticatedUsers"]}'::jsonb);

  perform lib_iam.organization_policy_add_binding('00000000-0000-0000-0000-0000000000d1'::uuid, 'test_manager', 'viewer', 'service_account:00000000-0000-0000-0000-0000000000f1');
  select row_to_json(policies) from lib_iam.policies where id = '00000000-0000-0000-0000-0000000000d1'::uuid into policy$;
  perform lib_test.assert_equal(policy$#>'{bindings,0}', '{"service":"test_manager","role":"viewer","members":["user:00000000-0000-0000-0000-0000000000e1", "service_account:00000000-0000-0000-0000-0000000000f1", "allUsers", "allAuthenticatedUsers"]}'::jsonb);
end;
$$ language plpgsql;

-- Upsert

create or replace function lib_test.test_case_lib_iam_policy_can_upsert_binding() returns void as $$
declare
  policy$ jsonb;
begin

  perform lib_iam.organization_policy_add_binding('00000000-0000-0000-0000-0000000000d3'::uuid, 'test_manager', 'viewer', 'allUsers');
  perform lib_iam.organization_policy_add_binding('00000000-0000-0000-0000-0000000000d3'::uuid, 'test_manager', 'viewer', 'allAuthenticatedUsers');
  select row_to_json(policies) from lib_iam.policies where id = '00000000-0000-0000-0000-0000000000d3'::uuid into policy$;
  perform lib_test.assert_equal(policy$#>'{bindings,0}', '{"service":"test_manager","role":"viewer","members":["allUsers", "allAuthenticatedUsers"]}'::jsonb);

  perform lib_iam.organization_policy_add_binding('00000000-0000-0000-0000-0000000000d3'::uuid, 'test_manager', 'editor', 'allUsers');
  select row_to_json(policies) from lib_iam.policies where id = '00000000-0000-0000-0000-0000000000d3'::uuid into policy$;
  perform lib_test.assert_equal(policy$#>'{bindings,0}', '{"service":"test_manager","role":"editor","members":["allUsers"]}'::jsonb);
  perform lib_test.assert_equal(policy$#>'{bindings,1}', '{"service":"test_manager","role":"viewer","members":["allAuthenticatedUsers"]}'::jsonb);

  perform lib_iam.organization_policy_add_binding('00000000-0000-0000-0000-0000000000d3'::uuid, 'test_manager2', 'viewer', 'allUsers');
  select row_to_json(policies) from lib_iam.policies where id = '00000000-0000-0000-0000-0000000000d3'::uuid into policy$;
  perform lib_test.assert_equal(policy$#>'{bindings,0}', '{"service":"test_manager","role":"editor","members":["allUsers"]}'::jsonb);
  perform lib_test.assert_equal(policy$#>'{bindings,1}', '{"service":"test_manager","role":"viewer","members":["allAuthenticatedUsers"]}'::jsonb);
  perform lib_test.assert_equal(policy$#>'{bindings,2}', '{"service":"test_manager2","role":"viewer","members":["allUsers"]}'::jsonb);
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_policy_can_upsert_binding2() returns void as $$
declare
  policy$ jsonb;
begin

  perform lib_iam.organization_policy_add_binding('00000000-0000-0000-0000-0000000000d5'::uuid, 'test_manager', 'viewer', 'user:00000000-0000-0000-0000-0000000000e1');
  select row_to_json(policies) from lib_iam.policies where id = '00000000-0000-0000-0000-0000000000d5'::uuid into policy$;
  perform lib_test.assert_equal(policy$#>'{bindings,0}', '{"service":"test_manager","role":"viewer","members":["user:00000000-0000-0000-0000-0000000000e1"]}'::jsonb);

  perform lib_iam.organization_policy_add_binding('00000000-0000-0000-0000-0000000000d5'::uuid, 'test_manager', 'editor', 'user:00000000-0000-0000-0000-0000000000e1');
  select row_to_json(policies) from lib_iam.policies where id = '00000000-0000-0000-0000-0000000000d5'::uuid into policy$;
  perform lib_test.assert_equal(policy$#>'{bindings,0}', '{"service":"test_manager","role":"editor","members":["user:00000000-0000-0000-0000-0000000000e1"]}'::jsonb);
end;
$$ language plpgsql;

-- Delete

create or replace function lib_test.test_case_lib_iam_policy_cannot_delete_binding_w_invalid_principal() returns void as $$
begin

  begin
    perform lib_iam.organization_policy_remove_binding('00000000-0000-0000-0000-0000000000d4'::uuid, 'test_manager', 'viewer', 'aaaa');
  exception
    when check_violation then
      perform lib_test.assert_equal(sqlerrm, 'value for domain lib_iam.principal violates check constraint "principal_check"');
      return;
  end;
  perform lib_test.fail('Policy unbinding should raise with invalid principal');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_policy_can_delete_binding_w_unknown_principal() returns void as $$
begin

  perform lib_iam.organization_policy_remove_binding('00000000-0000-0000-0000-0000000000d4'::uuid, 'test_manager', 'viewer', 'user:abcdefaa-0000-0000-0000-0000000000e1');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_policy_can_delete_non_existing_binding() returns void as $$
begin
  perform lib_iam.organization_policy_remove_binding('00000000-0000-0000-0000-0000000000d4'::uuid, 'test_manager', 'viewer', 'allUsers');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_policy_can_delete_binding() returns void as $$
declare
  count$ int;
  policy$ jsonb;
begin

  perform lib_iam.organization_policy_add_binding('00000000-0000-0000-0000-0000000000d4'::uuid, 'test_manager', 'viewer', 'allUsers');
  perform lib_iam.organization_policy_add_binding('00000000-0000-0000-0000-0000000000d4'::uuid, 'test_manager', 'viewer', 'allAuthenticatedUsers');
  select row_to_json(policies) from lib_iam.policies where id = '00000000-0000-0000-0000-0000000000d4'::uuid into policy$;
  perform lib_test.assert_equal(policy$#>'{bindings,0}', '{"service":"test_manager","role":"viewer","members":["allUsers", "allAuthenticatedUsers"]}'::jsonb);

  perform lib_iam.organization_policy_remove_binding('00000000-0000-0000-0000-0000000000d4'::uuid, 'test_manager', 'viewer', 'allAuthenticatedUsers');
  select row_to_json(policies) from lib_iam.policies where id = '00000000-0000-0000-0000-0000000000d4'::uuid into policy$;
  perform lib_test.assert_equal(policy$#>'{bindings,0}', '{"service":"test_manager","role":"viewer","members":["allUsers"]}'::jsonb);

  perform lib_iam.organization_policy_remove_binding('00000000-0000-0000-0000-0000000000d4'::uuid, 'test_manager', 'viewer', 'allUsers');
  select count(1) from lib_iam.policies where id = '00000000-0000-0000-0000-0000000000d4'::uuid into count$;
  perform lib_test.assert_equal(count$, 0);
end;
$$ language plpgsql;
