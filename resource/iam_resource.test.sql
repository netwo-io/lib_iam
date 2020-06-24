-- lib iam resource tests.

---------------- ORGANIZATION -------------------

create or replace function lib_test.test_case_lib_iam_resource_can_create_organization() returns void as $$
declare
  organization__id$ uuid;
  organization$     jsonb;
begin

  organization__id$ = lib_iam.organization_create('my-org-name', 'my org description');
  perform lib_test.assert_not_null(organization__id$, 'organization not created');
  select row_to_json(organizations) from lib_iam.organizations where id = organization__id$ into organization$;
  perform lib_test.assert_equal(organization$->>'id', organization__id$::text);
  perform lib_test.assert_equal(organization$->>'name', 'my-org-name');
  perform lib_test.assert_equal(organization$->>'description', 'my org description');
  perform lib_test.assert_equal(organization$->'status'->>'name', 'unspecified');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_resource_cannot_create_organization_w_invalid_parent() returns void as $$
declare
  organization__id$ uuid;
  organization$     jsonb;
begin

  begin
    perform lib_iam.organization_create('my-org-name', 'my org description', '603c3f8b-17a9-4cb6-aaaa-000000000abc'::uuid);
  exception
    when foreign_key_violation then return;
  end;
  perform lib_test.fail('Organization parent must be an organization or void');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_resource_can_create_organization_w_parent() returns void as $$
declare
  organization__id$ uuid;
  organization$     jsonb;
begin

  organization__id$ = lib_iam.organization_create('my-org-name', 'my org description', '00000000-0000-0000-0000-0000000000a1'::uuid);
  select row_to_json(organizations) from lib_iam.organizations where id = organization__id$ into organization$;
  perform lib_test.assert_equal((organization$->'parent_organization'->>'id')::uuid, '00000000-0000-0000-0000-0000000000a1'::uuid);
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_resource_can_delete_organization() returns void as $$
declare
  organization$ jsonb;
begin

  perform lib_iam.organization_delete('00000000-0000-0000-0000-0000000000a1'::uuid);
  select row_to_json(organizations) from lib_iam.organizations where id = '00000000-0000-0000-0000-0000000000a1'::uuid into organization$;
  perform lib_test.assert_equal(organization$->'status'->>'name', 'delete_requested');
end;
$$ language plpgsql;

-------------------- FOLDER -----------------

create or replace function lib_test.test_case_lib_iam_resource_cannot_create_folder_wo_parent() returns void as $$
declare
  organization__id$ uuid;
  organization$     jsonb;
begin

  begin
    perform lib_iam.folder_create('my-folder-name', 'my folder description');
  exception
    when check_violation then return;
  end;
  perform lib_test.fail('Folder should require a parent folder or organization');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_resource_can_create_folder_w_parent_org() returns void as $$
declare
  folder__id$ uuid;
  folder$ jsonb;
begin

  folder__id$ = lib_iam.folder_create('my-folder-name', 'my folder description', parent_folder__id$ => null, parent_organization__id$ => '00000000-0000-0000-0000-0000000000a1'::uuid);
  select row_to_json(folders) from lib_iam.folders where id = folder__id$ into folder$;
  perform lib_test.assert_equal(folder$->>'id', folder__id$::text);
  perform lib_test.assert_equal(folder$->>'name', 'my-folder-name');
  perform lib_test.assert_equal(folder$->>'description', 'my folder description');
  perform lib_test.assert_equal(folder$->'status'->>'name', 'unspecified');
  perform lib_test.assert_equal(folder$->'parent'->>'id', '00000000-0000-0000-0000-0000000000a1');
  perform lib_test.assert_equal(folder$->'parent'->>'type', 'organization');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_resource_can_create_folder_w_parent_folder() returns void as $$
declare
  folder__id$ uuid;
  folder$ jsonb;
begin

  folder__id$ = lib_iam.folder_create('my-folder-name', 'my folder description', parent_folder__id$ => '00000000-0000-0000-0000-0000000000b1'::uuid, parent_organization__id$ => null);
  select row_to_json(folders) from lib_iam.folders where id = folder__id$ into folder$;
  perform lib_test.assert_equal(folder$->>'id', folder__id$::text);
  perform lib_test.assert_equal(folder$->>'name', 'my-folder-name');
  perform lib_test.assert_equal(folder$->>'description', 'my folder description');
  perform lib_test.assert_equal(folder$->'status'->>'name', 'unspecified');
  perform lib_test.assert_equal(folder$->'parent'->>'id', '00000000-0000-0000-0000-0000000000b1');
  perform lib_test.assert_equal(folder$->'parent'->>'type', 'folder');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_resource_can_delete_folder() returns void as $$
declare
  folders$ jsonb;
begin

  perform lib_iam.folder_delete('00000000-0000-0000-0000-0000000000b1'::uuid);
  select row_to_json(folders) from lib_iam.folders where id = '00000000-0000-0000-0000-0000000000b1'::uuid into folders$;
  perform lib_test.assert_equal(folders$->'status'->>'name', 'delete_requested');
end;
$$ language plpgsql;

---------------- RESOURCE ------------------

create or replace function lib_test.test_case_lib_iam_resource_cannot_create_resource_with_invalid_type() returns void as $$
declare
  organization__id$ uuid;
  organization$     jsonb;
begin

  begin
    perform lib_iam.resource_create('my-resource-name', '00000000-0000-0000-0000-0000000000b1'::uuid, 'unknown_service', 'unknown_type');
  exception
    when foreign_key_violation then return;
  end;
  perform lib_test.fail('Resource creation should require an existing type');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_resource_cannot_create_resource_with_invalid_parent() returns void as $$
declare
  organization__id$ uuid;
  organization$     jsonb;
begin

  begin
    perform lib_iam.resource_create('my-resource-name', '00000000-0000-0000-0000-0000000000a1'::uuid, 'test_manager', 'invoice');
  exception
    when foreign_key_violation then return;
  end;
  perform lib_test.fail('Resource creation should require an existing parent folder');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_resource_can_create_resource() returns void as $$
declare
  resource__id$ uuid;
  resource$ jsonb;
begin

  resource__id$ = lib_iam.resource_create('my-resource-name', '00000000-0000-0000-0000-0000000000b1'::uuid, 'test_manager', 'invoice');
  perform lib_test.assert_not_null(resource__id$, 'resource not created');
  select row_to_json(resources) from lib_iam.resources where id = resource__id$ into resource$;
  perform lib_test.assert_equal(resource$->>'id', resource__id$::text);
  perform lib_test.assert_equal(resource$->>'name', 'my-resource-name');
  perform lib_test.assert_equal(resource$->'parent_folder'->>'id', '00000000-0000-0000-0000-0000000000b1');
  perform lib_test.assert_equal(resource$->'type'->>'id', 'invoice');
  perform lib_test.assert_equal(resource$->'type'->'service'->>'id', 'test_manager');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_resource_can_delete_resource() returns void as $$
declare
  count$ int;
begin

  perform lib_iam.resource_delete('00000000-0000-0000-0000-0000000000c1'::uuid);
  select count(1) from lib_iam.folders where id = '00000000-0000-0000-0000-0000000000c1'::uuid into count$;
  perform lib_test.assert_equal(count$, 0);
end;
$$ language plpgsql;
