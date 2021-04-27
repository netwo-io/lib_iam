-- lib iam functions tests.

create or replace function lib_test.test_case_lib_iam_functions_raise_w_wrong_permission_format() returns void as
$$
begin

    begin
        perform lib_iam.authorize('test_manager:invoice_get'::text, 'user:00000000-0000-0000-0000-0000000000e1'::text,
                                  'organization:00000000-0000-0000-0000-0000000000a3', true);
    exception
        when check_violation then
            perform lib_test.assert_equal(sqlerrm,
                                          'value for domain lib_iam.permission_name violates check constraint "permission_name_check"');
            return;
    end;
    perform lib_test.fail('Authorize should raise on unsupported permission serial.');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_functions_raise_w_wrong_resource_format() returns void as
$$
begin

    begin
        perform lib_iam.authorize('test_manager:invoice:get'::text, 'user:00000000-0000-0000-0000-0000000000e1'::text,
                                  'toto:00000000-0000-0000-0000-0000000000a3', true);
    exception
        when check_violation then
            perform lib_test.assert_equal(sqlerrm,
                                          'value for domain lib_iam.resource_name violates check constraint "resource_name_check"');
            return;
    end;
    perform lib_test.fail('Authorize should raise on unsupported resource serial.');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_functions_raise_w_wrong_principal_format() returns void as
$$
begin

    begin
        perform lib_iam.authorize('test_manager:invoice:create', 'useR:00000000-0000-0000-0000-00000000ffe1',
                                  'organization:00000000-0000-0000-0000-0000000000a3', true);
    exception
        when check_violation then
            perform lib_test.assert_equal(sqlerrm,
                                          'principal must be one of allUsers, allAuthenticatedUsers, member_type:id');
            return;
    end;
    perform lib_test.fail('Authorize should raise on unsupported permission serial.');
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_functions_can_check_access() returns void as
$$
declare
    access$ bool;
begin

    access$ = lib_iam.authorize('test_manager:invoice:get', 'user:00000000-0000-0000-0000-0000000000e1',
                                'organization:00000000-0000-0000-0000-0000000000a3', true);
    perform lib_test.assert_equal(access$, false);
    access$ = lib_iam.authorize('test_manager:invoice:get', 'allUsers',
                                'organization:00000000-0000-0000-0000-0000000000a3', true);
    perform lib_test.assert_equal(access$, false);
    access$ = lib_iam.authorize('test_manager:invoice:create', 'user:00000000-0000-0000-0000-0000000000e2',
                                'organization:00000000-0000-0000-0000-0000000000a3', true);
    perform lib_test.assert_equal(access$, false);
    access$ = lib_iam.authorize('test_manager2:log:get', 'user:00000000-0000-0000-0000-0000000000e1',
                                'folder:00000000-0000-0000-0000-0000000000b1', true);
    perform lib_test.assert_equal(access$, false);
    access$ = lib_iam.authorize('test_manager2:log:get', 'user:00000000-0000-0000-0000-0000000000e2',
                                'folder:00000000-0000-0000-0000-0000000000b1', true);
    perform lib_test.assert_equal(access$, false);
    access$ = lib_iam.authorize('test_manager2:log:get', 'user:00000000-0000-0000-0000-0000000000e1',
                                'resource:resource-3', true);
    perform lib_test.assert_equal(access$, false);
    access$ = lib_iam.authorize('test_manager2:log:get', 'allUsers', 'resource:resource-3',
                                true);
    perform lib_test.assert_equal(access$, false);
    access$ = lib_iam.authorize('test_manager:invoice:get', 'user:00000000-0000-0000-0000-0000000000e1',
                                'resource:resource-3', true);
    perform lib_test.assert_equal(access$, false);
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_functions_can_check_access() returns void as
$$
declare
    access$ bool;
begin

    access$ = lib_iam.authorize('test_manager:invoice:get', 'user:00000000-0000-0000-0000-0000000000e2',
                                'organization:00000000-0000-0000-0000-0000000000a3', true);
    perform lib_test.assert_equal(access$, true);
    access$ = lib_iam.authorize('test_manager2:log:get', 'user:00000000-0000-0000-0000-0000000000e2',
                                'organization:00000000-0000-0000-0000-0000000000a4', true);
    perform lib_test.assert_equal(access$, true);

    -- check permission * allow all sub verbs.
    access$ = lib_iam.authorize('test_manager2:entry:get', 'user:00000000-0000-0000-0000-0000000000e3',
                                'organization:00000000-0000-0000-0000-0000000000a5', true);
    perform lib_test.assert_equal(access$, true);
    access$ = lib_iam.authorize('test_manager2:entry:create', 'user:00000000-0000-0000-0000-0000000000e3',
                                'organization:00000000-0000-0000-0000-0000000000a5', true);
    perform lib_test.assert_equal(access$, true);
    -- invalid verb should not work
    access$ = lib_iam.authorize('test_manager2:entry:creat', 'user:00000000-0000-0000-0000-0000000000e3',
                                'organization:00000000-0000-0000-0000-0000000000a5', true);
    perform lib_test.assert_equal(access$, false);

    -- Test folder access by organization permissions.
    access$ = lib_iam.authorize('test_manager2:log:get', 'user:00000000-0000-0000-0000-0000000000e2',
                                'folder:00000000-0000-0000-0000-0000000000b4', true);
    perform lib_test.assert_equal(access$, true);
    access$ = lib_iam.authorize('test_manager2:log:get', 'user:00000000-0000-0000-0000-0000000000e2',
                                'folder:00000000-0000-0000-0000-0000000000b3', true);
    perform lib_test.assert_equal(access$, true);

    -- Test resource access by root organization permissions.
    access$ = lib_iam.authorize('test_manager2:log:get', 'user:00000000-0000-0000-0000-0000000000e2',
                                'resource:resource-3', true);
    perform lib_test.assert_equal(access$, true);
    access$ = lib_iam.authorize('test_manager2:log:get', 'user:00000000-0000-0000-0000-0000000000e2',
                                'resource:resource-2', true);
    perform lib_test.assert_equal(access$, true);
    access$ = lib_iam.authorize('test_manager2:log:get', 'service_account:00000000-0000-0000-0000-0000000000f1',
                                'resource:resource-2', true);
    perform lib_test.assert_equal(access$, true);

    access$ =
            lib_iam.authorize('test_manager2:log:get', 'allUsers', 'organization:00000000-0000-0000-0000-0000000000a6',
                              true);
    perform lib_test.assert_equal(access$, true);
    access$ = lib_iam.authorize('test_manager2:log:get', 'allAuthenticatedUsers',
                                'organization:00000000-0000-0000-0000-0000000000a7', true);
    perform lib_test.assert_equal(access$, true);
end;
$$ language plpgsql;

create or replace function lib_test.test_case_lib_iam_functions_can_find_parent_organizations_by_resource() returns void as
$$
declare
    access$                  bool;
    organization__id$        uuid;
    found_organization__id$  uuid;
    last_created_folder__id$ uuid;
    resource__id$            uuid;
begin

    organization__id$ = public.gen_random_uuid();
    perform lib_iam.organization_create('test_org', 'test_org', null, organization__id$);
    last_created_folder__id$ = lib_iam.folder_create('test-folder-L1', 'my folder level 1', null, organization__id$);
    last_created_folder__id$ =
            lib_iam.folder_create('test-folder-L2', 'my folder level 2', last_created_folder__id$, null);
    last_created_folder__id$ =
            lib_iam.folder_create('test-folder-L3', 'my folder level 3', last_created_folder__id$, null);
    last_created_folder__id$ =
            lib_iam.folder_create('test-folder-L4', 'my folder level 4', last_created_folder__id$, null);
    last_created_folder__id$ =
            lib_iam.folder_create('test-folder-L5', 'my folder level 5', last_created_folder__id$, null);
    resource__id$ = lib_iam.resource_create('test-resource-12', last_created_folder__id$, 'billing_manager', 'invoice');

    found_organization__id$ = lib_iam._find_parent_organizations_by_resource('test-resource-12'::lib_iam.identifier);
    perform lib_test.assert_equal(found_organization__id$, organization__id$);
end;
$$ language plpgsql;

create or replace function lib_test.test_case_iam_functions_can_allow_via_resource_acl() returns void as
$$
declare
    folder__id$       uuid;
    resource__id$     uuid;
    viewer_user__id$  uuid;
    editor_user__id$  uuid;
    invoice__id$      uuid = public.gen_random_uuid();
    organization__id$ uuid = public.gen_random_uuid();
begin
    perform lib_iam.organization_create('test_org_authorize_acl_1', 'test_org_authorize_acl_1', null,
                                        organization__id$);
    folder__id$ = lib_iam.folder_create('test-folder-authorize-acl-2', 'test-folder-authorize-acl-2', null,
                                        organization__id$);
    viewer_user__id$ = lib_iam.user_create('password');
    perform lib_iam.organization_policy_add_binding(lib_iam.organization_policy_create(organization__id$),
                                                    'test_manager', 'viewer',
                                                    'user:' || viewer_user__id$);

    editor_user__id$ = lib_iam.user_create('password');
    perform lib_iam.organization_policy_add_binding(lib_iam.organization_policy_create(organization__id$),
                                                    'test_manager', 'editor',
                                                    'user:' || editor_user__id$);

    resource__id$ =
            lib_iam.resource_create(invoice__id$::lib_iam.identifier, folder__id$, 'test_manager',
                                    'invoice');

    perform lib_test.assert_equal(
            lib_iam.authorize('test_manager:invoice:create'::lib_iam.permission_name,
                              ('user:' || viewer_user__id$)::lib_iam.principal,
                              ('resource:' || invoice__id$)::lib_iam.resource_name),
            false
        );

    perform lib_iam.resource_acl_set(invoice__id$, 'user:' || editor_user__id$, 'user:' || viewer_user__id$, 'create');

    perform lib_test.assert_equal(
            lib_iam.authorize('test_manager:invoice:create'::lib_iam.permission_name,
                              ('user:' || viewer_user__id$)::lib_iam.principal,
                              ('resource:' || invoice__id$)::lib_iam.resource_name),
            true
        );

    perform lib_iam.resource_acl_remove(invoice__id$, 'user:' || editor_user__id$, 'user:' || viewer_user__id$, 'create');

    perform lib_test.assert_equal(
            lib_iam.authorize('test_manager:invoice:create'::lib_iam.permission_name,
                              ('user:' || viewer_user__id$)::lib_iam.principal,
                              ('resource:' || invoice__id$)::lib_iam.resource_name),
            false
        );

    perform lib_iam.resource_acl_set(invoice__id$, 'user:' || editor_user__id$, 'allAuthenticatedUsers', 'create');
    perform lib_test.assert_equal(
            lib_iam.authorize('test_manager:invoice:create'::lib_iam.permission_name,
                              ('user:' || viewer_user__id$)::lib_iam.principal,
                              ('resource:' || invoice__id$)::lib_iam.resource_name),
            true
        );
    perform lib_iam.resource_acl_remove(invoice__id$, 'user:' || editor_user__id$, 'allAuthenticatedUsers', 'create');

    -- Test anonymous access
    perform lib_iam.resource_acl_set(invoice__id$, 'user:' || editor_user__id$, 'allUsers', 'create');
    perform lib_test.assert_equal(
            lib_iam.authorize('test_manager:invoice:create'::lib_iam.permission_name,
                              ('user:' || viewer_user__id$)::lib_iam.principal,
                              ('resource:' || invoice__id$)::lib_iam.resource_name),
            true
        );
    perform lib_test.assert_equal(
            lib_iam.authorize('test_manager:invoice:create'::lib_iam.permission_name,
                              'allUsers',
                              ('resource:' || invoice__id$)::lib_iam.resource_name),
            true
        );

    perform lib_iam.resource_acl_remove(invoice__id$, 'user:' || editor_user__id$, 'allUsers', 'create');
    perform lib_test.assert_equal(
            lib_iam.authorize('test_manager:invoice:create'::lib_iam.permission_name,
                              'allUsers',
                              ('resource:' || invoice__id$)::lib_iam.resource_name),
            false
        );

end ;
$$ language plpgsql;
