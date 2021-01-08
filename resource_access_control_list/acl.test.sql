create or replace function lib_test.test_case_lib_iam_can_create_resource_acl_when_authorized() returns void as
$$
declare
    organization__id$ uuid;
    folder__id$       uuid;
    user__id$         uuid;
    policy__id$       uuid;
    invoice__id$      uuid = public.gen_random_uuid();
    resource__id$     uuid;
begin
    organization__id$ = public.gen_random_uuid();
    perform lib_iam.organization_create('test_org_acl_1', 'test_org_acl_1', null, organization__id$);

    folder__id$ = lib_iam.folder_create('test-folder-acl-1', 'test-folder-acl-1', null, organization__id$);
    user__id$ = lib_iam.user_create('password');
    policy__id$ = lib_iam.organization_policy_create(organization__id$);
    perform lib_iam.organization_policy_add_binding(policy__id$, 'test_manager', 'editor',
                                                    'user:' || user__id$);
    resource__id$ =
            lib_iam.resource_create('invoice-' || invoice__id$, folder__id$, 'test_manager',
                                    'invoice', invoice__id$);

    perform lib_iam.resource_acl_set(invoice__id$, 'user:' || user__id$, 'user:' || user__id$, 'get');

    perform *
    from lib_iam.resource_acl
             join lib_iam.member_resource_acl using (policy__id)
    where resource__id = invoice__id$
      and member = 'user:'||user__id$
      and grant_verb = 'get';
    perform lib_test.assert_equal(found, true);

    perform lib_iam.resource_acl_set(invoice__id$, 'user:' || user__id$, 'allAuthenticatedUsers', 'get');

    perform *
    from lib_iam.resource_acl
             join lib_iam.all_authenticated_users_resource_acl using (policy__id)
    where resource__id = invoice__id$
      and grant_verb = 'get';
    perform lib_test.assert_equal(found, true);
end ;
$$ language plpgsql;


create or replace function lib_test.test_case_lib_iam_cant_create_resource_acl_when_not_authorized() returns void as
$$
declare
    organization__id$ uuid;
    folder__id$       uuid;
    user__id$         uuid;
    policy__id$       uuid;
    invoice__id$      uuid = public.gen_random_uuid();
    resource__id$     uuid;
    crashed_as_expected$ boolean = false;
begin
    organization__id$ = public.gen_random_uuid();
    perform lib_iam.organization_create('test_org_acl_2', 'test_org_acl_2', null, organization__id$);

    folder__id$ = lib_iam.folder_create('test-folder-acl-2', 'test-folder-acl-2', null, organization__id$);
    user__id$ = lib_iam.user_create('password');
    policy__id$ = lib_iam.organization_policy_create(organization__id$);
    perform lib_iam.organization_policy_add_binding(policy__id$, 'test_manager', 'viewer',
                                                    'user:' || user__id$);
    resource__id$ =
            lib_iam.resource_create('invoice-' || invoice__id$, folder__id$, 'test_manager',
                                    'invoice', invoice__id$);

    begin
        perform lib_iam.resource_acl_set(invoice__id$, 'user:' || user__id$, 'user:' || user__id$, 'get');
    exception
        when sqlstate '42501' then crashed_as_expected$ = true;
    end;

    perform lib_test.assert_equal(crashed_as_expected$, true);
end;
$$ language plpgsql;


create or replace function lib_test.test_case_lib_iam_can_remove_resource_acl_when_authorized() returns void as
$$
declare
    organization__id$ uuid;
    folder__id$       uuid;
    user__id$         uuid;
    policy__id$       uuid;
    invoice__id$      uuid = public.gen_random_uuid();
    resource__id$     uuid;
begin
    organization__id$ = public.gen_random_uuid();
    perform lib_iam.organization_create('test_org_acl_3', 'test_org_acl_3', null, organization__id$);

    folder__id$ = lib_iam.folder_create('test-folder-acl-3', 'test-folder-acl-3', null, organization__id$);
    user__id$ = lib_iam.user_create('password');
    policy__id$ = lib_iam.organization_policy_create(organization__id$);
    perform lib_iam.organization_policy_add_binding(policy__id$, 'test_manager', 'editor',
                                                    'user:' || user__id$);
    resource__id$ =
            lib_iam.resource_create('invoice-' || invoice__id$, folder__id$, 'test_manager',
                                    'invoice', invoice__id$);

    perform lib_iam.resource_acl_set(invoice__id$, 'user:' || user__id$, 'user:' || user__id$, 'get');

    perform *
    from lib_iam.resource_acl
             join lib_iam.member_resource_acl using (policy__id)
    where resource__id = invoice__id$
      and member = 'user:'||user__id$
      and grant_verb = 'get';
    perform lib_test.assert_equal(found, true);

    perform lib_iam.resource_acl_remove(invoice__id$, 'user:'||user__id$, 'user:'||user__id$, 'get');

    perform *
    from lib_iam.resource_acl
             join lib_iam.member_resource_acl using (policy__id)
    where resource__id = invoice__id$
      and member = 'user:'||user__id$
      and grant_verb = 'get';
    perform lib_test.assert_equal(found, false);
end;
$$ language plpgsql;


create or replace function lib_test.test_case_lib_iam_cant_remove_resource_acl_when_not_authorized() returns void as
$$
declare
    organization__id$ uuid;
    folder__id$       uuid;
    editor_user__id$         uuid;
    viewer_user__id$    uuid;
    invoice__id$      uuid = public.gen_random_uuid();
    resource__id$     uuid;
    crashed_as_expected$    boolean=false;
begin
    organization__id$ = public.gen_random_uuid();
    perform lib_iam.organization_create('test_org_acl_4', 'test_org_acl_4', null, organization__id$);

    folder__id$ = lib_iam.folder_create('test-folder-acl-4', 'test-folder-acl-4', null, organization__id$);
    editor_user__id$ = lib_iam.user_create('password');
    viewer_user__id$ = lib_iam.user_create('password');
    perform lib_iam.organization_policy_add_binding(lib_iam.organization_policy_create(organization__id$), 'test_manager', 'editor',
                                                    'user:' || editor_user__id$);
    perform lib_iam.organization_policy_add_binding(lib_iam.organization_policy_create(organization__id$), 'test_manager', 'viewer',
                                                    'user:' || viewer_user__id$);
    resource__id$ =
            lib_iam.resource_create('invoice-' || invoice__id$, folder__id$, 'test_manager',
                                    'invoice', invoice__id$);

    perform lib_iam.resource_acl_set(invoice__id$, 'user:' || editor_user__id$, 'user:' || editor_user__id$, 'get');

    perform *
    from lib_iam.resource_acl
             join lib_iam.member_resource_acl using (policy__id)
    where resource__id = invoice__id$
      and member = 'user:'||editor_user__id$
      and grant_verb = 'get';
    perform lib_test.assert_equal(found, true);

    begin
        perform lib_iam.resource_acl_remove(invoice__id$, 'user:'||viewer_user__id$, 'user:'||editor_user__id$, 'get');
    exception
        when sqlstate '42501' then crashed_as_expected$ = true;
    end;
    perform lib_test.assert_equal(crashed_as_expected$, true);
end;
$$ language plpgsql;


create or replace function lib_test.test_case_lib_iam_acl_cant_grant_a_permission_i_dont_have() returns void as
$$
declare
    organization__id$ uuid;
    folder__id$       uuid;
    user__id$         uuid;
    policy__id$       uuid;
    invoice__id$      uuid = public.gen_random_uuid();
    resource__id$     uuid;
    crashed_as_expected$ boolean = false;
begin
    organization__id$ = public.gen_random_uuid();
    perform lib_iam.organization_create('test_org_acl_5', 'test_org_acl_5', null, organization__id$);

    folder__id$ = lib_iam.folder_create('test-folder-acl-5', 'test-folder-acl-5', null, organization__id$);
    user__id$ = lib_iam.user_create('password');
    policy__id$ = lib_iam.organization_policy_create(organization__id$);
    perform lib_iam.organization_policy_add_binding(policy__id$, 'test_manager', 'editor',
                                                    'user:' || user__id$);
    resource__id$ =
            lib_iam.resource_create('invoice-' || invoice__id$, folder__id$, 'test_manager',
                                    'invoice', invoice__id$);

    begin
        -- Invoice editor does not have "test_manager:invoice:delete" permission thus cannot grant it on a resource
        -- This prevents privilege escalation
        perform lib_iam.resource_acl_set(invoice__id$, 'user:' || user__id$, 'user:' || user__id$, 'delete');
    exception
        when sqlstate '42501' then crashed_as_expected$ = true;
    end;

    perform lib_test.assert_equal(crashed_as_expected$, true);
end;
$$ language plpgsql
