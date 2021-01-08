\echo # filling table lib_iam.service
COPY lib_iam.service (service__id,description) FROM STDIN (FREEZE ON, DELIMITER ';');
test_manager;test manager
test_manager2;test manager 2
\.

\echo # filling table lib_iam.type
COPY lib_iam.type (type__id, service__id, description) FROM STDIN (FREEZE ON, DELIMITER ';');
invoice;test_manager;test manager invoice
log;test_manager2;test manager log
entry;test_manager2;test manager entry
\.

\echo # filling table lib_iam.permission
COPY lib_iam.permission (service__id, type__id, verb__id) FROM STDIN (FREEZE ON, DELIMITER ';');
test_manager;invoice;create
test_manager;invoice;get
test_manager;invoice;set_acl
test_manager;invoice;delete
test_manager2;log;get
test_manager2;entry;*
test_manager2;entry;get
test_manager2;entry;create
\.

\echo # filling table lib_iam.role
COPY lib_iam.role (service__id, role__id, title, description) FROM STDIN (FREEZE ON, DELIMITER ';');
test_manager;viewer;Billing Account Viewer;Provides access to see and manage all aspects of billing accounts.
test_manager;editor;Editor;Editor
test_manager2;viewer;Viewer;Viewer
test_manager2;admin;Admin;Admin
\.

\echo # filling table lib_iam.role__permission
COPY lib_iam.role__permission (
  permission_service__id,
  permission_type__id,
  permission_verb__id,
  service__id,
  role__id
) FROM STDIN (FREEZE ON, DELIMITER ';');
test_manager;invoice;get;test_manager;viewer
test_manager;invoice;get;test_manager;editor
test_manager;invoice;create;test_manager;editor
test_manager;invoice;set_acl;test_manager;editor
test_manager2;log;get;test_manager2;viewer
test_manager2;entry;*;test_manager2;admin
\.

\echo # filling table lib_iam.user
COPY lib_iam.user (member__id, password) FROM STDIN (FREEZE ON, DELIMITER ';');
00000000-0000-0000-0000-0000000000e1;pass
00000000-0000-0000-0000-0000000000e2;pass
00000000-0000-0000-0000-0000000000e3;pass
\.

\echo # filling table lib_iam.service_account
COPY lib_iam.service_account (member__id) FROM STDIN (FREEZE ON, DELIMITER ';');
00000000-0000-0000-0000-0000000000f1
\.

\echo # filling table lib_iam.organization
select lib_iam.organization_create('first-org', 'description', null, '00000000-0000-0000-0000-0000000000a1'::uuid);
select lib_iam.organization_create('second-org', 'description', null, '00000000-0000-0000-0000-0000000000a2'::uuid);
select lib_iam.organization_create('third-org', 'access test org', null, '00000000-0000-0000-0000-0000000000a3'::uuid);
select lib_iam.organization_create('fourth-org', 'access test org', null, '00000000-0000-0000-0000-0000000000a4'::uuid);
select lib_iam.organization_create('fifth-org', 'access test org', '00000000-0000-0000-0000-0000000000a4'::uuid, '00000000-0000-0000-0000-0000000000a5'::uuid);
select lib_iam.organization_create('sixth-org', 'access test org all', null, '00000000-0000-0000-0000-0000000000a6'::uuid);
select lib_iam.organization_create('seventh-org', 'access test org all auth', null, '00000000-0000-0000-0000-0000000000a7'::uuid);

\echo # filling table lib_iam.folter
select lib_iam.folder_create('first-folder', 'description', null, '00000000-0000-0000-0000-0000000000a1'::uuid, '00000000-0000-0000-0000-0000000000b1'::uuid);

select lib_iam.folder_create('folder-1', 'description', null, '00000000-0000-0000-0000-0000000000a4'::uuid, '00000000-0000-0000-0000-0000000000b2'::uuid);
select lib_iam.folder_create('folder-2', 'description', null, '00000000-0000-0000-0000-0000000000a4'::uuid, '00000000-0000-0000-0000-0000000000b3'::uuid);
select lib_iam.folder_create('folder-3', 'description', '00000000-0000-0000-0000-0000000000b2'::uuid, null, '00000000-0000-0000-0000-0000000000b4'::uuid);

\echo # filling table lib_iam.resource
COPY lib_iam.resource (resource__id, parent_folder__id, service__id, type__id, name) FROM STDIN (FREEZE ON, DELIMITER ';');
00000000-0000-0000-0000-0000000000c1;00000000-0000-0000-0000-0000000000b1;test_manager;invoice;first-resource
00000000-0000-0000-0000-0000000000c2;00000000-0000-0000-0000-0000000000b2;test_manager;invoice;resource-4
00000000-0000-0000-0000-0000000000c3;00000000-0000-0000-0000-0000000000b3;test_manager2;log;resource-2
00000000-0000-0000-0000-0000000000c4;00000000-0000-0000-0000-0000000000b4;test_manager2;log;resource-3
\.

\echo # filling table lib_iam.organization_policy
COPY lib_iam.organization_policy (policy__id, organization__id) FROM STDIN (FREEZE ON, DELIMITER ';');
00000000-0000-0000-0000-0000000000d1;00000000-0000-0000-0000-0000000000a1
00000000-0000-0000-0000-0000000000d2;00000000-0000-0000-0000-0000000000a1
00000000-0000-0000-0000-0000000000d3;00000000-0000-0000-0000-0000000000a1
00000000-0000-0000-0000-0000000000d4;00000000-0000-0000-0000-0000000000a1
00000000-0000-0000-0000-0000000000d5;00000000-0000-0000-0000-0000000000a1
00000000-0000-0000-0000-0000000000d6;00000000-0000-0000-0000-0000000000a3
00000000-0000-0000-0000-0000000000d7;00000000-0000-0000-0000-0000000000a4
00000000-0000-0000-0000-0000000000d8;00000000-0000-0000-0000-0000000000a1
00000000-0000-0000-0000-0000000000d9;00000000-0000-0000-0000-0000000000a5
00000000-0000-0000-0000-0000000000da;00000000-0000-0000-0000-0000000000a6
00000000-0000-0000-0000-0000000000db;00000000-0000-0000-0000-0000000000a7
\.

\echo # filling table lib_iam.all_users_organization_policy_binding
COPY lib_iam.all_users_organization_policy_binding (policy__id, service__id, role__id) FROM STDIN (FREEZE ON, DELIMITER ';');
00000000-0000-0000-0000-0000000000da;test_manager2;viewer
\.

\echo # filling table lib_iam.all_authenticated_users_organization_policy_binding
COPY lib_iam.all_authenticated_users_organization_policy_binding (policy__id, service__id, role__id) FROM STDIN (FREEZE ON, DELIMITER ';');
00000000-0000-0000-0000-0000000000db;test_manager2;viewer
\.

\echo # filling table lib_iam.user_organization_policy_binding
COPY lib_iam.user_organization_policy_binding (policy__id, member__id, service__id, role__id) FROM STDIN (FREEZE ON, DELIMITER ';');
00000000-0000-0000-0000-0000000000d6;00000000-0000-0000-0000-0000000000e2;test_manager;viewer
00000000-0000-0000-0000-0000000000d7;00000000-0000-0000-0000-0000000000e2;test_manager2;viewer
00000000-0000-0000-0000-0000000000d9;00000000-0000-0000-0000-0000000000e3;test_manager2;admin
\.
