truncate lib_iam.service restart identity cascade;
-- lib_iam.service truncate cascade to type.
truncate lib_iam.role__permission restart identity cascade;
truncate lib_iam.role restart identity cascade;
truncate lib_iam.permission restart identity cascade;
truncate lib_iam.verb restart identity cascade;
truncate lib_iam.member restart identity cascade;
truncate lib_iam.organization restart identity cascade;
-- lib_iam.organization cascade to folder and resource.
truncate lib_iam.organization_policy restart identity cascade;

\set lib_iam_resource_status_abstract_machine_id '081d831f-8f88-0000-aaaa-000000000001'
\set lib_iam_resource_status_abstract_state_unspecified_id '081d831f-8f88-0000-aaaa-000000000002'
\set lib_iam_resource_status_abstract_state_activated_id '081d831f-8f88-0000-aaaa-000000000003'
\set lib_iam_resource_status_abstract_state_deleting_id '081d831f-8f88-0000-aaaa-000000000004'

select lib_fsm.abstract_machine_create('lib_iam_resource_status', 'all availables resource statuses', :'lib_iam_resource_status_abstract_machine_id'::uuid, '2020-05-28 10:07:31.390495+00');
select lib_fsm.abstract_state_create(:'lib_iam_resource_status_abstract_machine_id'::uuid, 'unspecified', 'unspecified', is_initial$ => true, abstract_state__id$ => :'lib_iam_resource_status_abstract_state_unspecified_id'::uuid);
select lib_fsm.abstract_state_create(:'lib_iam_resource_status_abstract_machine_id'::uuid, 'activated', 'activated', is_initial$ => false, abstract_state__id$ => :'lib_iam_resource_status_abstract_state_activated_id'::uuid);
select lib_fsm.abstract_state_create(:'lib_iam_resource_status_abstract_machine_id'::uuid, 'delete_requested', 'pending deletion', is_initial$ => false, abstract_state__id$ => :'lib_iam_resource_status_abstract_state_deleting_id'::uuid);

select lib_fsm.abstract_transition_create(:'lib_iam_resource_status_abstract_state_unspecified_id'::uuid, 'activate', :'lib_iam_resource_status_abstract_state_activated_id'::uuid, 'make resource active', '2020-05-28 10:07:31.390495+00');
select lib_fsm.abstract_transition_create(:'lib_iam_resource_status_abstract_state_unspecified_id'::uuid, 'delete', :'lib_iam_resource_status_abstract_state_deleting_id'::uuid, 'cancel resource', '2020-05-28 10:07:31.390495+00');
select lib_fsm.abstract_transition_create(:'lib_iam_resource_status_abstract_state_activated_id'::uuid, 'delete', :'lib_iam_resource_status_abstract_state_deleting_id'::uuid, 'delete resource', '2020-05-28 10:07:31.390495+00');

\echo # filling table lib_iam.verb
COPY lib_iam.verb (verb__id) FROM STDIN (FREEZE ON, DELIMITER ';');
create
get
list
update
delete
enable
disable
set_acl
*
\.
