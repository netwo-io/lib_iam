drop schema if exists lib_iam cascade;
create schema lib_iam;
grant usage on schema lib_iam to public;
set search_path = pg_catalog;

\ir ./iam.sql

-- public views
\ir ./services.sql
\ir ./permissions.sql
\ir ./roles.sql

-- rbac modules

\ir ./member/init.sql
\ir ./resource/init.sql
\ir ./policy/init.sql

\ir ./rbac_authorize.sql

-- acl modules

\ir ./resource_access_control_list/init.sql

-- interface

\ir ./authorize.sql
