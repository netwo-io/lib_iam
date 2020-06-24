create view lib_iam.organizations as
  select
    organization.organization__id as id,
    organization.name,
    organization.description,
    row_to_json(lib_fsm.state_machine_get(organization.status)) as status,
    case when parent.organization__id is not null then json_build_object(
          'id', parent.organization__id,
          'name', parent.name,
          'description', parent.description
        )
      else null
    end as parent_organization
  from lib_iam.organization
    left join lib_iam.organization parent on parent.organization__id = organization.parent_organization__id;

create view lib_iam.folders as
  select
    folder.folder__id as id,
    folder.name,
    folder.description,
    row_to_json(lib_fsm.state_machine_get(folder.status)) as status,
    case
      when parent_folder.folder__id is not null then json_build_object(
          'id', parent_folder.folder__id,
          'type', 'folder',
          'name', parent_folder.name,
          'description', parent_folder.description
        )
      when parent_org.organization__id is not null then json_build_object(
          'id', parent_org.organization__id,
          'type', 'organization',
          'name', parent_org.name,
          'description', parent_org.description
        )
    end as parent
  from lib_iam.folder
    left join lib_iam.folder parent_folder on parent_folder.folder__id = folder.parent_folder__id
    left join lib_iam.organization parent_org on parent_org.organization__id = folder.parent_organization__id;

create view lib_iam.resources as
  select
    resource.resource__id as id,
    resource.name,
    row_to_json(types) as type,
    row_to_json(folders) as parent_folder
  from lib_iam.resource
    inner join lib_iam.folders on folders.id = resource.parent_folder__id
    inner join lib_iam.types on types.service->>'id' = resource.service__id and types.id = resource.type__id;
