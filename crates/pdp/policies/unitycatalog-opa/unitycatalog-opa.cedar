// Reference policies for the privilege-level `UnityCatalogOpa` namespace
// (UnityCatalogOpa.cedarschema): a privilege holds where it is granted
// (`authz.grants`) on the securable or one of its parents.

// Ownership isn't inherited: owning a catalog doesn't make one the owner of its
// tables (UC asks about each level). It is an `OWNER` grant on the securable
// itself, or the owner the client sends (unitycatalog-rs) being the principal's
// email.
@id("owner")
permit (principal, action == UnityCatalogOpa::Action::"OWNER", resource)
when {
  resource.privileges.contains("OWNER") ||
  (resource has owner && context has principal_email &&
   resource.owner == context.principal_email)
};

// `ALL_PRIVILEGES` on a securable or a parent covers every privilege but
// `OWNER` and `MANAGE`.
@id("all-privileges")
permit (principal, action, resource)
when { resource.inherited_privileges.contains("ALL_PRIVILEGES") }
unless {
  action == UnityCatalogOpa::Action::"OWNER" ||
  action == UnityCatalogOpa::Action::"MANAGE"
};

// Each privilege, granted on the securable or a parent.

@id("grant-CREATE_CATALOG")
permit (principal, action == UnityCatalogOpa::Action::"CREATE_CATALOG", resource)
when { resource.inherited_privileges.contains("CREATE_CATALOG") };

@id("grant-USE_CATALOG")
permit (principal, action == UnityCatalogOpa::Action::"USE_CATALOG", resource)
when { resource.inherited_privileges.contains("USE_CATALOG") };

@id("grant-CREATE_SCHEMA")
permit (principal, action == UnityCatalogOpa::Action::"CREATE_SCHEMA", resource)
when { resource.inherited_privileges.contains("CREATE_SCHEMA") };

@id("grant-USE_SCHEMA")
permit (principal, action == UnityCatalogOpa::Action::"USE_SCHEMA", resource)
when { resource.inherited_privileges.contains("USE_SCHEMA") };

@id("grant-CREATE_TABLE")
permit (principal, action == UnityCatalogOpa::Action::"CREATE_TABLE", resource)
when { resource.inherited_privileges.contains("CREATE_TABLE") };

@id("grant-SELECT")
permit (principal, action == UnityCatalogOpa::Action::"SELECT", resource)
when { resource.inherited_privileges.contains("SELECT") };

@id("grant-MODIFY")
permit (principal, action == UnityCatalogOpa::Action::"MODIFY", resource)
when { resource.inherited_privileges.contains("MODIFY") };

@id("grant-CREATE_FUNCTION")
permit (principal, action == UnityCatalogOpa::Action::"CREATE_FUNCTION", resource)
when { resource.inherited_privileges.contains("CREATE_FUNCTION") };

@id("grant-EXECUTE")
permit (principal, action == UnityCatalogOpa::Action::"EXECUTE", resource)
when { resource.inherited_privileges.contains("EXECUTE") };

@id("grant-CREATE_VOLUME")
permit (principal, action == UnityCatalogOpa::Action::"CREATE_VOLUME", resource)
when { resource.inherited_privileges.contains("CREATE_VOLUME") };

@id("grant-READ_VOLUME")
permit (principal, action == UnityCatalogOpa::Action::"READ_VOLUME", resource)
when { resource.inherited_privileges.contains("READ_VOLUME") };

@id("grant-WRITE_VOLUME")
permit (principal, action == UnityCatalogOpa::Action::"WRITE_VOLUME", resource)
when { resource.inherited_privileges.contains("WRITE_VOLUME") };

@id("grant-CREATE_MODEL")
permit (principal, action == UnityCatalogOpa::Action::"CREATE_MODEL", resource)
when { resource.inherited_privileges.contains("CREATE_MODEL") };

@id("grant-CREATE_MODEL_VERSION")
permit (principal, action == UnityCatalogOpa::Action::"CREATE_MODEL_VERSION", resource)
when { resource.inherited_privileges.contains("CREATE_MODEL_VERSION") };

@id("grant-CREATE_EXTERNAL_LOCATION")
permit (principal, action == UnityCatalogOpa::Action::"CREATE_EXTERNAL_LOCATION", resource)
when { resource.inherited_privileges.contains("CREATE_EXTERNAL_LOCATION") };

@id("grant-READ_FILES")
permit (principal, action == UnityCatalogOpa::Action::"READ_FILES", resource)
when { resource.inherited_privileges.contains("READ_FILES") };

@id("grant-WRITE_FILES")
permit (principal, action == UnityCatalogOpa::Action::"WRITE_FILES", resource)
when { resource.inherited_privileges.contains("WRITE_FILES") };

@id("grant-CREATE_EXTERNAL_TABLE")
permit (principal, action == UnityCatalogOpa::Action::"CREATE_EXTERNAL_TABLE", resource)
when { resource.inherited_privileges.contains("CREATE_EXTERNAL_TABLE") };

@id("grant-CREATE_EXTERNAL_VOLUME")
permit (principal, action == UnityCatalogOpa::Action::"CREATE_EXTERNAL_VOLUME", resource)
when { resource.inherited_privileges.contains("CREATE_EXTERNAL_VOLUME") };

@id("grant-CREATE_MANAGED_STORAGE")
permit (principal, action == UnityCatalogOpa::Action::"CREATE_MANAGED_STORAGE", resource)
when { resource.inherited_privileges.contains("CREATE_MANAGED_STORAGE") };

@id("grant-CREATE_STORAGE_CREDENTIAL")
permit (principal, action == UnityCatalogOpa::Action::"CREATE_STORAGE_CREDENTIAL", resource)
when { resource.inherited_privileges.contains("CREATE_STORAGE_CREDENTIAL") };

@id("grant-BROWSE")
permit (principal, action == UnityCatalogOpa::Action::"BROWSE", resource)
when { resource.inherited_privileges.contains("BROWSE") };

@id("grant-MANAGE")
permit (principal, action == UnityCatalogOpa::Action::"MANAGE", resource)
when { resource.inherited_privileges.contains("MANAGE") };

@id("grant-READ_METADATA")
permit (principal, action == UnityCatalogOpa::Action::"READ_METADATA", resource)
when { resource.inherited_privileges.contains("READ_METADATA") };
