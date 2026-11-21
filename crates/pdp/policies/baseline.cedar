// Policies that hold in every namespace, over the built-in `Lakehouse`
// principals (Lakehouse.cedarschema).

// A banned user may do nothing, whatever else permits it.
@id("banned")
forbid (principal is Lakehouse::User, action, resource)
when { principal.banned };

// Neither may a disabled service account (authentication refuses it already).
@id("disabled")
forbid (principal is Lakehouse::ServiceAccount, action, resource)
when { principal.disabled };
