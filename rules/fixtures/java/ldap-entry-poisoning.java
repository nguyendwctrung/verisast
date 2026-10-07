import javax.naming.directory.SearchControls;

class LdapEntryPoisoningNegative {
    SearchControls disableReturningObjects(
        int scope,
        long countLimit,
        int timeLimit,
        String[] attributes,
        boolean dereferenceLinks
    ) {
        // ok: ldap-entry-poisoning
        return new SearchControls(
            scope,
            countLimit,
            timeLimit,
            attributes,
            false,
            dereferenceLinks
        );
    }

    SearchControls disableThroughSetter() {
        SearchControls controls = new SearchControls();

        // ok: ldap-entry-poisoning
        controls.setReturningObjFlag(false);

        return controls;
    }

    SearchControls useDefaultControls() {
        // ok: ldap-entry-poisoning
        return new SearchControls();
    }
}
