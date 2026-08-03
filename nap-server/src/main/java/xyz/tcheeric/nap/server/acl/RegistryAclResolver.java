package xyz.tcheeric.nap.server.acl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.tcheeric.nap.core.AclDecision;
import xyz.tcheeric.nap.core.AclRecord;
import xyz.tcheeric.nap.core.AclStore;
import xyz.tcheeric.nap.server.AclResolver;

import java.util.ArrayList;
import java.util.List;

/**
 * ACL resolver backed by a PermissionRegistry and AclStore.
 *
 * <p>Resolves roles and permissions by looking up the ACL record for the pubkey,
 * then expanding the role's permissions from the registry.
 */
public final class RegistryAclResolver implements AclResolver {

    private static final Logger log = LoggerFactory.getLogger(RegistryAclResolver.class);

    private final PermissionRegistry registry;
    private final AclStore aclStore;
    private final boolean autoProvision;

    private RegistryAclResolver(PermissionRegistry registry, AclStore aclStore, boolean autoProvision) {
        this.registry = registry;
        this.aclStore = aclStore;
        this.autoProvision = autoProvision;
    }

    public static RegistryAclResolver create(PermissionRegistry registry, AclStore aclStore, boolean autoProvision) {
        PermissionRegistryValidator.validate(registry);
        return new RegistryAclResolver(registry, aclStore, autoProvision);
    }

    public static RegistryAclResolver create(PermissionRegistry registry, AclStore aclStore) {
        return create(registry, aclStore, true);
    }

    @Override
    public AclDecision resolve(String npub, String pubkey) {
        var record = aclStore.findByPubkey(registry.appId(), pubkey);

        if (record.isEmpty()) {
            if (!autoProvision) {
                return AclDecision.denied("no_acl_record");
            }

            var newRecord = new AclRecord(registry.appId(), pubkey, registry.defaultRole(), false);
            aclStore.create(newRecord);
            log.info("nap.acl.auto_provisioned pubkey={} app_id={} role={}",
                    pubkey, registry.appId(), registry.defaultRole());
            record = java.util.Optional.of(newRecord);
        }

        var aclRecord = record.get();

        if (aclRecord.suspended()) {
            // The only deny this resolver is certain enough about to end the principal's
            // sessions: the row was read, and it says suspended.
            return AclDecision.denied("suspended", true);
        }

        var roleDef = registry.roles().stream()
                .filter(r -> r.key().equals(aclRecord.role()))
                .findFirst();

        if (roleDef.isEmpty()) {
            log.warn("ACL role '{}' not found in registry for pubkey={}", aclRecord.role(), pubkey);
            return AclDecision.denied("unknown_role");
        }

        List<String> permissions = new ArrayList<>(roleDef.get().permissions());
        return AclDecision.allowed(List.of(aclRecord.role()), permissions);
    }
}
