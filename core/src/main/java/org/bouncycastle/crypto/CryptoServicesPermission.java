package org.bouncycastle.crypto;

import java.security.Permission;
import java.util.HashSet;
import java.util.Set;

/**
 * Permissions that need to be configured if a SecurityManager is used.
 */
public class CryptoServicesPermission
    extends Permission
{
    /**
     * Enable the setting of global configuration properties. This permission implies THREAD_LOCAL_CONFIG
     */
    public static final String GLOBAL_CONFIG = "globalConfig";

    /**
     * Enable the setting of thread local configuration properties.
     */
    public static final String THREAD_LOCAL_CONFIG = "threadLocalConfig";

    /**
     * Enable the setting of the default SecureRandom.
     */
    public static final String DEFAULT_RANDOM = "defaultRandomConfig";

    private final Set<String> actions = new HashSet<String>();

    public CryptoServicesPermission(String name)
    {
        super(name);

        this.actions.add(name);
    }

    public boolean implies(Permission permission)
    {
        if (permission instanceof CryptoServicesPermission)
        {
            CryptoServicesPermission other = (CryptoServicesPermission)permission;

            if (this.getName().equals(other.getName()))
            {
                return true;
            }

            if (this.actions.containsAll(other.actions))
            {
                return true;
            }
        }

        return false;
    }

    public boolean equals(Object obj)
    {
        if (obj instanceof CryptoServicesPermission)
        {
            CryptoServicesPermission other = (CryptoServicesPermission)obj;

            if (this.actions.equals(other.actions))
            {
                return true;
            }
        }

        return false;
    }

    public int hashCode()
    {
        return actions.hashCode();
    }

    public String getActions()
    {
        return actions.toString();
    }
}
