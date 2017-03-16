package org.bouncycastle.jcajce.provider.config;

import java.security.BasicPermission;
import java.security.Permission;
import java.util.StringTokenizer;

import org.bouncycastle.util.Strings;

/**
 * A permission class to define what can be done with the ConfigurableProvider interface.
 * <p>
 * Available permissions are "threadLocalEcImplicitlyCa" and "ecImplicitlyCa" which allow the setting
 * of the thread local and global ecImplicitlyCa parameters respectively.
 * </p>
 * <p>
 * Examples:
 * <ul>
 * <li>ProviderConfigurationPermission("BC"); // enable all permissions</li>
 * <li>ProviderConfigurationPermission("BC", "threadLocalEcImplicitlyCa"); // enable thread local only</li>
 * <li>ProviderConfigurationPermission("BC", "ecImplicitlyCa"); // enable global setting only</li>
 * <li>ProviderConfigurationPermission("BC", "threadLocalEcImplicitlyCa, ecImplicitlyCa"); // enable both explicitly</li>
 * </ul>
 * <p>
 * Note: permission checks are only enforced if a security manager is present.
 * </p>
 */
public class ProviderConfigurationPermission
    extends BasicPermission
{
    private static final int THREAD_LOCAL_EC_IMPLICITLY_CA = 0x01;
    private static final int EC_IMPLICITLY_CA = 0x02;
    private static final int THREAD_LOCAL_DH_DEFAULT_PARAMS = 0x04;
    private static final int DH_DEFAULT_PARAMS = 0x08;
    private static final int ACCEPTABLE_EC_CURVES = 0x10;
    private static final int ADDITIONAL_EC_PARAMETERS = 0x20;

    private static final int  ALL =
            THREAD_LOCAL_EC_IMPLICITLY_CA | EC_IMPLICITLY_CA | THREAD_LOCAL_DH_DEFAULT_PARAMS | DH_DEFAULT_PARAMS |
            ACCEPTABLE_EC_CURVES | ADDITIONAL_EC_PARAMETERS;

    private static final String THREAD_LOCAL_EC_IMPLICITLY_CA_STR = "threadlocalecimplicitlyca";
    private static final String EC_IMPLICITLY_CA_STR = "ecimplicitlyca";
    private static final String THREAD_LOCAL_DH_DEFAULT_PARAMS_STR = "threadlocaldhdefaultparams";
    private static final String DH_DEFAULT_PARAMS_STR = "dhdefaultparams";
    private static final String ACCEPTABLE_EC_CURVES_STR = "acceptableeccurves";
    private static final String ADDITIONAL_EC_PARAMETERS_STR = "additionalecparameters";
    private static final String ALL_STR = "all";

    private final String actions;
    private final int permissionMask;

    public ProviderConfigurationPermission(String name)
    {
        super(name);
        this.actions = "all";
        this.permissionMask = ALL;
    }

    public ProviderConfigurationPermission(String name, String actions)
    {
        super(name, actions);
        this.actions = actions;
        this.permissionMask = calculateMask(actions);
    }

    private int calculateMask(
        String actions)
    {
        StringTokenizer tok = new StringTokenizer(Strings.toLowerCase(actions), " ,");
        int             mask = 0;

        while (tok.hasMoreTokens())
        {
            String s = tok.nextToken();

            if (s.equals(THREAD_LOCAL_EC_IMPLICITLY_CA_STR))
            {
                mask |= THREAD_LOCAL_EC_IMPLICITLY_CA;
            }
            else if (s.equals(EC_IMPLICITLY_CA_STR))
            {
                mask |= EC_IMPLICITLY_CA;
            }
            else if (s.equals(THREAD_LOCAL_DH_DEFAULT_PARAMS_STR))
            {
                mask |= THREAD_LOCAL_DH_DEFAULT_PARAMS;
            }
            else if (s.equals(DH_DEFAULT_PARAMS_STR))
            {
                mask |= DH_DEFAULT_PARAMS;
            }
            else if (s.equals(ACCEPTABLE_EC_CURVES_STR))
            {
                mask |= ACCEPTABLE_EC_CURVES;
            }
            else if (s.equals(ADDITIONAL_EC_PARAMETERS_STR))
            {
                mask |= ADDITIONAL_EC_PARAMETERS;
            }
            else if (s.equals(ALL_STR))
            {
                mask |= ALL;
            }
        }

        if (mask == 0)
        {
            throw new IllegalArgumentException("unknown permissions passed to mask");
        }
        
        return mask;
    }

    public String getActions()
    {
        return actions;
    }

    public boolean implies(
        Permission permission)
    {
        if (!(permission instanceof ProviderConfigurationPermission))
        {
            return false;
        }

        if (!this.getName().equals(permission.getName()))
        {
            return false;
        }
        
        ProviderConfigurationPermission other = (ProviderConfigurationPermission)permission;
        
        return (this.permissionMask & other.permissionMask) == other.permissionMask;
    }

    public boolean equals(
        Object obj)
    {
        if (obj == this)
        {
            return true;
        }

        if (obj instanceof ProviderConfigurationPermission)
        {
            ProviderConfigurationPermission other = (ProviderConfigurationPermission)obj;

            return this.permissionMask == other.permissionMask && this.getName().equals(other.getName());
        }

        return false;
    }

    public int hashCode()
    {
        return this.getName().hashCode() + this.permissionMask;
    }
}
