package org.bouncycastle.util;

import java.math.BigInteger;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

/**
 * Utility method for accessing system properties.
 */
public class Properties
{
    private Properties()
    {

    }

    private static final ThreadLocal threadProperties = new ThreadLocal();
                          
    /**
     * Return whether a particular override has been set to true.
     *
     * @param propertyName the property name for the override.
     * @return true if the property is set to "true", false otherwise.
     */
    public static boolean isOverrideSet(String propertyName)
    {
        try
        {
            String p = fetchProperty(propertyName);

            if (p != null)
            {
                return "true".equals(Strings.toLowerCase(p));
            }

            return false;
        }
        catch (AccessControlException e)
        {
            return false;
        }
    }

    /**
     * Enable the specified override property for the current thread only.
     *
     * @param propertyName the property name for the override.
     * @param enable true if the override should be enabled, false if it should be disabled.
     * @return true if the override was already set, false otherwise.
     */
    public static boolean setThreadOverride(String propertyName, boolean enable)
    {
        boolean isSet = isOverrideSet(propertyName);

        Map localProps = (Map)threadProperties.get();
        if (localProps == null)
        {
            localProps = new HashMap();
        }

        localProps.put(propertyName, enable ? "true" : "false");

        threadProperties.set(localProps);

        return isSet;
    }

    /**
     * Enable the specified override property in the current thread only.
     *
     * @param propertyName the property name for the override.
     * @return true if the override set true in thread local, false otherwise.
     */
    public static boolean removeThreadOverride(String propertyName)
    {
        boolean isSet = isOverrideSet(propertyName);

        Map localProps = (Map)threadProperties.get();
        if (localProps == null)
        {
            return false;
        }

        localProps.remove(propertyName);

        if (localProps.isEmpty())
        {
            threadProperties.remove();
        }
        else
        {
            threadProperties.set(localProps);
        }

        return isSet;
    }

    public static BigInteger asBigInteger(String propertyName)
    {
        String p = fetchProperty(propertyName);

        if (p != null)
        {
            return new BigInteger(p);
        }

        return null;
    }

    public static Set<String> asKeySet(String propertyName)
    {
        Set<String> set = new HashSet<String>();

        String p = fetchProperty(propertyName);

        if (p != null)
        {
            StringTokenizer sTok = new StringTokenizer(p, ",");
            while (sTok.hasMoreElements())
            {
                set.add(Strings.toLowerCase(sTok.nextToken()).trim());
            }
        }

        return Collections.unmodifiableSet(set);
    }

    private static String fetchProperty(final String propertyName)
    {
        return (String)AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                Map localProps = (Map)threadProperties.get();
                if (localProps != null)
                {
                    return localProps.get(propertyName);
                }

                return System.getProperty(propertyName);
            }
        });
    }
}
