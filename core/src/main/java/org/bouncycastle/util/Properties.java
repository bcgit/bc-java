package org.bouncycastle.util;

import java.security.AccessControlException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Utility method for accessing system properties.
 */
public class Properties
{
    public static boolean isOverrideSet(final String propertyName)
    {
        try
        {
            return "true".equals(AccessController.doPrivileged(new PrivilegedAction()
            {
                // JDK 1.4 compatibility
                public Object run()
                {
                    String value = System.getProperty(propertyName);
                    if (value == null)
                    {
                        return null;
                    }

                    return Strings.toLowerCase(value);
                }
            }));
        }
        catch (AccessControlException e)
        {
            return false;
        }
    }

    public static Set<String> asKeySet(final String propertyName)
    {
        String[] p = System.getProperty(propertyName, "").split(",");
        HashSet<String> set = new HashSet<String>();
        for (String j : p)
        {
            set.add(Strings.toLowerCase(j).trim());
        }
        return Collections.unmodifiableSet(set);
    }

}
