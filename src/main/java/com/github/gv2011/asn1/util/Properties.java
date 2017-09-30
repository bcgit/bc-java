package com.github.gv2011.asn1.util;

import java.security.AccessControlException;
import java.security.AccessController;
import java.security.PrivilegedAction;

/**
 * Utility method for accessing system properties.
 */
public class Properties
{
    public static boolean isOverrideSet(final String propertyName)
    {
        try
        {
            return "true".equals(AccessController.doPrivileged((PrivilegedAction<?>) () -> {
                final String value = System.getProperty(propertyName);
                if (value == null)
                {
                    return null;
                }

                return Strings.toLowerCase(value);
            }));
        }
        catch (final AccessControlException e)
        {
            return false;
        }
    }
}
