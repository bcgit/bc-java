package org.bouncycastle.jsse.provider;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;

import org.bouncycastle.util.Strings;

/**
 * Settings can either be in java.security or set as system properties.
 * Settings provided in java.security will override system properties.
 */
class PropertyUtils
{
    static String getSetting(final String propertyName)
    {
        return AccessController.doPrivileged(new PrivilegedAction<String>()
        {
            public String run()
            {
                String value = Security.getProperty(propertyName);
                if (value != null)
                {
                    return value;
                }

                return System.getProperty(propertyName);
            }
        });
    }

    static String getSetting(final String propertyName, final String unsetValue)
    {
        String value = getSetting(propertyName);

        if (value == null)
        {
            return unsetValue;
        }

        return value;
    }

    static String getSettingLowerCase(final String propertyName)
    {
        String value = getSetting(propertyName);
        if (value != null)
        {
            return Strings.toLowerCase(value);
        }

        return null;
    }

    static String getSettingLowerCase(final String propertyName, String unsetValue)
    {
        String value = getSetting(propertyName, unsetValue);
        if (value != null)
        {
            return Strings.toLowerCase(value);
        }

        return null;
    }

    static String getSystemProperty(final String propertyName)
    {
        return AccessController.doPrivileged(new PrivilegedAction<String>()
        {
            public String run()
            {
                return System.getProperty(propertyName);
            }
        });
    }
}
