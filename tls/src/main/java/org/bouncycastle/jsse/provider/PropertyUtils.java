package org.bouncycastle.jsse.provider;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.util.Strings;

/**
 * Settings can either be in java.security or set as system properties.
 * Settings provided in java.security will override system properties.
 */
class PropertyUtils
{
    private static Logger LOG = Logger.getLogger(PropertyUtils.class.getName());

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
        try
        {
            return AccessController.doPrivileged(new PrivilegedAction<String>()
            {
                public String run()
                {
                    return System.getProperty(propertyName);
                }
            });
        }
        catch (RuntimeException e)
        {
            LOG.log(Level.WARNING, "Failed to get system property", e);
            return null;
        }
    }

    static boolean getBooleanSystemProperty(String propertyName, boolean defaultValue)
    {
        String propertyValue = getSystemProperty(propertyName);
        if (null != propertyValue)
        {
            if ("true".equals(propertyValue))
            {
                LOG.log(Level.INFO, "Found boolean system property [" + propertyName + "]: " + true);
                return true;
            }
            if ("false".equals(propertyValue))
            {
                LOG.log(Level.INFO, "Found boolean system property [" + propertyName + "]: " + false);
                return false;
            }
            LOG.log(Level.WARNING, "Unrecognized value for boolean system property [" + propertyName + "]: " + propertyValue);
        }
        LOG.log(Level.FINE, "Boolean system property [" + propertyName + "] defaulted to: " + defaultValue);
        return defaultValue;
    }

    static int getIntegerSystemProperty(String propertyName, int defaultValue, int minimumValue, int maximumValue)
    {
        String propertyValue = getSystemProperty(propertyName);
        if (null != propertyValue)
        {
            try
            {
                 int parsedValue = Integer.parseInt(propertyValue);
                 if (parsedValue >= minimumValue && parsedValue <= maximumValue)
                 {
                     LOG.log(Level. INFO, "Found integer system property [" + propertyName + "]: " + parsedValue);
                     return parsedValue;
                 }
                 if (LOG.isLoggable(Level.WARNING))
                 {
                     String range = getRangeString(minimumValue, maximumValue);
                     LOG.log(Level.WARNING, "Out-of-range (" + range + ") integer system property [" + propertyName + "]: " + propertyValue);
                 }
            }
            catch (Exception e)
            {
                LOG.log(Level.WARNING, "Unrecognized value for integer system property [" + propertyName + "]: " + propertyValue);
            }
        }
        LOG.log(Level.FINE, "Integer system property [" + propertyName + "] defaulted to: " + defaultValue);
        return defaultValue;
    }

    static String getStringSystemProperty(String propertyName)
    {
        String propertyValue = getSystemProperty(propertyName);
        if (null != propertyValue)
        {
            LOG.log(Level. INFO, "Found string system property [" + propertyName + "]: " + propertyValue);
            return propertyValue;
        }
        return null;
    }

    private static String getRangeString(int minimumValue, int maximumValue)
    {
        StringBuilder sb = new StringBuilder(32);
        if (Integer.MIN_VALUE != minimumValue)
        {
            sb.append(minimumValue);
            sb.append(" <= ");
        }
        sb.append('x');
        if (Integer.MAX_VALUE != maximumValue)
        {
            sb.append(" <= ");
            sb.append(maximumValue);
        }
        return sb.toString();
    }
}
