package org.bouncycastle.jsse.provider;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Settings can either be in java.security or set as system properties.
 * Settings provided in java.security will override system properties.
 */
class PropertyUtils
{
    private static final Logger LOG = Logger.getLogger(PropertyUtils.class.getName());

    static String getSecurityProperty(final String propertyName)
    {
        return AccessController.doPrivileged(new PrivilegedAction<String>()
        {
            public String run()
            {
                return Security.getProperty(propertyName);
            }
        });
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

    static boolean getBooleanSecurityProperty(String propertyName, boolean defaultValue)
    {
        String propertyValue = getSecurityProperty(propertyName);
        if (null != propertyValue)
        {
            if ("true".equalsIgnoreCase(propertyValue))
            {
                LOG.log(Level.INFO, "Found boolean security property [" + propertyName + "]: " + true);
                return true;
            }
            if ("false".equalsIgnoreCase(propertyValue))
            {
                LOG.log(Level.INFO, "Found boolean security property [" + propertyName + "]: " + false);
                return false;
            }
            LOG.log(Level.WARNING, "Unrecognized value for boolean security property [" + propertyName + "]: " + propertyValue);
        }
        LOG.log(Level.FINE, "Boolean security property [" + propertyName + "] defaulted to: " + defaultValue);
        return defaultValue;
    }

    static boolean getBooleanSystemProperty(String propertyName, boolean defaultValue)
    {
        String propertyValue = getSystemProperty(propertyName);
        if (null != propertyValue)
        {
            if ("true".equalsIgnoreCase(propertyValue))
            {
                LOG.log(Level.INFO, "Found boolean system property [" + propertyName + "]: " + true);
                return true;
            }
            if ("false".equalsIgnoreCase(propertyValue))
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

    static String getStringSecurityProperty(String propertyName, String defaultValue)
    {
        String propertyValue = getSecurityProperty(propertyName);
        if (null != propertyValue)
        {
            LOG.log(Level.INFO, "Found string security property [" + propertyName + "]: " + propertyValue);
            return propertyValue;
        }
        LOG.log(Level.WARNING, "String security property [" + propertyName + "] defaulted to: " + defaultValue);
        return defaultValue;
    }

    static String getStringSystemProperty(String propertyName)
    {
        String propertyValue = getSystemProperty(propertyName);
        if (null != propertyValue)
        {
            LOG.log(Level.INFO, "Found string system property [" + propertyName + "]: " + propertyValue);
            return propertyValue;
        }
        return null;
    }

    static String[] getStringArraySecurityProperty(String propertyName, String defaultValue)
    {
        String propertyValue = getStringSecurityProperty(propertyName, defaultValue);

        return parseStringArray(propertyValue);
    }

    static String[] getStringArraySystemProperty(String propertyName)
    {
        String propertyValue = getStringSystemProperty(propertyName);

        return parseStringArray(propertyValue);
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

    private static String[] parseStringArray(String propertyValue)
    {
        if (null == propertyValue)
        {
            return null;
        }

        String[] entries = JsseUtils.stripDoubleQuotes(propertyValue.trim()).split(",");
        String[] result = new String[entries.length];
        int count = 0;
        for (String entry : entries)
        {
            entry = entry.trim();
            if (entry.length() < 1)
            {
                continue;
            }

            result[count++] = entry;
        }
        return JsseUtils.resize(result, count);
    }
}
