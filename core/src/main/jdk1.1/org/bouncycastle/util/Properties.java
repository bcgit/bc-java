package org.bouncycastle.util;

import java.math.BigInteger;
import java.security.Security;
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

    /**
     * Return whether a particular override has been set to true.
     *
     * @param propertyName the property name for the override.
     * @return true if the property is set to "true", false otherwise.
     */
    public static boolean isOverrideSet(String propertyName)
    {
            String p = getPropertyValue(propertyName);

            return "true".equalsIgnoreCase(p);
    }

    public static BigInteger asBigInteger(String propertyName)
    {
        String p = getPropertyValue(propertyName);

        if (p != null)
        {
            return new BigInteger(p);
        }

        return null;
    }

    public static Set asKeySet(String propertyName)
    {
        Set set = new HashSet();

        String p = getPropertyValue(propertyName);

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

    public static String getPropertyValue(final String propertyName)
    {
        String val = Security.getProperty(propertyName);
        if (val != null)
        {
            return val;
        }

	return System.getProperty(propertyName);
    }

    /**
     * Return whether a particular override has been set to false.
     *
     * @param propertyName the property name for the override.
     * @param isTrue true if the override should be true, false otherwise.
     * @return true if the property is set to the value of isTrue, false otherwise.
     */
    public static boolean isOverrideSetTo(String propertyName, boolean isTrue)
    {
            String propertyValue = getPropertyValue(propertyName);
            if (isTrue)
            {
                return isSetTrue(propertyValue);
            }
            return isSetFalse(propertyValue);
    }

    private static boolean isSetFalse(String p)
    {
        if (p == null || p.length() != 5)
        {
            return false;
        }

        return (p.charAt(0) == 'f' || p.charAt(0) == 'F')
            && (p.charAt(1) == 'a' || p.charAt(1) == 'A')
            && (p.charAt(2) == 'l' || p.charAt(2) == 'L')
            && (p.charAt(3) == 's' || p.charAt(3) == 'S')
            && (p.charAt(4) == 'e' || p.charAt(4) == 'E');
    }

    private static boolean isSetTrue(String p)
    {
        if (p == null || p.length() != 4)
        {
            return false;
        }

        return (p.charAt(0) == 't' || p.charAt(0) == 'T')
            && (p.charAt(1) == 'r' || p.charAt(1) == 'R')
            && (p.charAt(2) == 'u' || p.charAt(2) == 'U')
            && (p.charAt(3) == 'e' || p.charAt(3) == 'E');
    }
}
