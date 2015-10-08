package org.bouncycastle.util;

/**
 * Utility method for accessing system properties.
 */
public class Properties
{
    public static boolean isOverrideSet(final String propertyName)
    {
	    String value = System.getProperty(propertyName);
	    if (value == null)
	    {
		return false;
	    }

	    return "true".equals(Strings.toLowerCase(value));
    }
}
