package org.bouncycastle.ldap;

import org.bouncycastle.util.Strings;

/**
 * General utility methods for assisting with preparation of LDAP queries.
 */
public class LDAPUtils
{
    private static String[] FILTER_ESCAPE_TABLE = new String['\\' + 1];

    static
    {
        // Filter encoding table -------------------------------------

        // fill with char itself
        for (char c = 0; c < FILTER_ESCAPE_TABLE.length; c++)
        {
            FILTER_ESCAPE_TABLE[c] = String.valueOf(c);
        }

        // escapes (RFC2254)
        FILTER_ESCAPE_TABLE['*'] = "\\2a";
        FILTER_ESCAPE_TABLE['('] = "\\28";
        FILTER_ESCAPE_TABLE[')'] = "\\29";
        FILTER_ESCAPE_TABLE['\\'] = "\\5c";
        FILTER_ESCAPE_TABLE[0] = "\\00";
    }

    /**
     * Parse out the contents of a particular subject attribute name from the string form of an X.500 DN.
     *
     * @param subject string form of an X.500 DN.
     * @param subjectAttributeName the RDN attribute name of interest.
     * @return an escaped string suitable for use in an LDAP query.
     */
    public static String parseDN(String subject, String subjectAttributeName)
    {
        String temp = subject;
        int begin = Strings.toLowerCase(temp).indexOf(Strings.toLowerCase(subjectAttributeName));
        if (begin == -1)
        {
            return "";
        }
        temp = temp.substring(begin + subjectAttributeName.length());
        int end = temp.indexOf(',');
        if (end == -1)
        {
            end = temp.length();
        }
        while (temp.charAt(end - 1) == '\\')
        {
            end = temp.indexOf(',', end + 1);
            if (end == -1)
            {
                end = temp.length();
            }
        }
        temp = temp.substring(0, end);
        begin = temp.indexOf('=');
        temp = temp.substring(begin + 1);
        if (temp.charAt(0) == ' ')
        {
            temp = temp.substring(1);
        }
        if (temp.startsWith("\""))
        {
            temp = temp.substring(1);
        }
        if (temp.endsWith("\""))
        {
            temp = temp.substring(0, temp.length() - 1);
        }
        return filterEncode(temp);
    }

    /**
     * Escape a value for use in a filter.
     *
     * @param value the value to escape.
     * @return a properly escaped representation of the supplied value.
     */
    private static String filterEncode(String value)
    {
        if (value == null)
        {
            return null;
        }

        // make buffer roomy
        StringBuilder encodedValue = new StringBuilder(value.length() * 2);

        int length = value.length();

        for (int i = 0; i < length; i++)
        {
            char c = value.charAt(i);

            if (c < FILTER_ESCAPE_TABLE.length)
            {
                encodedValue.append(FILTER_ESCAPE_TABLE[c]);
            }
            else
            {
                // default: add the char
                encodedValue.append(c);
            }
        }

        return encodedValue.toString();
    }
}
