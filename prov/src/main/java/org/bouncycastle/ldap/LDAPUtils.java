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
     * <p>
     * The attribute is only recognised as the type of an RDN component, that is as "name=" at the start
     * of the DN or after an unescaped ',' or '+' separator, never inside another attribute's value. The
     * value runs to the next unescaped separator outside a quoted string, without the spaces around it
     * or the quotes around a quoted value, so both the RFC 2253 and the RFC 1779 string forms are read.
     * An absent attribute, or one with an empty value, results in an empty string.
     * </p>
     *
     * @param subject string form of an X.500 DN.
     * @param subjectAttributeName the RDN attribute name of interest.
     * @return an escaped string suitable for use in an LDAP query.
     */
    public static String parseDN(String subject, String subjectAttributeName)
    {
        String name = Strings.toLowerCase(subjectAttributeName.trim());
        int length = subject.length();
        int pos = 0;

        while (pos < length)
        {
            int valueEnd = findValueEnd(subject, pos);
            int eq = subject.indexOf('=', pos);
            if (eq >= 0 && eq < valueEnd
                && Strings.toLowerCase(subject.substring(pos, eq).trim()).equals(name))
            {
                return filterEncode(trimValue(subject.substring(eq + 1, valueEnd)));
            }
            pos = valueEnd + 1;
        }

        return "";
    }

    /**
     * Return the index of the unescaped ',' or '+' ending the RDN component starting at start, ignoring
     * separators inside a quoted value, or the length of dn if the component is the last one.
     */
    private static int findValueEnd(String dn, int start)
    {
        boolean quoted = false;
        int length = dn.length();

        for (int i = start; i < length; i++)
        {
            char c = dn.charAt(i);

            if (c == '\\')
            {
                i++;
            }
            else if (c == '"')
            {
                quoted = !quoted;
            }
            else if (!quoted && (c == ',' || c == '+'))
            {
                return i;
            }
        }

        return length;
    }

    /**
     * Strip the spaces around an attribute value, as RFC 1779 puts them around a '+' separator, and the
     * quotes around a quoted value. A trailing space escaped with a '\' is part of the value and stays.
     */
    private static String trimValue(String value)
    {
        int start = 0;
        int end = value.length();

        while (start < end && value.charAt(start) == ' ')
        {
            start++;
        }
        while (end > start && value.charAt(end - 1) == ' '
            && (end - 1 == start || value.charAt(end - 2) != '\\'))
        {
            end--;
        }

        String temp = value.substring(start, end);
        if (temp.startsWith("\""))
        {
            temp = temp.substring(1);
        }
        if (temp.endsWith("\""))
        {
            temp = temp.substring(0, temp.length() - 1);
        }
        return temp;
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
