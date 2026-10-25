package org.bouncycastle.ldap;

import java.io.ByteArrayOutputStream;

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
     * The escapes of the string form are decoded, so the value is searched for as the directory stores
     * it. An absent attribute, or one with an empty value, results in an empty string.
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
                return filterEncode(decodeValue(subject, eq + 1, valueEnd));
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
     * Decode the attribute value in dn between start and end. The spaces around it, as RFC 1779 puts them
     * around a '+' separator, and the quotes around a quoted value are dropped, while a space that is
     * escaped or quoted stays. A '\' followed by two hex digits is an escaped UTF-8 byte and a '\'
     * followed by any other character is that character (RFC 2253 sec. 2.4, RFC 1779 sec. 2.3). A value
     * in the '#' hex form is returned as it is.
     */
    private static String decodeValue(String dn, int start, int end)
    {
        while (start < end && dn.charAt(start) == ' ')
        {
            start++;
        }
        if (start < end && dn.charAt(start) == '#')
        {
            while (dn.charAt(end - 1) == ' ')
            {
                end--;
            }
            return dn.substring(start, end);
        }

        StringBuilder value = new StringBuilder(end - start);
        ByteArrayOutputStream utf8 = new ByteArrayOutputStream();
        boolean quoted = false;
        int keep = 0;

        for (int i = start; i < end; i++)
        {
            char c = dn.charAt(i);

            if (c == '\\' && i + 2 < end && isHex(dn.charAt(i + 1)) && isHex(dn.charAt(i + 2)))
            {
                utf8.write((Character.digit(dn.charAt(i + 1), 16) << 4) | Character.digit(dn.charAt(i + 2), 16));
                i += 2;
                continue;
            }

            keep = appendUTF8(utf8, value, keep);

            if (c == '\\' && i + 1 < end)
            {
                value.append(dn.charAt(++i));
                keep = value.length();
            }
            else if (c == '"')
            {
                quoted = !quoted;
            }
            else
            {
                value.append(c);
                if (c != ' ' || quoted)
                {
                    keep = value.length();
                }
            }
        }

        keep = appendUTF8(utf8, value, keep);
        value.setLength(keep);

        return value.toString();
    }

    /**
     * Append any escaped bytes collected in utf8 to value as UTF-8, or byte by byte if they are not valid
     * UTF-8, returning the length of value to keep.
     */
    private static int appendUTF8(ByteArrayOutputStream utf8, StringBuilder value, int keep)
    {
        if (utf8.size() == 0)
        {
            return keep;
        }

        byte[] bytes = utf8.toByteArray();
        utf8.reset();
        try
        {
            value.append(Strings.fromUTF8ByteArray(bytes));
        }
        catch (IllegalArgumentException e)
        {
            for (int i = 0; i < bytes.length; i++)
            {
                value.append((char)(bytes[i] & 0xff));
            }
        }

        return value.length();
    }

    private static boolean isHex(char c)
    {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
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
