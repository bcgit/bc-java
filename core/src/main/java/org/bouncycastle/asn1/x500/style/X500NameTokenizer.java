package org.bouncycastle.asn1.x500.style;

/**
 * class for breaking up an X500 Name into it's component tokens, ala
 * java.util.StringTokenizer. We need this class as some of the
 * lightweight Java environment don't support classes like
 * StringTokenizer.
 */
public class X500NameTokenizer
{
    private final String value;
    private final char separator;

    private int index;

    public X500NameTokenizer(String oid)
    {
        this(oid, ',');
    }

    public X500NameTokenizer(String oid, char separator)
    {
        // TODO Null or empty value should return zero tokens?
        this.value = oid;
        this.index = -1;
        this.separator = separator;
    }

    public boolean hasMoreTokens()
    {
        return index < value.length();
    }

    public String nextToken()
    {
        if (index >= value.length())
        {
            return null;
        }

        boolean quoted = false;
        boolean escaped = false;

        int initialIndex = index;
        while (++index < value.length())
        {
            char c = value.charAt(index);

            if (escaped)
            {
                escaped = false;
            }
            else if (c == '"')
            {
                quoted = !quoted;
            }
            else if (quoted)
            {
            }
            else if (c == '\\')
            {
                escaped = true;
            }
            else if (c == separator)
            {
                break;
            }
        }

        // TODO Error if still escaped or quoted?

        return value.substring(initialIndex + 1, index);
    }
}
