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
        if (oid == null)
        {
            throw new NullPointerException();
        }
        if (separator == '"' || separator == '\\')
        {
            throw new IllegalArgumentException("reserved separator character");
        }

        this.value = oid;
        this.separator = separator;
        this.index = oid.length() < 1 ? 0 : -1;
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

        int beginIndex = index + 1;
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
                return value.substring(beginIndex, index);
            }
        }

        if (escaped || quoted)
        {
            throw new IllegalArgumentException("badly formatted directory string");
        }

        return value.substring(beginIndex, index);
    }
}
