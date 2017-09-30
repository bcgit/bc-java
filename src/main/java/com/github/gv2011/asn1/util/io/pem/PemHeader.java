package com.github.gv2011.asn1.util.io.pem;

/**
 * Class representing a PEM header (name, value) pair.
 */
public class PemHeader
{
    private final String name;
    private final String value;

    /**
     * Base constructor.
     *
     * @param name name of the header property.
     * @param value value of the header property.
     */
    public PemHeader(final String name, final String value)
    {
        this.name = name;
        this.value = value;
    }

    public String getName()
    {
        return name;
    }

    public String getValue()
    {
        return value;
    }

    @Override
    public int hashCode()
    {
        return getHashCode(name) + 31 * getHashCode(value);
    }

    @Override
    public boolean equals(final Object o)
    {
        if (!(o instanceof PemHeader))
        {
            return false;
        }

        final PemHeader other = (PemHeader)o;

        return other == this || (isEqual(name, other.name) && isEqual(value, other.value));
    }

    private int getHashCode(final String s)
    {
        if (s == null)
        {
            return 1;
        }

        return s.hashCode();
    }

    private boolean isEqual(final String s1, final String s2)
    {
        if (s1 == s2)
        {
            return true;
        }

        if (s1 == null || s2 == null)
        {
            return false;
        }

        return s1.equals(s2);
    }

}
