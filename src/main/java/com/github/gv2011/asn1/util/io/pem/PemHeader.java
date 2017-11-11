package com.github.gv2011.asn1.util.io.pem;

/*-
 * #%L
 * Vinz ASN.1
 * %%
 * Copyright (C) 2016 - 2017 Vinz (https://github.com/gv2011)
 * %%
 * Please note this should be read in the same way as the MIT license. (https://www.bouncycastle.org/licence.html)
 * 
 * Copyright (c) 2000-2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
 * and associated documentation files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 * #L%
 */


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
