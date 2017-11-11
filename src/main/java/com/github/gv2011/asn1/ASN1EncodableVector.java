package com.github.gv2011.asn1;

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


import java.util.Enumeration;
import java.util.Vector;

/**
 * Mutable class for building ASN.1 constructed objects.
 */
@SuppressWarnings("rawtypes")
public class ASN1EncodableVector
{
    private final Vector v = new Vector();

    /**
     * Base constructor.
     */
    public ASN1EncodableVector()
    {
    }

    /**
     * Add an encodable to the vector.
     *
     * @param obj the encodable to add.
     */
    @SuppressWarnings("unchecked")
    public void add(final ASN1Encodable obj)
    {
        v.addElement(obj);
    }

    /**
     * Add the contents of another vector.
     *
     * @param other the vector to add.
     */
    @SuppressWarnings("unchecked")
    public void addAll(final ASN1EncodableVector other)
    {
        for (final Enumeration en = other.v.elements(); en.hasMoreElements();)
        {
            v.addElement(en.nextElement());
        }
    }

    /**
     * Return the object at position i in this vector.
     *
     * @param i the index of the object of interest.
     * @return the object at position i.
     */
    public ASN1Encodable get(final int i)
    {
        return (ASN1Encodable)v.elementAt(i);
    }

    /**
     * Return the size of the vector.
     *
     * @return the object count in the vector.
     */
    public int size()
    {
        return v.size();
    }
}
