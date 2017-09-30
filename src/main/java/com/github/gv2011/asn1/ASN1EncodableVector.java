package com.github.gv2011.asn1;

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
