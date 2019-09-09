package org.bouncycastle.asn1;

/**
 * Mutable class for building ASN.1 constructed objects such as SETs or SEQUENCEs.
 */
public class ASN1EncodableVector
{
    static final ASN1Encodable[] EMPTY_ELEMENTS = new ASN1Encodable[0];

    private static final int DEFAULT_CAPACITY = 10;

    private ASN1Encodable[] elements;
    private int elementCount;
    private boolean copyOnWrite;

    public ASN1EncodableVector()
    {
        this(DEFAULT_CAPACITY);
    }

    public ASN1EncodableVector(int initialCapacity)
    {
        if (initialCapacity < 0)
        {
            throw new IllegalArgumentException("'initialCapacity' must not be negative");
        }

        this.elements = (initialCapacity == 0) ? EMPTY_ELEMENTS : new ASN1Encodable[initialCapacity];
        this.elementCount = 0;
        this.copyOnWrite = false;
    }

    public void add(ASN1Encodable element)
    {
        if (null == element)
        {
            throw new NullPointerException("'element' cannot be null");
        }

        int capacity = elements.length;
        int minCapacity = elementCount + 1;
        if ((minCapacity > capacity) | copyOnWrite)
        {
            reallocate(minCapacity);
        }

        this.elements[elementCount] = element;
        this.elementCount = minCapacity;
    }

    public void addAll(ASN1EncodableVector other)
    {
        if (null == other)
        {
            throw new NullPointerException("'other' cannot be null");
        }

        int otherElementCount = other.size();
        if (otherElementCount < 1)
        {
            return;
        }

        int capacity = elements.length;
        int minCapacity = elementCount + otherElementCount;
        if ((minCapacity > capacity) | copyOnWrite)
        {
            reallocate(minCapacity);
        }

        int i = 0;
        do
        {
            ASN1Encodable otherElement = other.get(i);
            if (null == otherElement)
            {
                throw new NullPointerException("'other' elements cannot be null");
            }

            this.elements[elementCount + i] = otherElement;
        }
        while (++i < otherElementCount);

        this.elementCount = minCapacity;
    }

    /**
     * Return the object at position i in this vector.
     *
     * @param i the index of the object of interest.
     * @return the object at position i.
     */
    public ASN1Encodable get(int i)
    {
        if (i >= elementCount)
        {
            throw new ArrayIndexOutOfBoundsException(i + " >= " + elementCount);
        }

        return elements[i];
    }

    /**
     * Return the size of the vector.
     *
     * @return the object count in the vector.
     */
    public int size()
    {
        return elementCount;
    }

    ASN1Encodable[] copyElements()
    {
        if (0 == elementCount)
        {
            return EMPTY_ELEMENTS;
        }

        ASN1Encodable[] copy = new ASN1Encodable[elementCount];
        System.arraycopy(elements, 0, copy, 0, elementCount);
        return copy;
    }

    ASN1Encodable[] takeElements()
    {
        if (0 == elementCount)
        {
            return EMPTY_ELEMENTS;
        }

        if (elements.length == elementCount)
        {
            this.copyOnWrite = true;
            return elements;
        }

        ASN1Encodable[] copy = new ASN1Encodable[elementCount];
        System.arraycopy(elements, 0, copy, 0, elementCount);
        return copy;
    }

    private void reallocate(int minCapacity)
    {
        int oldCapacity = elements.length;
        int newCapacity = Math.max(oldCapacity, minCapacity + (minCapacity >> 1));

        ASN1Encodable[] copy = new ASN1Encodable[newCapacity];
        System.arraycopy(elements, 0, copy, 0, elementCount);

        this.elements = copy;
        this.copyOnWrite = false;
    }

    static ASN1Encodable[] cloneElements(ASN1Encodable[] elements)
    {
        ASN1Encodable[] rv = new ASN1Encodable[elements.length];
        System.arraycopy(elements, 0, rv, 0, rv.length);
        return elements.length < 1 ? EMPTY_ELEMENTS : rv;
    }

    public Object clone()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(this.size());

        v.addAll(this);

        return v;
    }
}
