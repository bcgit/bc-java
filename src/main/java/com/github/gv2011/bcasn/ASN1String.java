package com.github.gv2011.bcasn;

/**
 * General interface implemented by ASN.1 STRING objects.
 */
public interface ASN1String
{
    /**
     * Return a Java String representation of this STRING type's content.
     * @return a Java String representation of this STRING.
     */
    public String getString();
}
