package org.bouncycastle.asn1;

/**
 * Marker class for extracting String from ASN.1 STRING objects.
 */

public interface ASN1String
{
    /**
     * Get String value of the ASN.1 STRING object.
     */
    public String getString();
}
