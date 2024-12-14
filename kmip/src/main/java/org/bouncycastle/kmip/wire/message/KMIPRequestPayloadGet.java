package org.bouncycastle.kmip.wire.message;

import org.bouncycastle.kmip.wire.attribute.KMIPUniqueIdentifier;
import org.bouncycastle.kmip.wire.enumeration.KMIPKeyCompressionType;
import org.bouncycastle.kmip.wire.enumeration.KMIPKeyFormatType;
import org.bouncycastle.kmip.wire.enumeration.KMIPKeyWrapType;

/**
 * Represents a Get Request Payload for requesting a managed object from the server.
 * The client specifies the Unique Identifier and various key formats if necessary.
 */
public class KMIPRequestPayloadGet
    extends KMIPRequestPayload
{

    /**
     * Determines the object being requested. If omitted, then the ID Placeholder value is used by the server as the Unique Identifier.
     * */
    private KMIPUniqueIdentifier uniqueIdentifier;

    // Optional Key Format Type.
    private KMIPKeyFormatType keyFormatType;

    // Optional Key Wrap Type.
    private KMIPKeyWrapType keyWrapType;

    // Optional Key Compression Type (for elliptic curve public keys).
    private KMIPKeyCompressionType keyCompressionType;

    // Optional Key Wrapping Specification.
    private String keyWrappingSpecification;

    public KMIPRequestPayloadGet()
    {
    }

    // Getters and Setters
    public KMIPUniqueIdentifier getUniqueIdentifier()
    {
        return uniqueIdentifier;
    }

    public void setUniqueIdentifier(KMIPUniqueIdentifier uniqueIdentifier)
    {
        this.uniqueIdentifier = uniqueIdentifier;
    }

    public KMIPKeyFormatType getKeyFormatType()
    {
        return keyFormatType;
    }

    public void setKeyFormatType(KMIPKeyFormatType keyFormatType)
    {
        this.keyFormatType = keyFormatType;
    }

    public KMIPKeyWrapType getKeyWrapType()
    {
        return keyWrapType;
    }

    public void setKeyWrapType(KMIPKeyWrapType keyWrapType)
    {
        this.keyWrapType = keyWrapType;
    }

    public KMIPKeyCompressionType getKeyCompressionType()
    {
        return keyCompressionType;
    }

    public void setKeyCompressionType(KMIPKeyCompressionType keyCompressionType)
    {
        this.keyCompressionType = keyCompressionType;
    }

    public String getKeyWrappingSpecification()
    {
        return keyWrappingSpecification;
    }

    public void setKeyWrappingSpecification(String keyWrappingSpecification)
    {
        this.keyWrappingSpecification = keyWrappingSpecification;
    }
}
