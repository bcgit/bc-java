package org.bouncycastle.kmip.wire.message;

import java.util.Map;

import org.bouncycastle.kmip.wire.enumeration.KMIPObjectType;

public class KMIPRequestPayloadCreate
    extends KMIPRequestPayload
{
    private KMIPObjectType KMIPObjectType;       // Type of object to be created (SymmetricKey, SecretData, etc.)
    private Map<String, Object> attributes;  // List of attributes for the object (e.g., Algorithm, Length)
    private int protectionStorageMask;  // Optional field for permissible storage masks

    /**
     * Constructor to create the CreateRequestPayload with the required fields.
     *
     * @param KMIPObjectType The type of object to be created.
     * @param attributes     A list of attributes to be associated with the object.
     */
    public KMIPRequestPayloadCreate(KMIPObjectType KMIPObjectType, Map<String, Object> attributes)
    {
        this.KMIPObjectType = KMIPObjectType;
        this.attributes = attributes;
    }

    /**
     * Constructor to create the CreateRequestPayload with the optional protection storage mask.
     *
     * @param KMIPObjectType        The type of object to be created.
     * @param attributes            A list of attributes to be associated with the object.
     * @param protectionStorageMask Optional field specifying permissible storage mask selections.
     */
    public KMIPRequestPayloadCreate(KMIPObjectType KMIPObjectType, Map<String, Object> attributes, int protectionStorageMask)
    {
        this.KMIPObjectType = KMIPObjectType;
        this.attributes = attributes;
        this.protectionStorageMask = protectionStorageMask;
    }

    public KMIPObjectType getKMIPObjectType()
    {
        return KMIPObjectType;
    }

    public void setKMIPObjectType(KMIPObjectType KMIPObjectType)
    {
        this.KMIPObjectType = KMIPObjectType;
    }

    public Map<String, Object> getAttributes()
    {
        return attributes;
    }

    public void setAttributes(Map<String, Object> attributes)
    {
        this.attributes = attributes;
    }

    public int getProtectionStorageMask()
    {
        return protectionStorageMask;
    }

    public void setProtectionStorageMask(int protectionStorageMask)
    {
        this.protectionStorageMask = protectionStorageMask;
    }
}
