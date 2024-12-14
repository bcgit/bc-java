package org.bouncycastle.kmip.wire.message;

import java.util.Map;

import org.bouncycastle.kmip.wire.attribute.KMIPUniqueIdentifier;
import org.bouncycastle.kmip.wire.enumeration.KMIPObjectType;
import org.bouncycastle.kmip.wire.enumeration.KMIPSecretDataType;

/**
 * Request payload for the Join Split Key operation.
 * This operation requests the server to combine a list of Split Keys into a single Managed Cryptographic Object.
 */
public class KMIPRequestPayloadJoinSplitKey
    extends KMIPRequestPayload
{

    // Required field to specify the type of object to be created.
    private KMIPObjectType objectType;

    // Required field that may repeat to determine the Split Keys to combine.
    private KMIPUniqueIdentifier[] uniqueIdentifiers;

    // Optional field to specify the secret data type if applicable.
    private KMIPSecretDataType secretDataType;

    // Optional field to specify desired object attributes.
    private Map<String, Object> attributes;

    // Optional field to specify permissible protection storage masks.
    private int protectionStorageMasks;

    // Constructor
    public KMIPRequestPayloadJoinSplitKey(KMIPObjectType objectType, KMIPUniqueIdentifier[] uniqueIdentifiers)
    {
        this.objectType = objectType;
        this.uniqueIdentifiers = uniqueIdentifiers;
    }

    public KMIPObjectType getObjectType()
    {
        return objectType;
    }

    public void setObjectType(KMIPObjectType objectType)
    {
        this.objectType = objectType;
    }

    public KMIPUniqueIdentifier[] getUniqueIdentifiers()
    {
        return uniqueIdentifiers;
    }

    public void setUniqueIdentifiers(KMIPUniqueIdentifier[] uniqueIdentifiers)
    {
        this.uniqueIdentifiers = uniqueIdentifiers;
    }

    public KMIPSecretDataType getSecretDataType()
    {
        return secretDataType;
    }

    public void setSecretDataType(KMIPSecretDataType secretDataType)
    {
        this.secretDataType = secretDataType;
    }

    public Map<String, Object> getAttributes()
    {
        return attributes;
    }

    public void setAttributes(Map<String, Object> attributes)
    {
        this.attributes = attributes;
    }

    public int getProtectionStorageMasks()
    {
        return protectionStorageMasks;
    }

    public void setProtectionStorageMasks(int protectionStorageMasks)
    {
        this.protectionStorageMasks = protectionStorageMasks;
    }
}

