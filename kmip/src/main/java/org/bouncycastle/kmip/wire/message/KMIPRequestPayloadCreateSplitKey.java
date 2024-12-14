package org.bouncycastle.kmip.wire.message;

import java.util.Map;

import org.bouncycastle.kmip.wire.attribute.KMIPUniqueIdentifier;
import org.bouncycastle.kmip.wire.enumeration.KMIPObjectType;
import org.bouncycastle.kmip.wire.enumeration.KMIPSplitKeyMethod;

/**
 * RequestPayload represents the payload of a request for creating or splitting a key.
 */
public class KMIPRequestPayloadCreateSplitKey
    extends KMIPRequestPayload
{
    // Required fields
    private KMIPObjectType objectType;
    private KMIPUniqueIdentifier uniqueIdentifier; // Optional
    private int splitKeyParts;
    private int splitKeyThreshold;
    private KMIPSplitKeyMethod splitKeyMethod;
    private int primeFieldSize; // Optional
    private Map<String, Object> attributes; // Use an appropriate type for attributes
    private int protectionStorageMasks; // Optional, adjust type as needed

    /**
     * Constructor for RequestPayload with required fields.
     *
     * @param objectType        Determines the type of object to be created.
     * @param splitKeyParts     The total number of parts in the split key.
     * @param splitKeyThreshold The minimum number of parts needed to reconstruct the key.
     * @param splitKeyMethod    The method used for splitting the key.
     * @param attributes        Specifies desired object attributes.
     */
    public KMIPRequestPayloadCreateSplitKey(KMIPObjectType objectType, int splitKeyParts, int splitKeyThreshold,
                                            KMIPSplitKeyMethod splitKeyMethod, Map<String, Object> attributes)
    {
        this.objectType = objectType;
        this.splitKeyParts = splitKeyParts;
        this.splitKeyThreshold = splitKeyThreshold;
        this.splitKeyMethod = splitKeyMethod;
        this.attributes = attributes;
    }

    public KMIPObjectType getObjectType()
    {
        return objectType;
    }

    public void setObjectType(KMIPObjectType objectType)
    {
        this.objectType = objectType;
    }

    public KMIPUniqueIdentifier getUniqueIdentifier()
    {
        return uniqueIdentifier;
    }

    public void setUniqueIdentifier(KMIPUniqueIdentifier uniqueIdentifier)
    {
        this.uniqueIdentifier = uniqueIdentifier;
    }

    public int getSplitKeyParts()
    {
        return splitKeyParts;
    }

    public void setSplitKeyParts(int splitKeyParts)
    {
        this.splitKeyParts = splitKeyParts;
    }

    public int getSplitKeyThreshold()
    {
        return splitKeyThreshold;
    }

    public void setSplitKeyThreshold(int splitKeyThreshold)
    {
        this.splitKeyThreshold = splitKeyThreshold;
    }

    public KMIPSplitKeyMethod getSplitKeyMethod()
    {
        return splitKeyMethod;
    }

    public void setSplitKeyMethod(KMIPSplitKeyMethod splitKeyMethod)
    {
        this.splitKeyMethod = splitKeyMethod;
    }

    public int getPrimeFieldSize()
    {
        return primeFieldSize;
    }

    public void setPrimeFieldSize(int primeFieldSize)
    {
        this.primeFieldSize = primeFieldSize;
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
