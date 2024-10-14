package org.bouncycastle.crypto.split.message;

import org.bouncycastle.crypto.split.KMIPSplitKeyMethod;

/**
 * RequestPayload represents the payload of a request for creating or splitting a key.
 */
public class KMIPRequestPayloadCreateSplitKey
    extends KMIPRequestPayload
{
    // Required fields
    private String objectType;
    private String uniqueIdentifier; // Optional
    private int splitKeyParts;
    private int splitKeyThreshold;
    private KMIPSplitKeyMethod splitKeyMethod;
    private int primeFieldSize; // Optional
    private Object attributes; // Use an appropriate type for attributes
    private Object protectionStorageMasks; // Optional, adjust type as needed

    /**
     * Constructor for RequestPayload with required fields.
     *
     * @param objectType           Determines the type of object to be created.
     * @param splitKeyParts        The total number of parts in the split key.
     * @param splitKeyThreshold    The minimum number of parts needed to reconstruct the key.
     * @param splitKeyMethod       The method used for splitting the key.
     * @param attributes           Specifies desired object attributes.
     */
    public KMIPRequestPayloadCreateSplitKey(String objectType, int splitKeyParts, int splitKeyThreshold,
                          KMIPSplitKeyMethod splitKeyMethod, Object attributes) {
        this.objectType = objectType;
        this.splitKeyParts = splitKeyParts;
        this.splitKeyThreshold = splitKeyThreshold;
        this.splitKeyMethod = splitKeyMethod;
        this.attributes = attributes;
    }

    // Getters and setters

    public String getObjectType() {
        return objectType;
    }

    public void setObjectType(String objectType) {
        this.objectType = objectType;
    }

    public String getUniqueIdentifier() {
        return uniqueIdentifier;
    }

    public void setUniqueIdentifier(String uniqueIdentifier) {
        this.uniqueIdentifier = uniqueIdentifier;
    }

    public int getSplitKeyParts() {
        return splitKeyParts;
    }

    public void setSplitKeyParts(int splitKeyParts) {
        this.splitKeyParts = splitKeyParts;
    }

    public int getSplitKeyThreshold() {
        return splitKeyThreshold;
    }

    public void setSplitKeyThreshold(int splitKeyThreshold) {
        this.splitKeyThreshold = splitKeyThreshold;
    }

    public KMIPSplitKeyMethod getSplitKeyMethod() {
        return splitKeyMethod;
    }

    public void setSplitKeyMethod(KMIPSplitKeyMethod splitKeyMethod) {
        this.splitKeyMethod = splitKeyMethod;
    }

    public int getPrimeFieldSize() {
        return primeFieldSize;
    }

    public void setPrimeFieldSize(int primeFieldSize) {
        this.primeFieldSize = primeFieldSize;
    }

    public Object getAttributes() {
        return attributes;
    }

    public void setAttributes(Object attributes) {
        this.attributes = attributes;
    }

    public Object getProtectionStorageMasks() {
        return protectionStorageMasks;
    }

    public void setProtectionStorageMasks(Object protectionStorageMasks) {
        this.protectionStorageMasks = protectionStorageMasks;
    }
}
