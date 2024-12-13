package org.bouncycastle.kmip.wire.message;

import org.bouncycastle.kmip.wire.attribute.KMIPUniqueIdentifier;
import org.bouncycastle.kmip.wire.enumeration.KMIPObjectType;

public class KMIPResponsePayloadCreate
    extends KMIPResponsePayload
{
    private KMIPObjectType objectType;        // Type of object created (e.g., symmetric key, secret data)
    private KMIPUniqueIdentifier uniqueIdentifier;  // The Unique Identifier of the newly created object

    /**
     * Constructor for ResponsePayload.
     *
     * @param objectType       The type of object created.
     * @param uniqueIdentifier The unique identifier of the newly created object.
     */
    public KMIPResponsePayloadCreate(KMIPObjectType objectType, KMIPUniqueIdentifier uniqueIdentifier)
    {
        this.objectType = objectType;
        this.uniqueIdentifier = uniqueIdentifier;
    }

    /**
     * Get the type of the created object.
     *
     * @return The object type as a String.
     */
    public KMIPObjectType getObjectType()
    {
        return objectType;
    }

    /**
     * Set the type of the created object.
     *
     * @param objectType The object type to set.
     */
    public void setObjectType(KMIPObjectType objectType)
    {
        this.objectType = objectType;
    }

    /**
     * Get the unique identifier of the newly created object.
     *
     * @return The unique identifier as a String.
     */
    public KMIPUniqueIdentifier getUniqueIdentifier()
    {
        return uniqueIdentifier;
    }

    /**
     * Set the unique identifier of the newly created object.
     *
     * @param uniqueIdentifier The unique identifier to set.
     */
    public void setUniqueIdentifier(KMIPUniqueIdentifier uniqueIdentifier)
    {
        this.uniqueIdentifier = uniqueIdentifier;
    }
}
