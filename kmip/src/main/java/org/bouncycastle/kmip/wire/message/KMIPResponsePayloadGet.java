package org.bouncycastle.kmip.wire.message;

import org.bouncycastle.kmip.wire.attribute.KMIPUniqueIdentifier;
import org.bouncycastle.kmip.wire.enumeration.KMIPObjectType;
import org.bouncycastle.kmip.wire.object.KMIPObject;

public class KMIPResponsePayloadGet
    extends KMIPResponsePayloadDefault
{

    // Required Object Type.
    private KMIPObjectType objectType;

    // Required Object being returned.
    private KMIPObject object;  // Can be of any type (Key, Certificate, Secret Data, etc.).

    // Constructor
    public KMIPResponsePayloadGet(KMIPObjectType objectType, KMIPUniqueIdentifier uniqueIdentifier, KMIPObject object)
    {
        super(uniqueIdentifier);
        this.objectType = objectType;
        this.object = object;
    }

    // Getters and Setters
    public KMIPObjectType getObjectType()
    {
        return objectType;
    }

    public void setObjectType(KMIPObjectType objectType)
    {
        this.objectType = objectType;
    }

    public KMIPObject getObject()
    {
        return object;
    }

    public void setObject(KMIPObject object)
    {
        this.object = object;
    }
}
