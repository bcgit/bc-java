package org.bouncycastle.kmip.wire.message;

import java.util.Map;

import org.bouncycastle.kmip.wire.enumeration.KMIPObjectType;
import org.bouncycastle.kmip.wire.object.KMIPObject;

public class KMIPRequestPayloadRegister
    extends KMIPRequestPayload
{
    /**
     * Determines the type of object being registered.
     */
    private KMIPObjectType objectType;

    /**
     * Specifies desired object attributes to be associated with the new object.
     */
    private Map<String, Object> attributes;

    /**
     * The object being registered. The object and attributes MAY be wrapped.
     */
    private KMIPObject object;

    /**
     * Specifies all permissible Protection Storage Mask selections for the new object
     */
    private int protectionStorageMasks;

    public KMIPRequestPayloadRegister(KMIPObjectType objectType, Map<String, Object> attributes, KMIPObject object)
    {
        this.objectType = objectType;
        this.attributes = attributes;
        this.object = object;
    }

    public KMIPObjectType getObjectType()
    {
        return objectType;
    }

    public void setObjectType(KMIPObjectType objectType)
    {
        this.objectType = objectType;
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

    public void setObject(KMIPObject object)
    {
        this.object = object;
    }

    public KMIPObject getObject()
    {
        return object;
    }

    public void setProtectionStorageMasks(int protectionStorageMasks)
    {
        this.protectionStorageMasks = protectionStorageMasks;
    }
}
