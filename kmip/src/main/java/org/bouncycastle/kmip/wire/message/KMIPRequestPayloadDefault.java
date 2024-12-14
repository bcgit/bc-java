package org.bouncycastle.kmip.wire.message;

import org.bouncycastle.kmip.wire.attribute.KMIPUniqueIdentifier;

public class KMIPRequestPayloadDefault
    extends KMIPRequestPayload
{
    protected KMIPUniqueIdentifier uniqueIdentifier;

    public KMIPRequestPayloadDefault()
    {
    }

    public void setUniqueIdentifier(KMIPUniqueIdentifier uniqueIdentifier)
    {
        this.uniqueIdentifier = uniqueIdentifier;
    }

    public KMIPUniqueIdentifier getUniqueIdentifiers()
    {
        return uniqueIdentifier;
    }
}
