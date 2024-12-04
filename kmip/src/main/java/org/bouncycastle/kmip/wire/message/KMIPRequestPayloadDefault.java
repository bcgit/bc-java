package org.bouncycastle.crypto.threshold.message;

import org.bouncycastle.crypto.threshold.attribute.KMIPUniqueIdentifier;

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
