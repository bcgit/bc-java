package org.bouncycastle.crypto.threshold.message;

import org.bouncycastle.crypto.threshold.attribute.KMIPUniqueIdentifier;

public class KMIPResponsePayloadDefault
    extends KMIPResponsePayload
{
    protected KMIPUniqueIdentifier uniqueIdentifier;

    public KMIPResponsePayloadDefault(KMIPUniqueIdentifier uniqueIdentifiers)
    {
        this.uniqueIdentifier = uniqueIdentifiers;
    }

    public KMIPUniqueIdentifier getUniqueIdentifiers()
    {
        return uniqueIdentifier;
    }
}
