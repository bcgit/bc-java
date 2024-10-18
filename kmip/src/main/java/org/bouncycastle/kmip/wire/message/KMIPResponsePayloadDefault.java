package org.bouncycastle.crypto.split.message;

import org.bouncycastle.crypto.split.attribute.KMIPUniqueIdentifier;

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
