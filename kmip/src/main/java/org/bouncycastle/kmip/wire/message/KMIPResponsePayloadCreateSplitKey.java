package org.bouncycastle.crypto.threshold.message;

import org.bouncycastle.crypto.threshold.attribute.KMIPUniqueIdentifier;

public class KMIPResponsePayloadCreateSplitKey
    extends KMIPResponsePayload
{
    private KMIPUniqueIdentifier[] uniqueIdentifiers;

    public KMIPResponsePayloadCreateSplitKey(KMIPUniqueIdentifier[] uniqueIdentifiers)
    {
        this.uniqueIdentifiers = uniqueIdentifiers;
    }

    public KMIPUniqueIdentifier[] getUniqueIdentifiers()
    {
        return uniqueIdentifiers;
    }
}
