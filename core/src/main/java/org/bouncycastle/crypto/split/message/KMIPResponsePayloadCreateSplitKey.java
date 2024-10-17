package org.bouncycastle.crypto.split.message;

import org.bouncycastle.crypto.split.attribute.KMIPUniqueIdentifier;

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
