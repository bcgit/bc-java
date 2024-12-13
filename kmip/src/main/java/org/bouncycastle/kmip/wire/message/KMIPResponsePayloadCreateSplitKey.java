package org.bouncycastle.kmip.wire.message;

import org.bouncycastle.kmip.wire.attribute.KMIPUniqueIdentifier;

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
