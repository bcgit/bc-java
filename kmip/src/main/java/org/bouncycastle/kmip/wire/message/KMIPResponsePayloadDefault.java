package org.bouncycastle.kmip.wire.message;

import org.bouncycastle.kmip.wire.attribute.KMIPUniqueIdentifier;

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
