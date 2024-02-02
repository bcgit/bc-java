package org.bouncycastle.its;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.oer.its.ieee1609dot2.IssuerIdentifier;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;
import org.bouncycastle.util.Arrays;

class ITSUtil
{
    static IssuerIdentifier getIssuerIdentifier(ASN1ObjectIdentifier digestAlg, byte[] parentDigest)
    {
        HashedId8 hashedID = new HashedId8(Arrays.copyOfRange(parentDigest, parentDigest.length - 8, parentDigest.length));
        IssuerIdentifier issuerIdentifier;
        if (digestAlg.equals(NISTObjectIdentifiers.id_sha256))
        {
            issuerIdentifier = IssuerIdentifier.sha256AndDigest(hashedID);
        }
        else if (digestAlg.equals(NISTObjectIdentifiers.id_sha384))
        {
            issuerIdentifier = IssuerIdentifier.sha384AndDigest(hashedID);
        }
        else
        {
            throw new IllegalStateException("unknown digest");
        }
        return issuerIdentifier;
    }
}
