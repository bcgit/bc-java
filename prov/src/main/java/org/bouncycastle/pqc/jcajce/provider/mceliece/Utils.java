package org.bouncycastle.pqc.jcajce.provider.mceliece;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

class Utils
{
    static AlgorithmIdentifier getDigAlgId(String digestName)
    {
        return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
    }

    static Digest getDigest(AlgorithmIdentifier digest)
    {
        if (digest.getAlgorithm().equals(OIWObjectIdentifiers.idSHA1))
        {
            return new SHA1Digest();
        }
        if (digest.getAlgorithm().equals(NISTObjectIdentifiers.id_sha224))
        {
            return new SHA224Digest();
        }
        if (digest.getAlgorithm().equals(NISTObjectIdentifiers.id_sha256))
        {
            return new SHA256Digest();
        }
        if (digest.getAlgorithm().equals(NISTObjectIdentifiers.id_sha384))
        {
            return new SHA384Digest();
        }
        if (digest.getAlgorithm().equals(NISTObjectIdentifiers.id_sha512))
        {
            return new SHA512Digest();
        }
        throw new IllegalArgumentException("unrecognised OID in digest algorithm identifier: " + digest.getAlgorithm());
    }
}
