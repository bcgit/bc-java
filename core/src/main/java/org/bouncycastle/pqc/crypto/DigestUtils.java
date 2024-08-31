package org.bouncycastle.pqc.crypto;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

public class DigestUtils
{

    /**
     * Retrieve oid of hash/XOF function used to calculate pre-hash signatures
     * for pre-hash versions of slh-dsa and ml-dsa
     */
    static final Map digestOids = new HashMap<String, ASN1ObjectIdentifier>();

    static
    {
        digestOids.put("SHA-1", X509ObjectIdentifiers.id_SHA1);
        digestOids.put("SHA-224", NISTObjectIdentifiers.id_sha224);
        digestOids.put("SHA-256", NISTObjectIdentifiers.id_sha256);
        digestOids.put("SHA-384", NISTObjectIdentifiers.id_sha384);
        digestOids.put("SHA-512", NISTObjectIdentifiers.id_sha512);
        digestOids.put("SHA-512/224", NISTObjectIdentifiers.id_sha512_224);
        digestOids.put("SHA-512/256", NISTObjectIdentifiers.id_sha512_256);

        digestOids.put("SHA3-224", NISTObjectIdentifiers.id_sha3_224);
        digestOids.put("SHA3-256", NISTObjectIdentifiers.id_sha3_256);
        digestOids.put("SHA3-384", NISTObjectIdentifiers.id_sha3_384);
        digestOids.put("SHA3-512", NISTObjectIdentifiers.id_sha3_512);

        digestOids.put("SHAKE128", NISTObjectIdentifiers.id_shake128);
        digestOids.put("SHAKE256", NISTObjectIdentifiers.id_shake256);
    }


    public static ASN1ObjectIdentifier getDigestOid(String digestName)
    {
        if (digestOids.containsKey(digestName))
        {
            return (ASN1ObjectIdentifier)digestOids.get(digestName);
        }

        throw new IllegalArgumentException("unrecognised digest algorithm: " + digestName);
    }
}
