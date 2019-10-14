package org.bouncycastle.pqc.crypto.xmss;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;

class DigestUtil
{
    private static Map<String, ASN1ObjectIdentifier> nameToOid = new HashMap<String, ASN1ObjectIdentifier>();
    private static Map<ASN1ObjectIdentifier, String> oidToName = new HashMap<ASN1ObjectIdentifier, String>();

    static
    {
        nameToOid.put("SHA-256", NISTObjectIdentifiers.id_sha256);
        nameToOid.put("SHA-512", NISTObjectIdentifiers.id_sha512);
        nameToOid.put("SHAKE128", NISTObjectIdentifiers.id_shake128);
        nameToOid.put("SHAKE256", NISTObjectIdentifiers.id_shake256);

        oidToName.put(NISTObjectIdentifiers.id_sha256, "SHA-256");
        oidToName.put(NISTObjectIdentifiers.id_sha512, "SHA-512");
        oidToName.put(NISTObjectIdentifiers.id_shake128, "SHAKE128");
        oidToName.put(NISTObjectIdentifiers.id_shake256, "SHAKE256");
    }

    static Digest getDigest(ASN1ObjectIdentifier oid)
    {
        if (oid.equals(NISTObjectIdentifiers.id_sha256))
        {
            return new SHA256Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_sha512))
        {
            return new SHA512Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_shake128))
        {
            return new SHAKEDigest(128);
        }
        if (oid.equals(NISTObjectIdentifiers.id_shake256))
        {
            return new SHAKEDigest(256);
        }

        throw new IllegalArgumentException("unrecognized digest OID: " + oid);
    }

    static String getDigestName(ASN1ObjectIdentifier oid)
    {
        String name = oidToName.get(oid);
        if (name != null)
        {
            return name;
        }

        throw new IllegalArgumentException("unrecognized digest oid: " + oid);
    }

    static ASN1ObjectIdentifier getDigestOID(String name)
    {
        ASN1ObjectIdentifier oid = nameToOid.get(name);
        if (oid != null)
        {
            return oid;
        }

        throw new IllegalArgumentException("unrecognized digest name: " + name);
    }

    public static int getDigestSize(Digest digest)
    {
        if (digest instanceof Xof)
        {
            return digest.getDigestSize() * 2;
        }

        return digest.getDigestSize();
    }
}
