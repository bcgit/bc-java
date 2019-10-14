package org.bouncycastle.pqc.jcajce.provider.xmss;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.jcajce.spec.XMSSParameterSpec;

class DigestUtil
{
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

    static ASN1ObjectIdentifier getDigestOID(String digest)
    {
        if (digest.equals("SHA-256"))
        {
            return NISTObjectIdentifiers.id_sha256;
        }
        if (digest.equals("SHA-512"))
        {
            return NISTObjectIdentifiers.id_sha512;
        }
        if (digest.equals("SHAKE128"))
        {
            return NISTObjectIdentifiers.id_shake128;
        }
        if (digest.equals("SHAKE256"))
        {
            return NISTObjectIdentifiers.id_shake256;
        }

        throw new IllegalArgumentException("unrecognized digest: " + digest);
    }

    public static byte[] getDigestResult(Digest digest)
    {
        byte[] hash = new byte[DigestUtil.getDigestSize(digest)];

        if (digest instanceof Xof)
        {
            ((Xof)digest).doFinal(hash, 0, hash.length);
        }
        else
        {
            digest.doFinal(hash, 0);
        }

        return hash;
    }

    public static int getDigestSize(Digest digest)
    {
        if (digest instanceof Xof)
        {
            return digest.getDigestSize() * 2;
        }

        return digest.getDigestSize();
    }

    public static String getXMSSDigestName(ASN1ObjectIdentifier treeDigest)
    {
        if (treeDigest.equals(NISTObjectIdentifiers.id_sha256))
        {
            return XMSSParameterSpec.SHA256;
        }
        if (treeDigest.equals(NISTObjectIdentifiers.id_sha512))
        {
            return XMSSParameterSpec.SHA512;
        }
        if (treeDigest.equals(NISTObjectIdentifiers.id_shake128))
        {
            return XMSSParameterSpec.SHAKE128;
        }
        if (treeDigest.equals(NISTObjectIdentifiers.id_shake256))
        {
            return XMSSParameterSpec.SHAKE256;
        }

        throw new IllegalArgumentException("unrecognized digest OID: " + treeDigest);
    }
}
