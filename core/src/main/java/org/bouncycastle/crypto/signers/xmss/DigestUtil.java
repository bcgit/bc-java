package org.bouncycastle.crypto.signers.xmss;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;

class DigestUtil
{
    private static final Map<String, ASN1ObjectIdentifier> nameToOid = new HashMap<String, ASN1ObjectIdentifier>();
    private static final Map<ASN1ObjectIdentifier, String> oidToName = new HashMap<ASN1ObjectIdentifier, String>();

    static
    {
        nameToOid.put("SHA-256", NISTObjectIdentifiers.id_sha256);
        nameToOid.put("SHA-512", NISTObjectIdentifiers.id_sha512);
        nameToOid.put("SHAKE128", NISTObjectIdentifiers.id_shake128);
        nameToOid.put("SHAKE256", NISTObjectIdentifiers.id_shake256);
        nameToOid.put("SHAKE256-LEN", NISTObjectIdentifiers.id_shake256_len);

        oidToName.put(NISTObjectIdentifiers.id_sha256, "SHA-256");
        oidToName.put(NISTObjectIdentifiers.id_sha512, "SHA-512");
        oidToName.put(NISTObjectIdentifiers.id_shake128, "SHAKE128");
        oidToName.put(NISTObjectIdentifiers.id_shake256, "SHAKE256");
        oidToName.put(NISTObjectIdentifiers.id_shake256_len, "SHAKE256-LEN");
    }

    /**
     * The digest an XMSS parameter set names, by OID.
     * <p>
     * Each comparison has the constant on the left, which is what lets a null OID reach the refusal
     * at the bottom rather than raising a NullPointerException on the first one - the answer
     * {@link #getDigestName} already gives the same mistake, from a map lookup that takes a null
     * key. The two are the pair a caller reaches this class through and they answered an absent OID
     * two different ways, which the removal of WOTSPlusParameters' own null check turned from a
     * detail into the whole of what an absent OID gets.
     * </p>
     *
     * @param oid the tree digest OID.
     * @return a fresh digest for it.
     * @throws IllegalArgumentException if the OID is not one of the five, or is null.
     */
    public static Digest getDigest(ASN1ObjectIdentifier oid)
    {
        if (NISTObjectIdentifiers.id_sha256.equals(oid))
        {
            return new SHA256Digest(CryptoServicePurpose.INTERNAL);
        }
        if (NISTObjectIdentifiers.id_sha512.equals(oid))
        {
            return new SHA512Digest(CryptoServicePurpose.INTERNAL);
        }
        if (NISTObjectIdentifiers.id_shake128.equals(oid))
        {
            return new SHAKEDigest(128, CryptoServicePurpose.INTERNAL);
        }
        if (NISTObjectIdentifiers.id_shake256.equals(oid))
        {
            return new SHAKEDigest(256, CryptoServicePurpose.INTERNAL);
        }
        if (NISTObjectIdentifiers.id_shake256_len.equals(oid))
        {
            return new SHAKEDigest(256, CryptoServicePurpose.INTERNAL);
        }

        throw new IllegalArgumentException("unrecognized digest OID: " + oid);
    }

    public static String getDigestName(ASN1ObjectIdentifier oid)
    {
        String name = oidToName.get(oid);
        if (name != null)
        {
            return name;
        }

        throw new IllegalArgumentException("unrecognized digest oid: " + oid);
    }

    public static ASN1ObjectIdentifier getDigestOID(String name)
    {
        ASN1ObjectIdentifier oid = nameToOid.get(name);
        if (oid != null)
        {
            return oid;
        }

        throw new IllegalArgumentException("unrecognized digest name: " + name);
    }
}
