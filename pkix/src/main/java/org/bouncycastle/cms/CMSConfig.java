package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class CMSConfig
{
    /**
     * Set the mapping for the encryption algorithm used in association with a SignedData generation
     * or interpretation.
     *
     * @param oid object identifier to map.
     * @param algorithmName algorithm name to use.
     */
    public static void setSigningEncryptionAlgorithmMapping(String oid, String algorithmName)
    {
        ASN1ObjectIdentifier id = new ASN1ObjectIdentifier(oid);

        CMSSignedHelper.INSTANCE.setSigningEncryptionAlgorithmMapping(id, algorithmName);
    }

    /**
     * Set the mapping for the digest algorithm to use in conjunction with a SignedData generation
     * or interpretation.
     *
     * @param oid object identifier to map.
     * @param algorithmName algorithm name to use.
     * @deprecated no longer required.
     */
    public static void setSigningDigestAlgorithmMapping(String oid, String algorithmName)
    {
        ASN1ObjectIdentifier id = new ASN1ObjectIdentifier(oid);

        //CMSSignedHelper.INSTANCE.setSigningDigestAlgorithmMapping(id, algorithmName);
    }
}
