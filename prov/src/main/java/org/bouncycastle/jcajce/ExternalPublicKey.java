package org.bouncycastle.jcajce;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.PublicKey;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.bc.ExternalValue;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.bouncycastle.util.Arrays;

/**
 * Wrapper class which returns an "ExternalValue" for the public key encoding. In this case
 * the key encoding is a hash and the actual key needs to be looked up somewhere else. Useful
 * for where the public keys are really large but it's required to keep certificates small.
 */
public class ExternalPublicKey
    implements PublicKey
{
    private final GeneralName location;
    private final AlgorithmIdentifier digestAlg;
    private final byte[] digest;

    /**
     * Base constructor with fundamental contents.
     *
     * @param location location URI for the actual public key.
     * @param digestAlg hashing algorithm used to hash the actual public key encoding.
     * @param digest digest of the actual public key.
     */
    public ExternalPublicKey(GeneralName location, AlgorithmIdentifier digestAlg, byte[] digest)
    {
        this.location = location;
        this.digestAlg = digestAlg;
        this.digest = Arrays.clone(digest);
    }

    /**
     * Helper constructor with JCA contents.
     *
     * @param key the public key we are externalising.
     * @param location location URI for the actual public key.
     * @param digest digest to use for hashing the key.
     */
    public ExternalPublicKey(PublicKey key, GeneralName location, MessageDigest digest)
    {
        this(location, MessageDigestUtils.getDigestAlgID(digest.getAlgorithm()), digest.digest(key.getEncoded()));
    }

    /**
     * Base constructor with ASN.1 structure.
     *
     * @param extKey structure with location, hashing algorithm and hash for the public key.
     */
    public ExternalPublicKey(ExternalValue extKey)
    {
        this(extKey.getLocation(), extKey.getHashAlg(), extKey.getHashValue());
    }

    /**
     * Return "ExternalKey"
     *
     * @return  "ExternalKey"
     */
    public String getAlgorithm()
    {
        return "ExternalKey";
    }

    /**
     * Return "X.509" (DER encoded SubjectPublicKeyInfo)
     *
     * @return  "X.509"
     */
    public String getFormat()
    {
        return "X.509";
    }

    /**
     * Return a SubjectPublicKeyInfo structure containing an ExternalValue encoding for the key.
     *
     * @return a DER encoding of SubjectPublicKeyInfo containing an ExternalValue structure.
     */
    public byte[] getEncoded()
    {
        try
        {
            return new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(BCObjectIdentifiers.external_value),
                    new ExternalValue(location, digestAlg, digest)).getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unable to encode composite key: " + e.getMessage());
        }
    }
}
