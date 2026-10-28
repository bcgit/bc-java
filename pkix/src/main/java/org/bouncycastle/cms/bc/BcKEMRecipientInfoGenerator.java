package org.bouncycastle.cms.bc;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.KEMRecipientInfoGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Generator for an RFC 9629 KEMRecipientInfo using the light-weight API. The recipient's key must
 * be an ML-KEM public key; the content-encryption key is wrapped with the AES key wrap named by
 * the wrap algorithm, under a key-encryption key derived with KDF3/SHA-256 unless
 * {@link #setKDF(AlgorithmIdentifier)} selects another of the KDFs RFC 9629 allows.
 */
public class BcKEMRecipientInfoGenerator
    extends KEMRecipientInfoGenerator
{
    public BcKEMRecipientInfoGenerator(X509CertificateHolder recipientCert, ASN1ObjectIdentifier symWrapAlgorithm)
        throws IOException
    {
        super(new IssuerAndSerialNumber(recipientCert.toASN1Structure()),
            new BcCMSKEMKeyWrapper(recipientCert.getSubjectPublicKeyInfo(), symWrapAlgorithm));
    }

    public BcKEMRecipientInfoGenerator(byte[] subjectKeyIdentifier, AsymmetricKeyParameter publicKey, ASN1ObjectIdentifier symWrapAlgorithm)
        throws IOException
    {
        super(subjectKeyIdentifier, new BcCMSKEMKeyWrapper(publicKey, symWrapAlgorithm));
    }

    public BcKEMRecipientInfoGenerator setSecureRandom(SecureRandom random)
    {
        ((BcCMSKEMKeyWrapper)this.wrapper).setSecureRandom(random);

        return this;
    }

    public BcKEMRecipientInfoGenerator setKDF(AlgorithmIdentifier kdfAlgorithm)
    {
        ((BcCMSKEMKeyWrapper)this.wrapper).setKDF(kdfAlgorithm);

        return this;
    }

    public BcKEMRecipientInfoGenerator setUserKeyingMaterial(byte[] userKeyingMaterial)
    {
        ((BcCMSKEMKeyWrapper)this.wrapper).setUKM(userKeyingMaterial);

        return this;
    }
}
