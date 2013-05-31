package org.bouncycastle.cms.jcajce;

import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.KeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;

public class JceKeyTransRecipientInfoGenerator
    extends KeyTransRecipientInfoGenerator
{
    public JceKeyTransRecipientInfoGenerator(X509Certificate recipientCert)
        throws CertificateEncodingException
    {
        super(new IssuerAndSerialNumber(new JcaX509CertificateHolder(recipientCert).toASN1Structure()), new JceAsymmetricKeyWrapper(recipientCert.getPublicKey()));
    }

    public JceKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, PublicKey publicKey)
    {
        super(subjectKeyIdentifier, new JceAsymmetricKeyWrapper(publicKey));
    }

    public JceKeyTransRecipientInfoGenerator setProvider(String providerName)
    {
        ((JceAsymmetricKeyWrapper)this.wrapper).setProvider(providerName);

        return this;
    }

    public JceKeyTransRecipientInfoGenerator setProvider(Provider provider)
    {
        ((JceAsymmetricKeyWrapper)this.wrapper).setProvider(provider);

        return this;
    }

    /**
     * Internally algorithm ids are converted into cipher names using a lookup table. For some providers
     * the standard lookup table won't work. Use this method to establish a specific mapping from an
     * algorithm identifier to a specific algorithm.
     * <p>
     *     For example:
     * <pre>
     *     unwrapper.setAlgorithmMapping(PKCSObjectIdentifiers.rsaEncryption, "RSA");
     * </pre>
     * </p>
     * @param algorithm  OID of algorithm in recipient.
     * @param algorithmName JCE algorithm name to use.
     * @return the current RecipientInfoGenerator.
     */
    public JceKeyTransRecipientInfoGenerator setAlgorithmMapping(ASN1ObjectIdentifier algorithm, String algorithmName)
    {
        ((JceAsymmetricKeyWrapper)this.wrapper).setAlgorithmMapping(algorithm, algorithmName);

        return this;
    }
}