package org.bouncycastle.cms.jcajce;

import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.KEMRecipientInfoGenerator;
import org.bouncycastle.operator.KEMKeyWrapper;

public class JceKEMRecipientInfoGenerator
    extends KEMRecipientInfoGenerator
{
    public JceKEMRecipientInfoGenerator(X509Certificate recipientCert, KEMKeyWrapper wrapper)
        throws CertificateEncodingException
    {
        super(new IssuerAndSerialNumber(new JcaX509CertificateHolder(recipientCert).toASN1Structure()), wrapper);
    }

    public JceKEMRecipientInfoGenerator(byte[] subjectKeyIdentifier, KEMKeyWrapper wrapper)
    {
        super(subjectKeyIdentifier, wrapper);
    }

    public JceKEMRecipientInfoGenerator setProvider(String providerName)
    {
        ((JceCMSKEMKeyWrapper)this.wrapper).setProvider(providerName);

        return this;
    }

    public JceKEMRecipientInfoGenerator setProvider(Provider provider)
    {
        ((JceCMSKEMKeyWrapper)this.wrapper).setProvider(provider);

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
     * @param algorithm  OID of algorithm in recipient.
     * @param algorithmName JCE algorithm name to use.
     * @return the current RecipientInfoGenerator.
     */
    public JceKEMRecipientInfoGenerator setAlgorithmMapping(ASN1ObjectIdentifier algorithm, String algorithmName)
    {
        ((JceCMSKEMKeyWrapper)this.wrapper).setAlgorithmMapping(algorithm, algorithmName);

        return this;
    }
}
