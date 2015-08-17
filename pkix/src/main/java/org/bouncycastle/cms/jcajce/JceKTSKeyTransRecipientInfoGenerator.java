package org.bouncycastle.cms.jcajce;

import java.io.IOException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.KeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;
import org.bouncycastle.operator.jcajce.JceKTSKeyWrapper;
import org.bouncycastle.util.encoders.Hex;

public class JceKTSKeyTransRecipientInfoGenerator
    extends KeyTransRecipientInfoGenerator
{
    private static final byte[] ANONYMOUS_SENDER = Hex.decode("0c14416e6f6e796d6f75732053656e64657220202020");   // "Anonymous Sender    "

    private JceKTSKeyTransRecipientInfoGenerator(X509Certificate recipientCert, IssuerAndSerialNumber recipientID, String symmetricWrappingAlg, int keySizeInBits)
        throws CertificateEncodingException
    {
        super(recipientID, new JceKTSKeyWrapper(recipientCert, symmetricWrappingAlg, keySizeInBits, ANONYMOUS_SENDER, getEncodedRecipID(recipientID)));
    }

    public JceKTSKeyTransRecipientInfoGenerator(X509Certificate recipientCert, String symmetricWrappingAlg, int keySizeInBits)
        throws CertificateEncodingException
    {
        this(recipientCert, new IssuerAndSerialNumber(new JcaX509CertificateHolder(recipientCert).toASN1Structure()), symmetricWrappingAlg, keySizeInBits);
    }

    public JceKTSKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, PublicKey publicKey, String symmetricWrappingAlg, int keySizeInBits)
    {
        super(subjectKeyIdentifier, new JceKTSKeyWrapper(publicKey, symmetricWrappingAlg, keySizeInBits, ANONYMOUS_SENDER, getEncodedSubKeyId(subjectKeyIdentifier)));
    }

    private static byte[] getEncodedRecipID(IssuerAndSerialNumber recipientID)
        throws CertificateEncodingException
    {
        try
        {
            return recipientID.getEncoded(ASN1Encoding.DER);
        }
        catch (final IOException e)
        {
            throw new CertificateEncodingException("Cannot process extracted IssuerAndSerialNumber: " + e.getMessage())
            {
                public Throwable getCause()
                {
                    return e;
                }
            };
        }
    }

    private static byte[] getEncodedSubKeyId(byte[] subjectKeyIdentifier)
    {
        try
        {
            return new DEROctetString(subjectKeyIdentifier).getEncoded();
        }
        catch (final IOException e)
        {
            throw new IllegalArgumentException("Cannot process subject key identifier: " + e.getMessage())
            {
                public Throwable getCause()
                {
                    return e;
                }
            };
        }
    }

    /**
     * Create a generator overriding the algorithm type implied by the public key in the certificate passed in.
     *
     * @param recipientCert       certificate carrying the public key.
     * @param algorithmIdentifier the identifier and parameters for the encryption algorithm to be used.
     */
    public JceKTSKeyTransRecipientInfoGenerator(X509Certificate recipientCert, AlgorithmIdentifier algorithmIdentifier)
        throws CertificateEncodingException
    {
        super(new IssuerAndSerialNumber(new JcaX509CertificateHolder(recipientCert).toASN1Structure()), new JceAsymmetricKeyWrapper(algorithmIdentifier, recipientCert.getPublicKey()));
    }

    /**
     * Create a generator overriding the algorithm type implied by the public key passed in.
     *
     * @param subjectKeyIdentifier the subject key identifier value to associate with the public key.
     * @param algorithmIdentifier  the identifier and parameters for the encryption algorithm to be used.
     * @param publicKey            the public key to use.
     */
    public JceKTSKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, AlgorithmIdentifier algorithmIdentifier, PublicKey publicKey)
    {
        super(subjectKeyIdentifier, new JceAsymmetricKeyWrapper(algorithmIdentifier, publicKey));
    }

    public JceKTSKeyTransRecipientInfoGenerator setProvider(String providerName)
    {
        ((JceKTSKeyWrapper)this.wrapper).setProvider(providerName);

        return this;
    }

    public JceKTSKeyTransRecipientInfoGenerator setProvider(Provider provider)
    {
        ((JceKTSKeyWrapper)this.wrapper).setProvider(provider);

        return this;
    }
}