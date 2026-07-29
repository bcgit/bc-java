package org.bouncycastle.cert.c509.jcajce;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.cert.c509.C509CertificateHolder;

/**
 * Converter for producing a JCA {@link X509Certificate} from the X.509 view of a CBOR
 * re-encoded (type 3) C509 certificate, mirroring the X.509 holder converter. A
 * natively signed certificate has no X.509 form and cannot be converted.
 */
public class JcaC509CertificateConverter
{
    private CertificateFactoryCreator factoryCreator = new CertificateFactoryCreator()
    {
        public CertificateFactory createFactory()
            throws CertificateException
        {
            return CertificateFactory.getInstance("X.509");
        }
    };

    private interface CertificateFactoryCreator
    {
        CertificateFactory createFactory()
            throws CertificateException, java.security.NoSuchProviderException;
    }

    /**
     * Base constructor - the default JCA provider will be used to produce the
     * certificate factory.
     */
    public JcaC509CertificateConverter()
    {
    }

    /**
     * Set the provider to use.
     */
    public JcaC509CertificateConverter setProvider(final Provider provider)
    {
        this.factoryCreator = new CertificateFactoryCreator()
        {
            public CertificateFactory createFactory()
                throws CertificateException
            {
                return CertificateFactory.getInstance("X.509", provider);
            }
        };
        return this;
    }

    /**
     * Set the name of the provider to use.
     */
    public JcaC509CertificateConverter setProvider(final String providerName)
    {
        this.factoryCreator = new CertificateFactoryCreator()
        {
            public CertificateFactory createFactory()
                throws CertificateException, java.security.NoSuchProviderException
            {
                return CertificateFactory.getInstance("X.509", providerName);
            }
        };
        return this;
    }

    /**
     * Return the JCA certificate for the X.509 certificate a type 3 holder stands for.
     *
     * @throws IllegalStateException if the holder wraps a natively signed certificate.
     */
    public X509Certificate getCertificate(C509CertificateHolder certificateHolder)
        throws CertificateException
    {
        try
        {
            byte[] derEncoding = certificateHolder.getC509Certificate().toX509Certificate()
                .getEncoded(ASN1Encoding.DER);
            CertificateFactory factory = factoryCreator.createFactory();
            return (X509Certificate)factory.generateCertificate(new ByteArrayInputStream(derEncoding));
        }
        catch (IOException e)
        {
            throw new CertificateException("unable to encode certificate: " + e.getMessage());
        }
        catch (java.security.NoSuchProviderException e)
        {
            throw new CertificateException("cannot find required provider: " + e.getMessage());
        }
    }
}
