package org.bouncycastle.openssl.jcajce;

import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.openssl.PEMEncryptor;

/**
 * PEM generator for the original set of PEM objects used in Open SSL.
 */
public class JcaMiscPEMGenerator
    extends MiscPEMGenerator
{
    private Object obj;
    private String algorithm;
    private char[] password;
    private SecureRandom random;
    private Provider provider;

    public JcaMiscPEMGenerator(Object o)
        throws IOException
    {
        super(convertObject(o));
    }

    public JcaMiscPEMGenerator(Object o, PEMEncryptor encryptor)
        throws IOException
    {
        super(convertObject(o), encryptor);
    }

    private static Object convertObject(Object o)
        throws IOException
    {
        if (o instanceof X509Certificate)
        {
            try
            {
                return new JcaX509CertificateHolder((X509Certificate)o);
            }
            catch (CertificateEncodingException e)
            {
                throw new IllegalArgumentException("Cannot encode object: " + e.toString());
            }
        }
        else if (o instanceof X509CRL)
        {
            try
            {
                return new JcaX509CRLHolder((X509CRL)o);
            }
            catch (CRLException e)
            {
                throw new IllegalArgumentException("Cannot encode object: " + e.toString());
            }
        }
        else if (o instanceof KeyPair)
        {
            return convertObject(((KeyPair)o).getPrivate());
        }
        else if (o instanceof PrivateKey)
        {
            return PrivateKeyInfo.getInstance(((Key)o).getEncoded());
        }
        else if (o instanceof PublicKey)
        {
            return SubjectPublicKeyInfo.getInstance(((PublicKey)o).getEncoded());
        }

        return o;
    }
}
