package org.bouncycastle.pkix.jcajce;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.pkix.PKIXIdentity;

/**
 * Holder class for public/private key based identity information.
 */
public class JcaPKIXIdentity
    extends PKIXIdentity
{
    private final PrivateKey privKey;
    private final X509Certificate[] certs;

    private static PrivateKeyInfo getPrivateKeyInfo(PrivateKey privateKey)
    {
         try
         {
             return PrivateKeyInfo.getInstance(privateKey.getEncoded());
         }
         catch (Exception e)             // for a HSM getEncoded() may do anything...
         {
             return null;
         }
    }

    private static X509CertificateHolder[] getCertificates(X509Certificate[] certs)
    {
        X509CertificateHolder[] certHldrs = new X509CertificateHolder[certs.length];

        try
        {
            for (int i = 0; i != certHldrs.length; i++)
            {
                certHldrs[i] = new JcaX509CertificateHolder(certs[i]);
            }

            return certHldrs;
        }
        catch (CertificateEncodingException e)
        {
            throw new IllegalArgumentException("Unable to process certificates: " + e.getMessage());
        }
    }

    /**
     * Base constructor - a private key and its associated certificate chain. The chain
     * should be ordered so that certs[0] is the matching public key for privKey.
     *
     * @param privKey the private key.
     * @param certs the public key certificates identifying it.
     */
    public JcaPKIXIdentity(PrivateKey privKey, X509Certificate[] certs)
    {
        super(getPrivateKeyInfo(privKey), getCertificates(certs));

        this.privKey = privKey;
        this.certs = new X509Certificate[certs.length];

        System.arraycopy(certs, 0, this.certs, 0, certs.length);
    }

    /**
     * Base constructor - a private key and its associated public key certificate.
     *
     * @param privKey the private key.
     * @param cert privKey's matching public key certificate.
     */
    public JcaPKIXIdentity(PrivateKey privKey, X509Certificate cert)
    {
        this(privKey, new X509Certificate[] { cert });
    }

    /**
     * Return the private key for this identity.
     *
     * @return the identity's private key.
     */
    public PrivateKey getPrivateKey()
    {
        return privKey;
    }

    /**
     * Return the certificate associated with the private key.
     *
     * @return the primary certificate.
     */
    public X509Certificate getX509Certificate()
    {
        return certs[0];
    }

    /**
     * Return the certificate chain associated with the private key.
     *
     * @return the certificate chain.
     */
    public X509Certificate[] getX509CertificateChain()
    {
        X509Certificate[] rv = new X509Certificate[certs.length];

        System.arraycopy(certs, 0, rv, 0, rv.length);

        return rv;
    }
}
