package org.bouncycastle.pkcs.jcajce;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Hashtable;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * JCA-aware extension of {@link PKCS10CertificationRequest} that returns the request's public
 * key as a JCA {@link PublicKey}. Use {@link #setProvider} to pin the underlying
 * {@link KeyFactory} lookup to a specific JCE provider.
 */
public class JcaPKCS10CertificationRequest
    extends PKCS10CertificationRequest
{
    private static Hashtable keyAlgorithms = new Hashtable();

    static
    {
        //
        // key types
        //
        keyAlgorithms.put(PKCSObjectIdentifiers.rsaEncryption, "RSA");
        keyAlgorithms.put(X9ObjectIdentifiers.id_dsa, "DSA");
        keyAlgorithms.put(X9ObjectIdentifiers.id_ecPublicKey, "EC");
    }

    private JcaJceHelper helper = new DefaultJcaJceHelper();

    /**
     * Wrap a parsed {@link CertificationRequest}.
     *
     * @param certificationRequest the underlying request.
     */
    public JcaPKCS10CertificationRequest(CertificationRequest certificationRequest)
    {
        super(certificationRequest);
    }

    /**
     * Parse a BER/DER encoded PKCS#10 request.
     *
     * @param encoding the encoded request bytes.
     * @throws IOException if the data is not a valid CertificationRequest.
     */
    public JcaPKCS10CertificationRequest(byte[] encoding)
        throws IOException
    {
        super(encoding);
    }

    /**
     * Re-wrap an existing {@link PKCS10CertificationRequest} as a JCA-aware holder.
     *
     * @param requestHolder the existing holder.
     */
    public JcaPKCS10CertificationRequest(PKCS10CertificationRequest requestHolder)
    {
        super(requestHolder.toASN1Structure());
    }

    /**
     * Pin {@link KeyFactory} lookups to the named JCE provider.
     *
     * @param providerName name of the registered provider.
     * @return this holder.
     */
    public JcaPKCS10CertificationRequest setProvider(String providerName)
    {
        helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    /**
     * Pin {@link KeyFactory} lookups to the supplied JCE provider.
     *
     * @param provider the provider instance.
     * @return this holder.
     */
    public JcaPKCS10CertificationRequest setProvider(Provider provider)
    {
        helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    /**
     * Return the public key carried by the request as a JCA {@link PublicKey}.
     *
     * @return the decoded public key.
     * @throws InvalidKeyException if the SubjectPublicKeyInfo cannot be parsed.
     * @throws NoSuchAlgorithmException if no matching KeyFactory can be located.
     */
    public PublicKey getPublicKey()
        throws InvalidKeyException, NoSuchAlgorithmException
    {
        try
        {
            SubjectPublicKeyInfo keyInfo = this.getSubjectPublicKeyInfo();
            X509EncodedKeySpec xspec = new X509EncodedKeySpec(keyInfo.getEncoded());
            KeyFactory kFact;

            try
            {
                kFact = helper.createKeyFactory(keyInfo.getAlgorithm().getAlgorithm().getId());
            }
            catch (NoSuchAlgorithmException e)
            {
                //
                // try an alternate
                //
                if (keyAlgorithms.get(keyInfo.getAlgorithm().getAlgorithm()) != null)
                {
                    String  keyAlgorithm = (String)keyAlgorithms.get(keyInfo.getAlgorithm().getAlgorithm());

                    kFact = helper.createKeyFactory(keyAlgorithm);
                }
                else
                {
                    throw e;
                }
            }

            return kFact.generatePublic(xspec);
        }
        catch (InvalidKeySpecException e)
        {
            throw new InvalidKeyException("error decoding public key");
        }
        catch (IOException e)
        {
            throw new InvalidKeyException("error extracting key encoding");
        }
        catch (NoSuchProviderException e)
        {
            throw new NoSuchAlgorithmException("cannot find provider: " + e.getMessage());
        }
    }
}
