package org.bouncycastle.mozilla.jcajce;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.mozilla.SignedPublicKeyAndChallenge;

/**
 * This is designed to parse the SignedPublicKeyAndChallenge created by the
 * KEYGEN tag included by Mozilla based browsers.
 *  <pre>
 *  PublicKeyAndChallenge ::= SEQUENCE {
 *    spki SubjectPublicKeyInfo,
 *    challenge IA5STRING
 *  }
 *
 *  SignedPublicKeyAndChallenge ::= SEQUENCE {
 *    publicKeyAndChallenge PublicKeyAndChallenge,
 *    signatureAlgorithm AlgorithmIdentifier,
 *    signature BIT STRING
 *  }
 *  </pre>
 */
public class JcaSignedPublicKeyAndChallenge
    extends SignedPublicKeyAndChallenge
{
    JcaJceHelper helper = new DefaultJcaJceHelper();

    private JcaSignedPublicKeyAndChallenge(org.bouncycastle.asn1.mozilla.SignedPublicKeyAndChallenge struct, JcaJceHelper helper)
    {
        super(struct);
        this.helper = helper;
    }

    /**
     * Parse a SignedPublicKeyAndChallenge from its DER encoding.
     *
     * @param bytes the encoded SPKAC bytes.
     */
    public JcaSignedPublicKeyAndChallenge(byte[] bytes)
    {
        super(bytes);
    }

    /**
     * Return a new holder that pins {@link KeyFactory} lookups to the named JCE provider.
     *
     * @param providerName the name of the JCE provider to use.
     * @return a new JcaSignedPublicKeyAndChallenge bound to {@code providerName}.
     */
    public JcaSignedPublicKeyAndChallenge setProvider(String providerName)
    {
        return new JcaSignedPublicKeyAndChallenge(this.spkacSeq, new NamedJcaJceHelper(providerName));
    }

    /**
     * Return a new holder that pins {@link KeyFactory} lookups to the supplied JCE provider.
     *
     * @param provider the JCE provider to use.
     * @return a new JcaSignedPublicKeyAndChallenge bound to {@code provider}.
     */
    public JcaSignedPublicKeyAndChallenge setProvider(Provider provider)
    {
        return new JcaSignedPublicKeyAndChallenge(this.spkacSeq, new ProviderJcaJceHelper(provider));
    }

    /**
     * Return the public key carried by the SPKAC as a JCA {@link PublicKey}, decoded via the
     * provider configured by {@link #setProvider}.
     *
     * @return the decoded public key.
     * @throws NoSuchAlgorithmException if no KeyFactory matches the SPKI algorithm.
     * @throws NoSuchProviderException  if the named provider is not registered.
     * @throws InvalidKeyException      if the SPKI cannot be decoded into a usable key.
     */
    public PublicKey getPublicKey()
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        try
        {
            SubjectPublicKeyInfo subjectPublicKeyInfo = spkacSeq.getPublicKeyAndChallenge().getSubjectPublicKeyInfo();
            X509EncodedKeySpec xspec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
            

            AlgorithmIdentifier keyAlg = subjectPublicKeyInfo.getAlgorithm();

            KeyFactory factory = helper.createKeyFactory(keyAlg.getAlgorithm().getId());

            return factory.generatePublic(xspec);
        }
        catch (Exception e)
        {
            throw new InvalidKeyException("error encoding public key");
        }
    }
}
