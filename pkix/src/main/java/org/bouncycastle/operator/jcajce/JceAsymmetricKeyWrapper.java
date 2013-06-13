package org.bouncycastle.operator.jcajce;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.NamedJcaJceHelper;
import org.bouncycastle.jcajce.ProviderJcaJceHelper;
import org.bouncycastle.operator.AsymmetricKeyWrapper;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorException;

public class JceAsymmetricKeyWrapper
    extends AsymmetricKeyWrapper
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private Map extraMappings = new HashMap();
    private PublicKey publicKey;
    private SecureRandom random;

    public JceAsymmetricKeyWrapper(PublicKey publicKey)
    {
        super(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()).getAlgorithm());

        this.publicKey = publicKey;
    }

    public JceAsymmetricKeyWrapper(X509Certificate certificate)
    {
        this(certificate.getPublicKey());
    }

    public JceAsymmetricKeyWrapper(PublicKey publicKey, AlgorithmParameterSpec algorithmParameterSpec)
    {
        super(getAlgID(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()), algorithmParameterSpec));

        this.publicKey = publicKey;
    }

    public JceAsymmetricKeyWrapper(X509Certificate certificate, AlgorithmParameterSpec algorithmParameterSpec)
    {
        this(certificate.getPublicKey(), algorithmParameterSpec);
    }

    public JceAsymmetricKeyWrapper setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public JceAsymmetricKeyWrapper setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

    public JceAsymmetricKeyWrapper setSecureRandom(SecureRandom random)
    {
        this.random = random;

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
     * @return the current Wrapper.
     */
    public JceAsymmetricKeyWrapper setAlgorithmMapping(ASN1ObjectIdentifier algorithm, String algorithmName)
    {
        extraMappings.put(algorithm, algorithmName);

        return this;
    }

    public byte[] generateWrappedKey(GenericKey encryptionKey)
        throws OperatorException
    {
        Cipher keyEncryptionCipher = helper.createAsymmetricWrapper(getAlgorithmIdentifier().getAlgorithm(), extraMappings);
        byte[] encryptedKeyBytes = null;

        try
        {
            keyEncryptionCipher.init(Cipher.WRAP_MODE, publicKey, random);
            encryptedKeyBytes = keyEncryptionCipher.wrap(OperatorUtils.getJceKey(encryptionKey));
        }
        catch (GeneralSecurityException e)
        {
        }
        catch (IllegalStateException e)
        {
        }
        catch (UnsupportedOperationException e)
        {
        }
        catch (ProviderException e)
        {
        }

        // some providers do not support WRAP (this appears to be only for asymmetric algorithms)
        if (encryptedKeyBytes == null)
        {
            try
            {
                keyEncryptionCipher.init(Cipher.ENCRYPT_MODE, publicKey, random);
                encryptedKeyBytes = keyEncryptionCipher.doFinal(OperatorUtils.getJceKey(encryptionKey).getEncoded());
            }
            catch (GeneralSecurityException e)
            {
                throw new OperatorException("unable to encrypt contents key", e);
            }
        }

        return encryptedKeyBytes;
    }

    private static AlgorithmIdentifier getAlgID(SubjectPublicKeyInfo pubKeyInfo, AlgorithmParameterSpec algorithmSpec)
    {
        if (PKCSObjectIdentifiers.rsaEncryption.equals(pubKeyInfo.getAlgorithm().getAlgorithm())
            || PKCSObjectIdentifiers.id_RSAES_OAEP.equals(pubKeyInfo.getAlgorithm().getAlgorithm()))
        {
            if (algorithmSpec.equals(OAEPParameterSpec.DEFAULT))
            {
                return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP,
                    new RSAESOAEPparams(RSAESOAEPparams.DEFAULT_HASH_ALGORITHM, RSAESOAEPparams.DEFAULT_MASK_GEN_FUNCTION, RSAESOAEPparams.DEFAULT_P_SOURCE_ALGORITHM));
            }
            else
            {
                OAEPParameterSpec oaepSpec = (OAEPParameterSpec)algorithmSpec;
                PSource pSource = oaepSpec.getPSource();

                AlgorithmIdentifier hashAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find(oaepSpec.getDigestAlgorithm());
                return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP,
                                    new RSAESOAEPparams(hashAlgorithm, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, hashAlgorithm),
                                                        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_pSpecified, new DEROctetString(((PSource.PSpecified)pSource).getValue()))));
            }
        }

        throw new IllegalArgumentException("unknown parameter spec passed.");
    }
}
