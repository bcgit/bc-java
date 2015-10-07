package org.bouncycastle.operator.jcajce;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.operator.AsymmetricKeyUnwrapper;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorException;

public class JceAsymmetricKeyUnwrapper
    extends AsymmetricKeyUnwrapper
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private Map extraMappings = new HashMap();
    private PrivateKey privKey;
    private boolean unwrappedKeyMustBeEncodable;

    public JceAsymmetricKeyUnwrapper(AlgorithmIdentifier algorithmIdentifier, PrivateKey privKey)
    {
        super(algorithmIdentifier);

        this.privKey = privKey;
    }

    public JceAsymmetricKeyUnwrapper setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public JceAsymmetricKeyUnwrapper setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

    /**
     * Flag that unwrapping must produce a key that will return a meaningful value from a call to Key.getEncoded().
     * This is important if you are using a HSM for unwrapping and using a software based provider for
     * with the unwrapped key. Default value: false.
     *
     * @param unwrappedKeyMustBeEncodable true if getEncoded() should return key bytes, false if not necessary.
     * @return this recipient.
     */
    public JceAsymmetricKeyUnwrapper setMustProduceEncodableUnwrappedKey(boolean unwrappedKeyMustBeEncodable)
    {
        this.unwrappedKeyMustBeEncodable = unwrappedKeyMustBeEncodable;

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
     * @return  the current Unwrapper.
     */
    public JceAsymmetricKeyUnwrapper setAlgorithmMapping(ASN1ObjectIdentifier algorithm, String algorithmName)
    {
        extraMappings.put(algorithm, algorithmName);

        return this;
    }

    public GenericKey generateUnwrappedKey(AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedKey)
        throws OperatorException
    {
        try
        {
            Key sKey = null;

            Cipher keyCipher = helper.createAsymmetricWrapper(this.getAlgorithmIdentifier().getAlgorithm(), extraMappings);
            AlgorithmParameters algParams = helper.createAlgorithmParameters(this.getAlgorithmIdentifier());

            try
            {
                if (algParams != null)
                {
                    keyCipher.init(Cipher.UNWRAP_MODE, privKey, algParams);
                }
                else
                {
                    keyCipher.init(Cipher.UNWRAP_MODE, privKey);
                }

                sKey = keyCipher.unwrap(encryptedKey, helper.getKeyAlgorithmName(encryptedKeyAlgorithm.getAlgorithm()), Cipher.SECRET_KEY);

                // check key will work with a software provider.
                if (unwrappedKeyMustBeEncodable)
                {
                    try
                    {
                        byte[] keyBytes = sKey.getEncoded();

                        if (keyBytes == null || keyBytes.length == 0)
                        {
                            sKey = null;
                        }
                    }
                    catch (Exception e)
                    {
                        sKey = null; // try doing a decrypt
                    }
                }
            }
            catch (Exception e)
            {   // try decrypt
            }

            // some providers do not support UNWRAP (this appears to be only for asymmetric algorithms)
            if (sKey == null)
            {
                keyCipher.init(Cipher.DECRYPT_MODE, privKey);
                sKey = new SecretKeySpec(keyCipher.doFinal(encryptedKey), encryptedKeyAlgorithm.getAlgorithm().getId());
            }

            return new JceGenericKey(encryptedKeyAlgorithm, sKey);
        }
        catch (InvalidKeyException e)
        {
            throw new OperatorException("key invalid: " + e.getMessage(), e);
        }
        catch (IllegalBlockSizeException e)
        {
            throw new OperatorException("illegal blocksize: " + e.getMessage(), e);
        }
        catch (BadPaddingException e)
        {
            throw new OperatorException("bad padding: " + e.getMessage(), e);
        }
    }
}
