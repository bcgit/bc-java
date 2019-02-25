package org.bouncycastle.cms.jcajce;

import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.Gost2814789EncryptedKey;
import org.bouncycastle.asn1.cryptopro.GostR3410KeyTransport;
import org.bouncycastle.asn1.cryptopro.GostR3410TransportParameters;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyTransRecipient;
import org.bouncycastle.jcajce.spec.GOST28147WrapParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyUnwrapper;
import org.bouncycastle.util.Arrays;

public abstract class JceKeyTransRecipient
    implements KeyTransRecipient
{
    private PrivateKey recipientKey;

    protected EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
    protected EnvelopedDataHelper contentHelper = helper;
    protected Map extraMappings = new HashMap();
    protected boolean validateKeySize = false;
    protected boolean unwrappedKeyMustBeEncodable;

    public JceKeyTransRecipient(PrivateKey recipientKey)
    {
        this.recipientKey = CMSUtils.cleanPrivateKey(recipientKey);
    }

    /**
     * Set the provider to use for key recovery and content processing.
     *
     * @param provider provider to use.
     * @return this recipient.
     */
    public JceKeyTransRecipient setProvider(Provider provider)
    {
        this.helper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));
        this.contentHelper = helper;

        return this;
    }

    /**
     * Set the provider to use for key recovery and content processing.
     *
     * @param providerName the name of the provider to use.
     * @return this recipient.
     */
    public JceKeyTransRecipient setProvider(String providerName)
    {
        this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));
        this.contentHelper = helper;

        return this;
    }

    /**
     * Internally algorithm ids are converted into cipher names using a lookup table. For some providers
     * the standard lookup table won't work. Use this method to establish a specific mapping from an
     * algorithm identifier to a specific algorithm.
     * <p>
     * For example:
     * <pre>
     *     unwrapper.setAlgorithmMapping(PKCSObjectIdentifiers.rsaEncryption, "RSA");
     * </pre>
     *
     * @param algorithm     OID of algorithm in recipient.
     * @param algorithmName JCE algorithm name to use.
     * @return the current Recipient.
     */
    public JceKeyTransRecipient setAlgorithmMapping(ASN1ObjectIdentifier algorithm, String algorithmName)
    {
        extraMappings.put(algorithm, algorithmName);

        return this;
    }

    /**
     * Set the provider to use for content processing.  If providerName is null a "no provider" search will be
     * used to satisfy getInstance calls.
     *
     * @param provider the provider to use.
     * @return this recipient.
     */
    public JceKeyTransRecipient setContentProvider(Provider provider)
    {
        this.contentHelper = CMSUtils.createContentHelper(provider);

        return this;
    }

    /**
     * Flag that unwrapping must produce a key that will return a meaningful value from a call to Key.getEncoded().
     * This is important if you are using a HSM for unwrapping and using a software based provider for
     * decrypting the content. Default value: false.
     *
     * @param unwrappedKeyMustBeEncodable true if getEncoded() should return key bytes, false if not necessary.
     * @return this recipient.
     */
    public JceKeyTransRecipient setMustProduceEncodableUnwrappedKey(boolean unwrappedKeyMustBeEncodable)
    {
        this.unwrappedKeyMustBeEncodable = unwrappedKeyMustBeEncodable;

        return this;
    }

    /**
     * Set the provider to use for content processing.  If providerName is null a "no provider" search will be
     * used to satisfy getInstance calls.
     *
     * @param providerName the name of the provider to use.
     * @return this recipient.
     */
    public JceKeyTransRecipient setContentProvider(String providerName)
    {
        this.contentHelper = CMSUtils.createContentHelper(providerName);

        return this;
    }

    /**
     * Set validation of retrieved key sizes against the algorithm parameters for the encrypted key where possible - default is off.
     * <p>
     * This setting will not have any affect if the encryption algorithm in the recipient does not specify a particular key size, or
     * if the unwrapper is a HSM and the byte encoding of the unwrapped secret key is not available.
     * </p>
     *
     * @param doValidate true if unwrapped key's should be validated against the content encryption algorithm, false otherwise.
     * @return this recipient.
     */
    public JceKeyTransRecipient setKeySizeValidation(boolean doValidate)
    {
        this.validateKeySize = doValidate;

        return this;
    }

    protected Key extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedEncryptionKey)
        throws CMSException
    {
        if (CMSUtils.isGOST(keyEncryptionAlgorithm.getAlgorithm()))
        {
            try
            {
                GostR3410KeyTransport transport = GostR3410KeyTransport.getInstance(encryptedEncryptionKey);

                GostR3410TransportParameters transParams = transport.getTransportParameters();

                KeyFactory keyFactory = helper.createKeyFactory(keyEncryptionAlgorithm.getAlgorithm());

                PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(transParams.getEphemeralPublicKey().getEncoded()));

                KeyAgreement agreement = helper.createKeyAgreement(keyEncryptionAlgorithm.getAlgorithm());

                agreement.init(recipientKey, new UserKeyingMaterialSpec(transParams.getUkm()));

                agreement.doPhase(pubKey, true);

                SecretKey key = agreement.generateSecret(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_KeyWrap.getId());

                Cipher keyCipher = helper.createCipher(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_KeyWrap);

                keyCipher.init(Cipher.UNWRAP_MODE, key, new GOST28147WrapParameterSpec(transParams.getEncryptionParamSet(), transParams.getUkm()));

                Gost2814789EncryptedKey encKey = transport.getSessionEncryptedKey();

                return keyCipher.unwrap(Arrays.concatenate(encKey.getEncryptedKey(), encKey.getMacKey()), helper.getBaseCipherName(encryptedKeyAlgorithm.getAlgorithm()), Cipher.SECRET_KEY);
            }
            catch (Exception e)
            {
                throw new CMSException("exception unwrapping key: " + e.getMessage(), e);
            }
        }
        else
        {
            JceAsymmetricKeyUnwrapper unwrapper = helper.createAsymmetricUnwrapper(keyEncryptionAlgorithm, recipientKey).setMustProduceEncodableUnwrappedKey(unwrappedKeyMustBeEncodable);

            if (!extraMappings.isEmpty())
            {
                for (Iterator it = extraMappings.keySet().iterator(); it.hasNext(); )
                {
                    ASN1ObjectIdentifier algorithm = (ASN1ObjectIdentifier)it.next();

                    unwrapper.setAlgorithmMapping(algorithm, (String)extraMappings.get(algorithm));
                }
            }

            try
            {
                Key key = helper.getJceKey(encryptedKeyAlgorithm.getAlgorithm(), unwrapper.generateUnwrappedKey(encryptedKeyAlgorithm, encryptedEncryptionKey));

                if (validateKeySize)
                {
                    helper.keySizeCheck(encryptedKeyAlgorithm, key);
                }

                return key;
            }
            catch (OperatorException e)
            {
                throw new CMSException("exception unwrapping key: " + e.getMessage(), e);
            }
        }
    }
}
