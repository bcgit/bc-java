package org.bouncycastle.cms.jcajce;

import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.interfaces.RSAPrivateKey;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSORIforKEMOtherInfo;
import org.bouncycastle.asn1.cms.KEMRecipientInfo;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.operator.AsymmetricKeyUnwrapper;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.SymmetricKeyUnwrapper;
import org.bouncycastle.operator.jcajce.JceGenericKey;
import org.bouncycastle.operator.jcajce.JceSymmetricKeyUnwrapper;
import org.bouncycastle.util.Arrays;

class JceCMSKEMKeyUnwrapper
    extends AsymmetricKeyUnwrapper
{
    private final AlgorithmIdentifier symWrapAlgorithm;
    private final int kekLength;

    private JcaJceExtHelper helper = new DefaultJcaJceExtHelper();
    private Map extraMappings = new HashMap();
    private PrivateKey privateKey;

    public JceCMSKEMKeyUnwrapper(AlgorithmIdentifier symWrapAlg, PrivateKey privateKey)
    {
        super(PrivateKeyInfo.getInstance(privateKey.getEncoded()).getPrivateKeyAlgorithm());

        KEMRecipientInfo gktParams = KEMRecipientInfo.getInstance(symWrapAlg.getParameters());

        this.privateKey = privateKey;
        this.symWrapAlgorithm = symWrapAlg;
        this.kekLength = CMSUtils.getKekSize(gktParams.getWrap().getAlgorithm());
    }

    public JceCMSKEMKeyUnwrapper setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceExtHelper(provider);

        return this;
    }

    public JceCMSKEMKeyUnwrapper setProvider(String providerName)
    {
        this.helper = new NamedJcaJceExtHelper(providerName);

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
     * @return the current Wrapper.
     */
    public JceCMSKEMKeyUnwrapper setAlgorithmMapping(ASN1ObjectIdentifier algorithm, String algorithmName)
    {
        extraMappings.put(algorithm, algorithmName);

        return this;
    }

    public int getKekLength()
    {
        return kekLength;
    }

//    @Override
//    public AlgorithmIdentifier getWrapAlgorithmIdentifier()
//    {
//        return symWrapAlgorithm;
//    }

    public GenericKey generateUnwrappedKey(AlgorithmIdentifier encryptionKeyAlgorithm, byte[] encryptedKey)
        throws OperatorException
    {
        KEMRecipientInfo kemInfo = KEMRecipientInfo.getInstance(symWrapAlgorithm.getParameters());
        AlgorithmIdentifier symWrapAlgorithm = kemInfo.getWrap();
        try
        {
            byte[] oriInfoEnc = new CMSORIforKEMOtherInfo(symWrapAlgorithm, kekLength).getEncoded();

            if (privateKey instanceof RSAPrivateKey)
            {
                Cipher keyEncryptionCipher = CMSUtils.createAsymmetricWrapper(helper, kemInfo.getKem().getAlgorithm(), new HashMap());

                try
                {
                    String wrapAlgorithmName = CMSUtils.getWrapAlgorithmName(symWrapAlgorithm.getAlgorithm());
                    KTSParameterSpec ktsSpec = new KTSParameterSpec.Builder(wrapAlgorithmName, kekLength * 8, oriInfoEnc).withKdfAlgorithm(kemInfo.getKdf()).build();

                    keyEncryptionCipher.init(Cipher.UNWRAP_MODE, privateKey, ktsSpec);

                    Key wrapKey = keyEncryptionCipher.unwrap(Arrays.concatenate(kemInfo.getKemct().getOctets(), kemInfo.getEncryptedKey().getOctets()), wrapAlgorithmName, Cipher.SECRET_KEY);

                    return new JceGenericKey(encryptionKeyAlgorithm, wrapKey);
                }
                catch (Exception e)
                {
                    throw new OperatorException("Unable to wrap contents key: " + e.getMessage(), e);
                }
            }
            else
            {
                KeyGenerator kGen = KeyGenerator.getInstance(getAlgorithmIdentifier().getAlgorithm().getId(), "BCPQC");

                kGen.init(new KEMExtractSpec(privateKey, kemInfo.getKemct().getOctets(), "Secret"));

                SecretKeyWithEncapsulation secretKey = (SecretKeyWithEncapsulation)kGen.generateKey();

                AlgorithmIdentifier wrapAlg = kemInfo.getWrap();

                byte[] secretEnc = secretKey.getEncoded();           // TODO: add UKM
                SHAKEDigest sd = new SHAKEDigest(256);               // TODO: support something other than SHAKE256

                sd.update(secretEnc, 0, secretEnc.length);

                sd.update(oriInfoEnc, 0, oriInfoEnc.length);

                byte[] keyEnc = new byte[kekLength];

                sd.doFinal(keyEnc, 0, keyEnc.length);

                SecretKey wrapKey = new SecretKeySpec(keyEnc, wrapAlg.getAlgorithm().getId());
                SymmetricKeyUnwrapper keyWrapper = new JceSymmetricKeyUnwrapper(wrapAlg, wrapKey).setProvider("BC");

                return keyWrapper.generateUnwrappedKey(encryptionKeyAlgorithm, kemInfo.getEncryptedKey().getOctets());
            }
        }
        catch (Exception e)
        {
            throw new OperatorException("exception encrypting key: " + e.getMessage(), e);
        }
    }
}
