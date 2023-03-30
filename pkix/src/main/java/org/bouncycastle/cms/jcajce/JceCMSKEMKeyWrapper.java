package org.bouncycastle.cms.jcajce;

import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.CMSORIforKEMOtherInfo;
import org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.KEMKeyWrapper;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.pqc.jcajce.interfaces.KyberPublicKey;
import org.bouncycastle.pqc.jcajce.interfaces.NTRUKey;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.NTRUParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

class JceCMSKEMKeyWrapper
    extends KEMKeyWrapper
{
    private final AlgorithmIdentifier symWrapAlgorithm;
    private final int kekLength;

    private JcaJceExtHelper helper = new DefaultJcaJceExtHelper();
    private Map extraMappings = new HashMap();
    private PublicKey publicKey;
    private SecureRandom random;
    private AlgorithmIdentifier kdfAlgorithm = new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE));
    private byte[] encapsulation;

    public JceCMSKEMKeyWrapper(PublicKey publicKey, ASN1ObjectIdentifier symWrapAlg)
    {
        super(publicKey instanceof RSAPublicKey ? new AlgorithmIdentifier(ISOIECObjectIdentifiers.id_kem_rsa) : SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()).getAlgorithm());

        this.publicKey = publicKey;
        this.symWrapAlgorithm = new AlgorithmIdentifier(symWrapAlg);
        this.kekLength = CMSUtils.getKekSize(symWrapAlg);
    }

    public JceCMSKEMKeyWrapper setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceExtHelper(provider);

        return this;
    }

    public JceCMSKEMKeyWrapper setProvider(String providerName)
    {
        this.helper = new NamedJcaJceExtHelper(providerName);

        return this;
    }

    public JceCMSKEMKeyWrapper setKDF(AlgorithmIdentifier kdfAlgorithm)
    {
        this.kdfAlgorithm = kdfAlgorithm;

        return this;
    }

    public JceCMSKEMKeyWrapper setSecureRandom(SecureRandom random)
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
     * @param algorithm  OID of algorithm in recipient.
     * @param algorithmName JCE algorithm name to use.
     * @return the current Wrapper.
     */
    public JceCMSKEMKeyWrapper setAlgorithmMapping(ASN1ObjectIdentifier algorithm, String algorithmName)
    {
        extraMappings.put(algorithm, algorithmName);

        return this;
    }

    public byte[] getEncapsulation()
    {
        return encapsulation;
    }

    public AlgorithmIdentifier getKdfAlgorithmIdentifier()
    {
        return kdfAlgorithm;
    }

    public int getKekLength()
    {
        return kekLength;
    }

    public AlgorithmIdentifier getWrapAlgorithmIdentifier()
    {
        return symWrapAlgorithm;
    }

    public byte[] generateWrappedKey(GenericKey encryptionKey)
        throws OperatorException
    {
        try
        {
            byte[] oriInfoEnc = new CMSORIforKEMOtherInfo(symWrapAlgorithm, kekLength).getEncoded();

            if (publicKey instanceof RSAPublicKey)
            {
                Cipher keyEncryptionCipher = CMSUtils.createAsymmetricWrapper(helper, getAlgorithmIdentifier().getAlgorithm(), new HashMap());
                      
                try
                {
                    KTSParameterSpec ktsSpec = new KTSParameterSpec.Builder(CMSUtils.getWrapAlgorithmName(symWrapAlgorithm.getAlgorithm()), kekLength * 8, oriInfoEnc).withKdfAlgorithm(kdfAlgorithm).build();

                    keyEncryptionCipher.init(Cipher.WRAP_MODE, publicKey, ktsSpec, random);

                    byte[] encWithKey = keyEncryptionCipher.wrap(CMSUtils.getJceKey(encryptionKey));

                    int modLength = (((RSAPublicKey)publicKey).getModulus().bitLength() + 7) / 8;

                    encapsulation = Arrays.copyOfRange(encWithKey, 0, modLength);

                    return Arrays.copyOfRange(encWithKey, modLength, encWithKey.length);
                }
                catch (Exception e)
                {
                    throw new OperatorException("Unable to wrap contents key: " + e.getMessage(), e);
                }
            }
            else
            {
                Cipher keyEncryptionCipher = CMSUtils.createAsymmetricWrapper(helper, getAlgorithmIdentifier().getAlgorithm(), new HashMap());

                try
                {
                    KTSParameterSpec ktsSpec = new KTSParameterSpec.Builder(CMSUtils.getWrapAlgorithmName(symWrapAlgorithm.getAlgorithm()), kekLength * 8, oriInfoEnc).withKdfAlgorithm(kdfAlgorithm).build();

                    keyEncryptionCipher.init(Cipher.WRAP_MODE, publicKey, ktsSpec, random);

                    byte[] encWithKey = keyEncryptionCipher.wrap(CMSUtils.getJceKey(encryptionKey));

                    int encLength = getKemEncLength(publicKey);

                    encapsulation = Arrays.copyOfRange(encWithKey, 0, encLength);

                    return Arrays.copyOfRange(encWithKey, encLength, encWithKey.length);
                }
                catch (Exception e)
                {
                    throw new OperatorException("Unable to wrap contents key: " + e.getMessage(), e);
                }
            }
        }
        catch (Exception e)
        {
            throw new OperatorException("unable to wrap contents key: " + e.getMessage(), e);
        }
    }

    private static Map encLengths = new HashMap();

    static
    {
        encLengths.put(KyberParameterSpec.kyber512.getName(), Integers.valueOf(768));
        encLengths.put(KyberParameterSpec.kyber768.getName(), Integers.valueOf(1088));
        encLengths.put(KyberParameterSpec.kyber1024.getName(), Integers.valueOf(1568));

        encLengths.put(NTRUParameterSpec.ntruhps2048509.getName(), Integers.valueOf(699));
        encLengths.put(NTRUParameterSpec.ntruhps2048677.getName(), Integers.valueOf(930));
        encLengths.put(NTRUParameterSpec.ntruhps4096821.getName(), Integers.valueOf(1230));
        encLengths.put(NTRUParameterSpec.ntruhrss701.getName(), Integers.valueOf(1138));
    }

    private int getKemEncLength(PublicKey publicKey)
    {
        if (publicKey instanceof KyberPublicKey)
        {
            return ((Integer)encLengths.get(((KyberPublicKey)publicKey).getParameterSpec().getName())).intValue();
        }
        if (publicKey instanceof NTRUKey)
        {
            return ((Integer)encLengths.get(((NTRUKey)publicKey).getParameterSpec().getName())).intValue();
        }
        return 0;
    }
}
