package org.bouncycastle.cms.jcajce;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.KEMKeyWrapper;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.SymmetricKeyWrapper;
import org.bouncycastle.operator.jcajce.JceSymmetricKeyWrapper;

public class JceCMSKEMKeyWrapper
    extends KEMKeyWrapper
{
    private final AlgorithmIdentifier kdfAlgorithm;
    private final AlgorithmIdentifier symWrapAlgorithm;
    private final int kekLength;

    private JcaJceExtHelper helper = new DefaultJcaJceExtHelper();
    private Map extraMappings = new HashMap();
    private PublicKey publicKey;
    private SecureRandom random;
    private byte[] encapsulation;

    public JceCMSKEMKeyWrapper(PublicKey publicKey, ASN1ObjectIdentifier kdfAlg, ASN1ObjectIdentifier symWrapAlg)
    {
        super(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()).getAlgorithm());

        this.publicKey = publicKey;
        this.symWrapAlgorithm = new AlgorithmIdentifier(symWrapAlg);
        if (symWrapAlg.equals(CMSAlgorithm.AES256_WRAP))
        {
            this.kekLength = 32;
        }
        else
        {
            throw new IllegalArgumentException("unknown wrap algorithm");
        }
        this.kdfAlgorithm = new AlgorithmIdentifier(kdfAlg, new ASN1Integer(this.kekLength * 8));
    }

    public JceCMSKEMKeyWrapper(X509Certificate certificate, ASN1ObjectIdentifier kdfAlg, ASN1ObjectIdentifier symWrapAlg)
    {
        this(certificate.getPublicKey(), kdfAlg, symWrapAlg);
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

    @Override
    public AlgorithmIdentifier getWrapAlgorithmIdentifier()
    {
        return symWrapAlgorithm;
    }

    public byte[] generateWrappedKey(GenericKey encryptionKey)
        throws OperatorException
    {
        byte[] encryptedKeyBytes = null;

        try
        {
            random = CryptoServicesRegistrar.getSecureRandom(random);
            
            KeyGenerator kGen = KeyGenerator.getInstance(getAlgorithmIdentifier().getAlgorithm().getId(), "BCPQC");
                    
            kGen.init(new KEMGenerateSpec(publicKey, "Secret"), random);

            SecretKeyWithEncapsulation secretKey = (SecretKeyWithEncapsulation)kGen.generateKey();

            this.encapsulation = secretKey.getEncapsulation();

            byte[] secretEnc = secretKey.getEncoded();           // TODO: add UKM
            SHAKEDigest sd = new SHAKEDigest(256);               // TODO: support something other than SHAKE256

            sd.update(secretEnc, 0, secretEnc.length);

            byte[] keyEnc = new byte[kekLength];

            sd.doFinal(keyEnc, 0, keyEnc.length);

            SecretKey wrapKey = new SecretKeySpec(keyEnc, symWrapAlgorithm.getAlgorithm().getId());
            SymmetricKeyWrapper keyWrapper = new JceSymmetricKeyWrapper(wrapKey).setProvider("BC");

            encryptedKeyBytes = keyWrapper.generateWrappedKey(encryptionKey);
        }
        catch (GeneralSecurityException e)
        {
            throw new OperatorException("exception encrypting key: " + e.getMessage(), e);
        }

        return encryptedKeyBytes;
    }
}
