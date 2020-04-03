package org.bouncycastle.operator.jcajce;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.Gost2814789EncryptedKey;
import org.bouncycastle.asn1.cryptopro.GostR3410KeyTransport;
import org.bouncycastle.asn1.cryptopro.GostR3410TransportParameters;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.spec.GOST28147WrapParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.operator.AsymmetricKeyWrapper;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.util.Arrays;

public class JceAsymmetricKeyWrapper
    extends AsymmetricKeyWrapper
{
    private static final Set gostAlgs = new HashSet();

    static
    {
        gostAlgs.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_ESDH);
        gostAlgs.add(CryptoProObjectIdentifiers.gostR3410_2001);
        gostAlgs.add(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256);
        gostAlgs.add(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512);
        gostAlgs.add(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256);
        gostAlgs.add(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512);
    }

    static boolean isGOST(ASN1ObjectIdentifier algorithm)
    {
        return gostAlgs.contains(algorithm);
    }

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

    /**
     * Create a wrapper, overriding the algorithm type that is stored in the public key.
     *
     * @param algorithmIdentifier identifier for encryption algorithm to be used.
     * @param publicKey the public key to be used.
     */
    public JceAsymmetricKeyWrapper(AlgorithmIdentifier algorithmIdentifier, PublicKey publicKey)
    {
        super(algorithmIdentifier);

        this.publicKey = publicKey;
    }

    /**
     * Create a wrapper, overriding the algorithm type that is stored in the public key.
     *
     * @param algorithmParams algorithm parameters for encryption algorithm to be used.
     * @param publicKey the public key to be used.
     */
    public JceAsymmetricKeyWrapper(AlgorithmParameters algorithmParams, PublicKey publicKey)
        throws InvalidParameterSpecException
    {
        super(extractFromSpec(algorithmParams.getParameterSpec(AlgorithmParameterSpec.class)));

        this.publicKey = publicKey;
    }

    /**
     * Create a wrapper, overriding the algorithm type that is stored in the public key.
     *
     * @param algorithmParameterSpec the parameterSpec for encryption algorithm to be used.
     * @param publicKey the public key to be used.
     */
    public JceAsymmetricKeyWrapper(AlgorithmParameterSpec algorithmParameterSpec, PublicKey publicKey)
    {
        super(extractFromSpec(algorithmParameterSpec));

        this.publicKey = publicKey;
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
        byte[] encryptedKeyBytes = null;

        if (isGOST(getAlgorithmIdentifier().getAlgorithm()))
        {
            try
            {
                random = CryptoServicesRegistrar.getSecureRandom(random);

                KeyPairGenerator kpGen = helper.createKeyPairGenerator(getAlgorithmIdentifier().getAlgorithm());

                kpGen.initialize(((ECPublicKey)publicKey).getParams(), random);

                KeyPair ephKp = kpGen.generateKeyPair();

                byte[] ukm = new byte[8];

                random.nextBytes(ukm);

                SubjectPublicKeyInfo ephKeyInfo = SubjectPublicKeyInfo.getInstance(ephKp.getPublic().getEncoded());

                GostR3410TransportParameters transParams;

                if (ephKeyInfo.getAlgorithm().getAlgorithm().on(RosstandartObjectIdentifiers.id_tc26))
                {
                    transParams = new GostR3410TransportParameters(
                        RosstandartObjectIdentifiers.id_tc26_gost_28147_param_Z, ephKeyInfo, ukm);
                }
                else
                {
                    transParams = new GostR3410TransportParameters(
                                CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_A_ParamSet, ephKeyInfo, ukm);
                }

                KeyAgreement agreement = helper.createKeyAgreement(getAlgorithmIdentifier().getAlgorithm());

                agreement.init(ephKp.getPrivate(), new UserKeyingMaterialSpec(transParams.getUkm()));

                agreement.doPhase(publicKey, true);

                SecretKey key = agreement.generateSecret(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_KeyWrap.getId());
      
                byte[] encKey = OperatorUtils.getJceKey(encryptionKey).getEncoded();

                Cipher keyCipher = helper.createCipher(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_KeyWrap);

                keyCipher.init(Cipher.WRAP_MODE, key, new GOST28147WrapParameterSpec(transParams.getEncryptionParamSet(), transParams.getUkm()));

                byte[] keyData = keyCipher.wrap(new SecretKeySpec(encKey, "GOST"));

                GostR3410KeyTransport transport = new GostR3410KeyTransport(
                                new Gost2814789EncryptedKey(
                                    Arrays.copyOfRange(keyData, 0, 32), Arrays.copyOfRange(keyData, 32, 36)), transParams);

                return transport.getEncoded();
            }
            catch (Exception e)
            {
                throw new OperatorException("exception wrapping key: " + e.getMessage(), e);
            }
        }
        else
        {
            Cipher keyEncryptionCipher = helper.createAsymmetricWrapper(getAlgorithmIdentifier().getAlgorithm(), extraMappings);

            try
            {
                AlgorithmParameters algParams = helper.createAlgorithmParameters(this.getAlgorithmIdentifier());

                if (algParams != null)
                {
                    keyEncryptionCipher.init(Cipher.WRAP_MODE, publicKey, algParams, random);
                }
                else
                {
                    keyEncryptionCipher.init(Cipher.WRAP_MODE, publicKey, random);
                }
                encryptedKeyBytes = keyEncryptionCipher.wrap(OperatorUtils.getJceKey(encryptionKey));
            }
            catch (InvalidKeyException e)
            {
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
                catch (InvalidKeyException e)
                {
                    throw new OperatorException("unable to encrypt contents key", e);
                }
                catch (GeneralSecurityException e)
                {
                    throw new OperatorException("unable to encrypt contents key", e);
                }
            }
        }

        return encryptedKeyBytes;
    }

    private static AlgorithmIdentifier extractFromSpec(AlgorithmParameterSpec algorithmParameterSpec)
    {
        if (algorithmParameterSpec instanceof OAEPParameterSpec)
        {
            OAEPParameterSpec oaepSpec = (OAEPParameterSpec)algorithmParameterSpec;

            if (oaepSpec.getMGFAlgorithm().equals(OAEPParameterSpec.DEFAULT.getMGFAlgorithm()))
            {
                if (oaepSpec.getPSource() instanceof PSource.PSpecified)
                {
                    return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP,
                        new RSAESOAEPparams(getDigest(oaepSpec.getDigestAlgorithm()),
                            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, getDigest(((MGF1ParameterSpec)oaepSpec.getMGFParameters()).getDigestAlgorithm())),
                            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_pSpecified, new DEROctetString(((PSource.PSpecified)oaepSpec.getPSource()).getValue()))));
                }
                else
                {
                    throw new IllegalArgumentException("unknown PSource: " + oaepSpec.getPSource().getAlgorithm());
                }
            }
            else
            {
                throw new IllegalArgumentException("unknown MGF: " + oaepSpec.getMGFAlgorithm());
            }
        }

        throw new IllegalArgumentException("unknown spec: " + algorithmParameterSpec.getClass().getName());
    }

    private static final Map digests = new HashMap();

    static
    {
        digests.put("SHA1", new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE));
        digests.put("SHA-1", new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE));
        digests.put("SHA224", new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha224, DERNull.INSTANCE));
        digests.put("SHA-224", new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha224, DERNull.INSTANCE));
        digests.put("SHA256", new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE));
        digests.put("SHA-256", new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE));
        digests.put("SHA384", new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384, DERNull.INSTANCE));
        digests.put("SHA-384", new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384, DERNull.INSTANCE));
        digests.put("SHA512", new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512, DERNull.INSTANCE));
        digests.put("SHA-512", new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512, DERNull.INSTANCE));
        digests.put("SHA512/224", new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512_224, DERNull.INSTANCE));
        digests.put("SHA-512/224", new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512_224, DERNull.INSTANCE));
        digests.put("SHA-512(224)", new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512_224, DERNull.INSTANCE));
        digests.put("SHA512/256", new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512_256, DERNull.INSTANCE));
        digests.put("SHA-512/256", new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512_256, DERNull.INSTANCE));
        digests.put("SHA-512(256)", new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512_256, DERNull.INSTANCE));
    }

    private static AlgorithmIdentifier getDigest(String digest)
    {
        AlgorithmIdentifier algId = (AlgorithmIdentifier)digests.get(digest);

        if (algId != null)
        {
            return algId;
        }

        throw new IllegalArgumentException("unknown digest name: " + digest);
    }
}
