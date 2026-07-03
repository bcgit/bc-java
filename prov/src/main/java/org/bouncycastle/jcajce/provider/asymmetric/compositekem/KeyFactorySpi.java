package org.bouncycastle.jcajce.provider.asymmetric.compositekem;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

/**
 * KeyFactory for Composite ML-KEM keys as defined in
 * <a href="https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html">
 *     Composite ML-KEM for use in X.509 Public Key Infrastructure</a>.
 * The supported parameter sets are registered in {@link CompositeIndex}.
 */
public class KeyFactorySpi
    extends BaseKeyFactorySpi
    implements AsymmetricKeyInfoConverter
{
    //Specific algorithm identifiers of all component signature algorithms for SubjectPublicKeyInfo. These do not need to be all initialized here but makes the code more readable IMHO.
    private static final AlgorithmIdentifier mlKem768 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_alg_ml_kem_768);
    private static final AlgorithmIdentifier mlKem1024 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_alg_ml_kem_1024);

    // RSA-OAEP AlgorithmIdentifier (not RSA encryption)
    private static final AlgorithmIdentifier rsaOAEP = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, createRSAOAEPParams());

    // X25519 AlgorithmIdentifier
    private static final AlgorithmIdentifier x25519KEM = new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519);

    // X448 AlgorithmIdentifier
    private static final AlgorithmIdentifier x448KEM = new AlgorithmIdentifier(EdECObjectIdentifiers.id_X448);

    // ECDH with specific curve parameters (we'll create these as needed)
    private static final AlgorithmIdentifier ecDHP256 = createECDHAlgID(SECObjectIdentifiers.secp256r1);
    private static final AlgorithmIdentifier ecDHP384 = createECDHAlgID(SECObjectIdentifiers.secp384r1);
    private static final AlgorithmIdentifier ecDHP521 = createECDHAlgID(SECObjectIdentifiers.secp521r1);
    private static final AlgorithmIdentifier ecDHBrainpoolP256r1 = createECDHAlgID(TeleTrusTObjectIdentifiers.brainpoolP256r1);
    private static final AlgorithmIdentifier ecDHBrainpoolP384r1 = createECDHAlgID(TeleTrusTObjectIdentifiers.brainpoolP384r1);

    // Helper method to create ECDH AlgorithmIdentifier with curve parameter
    private static AlgorithmIdentifier createECDHAlgID(ASN1ObjectIdentifier curveOID)
    {
        return new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, curveOID);
    }

    // Helper method to create RSA-OAEP parameters as per Section 6.1
    private static ASN1Encodable createRSAOAEPParams()
    {
        try
        {
            AlgorithmIdentifier hashAlg = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
            return new RSAESOAEPparams(hashAlg, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, hashAlg),
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_pSpecified, new DEROctetString(new byte[0])));
        }
        catch (Exception e)
        {
            throw new RuntimeException("Failed to create RSA-OAEP parameters", e);
        }
    }

    private static final Map<ASN1ObjectIdentifier, AlgorithmIdentifier[]> pairings = new HashMap<ASN1ObjectIdentifier, AlgorithmIdentifier[]>();
    private static final Map<ASN1ObjectIdentifier, int[]> componentKeySizes = new HashMap<ASN1ObjectIdentifier, int[]>();

    static
    {
        // ML-KEM-768 + RSA-OAEP algorithms
        pairings.put(IANAObjectIdentifiers.id_MLKEM768_RSA2048_SHA3_256, new AlgorithmIdentifier[]{mlKem768, rsaOAEP});
        pairings.put(IANAObjectIdentifiers.id_MLKEM768_RSA3072_SHA3_256, new AlgorithmIdentifier[]{mlKem768, rsaOAEP});
        pairings.put(IANAObjectIdentifiers.id_MLKEM768_RSA4096_SHA3_256, new AlgorithmIdentifier[]{mlKem768, rsaOAEP});

        // ML-KEM-768 + X25519
        pairings.put(IANAObjectIdentifiers.id_MLKEM768_X25519_SHA3_256, new AlgorithmIdentifier[]{mlKem768, x25519KEM});

        // ML-KEM-768 + ECDH algorithms
        pairings.put(IANAObjectIdentifiers.id_MLKEM768_ECDH_P256_SHA3_256, new AlgorithmIdentifier[]{mlKem768, ecDHP256});
        pairings.put(IANAObjectIdentifiers.id_MLKEM768_ECDH_P384_SHA3_256, new AlgorithmIdentifier[]{mlKem768, ecDHP384});
        pairings.put(IANAObjectIdentifiers.id_MLKEM768_ECDH_BP256_SHA3_256, new AlgorithmIdentifier[]{mlKem768, ecDHBrainpoolP256r1});

        // ML-KEM-1024 + RSA-OAEP algorithms
        pairings.put(IANAObjectIdentifiers.id_MLKEM1024_RSA3072_SHA3_256, new AlgorithmIdentifier[]{mlKem1024, rsaOAEP});

        // ML-KEM-1024 + ECDH algorithms
        pairings.put(IANAObjectIdentifiers.id_MLKEM1024_ECDH_P384_SHA3_256, new AlgorithmIdentifier[]{mlKem1024, ecDHP384});
        pairings.put(IANAObjectIdentifiers.id_MLKEM1024_ECDH_BP384_SHA3_256, new AlgorithmIdentifier[]{mlKem1024, ecDHBrainpoolP384r1});

        // ML-KEM-1024 + X448
        pairings.put(IANAObjectIdentifiers.id_MLKEM1024_X448_SHA3_256, new AlgorithmIdentifier[]{mlKem1024, x448KEM});

        // ML-KEM-1024 + ECDH P521
        pairings.put(IANAObjectIdentifiers.id_MLKEM1024_ECDH_P521_SHA3_256, new AlgorithmIdentifier[]{mlKem1024, ecDHP521});

        // ML-KEM-768 + RSA algorithms
        componentKeySizes.put(IANAObjectIdentifiers.id_MLKEM768_RSA2048_SHA3_256, new int[]{1184, 270}); // 1454 - 1184 = 270
        componentKeySizes.put(IANAObjectIdentifiers.id_MLKEM768_RSA3072_SHA3_256, new int[]{1184, 398}); // 1582 - 1184 = 398
        componentKeySizes.put(IANAObjectIdentifiers.id_MLKEM768_RSA4096_SHA3_256, new int[]{1184, 526}); // 1710 - 1184 = 526

        // ML-KEM-768 + X25519
        componentKeySizes.put(IANAObjectIdentifiers.id_MLKEM768_X25519_SHA3_256, new int[]{1184, 32}); // 1216 - 1184 = 32

        // ML-KEM-768 + ECDH algorithms
        componentKeySizes.put(IANAObjectIdentifiers.id_MLKEM768_ECDH_P256_SHA3_256, new int[]{1184, 65}); // 1249 - 1184 = 65
        componentKeySizes.put(IANAObjectIdentifiers.id_MLKEM768_ECDH_P384_SHA3_256, new int[]{1184, 97}); // 1281 - 1184 = 97
        componentKeySizes.put(IANAObjectIdentifiers.id_MLKEM768_ECDH_BP256_SHA3_256, new int[]{1184, 65}); // 1249 - 1184 = 65

        // ML-KEM-1024 + RSA algorithms
        componentKeySizes.put(IANAObjectIdentifiers.id_MLKEM1024_RSA3072_SHA3_256, new int[]{1568, 398}); // 1966 - 1568 = 398

        // ML-KEM-1024 + ECDH algorithms
        componentKeySizes.put(IANAObjectIdentifiers.id_MLKEM1024_ECDH_P384_SHA3_256, new int[]{1568, 97}); // 1665 - 1568 = 97
        componentKeySizes.put(IANAObjectIdentifiers.id_MLKEM1024_ECDH_BP384_SHA3_256, new int[]{1568, 97}); // 1665 - 1568 = 97

        // ML-KEM-1024 + X448
        componentKeySizes.put(IANAObjectIdentifiers.id_MLKEM1024_X448_SHA3_256, new int[]{1568, 56}); // 1624 - 1568 = 56

        // ML-KEM-1024 + ECDH P521
        componentKeySizes.put(IANAObjectIdentifiers.id_MLKEM1024_ECDH_P521_SHA3_256, new int[]{1568, 133}); // 1701 - 1568 = 133
    }

    private JcaJceHelper helper;

    public KeyFactorySpi()
    {
        this(null);
    }

    public KeyFactorySpi(JcaJceHelper helper)
    {
        this.helper = helper;
    }

    protected Key engineTranslateKey(Key key)
        throws InvalidKeyException
    {
        if (helper == null)
        {
            helper = new BCJcaJceHelper();
        }

        try
        {
            if (key instanceof PrivateKey)
            {
                return generatePrivate(PrivateKeyInfo.getInstance(key.getEncoded()));
            }
            else if (key instanceof PublicKey)
            {
                return generatePublic(SubjectPublicKeyInfo.getInstance(key.getEncoded()));
            }
        }
        catch (IOException e)
        {
            throw new InvalidKeyException("Key could not be parsed: " + e.getMessage());
        }

        throw new InvalidKeyException("Key not recognized");
    }

    /**
     * Creates a {@link CompositePrivateKey} from its PrivateKeyInfo encoded form. Per
     * draft-ietf-lamps-pq-composite-kem the private key body is the 64-byte ML-KEM seed concatenated
     * with the traditional private key encoding; the two components are split and decoded with their
     * respective component key factories.
     *
     * @param keyInfo PrivateKeyInfo whose key body is the concatenation of the two component keys.
     * @return A CompositePrivateKey holding both component private keys.
     * @throws IOException on a malformed encoding.
     */
    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        if (helper == null)
        {
            helper = new BCJcaJceHelper();
        }

        ASN1ObjectIdentifier keyIdentifier = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

        try
        {
            // Composite ML-KEM private key body is the 64-byte ML-KEM seed followed by the
            // traditional private key encoding (draft-ietf-lamps-pq-composite-kem).
            List<KeyFactory> factories = getKeyFactoriesFromIdentifier(keyIdentifier); //Get key factories for each component algorithm.
            byte[] data = keyInfo.getPrivateKey().getOctets();
            int split = 64;
            if (data.length < split)
            {
                throw new IOException("malformed composite private key: body shorter than the ML-KEM seed");
            }
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new DEROctetString(Arrays.copyOfRange(data, 0, split)));
            v.add(new DEROctetString(Arrays.copyOfRange(data, split, data.length)));

            ASN1Sequence seq = new DERSequence(v);

            CompositePrivateKey.Builder builder = CompositePrivateKey.builder(keyIdentifier);
            AlgorithmIdentifier[] algIds = pairings.get(keyIdentifier);
            for (int i = 0; i < seq.size(); i++)
            {
                PKCS8EncodedKeySpec keySpec;
                if (seq.getObjectAt(i) instanceof ASN1OctetString)
                {
                    v = new ASN1EncodableVector(3);

                    v.add(keyInfo.getVersion());
                    v.add(algIds[i]);
                    v.add(seq.getObjectAt(i));

                    keySpec = new PKCS8EncodedKeySpec(PrivateKeyInfo.getInstance(new DERSequence(v)).getEncoded());
                }
                else
                {
                    ASN1Sequence keySeq = ASN1Sequence.getInstance(seq.getObjectAt(i));

                    // We assume each component is of type OneAsymmetricKey (PrivateKeyInfo) as defined by the draft RFC
                    // and use the component key factory to decode the component key from PrivateKeyInfo.
                    keySpec = new PKCS8EncodedKeySpec(PrivateKeyInfo.getInstance(keySeq).getEncoded());
                }
                builder.addPrivateKey(factories.get(i).generatePrivate(keySpec), factories.get(i).getProvider());
            }
            return builder.build();
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.ioException(e.getMessage(), e);
        }
    }

    /**
     * Creates a {@link CompositePublicKey} from its SubjectPublicKeyInfo encoded form. Per
     * draft-ietf-lamps-pq-composite-kem the public key is the concatenation of the two raw component
     * public keys; it is split at the fixed ML-KEM public key size and each component is decoded with
     * its key factory.
     *
     * @param keyInfo SubjectPublicKeyInfo whose key body is the concatenation of the two component public keys.
     * @return A CompositePublicKey holding both component public keys.
     * @throws IOException on a malformed encoding.
     */
    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        if (helper == null)
        {
            helper = new BCJcaJceHelper();
        }

        ASN1ObjectIdentifier keyIdentifier = keyInfo.getAlgorithm().getAlgorithm();

        byte[][] componentKeys = split(keyIdentifier, keyInfo.getPublicKeyData());

        try
        {
            int numKeys = componentKeys.length;

            List<KeyFactory> factories = getKeyFactoriesFromIdentifier(keyIdentifier);
            ASN1BitString[] componentBitStrings = new ASN1BitString[numKeys];
            for (int i = 0; i < numKeys; i++)
            {
                componentBitStrings[i] = new DERBitString(componentKeys[i]);
            }

            // We need to get X509EncodedKeySpec to use key factories to produce component public keys.
            X509EncodedKeySpec[] x509EncodedKeySpecs = getKeysSpecs(keyIdentifier, componentBitStrings);
            CompositePublicKey.Builder builder = CompositePublicKey.builder(keyIdentifier);
            for (int i = 0; i < numKeys; i++)
            {
                builder.addPublicKey(factories.get(i).generatePublic(x509EncodedKeySpecs[i]), factories.get(i).getProvider());
            }
            return builder.build();
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.ioException(e.getMessage(), e);
        }
    }

    byte[][] split(ASN1ObjectIdentifier algorithm, ASN1BitString publicKeyData)
        throws IOException
    {
        int[] sizes = componentKeySizes.get(algorithm);
        byte[] keyData = publicKeyData.getOctets();
        if (sizes == null || keyData.length < sizes[0])
        {
            throw new IOException("malformed composite public key: body shorter than the first component");
        }
        byte[][] components = new byte[][]{new byte[sizes[0]], new byte[keyData.length - sizes[0]]};
        System.arraycopy(keyData, 0, components[0], 0, sizes[0]);
        System.arraycopy(keyData, sizes[0], components[1], 0, components[1].length);
        return components;
    }

    /**
     * A helper method that returns a list of KeyFactory objects based on the composite signature OID.
     *
     * @param algorithmIdentifier OID of a composite signature.
     * @return A list of KeyFactories ordered by the composite signature definition.
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    private List<KeyFactory> getKeyFactoriesFromIdentifier(ASN1ObjectIdentifier algorithmIdentifier)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        List<KeyFactory> factories = new ArrayList<KeyFactory>();

        String[] pairings = CompositeIndex.getPairing(algorithmIdentifier);

        if (pairings == null)
        {
            throw new NoSuchAlgorithmException("Cannot create KeyFactories. Unsupported algorithm identifier.");
        }

        factories.add(helper.createKeyFactory(CompositeIndex.getBaseName(pairings[0])));
        factories.add(helper.createKeyFactory(CompositeIndex.getBaseName(pairings[1])));
        return Collections.unmodifiableList(factories);
    }


    /**
     * A helper method that returns an array of X509EncodedKeySpecs based on the composite signature OID
     * and the content of provided BIT STRINGs in subjectPublicKeys
     *
     * @param algorithmIdentifier OID of a composite signature.
     * @param subjectPublicKeys   A BIT STRING array containing encoded component SubjectPublicKeyInfos.
     * @return An array of X509EncodedKeySpecs
     * @throws IOException
     */
    private X509EncodedKeySpec[] getKeysSpecs(ASN1ObjectIdentifier algorithmIdentifier, ASN1BitString[] subjectPublicKeys)
        throws IOException
    {
        X509EncodedKeySpec[] specs = new X509EncodedKeySpec[subjectPublicKeys.length];
        SubjectPublicKeyInfo[] keyInfos = new SubjectPublicKeyInfo[subjectPublicKeys.length];

        AlgorithmIdentifier[] algIds = pairings.get(algorithmIdentifier);

        if (algIds == null)
        {
            throw new IOException("Cannot create key specs. Unsupported algorithm identifier.");
        }

        keyInfos[0] = new SubjectPublicKeyInfo(algIds[0], subjectPublicKeys[0]);
        keyInfos[1] = new SubjectPublicKeyInfo(algIds[1], subjectPublicKeys[1]);

        specs[0] = new X509EncodedKeySpec(keyInfos[0].getEncoded());
        specs[1] = new X509EncodedKeySpec(keyInfos[1].getEncoded());
        return specs;
    }
}
