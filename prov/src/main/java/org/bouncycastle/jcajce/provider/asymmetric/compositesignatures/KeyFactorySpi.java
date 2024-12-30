package org.bouncycastle.jcajce.provider.asymmetric.compositesignatures;

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
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.math.ec.rfc8032.Ed448;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

/**
 * KeyFactory for composite signatures. List of supported combinations is in CompositeSignaturesConstants
 */
public class KeyFactorySpi
    extends BaseKeyFactorySpi
    implements AsymmetricKeyInfoConverter
{

    //Specific algorithm identifiers of all component signature algorithms for SubjectPublicKeyInfo. These do not need to be all initialized here but makes the code more readable IMHO.
    private static final AlgorithmIdentifier mlDsa44 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_44);
    private static final AlgorithmIdentifier mlDsa65 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_65);
    private static final AlgorithmIdentifier mlDsa87 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_87);
    private static final AlgorithmIdentifier falcon512Identifier = new AlgorithmIdentifier(BCObjectIdentifiers.falcon_512);
    private static final AlgorithmIdentifier ed25519 = new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519);
    private static final AlgorithmIdentifier ecDsaP256 = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, new X962Parameters(SECObjectIdentifiers.secp256r1));
    private static final AlgorithmIdentifier ecDsaBrainpoolP256r1 = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, new X962Parameters(TeleTrusTObjectIdentifiers.brainpoolP256r1));
    private static final AlgorithmIdentifier rsa = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption);
    private static final AlgorithmIdentifier ed448 = new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448);
    private static final AlgorithmIdentifier ecDsaP384 = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, new X962Parameters(SECObjectIdentifiers.secp384r1));
    private static final AlgorithmIdentifier ecDsaBrainpoolP384r1 = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, new X962Parameters(TeleTrusTObjectIdentifiers.brainpoolP384r1));

    private static Map<ASN1ObjectIdentifier, AlgorithmIdentifier[]> pairings = new HashMap<ASN1ObjectIdentifier, AlgorithmIdentifier[]>();
    private static Map<ASN1ObjectIdentifier, int[]> componentKeySizes = new HashMap<ASN1ObjectIdentifier, int[]>();
    
    static
    {
        pairings.put(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256, new AlgorithmIdentifier[]{mlDsa44, rsa});
        pairings.put(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256, new AlgorithmIdentifier[]{mlDsa44, rsa});
        pairings.put(MiscObjectIdentifiers.id_MLDSA44_Ed25519_SHA512, new AlgorithmIdentifier[]{mlDsa44, ed25519});
        pairings.put(MiscObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256, new AlgorithmIdentifier[]{mlDsa44, ecDsaP256});
        pairings.put(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA256, new AlgorithmIdentifier[]{mlDsa65, rsa});
        pairings.put(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA256, new AlgorithmIdentifier[]{mlDsa65, rsa});
        pairings.put(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA384, new AlgorithmIdentifier[]{mlDsa65, rsa});
        pairings.put(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA384, new AlgorithmIdentifier[]{mlDsa65, rsa});
        pairings.put(MiscObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA384, new AlgorithmIdentifier[]{mlDsa65, ecDsaP384});
        pairings.put(MiscObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA256, new AlgorithmIdentifier[]{mlDsa65, ecDsaBrainpoolP256r1});
        pairings.put(MiscObjectIdentifiers.id_MLDSA65_Ed25519_SHA512, new AlgorithmIdentifier[]{mlDsa65, ed25519});
        pairings.put(MiscObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA384, new AlgorithmIdentifier[]{mlDsa87, ecDsaP384});
        pairings.put(MiscObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA384, new AlgorithmIdentifier[]{mlDsa87, ecDsaBrainpoolP384r1});
        pairings.put(MiscObjectIdentifiers.id_MLDSA87_Ed448_SHA512, new AlgorithmIdentifier[]{mlDsa87, ed448});

        pairings.put(MiscObjectIdentifiers.id_HashMLDSA44_RSA2048_PSS_SHA256, new AlgorithmIdentifier[]{mlDsa44, rsa});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA44_RSA2048_PKCS15_SHA256, new AlgorithmIdentifier[]{mlDsa44, rsa});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA44_Ed25519_SHA512, new AlgorithmIdentifier[]{mlDsa44, ed25519});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA44_ECDSA_P256_SHA256, new AlgorithmIdentifier[]{mlDsa44, ecDsaP256});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA65_RSA3072_PSS_SHA512, new AlgorithmIdentifier[]{mlDsa65, rsa});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA65_RSA3072_PKCS15_SHA512, new AlgorithmIdentifier[]{mlDsa65, rsa});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA65_RSA4096_PSS_SHA512, new AlgorithmIdentifier[]{mlDsa65, rsa});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA65_RSA4096_PKCS15_SHA512, new AlgorithmIdentifier[]{mlDsa65, rsa});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA65_ECDSA_P384_SHA512, new AlgorithmIdentifier[]{mlDsa65, ecDsaP384});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA65_ECDSA_brainpoolP256r1_SHA512, new AlgorithmIdentifier[]{mlDsa65, ecDsaBrainpoolP256r1});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA65_Ed25519_SHA512, new AlgorithmIdentifier[]{mlDsa65, ed25519});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA87_ECDSA_P384_SHA512, new AlgorithmIdentifier[]{mlDsa87, ecDsaP384});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA87_ECDSA_brainpoolP384r1_SHA512, new AlgorithmIdentifier[]{mlDsa87, ecDsaBrainpoolP384r1});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA87_Ed448_SHA512, new AlgorithmIdentifier[] { mlDsa87, ed448});

        componentKeySizes.put(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256, new int[]{1328, 268});
        componentKeySizes.put(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256, new int[]{1312, 284});
        componentKeySizes.put(MiscObjectIdentifiers.id_MLDSA44_Ed25519_SHA512, new int[]{1312, Ed25519.PUBLIC_KEY_SIZE});
        componentKeySizes.put(MiscObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256, new int[]{1312, 76});
        componentKeySizes.put(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA256, new int[]{1952, 256});
        componentKeySizes.put(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA256, new int[]{1952, 256});
        componentKeySizes.put(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA384, new int[]{1952, 542});
        componentKeySizes.put(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA384, new int[]{1952, 542});
        componentKeySizes.put(MiscObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA384, new int[]{1952, 87});
        componentKeySizes.put(MiscObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA256, new int[]{1952, 76});
        componentKeySizes.put(MiscObjectIdentifiers.id_MLDSA65_Ed25519_SHA512, new int[]{1952, Ed25519.PUBLIC_KEY_SIZE});
        componentKeySizes.put(MiscObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA384, new int[]{2592, 87});
        componentKeySizes.put(MiscObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA384, new int[]{2592, 87});
        componentKeySizes.put(MiscObjectIdentifiers.id_MLDSA87_Ed448_SHA512, new int[]{2592, Ed448.PUBLIC_KEY_SIZE});

        componentKeySizes.put(MiscObjectIdentifiers.id_HashMLDSA44_RSA2048_PSS_SHA256, new int[]{1328, 268});
        componentKeySizes.put(MiscObjectIdentifiers.id_HashMLDSA44_RSA2048_PKCS15_SHA256, new int[]{1312, 284});
        componentKeySizes.put(MiscObjectIdentifiers.id_HashMLDSA44_Ed25519_SHA512, new int[]{1312, Ed25519.PUBLIC_KEY_SIZE});
        componentKeySizes.put(MiscObjectIdentifiers.id_HashMLDSA44_ECDSA_P256_SHA256, new int[]{1312, 76});
        componentKeySizes.put(MiscObjectIdentifiers.id_HashMLDSA65_RSA3072_PSS_SHA512, new int[]{1952, 256});
        componentKeySizes.put(MiscObjectIdentifiers.id_HashMLDSA65_RSA3072_PKCS15_SHA512, new int[]{1952, 256});
        componentKeySizes.put(MiscObjectIdentifiers.id_HashMLDSA65_RSA4096_PSS_SHA512, new int[]{1952, 542});
        componentKeySizes.put(MiscObjectIdentifiers.id_HashMLDSA65_RSA4096_PKCS15_SHA512, new int[]{1952, 542});
        componentKeySizes.put(MiscObjectIdentifiers.id_HashMLDSA65_ECDSA_P384_SHA512, new int[]{1952, 87});
        componentKeySizes.put(MiscObjectIdentifiers.id_HashMLDSA65_ECDSA_brainpoolP256r1_SHA512, new int[]{1952, 76});
        componentKeySizes.put(MiscObjectIdentifiers.id_HashMLDSA65_Ed25519_SHA512, new int[]{1952, Ed25519.PUBLIC_KEY_SIZE});
        componentKeySizes.put(MiscObjectIdentifiers.id_HashMLDSA87_ECDSA_P384_SHA512, new int[]{2592, 87});
        componentKeySizes.put(MiscObjectIdentifiers.id_HashMLDSA87_ECDSA_brainpoolP384r1_SHA512, new int[]{2592, 87});
        componentKeySizes.put(MiscObjectIdentifiers.id_HashMLDSA87_Ed448_SHA512, new int[] { 2592, Ed448.PUBLIC_KEY_SIZE});
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
     * Creates a CompositePrivateKey from its PrivateKeyInfo encoded form.
     * It is compliant with https://www.ietf.org/archive/id/draft-ounsworth-pq-composite-sigs-13.html where
     * CompositeSignaturePrivateKey is a sequence of two OneAsymmetricKey which a newer name for PrivateKeyInfo.
     *
     * @param keyInfo PrivateKeyInfo containing a sequence of PrivateKeyInfos corresponding to each component.
     * @return A CompositePrivateKey created from all components in the sequence.
     * @throws IOException
     */
    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        if (helper == null)
        {
            helper = new BCJcaJceHelper();
        }

        ASN1ObjectIdentifier keyIdentifier = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

        if (MiscObjectIdentifiers.id_alg_composite.equals(keyIdentifier)
            || MiscObjectIdentifiers.id_composite_key.equals(keyIdentifier))
        {
            ASN1Sequence seq = DERSequence.getInstance(keyInfo.parsePrivateKey());

            PrivateKey[] privKeys = new PrivateKey[seq.size()];

            for (int i = 0; i != seq.size(); i++)
            {
                ASN1Sequence kSeq = ASN1Sequence.getInstance(seq.getObjectAt(i));

                PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(kSeq);

                try
                {
                    privKeys[i] = helper.createKeyFactory(
                        privInfo.getPrivateKeyAlgorithm().getAlgorithm().getId()).generatePrivate(new PKCS8EncodedKeySpec(privInfo.getEncoded()));
                }
                catch (Exception e)
                {
                    throw new IOException("cannot decode generic composite: " + e.getMessage(), e);
                }
            }

            return new CompositePrivateKey(privKeys);
        }
        try
        {
            ASN1Sequence seq;
            // TODO: backwards compatibility code - should be deleted after 1.84.
            try
            {
                ASN1Encodable obj = keyInfo.parsePrivateKey();
                if (obj instanceof ASN1OctetString)
                {
                    seq = DERSequence.getInstance(ASN1OctetString.getInstance(obj).getOctets());
                }
                else
                {
                    seq = DERSequence.getInstance(obj);
                }
            }
            catch (Exception e)
            {
                // new raw encoding - we capitalise on the fact initial key is first 32 bytes.
                ASN1EncodableVector v = new ASN1EncodableVector();
                byte[] data = keyInfo.getPrivateKey().getOctets();

                v.add(new DEROctetString(Arrays.copyOfRange(data, 0, 32)));
                v.add(new DEROctetString(Arrays.copyOfRange(data, 32, data.length)));

                seq = new DERSequence(v);
            }

            List<KeyFactory> factories = getKeyFactoriesFromIdentifier(keyIdentifier); //Get key factories for each component algorithm.
            PrivateKey[] privateKeys = new PrivateKey[seq.size()];
            AlgorithmIdentifier[] algIds = pairings.get(keyIdentifier);
            for (int i = 0; i < seq.size(); i++)
            {
                if (seq.getObjectAt(i) instanceof ASN1OctetString)
                {
                    ASN1EncodableVector v = new ASN1EncodableVector(3);

                    v.add(keyInfo.getVersion());
                    v.add(algIds[i]);
                    v.add(seq.getObjectAt(i));

                    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(
                        PrivateKeyInfo.getInstance(new DERSequence(v)).getEncoded());
                    privateKeys[i] = factories.get(i).generatePrivate(keySpec);
                }
                else
                {
                    ASN1Sequence keySeq = ASN1Sequence.getInstance(seq.getObjectAt(i));

                    // We assume each component is of type OneAsymmetricKey (PrivateKeyInfo) as defined by the draft RFC
                    // and use the component key factory to decode the component key from PrivateKeyInfo.
                    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(PrivateKeyInfo.getInstance(keySeq).getEncoded());
                    privateKeys[i] = factories.get(i).generatePrivate(keySpec);
                }
            }
            return new CompositePrivateKey(keyIdentifier, privateKeys);
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.ioException(e.getMessage(), e);
        }
    }

    /**
     * Creates a CompositePublicKey from its SubjectPublicKeyInfo encoded form.
     * It is compliant with https://www.ietf.org/archive/id/draft-ounsworth-pq-composite-sigs-13.html where
     * CompositeSignaturePublicKey is a sequence of two BIT STRINGs which contain the encoded component public keys.
     * In BC implementation - CompositePublicKey is encoded into a BIT STRING in the form of SubjectPublicKeyInfo.
     *
     * @param keyInfo SubjectPublicKeyInfo containing a sequence of BIT STRINGs corresponding to each component.
     * @return
     * @throws IOException
     */
    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        if (helper == null)
        {
            helper = new BCJcaJceHelper();
        }

        ASN1ObjectIdentifier keyIdentifier = keyInfo.getAlgorithm().getAlgorithm();
        
        ASN1Sequence seq = null;
        byte[][] componentKeys = new byte[2][];
        
        try
        {
            seq = DERSequence.getInstance(keyInfo.getPublicKeyData().getBytes());
        }
        catch (Exception e)
        {
           componentKeys = split(keyIdentifier, keyInfo.getPublicKeyData());
        }
        
        if (MiscObjectIdentifiers.id_alg_composite.equals(keyIdentifier)
            || MiscObjectIdentifiers.id_composite_key.equals(keyIdentifier))
        {
            ASN1Sequence keySeq = ASN1Sequence.getInstance(keyInfo.getPublicKeyData().getBytes());
            PublicKey[] pubKeys = new PublicKey[keySeq.size()];

            for (int i = 0; i != keySeq.size(); i++)
            {
                SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(keySeq.getObjectAt(i));

                try
                {
                    pubKeys[i] = helper.createKeyFactory((pubInfo.getAlgorithm().getAlgorithm().getId())).generatePublic(new X509EncodedKeySpec(pubInfo.getEncoded()));
                }
                catch (Exception e)
                {
                    throw new IOException("cannot decode generic composite: " + e.getMessage(), e);
                }
            }

            return new CompositePublicKey(pubKeys);
        }

        try
        {
            int numKeys = (seq == null) ? componentKeys.length : seq.size();

            List<KeyFactory> factories = getKeyFactoriesFromIdentifier(keyIdentifier);
            ASN1BitString[] componentBitStrings = new ASN1BitString[numKeys];
            for (int i = 0; i < numKeys; i++)
            {
                // Check if component is OCTET STRING. If yes, convert it to BIT STRING.
                // This check should not be necessary since the draft RFC specifies components as BIT STRING encoded,
                // but currently the example public keys are OCTET STRING. So we leave it for interoperability.
                if (seq != null)
                {
                    if (seq.getObjectAt(i) instanceof DEROctetString)
                    {
                        componentBitStrings[i] = new DERBitString(((DEROctetString)seq.getObjectAt(i)).getOctets());
                    }
                    else
                    {
                        componentBitStrings[i] = (DERBitString)seq.getObjectAt(i);
                    }
                }
                else
                {
                    componentBitStrings[i] = new DERBitString(componentKeys[i]);
                }
            }

            // We need to get X509EncodedKeySpec to use key factories to produce component public keys.
            X509EncodedKeySpec[] x509EncodedKeySpecs = getKeysSpecs(keyIdentifier, componentBitStrings);
            PublicKey[] publicKeys = new PublicKey[numKeys];
            for (int i = 0; i < numKeys; i++)
            {
                publicKeys[i] = factories.get(i).generatePublic(x509EncodedKeySpecs[i]);
            }

            return new CompositePublicKey(keyIdentifier, publicKeys);
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.ioException(e.getMessage(), e);
        }
    }

    byte[][] split(ASN1ObjectIdentifier algorithm, ASN1BitString publicKeyData)
    {
        int[] sizes = componentKeySizes.get(algorithm);
        byte[] keyData = publicKeyData.getOctets();
        byte[][] components = new byte[][] { new byte[sizes[0]], new byte[sizes[1]] };

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
        List<String> algorithmNames = new ArrayList<String>();

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
