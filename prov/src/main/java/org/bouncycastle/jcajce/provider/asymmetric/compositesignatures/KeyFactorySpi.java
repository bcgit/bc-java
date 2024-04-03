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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
import org.bouncycastle.util.Exceptions;

/**
 * KeyFactory for composite signatures. List of supported combinations is in CompositeSignaturesConstants
 */
public class KeyFactorySpi
    extends BaseKeyFactorySpi
{

    //Specific algorithm identifiers of all component signature algorithms for SubjectPublicKeyInfo. These do not need to be all initialized here but makes the code more readable IMHO.
    private static final AlgorithmIdentifier dilithium2Identifier = new AlgorithmIdentifier(BCObjectIdentifiers.dilithium2);
    private static final AlgorithmIdentifier dilithium3Identifier = new AlgorithmIdentifier(BCObjectIdentifiers.dilithium3);
    private static final AlgorithmIdentifier dilithium5Identifier = new AlgorithmIdentifier(BCObjectIdentifiers.dilithium5);
    private static final AlgorithmIdentifier falcon512Identifier = new AlgorithmIdentifier(BCObjectIdentifiers.falcon_512);
    private static final AlgorithmIdentifier ed25519Identifier = new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519);
    private static final AlgorithmIdentifier ecdsaP256Identifier = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, new X962Parameters(SECObjectIdentifiers.secp256r1));
    private static final AlgorithmIdentifier ecdsaBrainpoolP256r1Identifier = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, new X962Parameters(TeleTrusTObjectIdentifiers.brainpoolP256r1));
    private static final AlgorithmIdentifier rsaIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption);
    private static final AlgorithmIdentifier ed448Identifier = new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448);
    private static final AlgorithmIdentifier ecdsaP384Identifier = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, new X962Parameters(SECObjectIdentifiers.secp384r1));
    private static final AlgorithmIdentifier ecdsaBrainpoolP384r1Identifier = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, new X962Parameters(TeleTrusTObjectIdentifiers.brainpoolP384r1));

    protected Key engineTranslateKey(Key key)
        throws InvalidKeyException
    {
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
        ASN1Sequence seq = DERSequence.getInstance(keyInfo.parsePrivateKey());
        ASN1ObjectIdentifier keyIdentifier = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

        try
        {
            List<KeyFactory> factories = getKeyFactoriesFromIdentifier(keyIdentifier); //Get key factories for each component algorithm.
            PrivateKey[] privateKeys = new PrivateKey[seq.size()];
            for (int i = 0; i < seq.size(); i++)
            {
                // We assume each component is of type OneAsymmetricKey (PrivateKeyInfo) as defined by the draft RFC
                // and use the component key factory to decode the component key from PrivateKeyInfo.
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(PrivateKeyInfo.getInstance(seq.getObjectAt(i)).getEncoded());
                privateKeys[i] = factories.get(i).generatePrivate(keySpec);
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
        ASN1Sequence seq = DERSequence.getInstance(keyInfo.getPublicKeyData().getBytes());
        ASN1ObjectIdentifier keyIdentifier = keyInfo.getAlgorithm().getAlgorithm();

        try
        {
            List<KeyFactory> factories = getKeyFactoriesFromIdentifier(keyIdentifier);
            ASN1BitString[] componentBitStrings = new ASN1BitString[seq.size()];
            for (int i = 0; i < seq.size(); i++)
            {
                // Check if component is OCTET STRING. If yes, convert it to BIT STRING.
                // This check should not be necessary since the draft RFC specifies components as BIT STRING encoded,
                // but currently the example public keys are OCTET STRING. So we leave it for interoperability.
                if (seq.getObjectAt(i) instanceof DEROctetString)
                {
                    componentBitStrings[i] = new DERBitString(((DEROctetString)seq.getObjectAt(i)).getOctets());
                }
                else
                {
                    componentBitStrings[i] = (DERBitString)seq.getObjectAt(i);
                }
            }

            // We need to get X509EncodedKeySpec to use key factories to produce component public keys.
            X509EncodedKeySpec[] x509EncodedKeySpecs = getKeysSpecs(keyIdentifier, componentBitStrings);
            PublicKey[] publicKeys = new PublicKey[seq.size()];
            for (int i = 0; i < seq.size(); i++)
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

        switch (CompositeSignaturesConstants.ASN1IdentifierCompositeNameMap.get(algorithmIdentifier))
        {
        case MLDSA44_Ed25519_SHA512:
        case MLDSA65_Ed25519_SHA512:
            algorithmNames.add("Dilithium");
            algorithmNames.add("Ed25519");
            break;
        case MLDSA87_Ed448_SHA512:
            algorithmNames.add("Dilithium");
            algorithmNames.add("Ed448");
            break;
        case MLDSA44_RSA2048_PSS_SHA256:
        case MLDSA44_RSA2048_PKCS15_SHA256:
        case MLDSA65_RSA3072_PSS_SHA512:
        case MLDSA65_RSA3072_PKCS15_SHA512:
            algorithmNames.add("Dilithium");
            algorithmNames.add("RSA");
            break;
        case MLDSA44_ECDSA_P256_SHA256:
        case MLDSA44_ECDSA_brainpoolP256r1_SHA256:
        case MLDSA65_ECDSA_P256_SHA512:
        case MLDSA65_ECDSA_brainpoolP256r1_SHA512:
        case MLDSA87_ECDSA_P384_SHA512:
        case MLDSA87_ECDSA_brainpoolP384r1_SHA512:
            algorithmNames.add("Dilithium");
            algorithmNames.add("ECDSA");
            break;
        case Falcon512_Ed25519_SHA512:
            algorithmNames.add("Falcon");
            algorithmNames.add("Ed25519");
            break;
        case Falcon512_ECDSA_P256_SHA256:
        case Falcon512_ECDSA_brainpoolP256r1_SHA256:
            algorithmNames.add("Falcon");
            algorithmNames.add("ECDSA");
            break;
        default:
            throw new IllegalArgumentException("Cannot create KeyFactories. Unsupported algorithm identifier.");
        }

        factories.add(KeyFactory.getInstance(algorithmNames.get(0), "BC"));
        factories.add(KeyFactory.getInstance(algorithmNames.get(1), "BC"));
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

        switch (CompositeSignaturesConstants.ASN1IdentifierCompositeNameMap.get(algorithmIdentifier))
        {
        case MLDSA44_Ed25519_SHA512:
            keyInfos[0] = new SubjectPublicKeyInfo(dilithium2Identifier, subjectPublicKeys[0]);
            keyInfos[1] = new SubjectPublicKeyInfo(ed25519Identifier, subjectPublicKeys[1]);
            break;
        case MLDSA44_ECDSA_P256_SHA256:
            keyInfos[0] = new SubjectPublicKeyInfo(dilithium2Identifier, subjectPublicKeys[0]);
            keyInfos[1] = new SubjectPublicKeyInfo(ecdsaP256Identifier, subjectPublicKeys[1]);
            break;
        case MLDSA44_ECDSA_brainpoolP256r1_SHA256:
            keyInfos[0] = new SubjectPublicKeyInfo(dilithium2Identifier, subjectPublicKeys[0]);
            keyInfos[1] = new SubjectPublicKeyInfo(ecdsaBrainpoolP256r1Identifier, subjectPublicKeys[1]);
            break;
        case MLDSA44_RSA2048_PSS_SHA256:
        case MLDSA44_RSA2048_PKCS15_SHA256:
            keyInfos[0] = new SubjectPublicKeyInfo(dilithium2Identifier, subjectPublicKeys[0]);
            keyInfos[1] = new SubjectPublicKeyInfo(rsaIdentifier, subjectPublicKeys[1]);
            break;
        case MLDSA65_Ed25519_SHA512:
            keyInfos[0] = new SubjectPublicKeyInfo(dilithium3Identifier, subjectPublicKeys[0]);
            keyInfos[1] = new SubjectPublicKeyInfo(ed25519Identifier, subjectPublicKeys[1]);
            break;
        case MLDSA65_ECDSA_P256_SHA512:
            keyInfos[0] = new SubjectPublicKeyInfo(dilithium3Identifier, subjectPublicKeys[0]);
            keyInfos[1] = new SubjectPublicKeyInfo(ecdsaP256Identifier, subjectPublicKeys[1]);
            break;
        case MLDSA65_ECDSA_brainpoolP256r1_SHA512:
            keyInfos[0] = new SubjectPublicKeyInfo(dilithium3Identifier, subjectPublicKeys[0]);
            keyInfos[1] = new SubjectPublicKeyInfo(ecdsaBrainpoolP256r1Identifier, subjectPublicKeys[1]);
            break;
        case MLDSA65_RSA3072_PSS_SHA512:
        case MLDSA65_RSA3072_PKCS15_SHA512:
            keyInfos[0] = new SubjectPublicKeyInfo(dilithium3Identifier, subjectPublicKeys[0]);
            keyInfos[1] = new SubjectPublicKeyInfo(rsaIdentifier, subjectPublicKeys[1]);
            break;
        case MLDSA87_Ed448_SHA512:
            keyInfos[0] = new SubjectPublicKeyInfo(dilithium5Identifier, subjectPublicKeys[0]);
            keyInfos[1] = new SubjectPublicKeyInfo(ed448Identifier, subjectPublicKeys[1]);
            break;
        case MLDSA87_ECDSA_P384_SHA512:
            keyInfos[0] = new SubjectPublicKeyInfo(dilithium5Identifier, subjectPublicKeys[0]);
            keyInfos[1] = new SubjectPublicKeyInfo(ecdsaP384Identifier, subjectPublicKeys[1]);
            break;
        case MLDSA87_ECDSA_brainpoolP384r1_SHA512:
            keyInfos[0] = new SubjectPublicKeyInfo(dilithium5Identifier, subjectPublicKeys[0]);
            keyInfos[1] = new SubjectPublicKeyInfo(ecdsaBrainpoolP384r1Identifier, subjectPublicKeys[1]);
            break;
        case Falcon512_Ed25519_SHA512:
            keyInfos[0] = new SubjectPublicKeyInfo(falcon512Identifier, subjectPublicKeys[0]);
            keyInfos[1] = new SubjectPublicKeyInfo(ed25519Identifier, subjectPublicKeys[1]);
            break;
        case Falcon512_ECDSA_P256_SHA256:
            keyInfos[0] = new SubjectPublicKeyInfo(falcon512Identifier, subjectPublicKeys[0]);
            keyInfos[1] = new SubjectPublicKeyInfo(ecdsaP256Identifier, subjectPublicKeys[1]);
            break;
        case Falcon512_ECDSA_brainpoolP256r1_SHA256:
            keyInfos[0] = new SubjectPublicKeyInfo(falcon512Identifier, subjectPublicKeys[0]);
            keyInfos[1] = new SubjectPublicKeyInfo(ecdsaBrainpoolP256r1Identifier, subjectPublicKeys[1]);
            break;
        default:
            throw new IllegalArgumentException("Cannot create key specs. Unsupported algorithm identifier.");
        }

        specs[0] = new X509EncodedKeySpec(keyInfos[0].getEncoded());
        specs[1] = new X509EncodedKeySpec(keyInfos[1].getEncoded());
        return specs;
    }
}
