package org.bouncycastle.crypto.hpke;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.agreement.ECDHCRawAgreement;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * The MLKEM768-P256 and MLKEM1024-P384 hybrid KEMs of draft-irtf-cfrg-concrete-hybrid-kems as HPKE
 * KEMs per draft-ietf-hpke-pq sec. 4.
 * <p>
 * Both are the CG framework of draft-irtf-cfrg-hybrid-kems: a 32-byte seed is expanded with SHAKE256
 * into the ML-KEM (d, z) seed and the group seed, the curve scalar is taken from the group seed by
 * rejection sampling, keys and ciphertexts are the ML-KEM value followed by the uncompressed curve
 * point, and the shared secret is SHA3-256(ss_PQ || ss_T || ct_T || ek_T || label). The private key
 * wire format is the seed; {@code DeriveKeyPair} derives the seed as the SHAKE256 LabeledDerive of
 * the ikm with the label "DeriveKeyPair". Neither KEM is authenticated, so the auth and auth_psk
 * modes are not supported.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-irtf-cfrg-concrete-hybrid-kems/">Concrete Hybrid PQ/T Key Encapsulation Mechanisms</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/">Post-Quantum and Post-Quantum/Traditional Hybrid Algorithms for HPKE</a>
 */
class MLKEMECHybridKEM
    extends KEM
{
    private static final int Nseed = 32;
    private static final int Nss = 32;
    private static final int NseedPQ = 64;
    private static final int NrandomPQ = 32;

    private final short kemId;
    private final MLKEMParameters pqParameters;
    private final ECDomainParameters domainParams;
    private final byte[] label;
    private final int NekPQ;
    private final int NctPQ;
    private final int Nelem;
    private final int Nscalar;
    private final int NseedT;

    MLKEMECHybridKEM(short kemId)
    {
        this.kemId = kemId;

        switch (kemId)
        {
        case HPKE.kem_MLKEM768_P256:
            pqParameters = MLKEMParameters.ml_kem_768;
            domainParams = ECNamedDomainParameters.lookup(SECObjectIdentifiers.secp256r1);
            label = Strings.toByteArray("MLKEM768-P256");
            NekPQ = 1184;
            NctPQ = 1088;
            Nelem = 65;
            Nscalar = 32;
            NseedT = 128;
            break;
        case HPKE.kem_MLKEM1024_P384:
            pqParameters = MLKEMParameters.ml_kem_1024;
            domainParams = ECNamedDomainParameters.lookup(SECObjectIdentifiers.secp384r1);
            label = Strings.toByteArray("MLKEM1024-P384");
            NekPQ = 1568;
            NctPQ = 1568;
            Nelem = 97;
            Nscalar = 48;
            NseedT = 48;
            break;
        default:
            throw new IllegalArgumentException("invalid kem id");
        }
    }

    AsymmetricCipherKeyPair GeneratePrivateKey()
    {
        byte[] seed = new byte[Nseed];
        CryptoServicesRegistrar.getSecureRandom().nextBytes(seed);

        return keyPairFromSeed(seed);
    }

    AsymmetricCipherKeyPair DeriveKeyPair(byte[] ikm)
    {
        if (ikm == null)
        {
            throw new NullPointerException("'ikm' cannot be null");
        }
        if (ikm.length < Nseed)
        {
            throw new IllegalArgumentException("'ikm' must be at least " + Nseed + " bytes");
        }

        return keyPairFromSeed(labeledDeriveSHAKE256(kemId, ikm, "DeriveKeyPair", null, Nseed));
    }

    byte[][] Encap(AsymmetricKeyParameter recipientPublicKey)
    {
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        byte[] randomness = new byte[NrandomPQ + NseedT];
        random.nextBytes(randomness);

        return Encap(recipientPublicKey, randomness);
    }

    byte[][] Encap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpE)
    {
        throw new UnsupportedOperationException(
            "hybrid KEM encapsulation does not use an ephemeral key pair; use Encap(pkR, randomness) for deterministic encapsulation");
    }

    byte[][] Encap(AsymmetricKeyParameter pkR, byte[] ier)
    {
        if (ier == null || ier.length != NrandomPQ + NseedT)
        {
            throw new IllegalArgumentException("'ier' must be " + (NrandomPQ + NseedT) + " bytes");
        }

        byte[] ek = checkPublicKey(pkR).getEncoded();
        MLKEMPublicKeyParameters ekPQ = new MLKEMPublicKeyParameters(pqParameters, Arrays.copyOfRange(ek, 0, NekPQ));
        byte[] ekT = Arrays.copyOfRange(ek, NekPQ, ek.length);
        ECPublicKeyParameters ekTKey = new ECPublicKeyParameters(domainParams.getCurve().decodePoint(ekT), domainParams);

        // the PQ component takes the first PQ.Nrandom bytes, the group the final Group.Nseed bytes
        SecretWithEncapsulation pq = MLKEMGenerator.internalGenerateEncapsulated(ekPQ, Arrays.copyOfRange(ier, 0, NrandomPQ));

        BigInteger skE = randomScalar(Arrays.copyOfRange(ier, NrandomPQ, ier.length));
        ECPoint ctTPoint = domainParams.getG().multiply(skE).normalize();
        byte[] ctT = ctTPoint.getEncoded(false);
        byte[] ssT = elementToSharedSecret(new ECPrivateKeyParameters(skE, domainParams), ekTKey);

        byte[][] output = new byte[2][];
        output[0] = combine(pq.getSecret(), ssT, ctT, ekT);
        output[1] = Arrays.concatenate(pq.getEncapsulation(), ctT);
        return output;
    }

    byte[][] AuthEncap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpS)
    {
        throw new UnsupportedOperationException("hybrid KEM is not an authenticated KEM");
    }

    byte[] Decap(byte[] encapsulatedKey, AsymmetricCipherKeyPair recipientKeyPair)
    {
        if (encapsulatedKey == null)
        {
            throw new NullPointerException("'encapsulatedKey' cannot be null");
        }
        if (encapsulatedKey.length != NctPQ + Nelem)
        {
            throw new IllegalArgumentException("'encapsulatedKey' has invalid length");
        }

        HybridKEMPrivateKeyParameters sk = (HybridKEMPrivateKeyParameters)recipientKeyPair.getPrivate();
        if (sk.getKemId() != kemId)
        {
            throw new IllegalArgumentException("private key does not match KEM");
        }

        byte[] ctPQ = Arrays.copyOfRange(encapsulatedKey, 0, NctPQ);
        byte[] ctT = Arrays.copyOfRange(encapsulatedKey, NctPQ, encapsulatedKey.length);

        byte[] ssPQ = new MLKEMExtractor(sk.getPQKey()).extractSecret(ctPQ);

        ECPublicKeyParameters ctTKey = new ECPublicKeyParameters(domainParams.getCurve().decodePoint(ctT), domainParams);
        byte[] ssT = elementToSharedSecret(sk.getTKey(), ctTKey);

        byte[] ek = sk.getPublicKeyParameters().getEncoded();
        byte[] ekT = Arrays.copyOfRange(ek, NekPQ, ek.length);

        return combine(ssPQ, ssT, ctT, ekT);
    }

    byte[] AuthDecap(byte[] enc, AsymmetricCipherKeyPair kpR, AsymmetricKeyParameter pkS)
    {
        throw new UnsupportedOperationException("hybrid KEM is not an authenticated KEM");
    }

    byte[] SerializePublicKey(AsymmetricKeyParameter publicKey)
    {
        return checkPublicKey(publicKey).getEncoded();
    }

    byte[] SerializePrivateKey(AsymmetricKeyParameter key)
    {
        HybridKEMPrivateKeyParameters sk = (HybridKEMPrivateKeyParameters)key;
        if (sk.getKemId() != kemId)
        {
            throw new IllegalArgumentException("private key does not match KEM");
        }
        return sk.getSeed();
    }

    AsymmetricKeyParameter DeserializePublicKey(byte[] encodedPublicKey)
    {
        if (encodedPublicKey == null)
        {
            throw new NullPointerException("'pkEncoded' cannot be null");
        }
        if (encodedPublicKey.length != NekPQ + Nelem)
        {
            throw new IllegalArgumentException("'pkEncoded' has invalid length");
        }

        // validate both components: the ML-KEM modulus check and the point decoding (on-curve check)
        new MLKEMPublicKeyParameters(pqParameters, Arrays.copyOfRange(encodedPublicKey, 0, NekPQ));
        domainParams.getCurve().decodePoint(Arrays.copyOfRange(encodedPublicKey, NekPQ, encodedPublicKey.length));

        return new HybridKEMPublicKeyParameters(kemId, encodedPublicKey);
    }

    AsymmetricCipherKeyPair DeserializePrivateKey(byte[] skEncoded, byte[] pkEncoded)
    {
        if (skEncoded == null)
        {
            throw new NullPointerException("'skEncoded' cannot be null");
        }
        if (skEncoded.length != Nseed)
        {
            throw new IllegalArgumentException("'skEncoded' has invalid length");
        }

        AsymmetricCipherKeyPair kp = keyPairFromSeed(skEncoded);

        if (pkEncoded != null && !Arrays.areEqual(pkEncoded, SerializePublicKey(kp.getPublic())))
        {
            throw new IllegalArgumentException("'pkEncoded' does not match private key");
        }

        return kp;
    }

    int getEncryptionSize()
    {
        return NctPQ + Nelem;
    }

    private AsymmetricCipherKeyPair keyPairFromSeed(byte[] seed)
    {
        // expandDecapsKeyG: seed_full = SHAKE256(seed, KEM_PQ.Nseed + Group_T.Nseed), split (PQ, T)
        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(seed, 0, seed.length);
        byte[] seedFull = new byte[NseedPQ + NseedT];
        shake.doFinal(seedFull, 0, seedFull.length);

        MLKEMPrivateKeyParameters dkPQ = new MLKEMPrivateKeyParameters(pqParameters, Arrays.copyOfRange(seedFull, 0, NseedPQ));
        BigInteger dkT = randomScalar(Arrays.copyOfRange(seedFull, NseedPQ, seedFull.length));
        Arrays.clear(seedFull);

        ECPoint ekT = domainParams.getG().multiply(dkT).normalize();

        byte[] ek = Arrays.concatenate(dkPQ.getPublicKeyParameters().getEncoded(), ekT.getEncoded(false));

        HybridKEMPublicKeyParameters pub = new HybridKEMPublicKeyParameters(kemId, ek);
        HybridKEMPrivateKeyParameters priv = new HybridKEMPrivateKeyParameters(kemId, seed, dkPQ,
            new ECPrivateKeyParameters(dkT, domainParams), pub);

        return new AsymmetricCipherKeyPair(pub, priv);
    }

    /**
     * RandomScalar of draft-irtf-cfrg-concrete-hybrid-kems sec. 3.1.1: read Nscalar-byte big-endian
     * chunks of the seed until one is in [1, order - 1].
     */
    private BigInteger randomScalar(byte[] seed)
    {
        BigInteger n = domainParams.getN();

        for (int start = 0; start + Nscalar <= seed.length; start += Nscalar)
        {
            BigInteger sk = new BigInteger(1, Arrays.copyOfRange(seed, start, start + Nscalar));
            if (sk.signum() != 0 && sk.compareTo(n) < 0)
            {
                return sk;
            }
        }

        throw new IllegalStateException("rejection sampling failed");
    }

    // ElementToSharedSecret: the X coordinate of the Diffie-Hellman point as a field element octet string
    private byte[] elementToSharedSecret(ECPrivateKeyParameters sk, ECPublicKeyParameters pk)
    {
        ECDHCRawAgreement agreement = new ECDHCRawAgreement();
        agreement.init(sk);
        byte[] ss = new byte[agreement.getAgreementSize()];
        agreement.calculateAgreement(pk, ss, 0);
        return ss;
    }

    // C2PRICombiner: SHA3-256(ss_PQ || ss_T || ct_T || ek_T || label)
    private byte[] combine(byte[] ssPQ, byte[] ssT, byte[] ctT, byte[] ekT)
    {
        SHA3Digest sha3 = new SHA3Digest(256);
        sha3.update(ssPQ, 0, ssPQ.length);
        sha3.update(ssT, 0, ssT.length);
        sha3.update(ctT, 0, ctT.length);
        sha3.update(ekT, 0, ekT.length);
        sha3.update(label, 0, label.length);

        byte[] ss = new byte[Nss];
        sha3.doFinal(ss, 0);
        Arrays.clear(ssPQ);
        Arrays.clear(ssT);
        return ss;
    }

    private HybridKEMPublicKeyParameters checkPublicKey(AsymmetricKeyParameter publicKey)
    {
        HybridKEMPublicKeyParameters pk = (HybridKEMPublicKeyParameters)publicKey;
        if (pk.getKemId() != kemId)
        {
            throw new IllegalArgumentException("public key does not match KEM");
        }
        return pk;
    }
}
