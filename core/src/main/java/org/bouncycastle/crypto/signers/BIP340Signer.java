package org.bouncycastle.crypto.signers;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.Strings;

/**
 * Schnorr signatures for secp256k1 per
 * <a href="https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki">BIP-340</a> (with the
 * BIP-340bis variable-length-message extension).
 * <p>
 * Public keys are the 32-byte big-endian X coordinate of the unique even-Y curve point with that X.
 * Signatures are the fixed 64-byte concatenation {@code bytes(R) || bytes(s)} — neither encoding
 * matches BC's ECDSA defaults.
 * <p>
 * Auxiliary randomness follows the usual BC low-level signer convention: the signer is randomized by
 * default. A {@link ParametersWithRandom} on {@link #init} supplies the source for the fresh 32-byte
 * {@code aux_rand} drawn per {@link #generateSignature} call (BIP-340 §3.2, recommended for side-channel
 * hardening); when none is supplied the default {@link CryptoServicesRegistrar} source is substituted, as
 * for {@link SM2Signer} / {@link ECDSASigner}. Deterministic Schnorr (aux_rand = 0^32) is BIP-340 compliant
 * but must be requested explicitly via {@link #BIP340Signer(boolean)} — the absence of a supplied
 * SecureRandom does not silently select it.
 */
public class BIP340Signer
    implements Signer
{
    private static final int X_SIZE = 32;
    private static final int AUX_RAND_SIZE = 32;
    private static final int SIGNATURE_SIZE = 64;

    private static final ECDomainParameters SECP256K1;
    private static final BigInteger P;

    // Pre-hashed tag bytes per BIP-340 sec. 3.2: T = SHA256(tag), H_tag(x) = SHA256(T || T || x).
    private static final byte[] TAG_HASH_AUX;
    private static final byte[] TAG_HASH_NONCE;
    private static final byte[] TAG_HASH_CHALLENGE;

    static
    {
        X9ECParameters x9 = CustomNamedCurves.getByName("secp256k1");
        SECP256K1 = new ECDomainParameters(x9);
        P = SECP256K1.getCurve().getField().getCharacteristic();

        TAG_HASH_AUX = tagHash("BIP0340/aux");
        TAG_HASH_NONCE = tagHash("BIP0340/nonce");
        TAG_HASH_CHALLENGE = tagHash("BIP0340/challenge");
    }

    private final Buffer buffer = new Buffer();

    private final boolean deterministic;

    private boolean forSigning;
    private ECPrivateKeyParameters privateKey;
    private ECPublicKeyParameters publicKey;
    private SecureRandom auxRandSource;

    /**
     * Create a randomized BIP-340 signer: a per-signature {@code aux_rand} is drawn from the supplied
     * {@link ParametersWithRandom} source, or the default {@link CryptoServicesRegistrar} source when none
     * is supplied.
     */
    public BIP340Signer()
    {
        this(false);
    }

    /**
     * @param deterministic when {@code true}, sign deterministically with {@code aux_rand = 0^32} (BIP-340
     *                      §3.3 default signing with empty auxiliary randomness) and ignore any supplied
     *                      SecureRandom; when {@code false} (the usual case) draw a per-signature 32-byte
     *                      {@code aux_rand} from the supplied or default SecureRandom.
     */
    public BIP340Signer(boolean deterministic)
    {
        this.deterministic = deterministic;
    }

    /**
     * secp256k1 domain parameters. Use to construct {@link ECPrivateKeyParameters} / call an
     * {@link org.bouncycastle.crypto.generators.ECKeyPairGenerator} for BIP-340.
     */
    public static ECDomainParameters getDomain()
    {
        return SECP256K1;
    }

    /**
     * Lift a 32-byte x-only BIP-340 public key to an {@link ECPublicKeyParameters} carrying the unique
     * even-Y secp256k1 point with that X. Returns {@code null} for the cases BIP-340 §3.1 defines as
     * verification failures: wrong length, X out of {@code [0, p)}, or no curve point with that X.
     */
    public static ECPublicKeyParameters decodePublicKey(byte[] xOnly)
    {
        if (xOnly != null && xOnly.length == X_SIZE)
        {
            try
            {
                ECPoint q = SECP256K1.getCurve().decodePoint(Arrays.prepend(xOnly, (byte)0x02));
                return new ECPublicKeyParameters(q, SECP256K1);
            }
            catch (RuntimeException e)
            {
            }
        }
        return null;
    }

    public void init(boolean forSigning, CipherParameters parameters)
    {
        SecureRandom providedRandom = null;
        if (parameters instanceof ParametersWithRandom)
        {
            ParametersWithRandom withRandom = (ParametersWithRandom)parameters;
            parameters = withRandom.getParameters();
            providedRandom = withRandom.getRandom();
        }

        this.forSigning = forSigning;
        if (forSigning)
        {
            ECPrivateKeyParameters ecPrivateKey = (ECPrivateKeyParameters)parameters;
            checkSecp256k1(ecPrivateKey.getParameters());
            this.privateKey = ecPrivateKey;
            this.publicKey = null;
            this.auxRandSource = deterministic ? null : CryptoServicesRegistrar.getSecureRandom(providedRandom);
        }
        else
        {
            ECPublicKeyParameters ecPublicKey = (ECPublicKeyParameters)parameters;
            checkSecp256k1(ecPublicKey.getParameters());
            this.privateKey = null;
            this.publicKey = ecPublicKey;
            this.auxRandSource = null;
        }

        CryptoServicesRegistrar.checkConstraints(
            Utils.getDefaultProperties("BIP340", forSigning ? (ECKeyParameters)privateKey : publicKey, forSigning));

        reset();
    }

    public void update(byte b)
    {
        buffer.write(b);
    }

    public void update(byte[] in, int off, int len)
    {
        buffer.write(in, off, len);
    }

    public byte[] generateSignature()
    {
        if (!forSigning || null == privateKey)
        {
            throw new IllegalStateException("BIP340Signer not initialised for signature generation");
        }

        byte[] auxRand = new byte[AUX_RAND_SIZE];
        if (auxRandSource != null)
        {
            auxRandSource.nextBytes(auxRand);
        }

        return buffer.generateSignature(privateKey, auxRand);
    }

    public boolean verifySignature(byte[] signature)
    {
        if (forSigning || null == publicKey)
        {
            throw new IllegalStateException("BIP340Signer not initialised for verification");
        }

        return buffer.verifySignature(publicKey, signature);
    }

    public void reset()
    {
        buffer.reset();
    }

    // BIP-340 sec. 3.3 Default Signing.
    private static byte[] sign(ECPrivateKeyParameters privateKey, byte[] m, byte[] auxRand)
    {
        BigInteger n = SECP256K1.getN();

        // Steps 1-2: d' = int(sk); fail if d' = 0 or d' >= n.
        BigInteger d = privateKey.getD();
        if (d.signum() <= 0 || d.compareTo(n) >= 0)
        {
            throw new IllegalArgumentException("BIP-340 private key out of range");
        }

        ECMultiplier mult = new FixedPointCombMultiplier();

        // Steps 3-4: P = d' * G; d = d' if has_even_y(P) else n - d'.
        ECPoint P_pt = mult.multiply(SECP256K1.getG(), d).normalize();
        if (!hasEvenY(P_pt))
        {
            d = n.subtract(d);
        }
        byte[] pBytes = xBytes(P_pt);

        // Steps 5-8: t = bytes(d) XOR H_aux(a); k' = int(H_nonce(t || bytes(P) || m)) mod n; fail if k' = 0.
        byte[] t = BigIntegers.asUnsignedByteArray(X_SIZE, d);
        Bytes.xorTo(X_SIZE, taggedHash(TAG_HASH_AUX, auxRand), t);

        SHA256Digest h = taggedDigest(TAG_HASH_NONCE);
        h.update(t, 0, X_SIZE);
        h.update(pBytes, 0, X_SIZE);
        h.update(m, 0, m.length);
        byte[] rand = new byte[X_SIZE];
        h.doFinal(rand, 0);

        BigInteger k = BigIntegers.fromUnsignedByteArray(rand).mod(n);
        if (k.signum() == 0)
        {
            throw new IllegalStateException("BIP-340 nonce derivation produced zero");
        }

        // Steps 9-10: R = k' * G; k = k' if has_even_y(R) else n - k'.
        ECPoint R_pt = mult.multiply(SECP256K1.getG(), k).normalize();
        if (!hasEvenY(R_pt))
        {
            k = n.subtract(k);
        }
        byte[] rBytes = xBytes(R_pt);

        // Steps 11-12: e = int(H_challenge(bytes(R) || bytes(P) || m)) mod n; sig = bytes(R) || bytes((k + e*d) mod n).
        BigInteger e = challengeScalar(rBytes, pBytes, m);
        BigInteger s = k.add(e.multiply(d)).mod(n);

        byte[] sig = new byte[SIGNATURE_SIZE];
        System.arraycopy(rBytes, 0, sig, 0, X_SIZE);
        BigIntegers.asUnsignedByteArray(s, sig, X_SIZE, X_SIZE);
        return sig;
    }

    // BIP-340 sec. 3.4 Verification.
    private static boolean verify(ECPublicKeyParameters publicKey, byte[] m, byte[] sig)
    {
        if (sig == null || sig.length != SIGNATURE_SIZE)
        {
            return false;
        }

        BigInteger n = SECP256K1.getN();

        // Steps 2-3: r = int(sig[0:32]); s = int(sig[32:64]); fail if r >= p or s >= n.
        BigInteger r = BigIntegers.fromUnsignedByteArray(sig, 0, X_SIZE);
        BigInteger s = BigIntegers.fromUnsignedByteArray(sig, X_SIZE, X_SIZE);
        if (r.compareTo(P) >= 0 || s.compareTo(n) >= 0)
        {
            return false;
        }

        // Step 1: P = lift_x(int(pk)). The key arrived through a validating decode, so just normalise parity.
        ECPoint P_lift = publicKey.getQ(); // Guaranteed normalized and validated already
        if (!hasEvenY(P_lift))
        {
            P_lift = P_lift.negate();
        }
        byte[] pBytes = xBytes(P_lift);
        byte[] rBytes = BigIntegers.asUnsignedByteArray(X_SIZE, r);

        // Steps 4-5: e = int(H_challenge(bytes(r) || bytes(P) || m)) mod n; R = s*G - e*P.
        BigInteger e = challengeScalar(rBytes, pBytes, m);
        ECPoint R_pt = ECAlgorithms.sumOfTwoMultiplies(
            SECP256K1.getG(), s,
            P_lift, n.subtract(e)).normalize();

        // Steps 6-8: accept iff R is finite, has_even_y(R), x(R) = r.
        if (R_pt.isInfinity() || !hasEvenY(R_pt))
        {
            return false;
        }
        return R_pt.getAffineXCoord().toBigInteger().equals(r);
    }

    private static BigInteger challengeScalar(byte[] rBytes, byte[] pBytes, byte[] m)
    {
        SHA256Digest h = taggedDigest(TAG_HASH_CHALLENGE);
        h.update(rBytes, 0, X_SIZE);
        h.update(pBytes, 0, X_SIZE);
        h.update(m, 0, m.length);
        byte[] out = new byte[X_SIZE];
        h.doFinal(out, 0);
        return BigIntegers.fromUnsignedByteArray(out).mod(SECP256K1.getN());
    }

    private static boolean hasEvenY(ECPoint point)
    {
        return !point.getAffineYCoord().testBitZero();
    }

    private static byte[] xBytes(ECPoint point)
    {
        return point.getAffineXCoord().getEncoded();
    }

    private static SHA256Digest taggedDigest(byte[] tagHash)
    {
        SHA256Digest h = new SHA256Digest();
        h.update(tagHash, 0, X_SIZE);
        h.update(tagHash, 0, X_SIZE);
        return h;
    }

    private static byte[] taggedHash(byte[] tagHash, byte[] data)
    {
        SHA256Digest h = taggedDigest(tagHash);
        h.update(data, 0, data.length);
        byte[] out = new byte[X_SIZE];
        h.doFinal(out, 0);
        return out;
    }

    private static byte[] tagHash(String tag)
    {
        byte[] tagBytes = Strings.toUTF8ByteArray(tag);
        SHA256Digest h = new SHA256Digest();
        h.update(tagBytes, 0, tagBytes.length);
        byte[] out = new byte[X_SIZE];
        h.doFinal(out, 0);
        return out;
    }

    private static void checkSecp256k1(ECDomainParameters params)
    {
        if (!SECP256K1.getN().equals(params.getN()))
        {
            throw new IllegalArgumentException("BIP-340 requires secp256k1");
        }
    }

    private static final class Buffer
        extends ByteArrayOutputStream
    {
        synchronized byte[] generateSignature(ECPrivateKeyParameters privateKey, byte[] auxRand)
        {
            try
            {
                return sign(privateKey, Arrays.copyOf(buf, count), auxRand);
            }
            finally
            {
                reset();
            }
        }

        synchronized boolean verifySignature(ECPublicKeyParameters publicKey, byte[] signature)
        {
            try
            {
                return verify(publicKey, Arrays.copyOf(buf, count), signature);
            }
            finally
            {
                reset();
            }
        }

        public synchronized void reset()
        {
            Arrays.fill(buf, 0, count, (byte)0);
            this.count = 0;
        }
    }
}
