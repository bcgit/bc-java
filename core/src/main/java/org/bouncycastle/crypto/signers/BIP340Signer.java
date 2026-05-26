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
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;

/**
 * Schnorr signatures for secp256k1 per BIP-340 (and the BIP-340bis variable-length-message extension).
 * <p>
 * Reference: <a href="https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki">BIP-340</a>.
 * <p>
 * Public keys are x-only (the 32-byte big-endian X coordinate of the unique even-Y curve point with that X).
 * Signatures are the fixed 64-byte concatenation {@code bytes(R) || bytes(s)} where R is an x-only point and s is a
 * scalar in {@code [0, n)}. Both keys and signature deviate from BC's usual ECDSA encoding: signatures are not DER and
 * public points are not SEC1.
 * <pre>
 *   Sign(sk, m, a):
 *     d' = int(sk); fail if d' = 0 or d' &gt;= n
 *     P  = d' * G
 *     d  = d' if has_even_y(P) else n - d'
 *     t  = bytes(d) XOR H_aux(a)
 *     k' = int(H_nonce(t || bytes(P) || m)) mod n; fail if k' = 0
 *     R  = k' * G
 *     k  = k' if has_even_y(R) else n - k'
 *     e  = int(H_challenge(bytes(R) || bytes(P) || m)) mod n
 *     return bytes(R) || bytes((k + e * d) mod n)
 *
 *   Verify(pk_x, m, sig):
 *     P = lift_x(int(pk_x)); fail if None
 *     r = int(sig[0:32]);  fail if r &gt;= p
 *     s = int(sig[32:64]); fail if s &gt;= n
 *     e = int(H_challenge(bytes(r) || bytes(P) || m)) mod n
 *     R = s*G - e*P
 *     accept iff R is finite, has_even_y(R), and x(R) = r
 * </pre>
 * The three tagged-hash domain separators are {@code BIP0340/aux}, {@code BIP0340/nonce} and
 * {@code BIP0340/challenge}; {@code H_tag(x) = SHA256(SHA256(tag) || SHA256(tag) || x)}.
 * <p>
 * <b>Auxiliary randomness.</b> Pass a {@link ParametersWithRandom} wrapping the private key to draw a fresh
 * 32-byte {@code aux_rand} per call to {@link #generateSignature()} (RFC-recommended). Initialising with the bare
 * {@link ECPrivateKeyParameters} produces deterministic Schnorr signatures (aux_rand = 0^32), still spec-compliant
 * but without the side-channel hardening BIP-340 §3.2 calls out.
 * <p>
 * <b>Public-key supply.</b> Verification keys come in as {@link ECPublicKeyParameters}; only the X coordinate is
 * used, and the verifier internally re-lifts to the even-Y point. Callers may therefore pass either the lifted
 * point or any point sharing the X — the result is the same.
 */
public class BIP340Signer
    implements Signer
{
    private static final int SIGNATURE_SIZE = 64;
    private static final int X_SIZE = 32;
    private static final int AUX_RAND_SIZE = 32;

    private static final ECDomainParameters SECP256K1;
    private static final BigInteger P;

    private static final byte[] TAG_HASH_AUX;
    private static final byte[] TAG_HASH_NONCE;
    private static final byte[] TAG_HASH_CHALLENGE;

    static
    {
        X9ECParameters x9 = CustomNamedCurves.getByName("secp256k1");
        SECP256K1 = new ECDomainParameters(x9);
        P = SECP256K1.getCurve().getField().getCharacteristic();

        TAG_HASH_AUX = precomputedTagHash("BIP0340/aux");
        TAG_HASH_NONCE = precomputedTagHash("BIP0340/nonce");
        TAG_HASH_CHALLENGE = precomputedTagHash("BIP0340/challenge");
    }

    private final Buffer buffer = new Buffer();

    private boolean forSigning;
    private ECPrivateKeyParameters privateKey;
    private ECPublicKeyParameters publicKey;
    private SecureRandom auxRandSource;

    public BIP340Signer()
    {
    }

    /**
     * Return the secp256k1 domain parameters BIP-340 is locked to. Suitable for constructing
     * {@link ECPrivateKeyParameters} for {@link #init(boolean, CipherParameters) init}.
     */
    public static ECDomainParameters getDomainParameters()
    {
        return SECP256K1;
    }

    /**
     * Lift a 32-byte x-only BIP-340 public key encoding to an {@link ECPublicKeyParameters} carrying the unique
     * even-Y secp256k1 point with that X. Returns {@code null} when the encoding is not 32 bytes, when X is
     * outside {@code [0, p)}, or when no curve point exists with that X — matching the cases BIP-340 §3.1
     * defines as verification failures, so the caller can treat a null return as an a-priori-invalid public key.
     */
    public static ECPublicKeyParameters liftXOnlyPublicKey(byte[] xOnly)
    {
        if (xOnly == null || xOnly.length != X_SIZE)
        {
            return null;
        }
        ECPoint q = liftX(new BigInteger(1, xOnly));
        if (q == null)
        {
            return null;
        }
        return new ECPublicKeyParameters(q, SECP256K1);
    }

    public void init(boolean forSigning, CipherParameters parameters)
    {
        this.forSigning = forSigning;
        this.auxRandSource = null;

        if (parameters instanceof ParametersWithRandom)
        {
            ParametersWithRandom withRandom = (ParametersWithRandom)parameters;
            parameters = withRandom.getParameters();
            this.auxRandSource = withRandom.getRandom();
        }

        if (forSigning)
        {
            ECPrivateKeyParameters ecPrivateKey = (ECPrivateKeyParameters)parameters;
            checkSecp256k1(ecPrivateKey.getParameters());
            this.privateKey = ecPrivateKey;
            this.publicKey = null;
        }
        else
        {
            ECPublicKeyParameters ecPublicKey = (ECPublicKeyParameters)parameters;
            checkSecp256k1(ecPublicKey.getParameters());
            this.privateKey = null;
            this.publicKey = ecPublicKey;
        }

        CryptoServicesRegistrar.checkConstraints(
            Utils.getDefaultProperties("BIP340", forSigning ? privateKey : publicKey, forSigning));

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

    private static byte[] sign(ECPrivateKeyParameters privateKey, byte[] message, byte[] auxRand)
    {
        BigInteger n = SECP256K1.getN();
        BigInteger dPrime = privateKey.getD();

        if (dPrime.signum() <= 0 || dPrime.compareTo(n) >= 0)
        {
            throw new IllegalArgumentException("BIP-340 private key out of range");
        }

        ECMultiplier multiplier = new FixedPointCombMultiplier();
        ECPoint pubPoint = multiplier.multiply(SECP256K1.getG(), dPrime).normalize();
        BigInteger d = hasEvenY(pubPoint) ? dPrime : n.subtract(dPrime);

        byte[] pBytes = xBytes(pubPoint);

        byte[] t = xor(BigIntegers.asUnsignedByteArray(X_SIZE, d), taggedHash(TAG_HASH_AUX, auxRand));

        SHA256Digest nonceHash = taggedDigest(TAG_HASH_NONCE);
        nonceHash.update(t, 0, t.length);
        nonceHash.update(pBytes, 0, pBytes.length);
        nonceHash.update(message, 0, message.length);
        byte[] rand = new byte[X_SIZE];
        nonceHash.doFinal(rand, 0);

        BigInteger kPrime = new BigInteger(1, rand).mod(n);
        if (kPrime.signum() == 0)
        {
            throw new IllegalStateException("BIP-340 nonce derivation produced zero");
        }

        ECPoint rPoint = multiplier.multiply(SECP256K1.getG(), kPrime).normalize();
        BigInteger k = hasEvenY(rPoint) ? kPrime : n.subtract(kPrime);

        byte[] rBytes = xBytes(rPoint);
        BigInteger e = challengeScalar(rBytes, pBytes, message);
        BigInteger s = k.add(e.multiply(d)).mod(n);

        byte[] sig = new byte[SIGNATURE_SIZE];
        System.arraycopy(rBytes, 0, sig, 0, X_SIZE);
        byte[] sBytes = BigIntegers.asUnsignedByteArray(X_SIZE, s);
        System.arraycopy(sBytes, 0, sig, X_SIZE, X_SIZE);
        return sig;
    }

    private static boolean verify(ECPublicKeyParameters publicKey, byte[] message, byte[] signature)
    {
        if (signature == null || signature.length != SIGNATURE_SIZE)
        {
            return false;
        }

        BigInteger r = new BigInteger(1, Arrays.copyOfRange(signature, 0, X_SIZE));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, X_SIZE, SIGNATURE_SIZE));
        if (r.compareTo(P) >= 0 || s.compareTo(SECP256K1.getN()) >= 0)
        {
            return false;
        }

        BigInteger publicX = publicKey.getQ().normalize().getAffineXCoord().toBigInteger();
        ECPoint P_lift = liftX(publicX);
        if (P_lift == null)
        {
            return false;
        }

        byte[] pBytes = BigIntegers.asUnsignedByteArray(X_SIZE, publicX);
        byte[] rBytes = BigIntegers.asUnsignedByteArray(X_SIZE, r);
        BigInteger e = challengeScalar(rBytes, pBytes, message);

        ECPoint R = ECAlgorithms.sumOfTwoMultiplies(
            SECP256K1.getG(), s,
            P_lift, SECP256K1.getN().subtract(e)).normalize();

        if (R.isInfinity() || !hasEvenY(R))
        {
            return false;
        }
        return R.getAffineXCoord().toBigInteger().equals(r);
    }

    private static BigInteger challengeScalar(byte[] rBytes, byte[] pBytes, byte[] message)
    {
        SHA256Digest h = taggedDigest(TAG_HASH_CHALLENGE);
        h.update(rBytes, 0, rBytes.length);
        h.update(pBytes, 0, pBytes.length);
        h.update(message, 0, message.length);
        byte[] out = new byte[X_SIZE];
        h.doFinal(out, 0);
        return new BigInteger(1, out).mod(SECP256K1.getN());
    }

    private static ECPoint liftX(BigInteger x)
    {
        if (x.signum() < 0 || x.compareTo(P) >= 0)
        {
            return null;
        }
        ECCurve curve = SECP256K1.getCurve();
        ECFieldElement xFe = curve.fromBigInteger(x);
        // y^2 = x^3 + a*x + b; secp256k1 has a = 0, but the general form costs nothing extra.
        ECFieldElement ySq = xFe.square().add(curve.getA()).multiply(xFe).add(curve.getB());
        ECFieldElement y = ySq.sqrt();
        if (y == null)
        {
            return null;
        }
        if (y.testBitZero())
        {
            y = y.negate();
        }
        return curve.createPoint(x, y.toBigInteger());
    }

    private static boolean hasEvenY(ECPoint point)
    {
        return !point.getAffineYCoord().testBitZero();
    }

    private static byte[] xBytes(ECPoint point)
    {
        return BigIntegers.asUnsignedByteArray(X_SIZE, point.getAffineXCoord().toBigInteger());
    }

    private static byte[] xor(byte[] a, byte[] b)
    {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++)
        {
            out[i] = (byte)(a[i] ^ b[i]);
        }
        return out;
    }

    private static SHA256Digest taggedDigest(byte[] precomputedTagHash)
    {
        SHA256Digest h = new SHA256Digest();
        h.update(precomputedTagHash, 0, precomputedTagHash.length);
        h.update(precomputedTagHash, 0, precomputedTagHash.length);
        return h;
    }

    private static byte[] taggedHash(byte[] precomputedTagHash, byte[] data)
    {
        SHA256Digest h = taggedDigest(precomputedTagHash);
        h.update(data, 0, data.length);
        byte[] out = new byte[X_SIZE];
        h.doFinal(out, 0);
        return out;
    }

    private static byte[] precomputedTagHash(String tag)
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
