package org.bouncycastle.crypto.signers;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.bls.BLS12_381BasicScheme;
import org.bouncycastle.crypto.bls.BLS12_381G1;
import org.bouncycastle.crypto.bls.BLS12_381G2HashToCurve;
import org.bouncycastle.crypto.bls.BLS12_381G2Point;
import org.bouncycastle.crypto.bls.BLS12_381Pairing;
import org.bouncycastle.crypto.bls.BLS12_381ProofOfPossession;
import org.bouncycastle.crypto.bls.BLS12_381Serialization;
import org.bouncycastle.crypto.bls.BLS12_381SubgroupCheck;
import org.bouncycastle.crypto.bls.Fp12Element;
import org.bouncycastle.crypto.params.BLSPrivateKeyParameters;
import org.bouncycastle.crypto.params.BLSPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

/**
 * Generic BLS12-381 signer implementing the BC {@link Signer} interface.
 * <p>
 * Signs and verifies under a configurable BLS hash-to-curve domain
 * separation tag, defaulting to the BasicScheme DST
 * {@code BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_}. The
 * {@link #BLSSigner(byte[])} constructor lets callers select the
 * ProofOfPossession DST
 * ({@link BLS12_381ProofOfPossession#DST}) for Eth2 interop, or supply any
 * other RFC 9380 DST.
 * <p>
 * Note that the MessageAugmentation suite is intentionally NOT supported
 * here, since its hash input is {@code pk || msg} — the pubkey must be
 * available at sign time, which doesn't fit the {@link Signer}
 * "sk + buffered message" contract cleanly. Callers wanting AUG should
 * use {@link org.bouncycastle.crypto.bls.BLS12_381MessageAugmentation}
 * directly.
 * <p>
 * Produces and accepts 96-byte Zcash-format compressed G2 signatures, the
 * same encoding used by Eth2 / IETF draft-irtf-cfrg-bls-signature.
 */
public class BLSSigner
    implements Signer
{
    private final byte[] dst;
    private final WipingBuffer buffer = new WipingBuffer();

    private boolean forSigning;
    private BLSPrivateKeyParameters privateKey;
    private BLSPublicKeyParameters publicKey;

    /**
     * Construct a signer with the BasicScheme DST
     * ({@code BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_}).
     */
    public BLSSigner()
    {
        this(BLS12_381BasicScheme.DST);
    }

    /**
     * Construct a signer with an explicit hash-to-curve DST. For Eth2
     * interop pass {@link BLS12_381ProofOfPossession#DST}.
     */
    public BLSSigner(byte[] dst)
    {
        if (dst == null)
        {
            throw new IllegalArgumentException("dst must not be null");
        }
        this.dst = Arrays.clone(dst);
    }

    public void init(boolean forSigning, CipherParameters param)
    {
        this.forSigning = forSigning;
        if (forSigning)
        {
            if (!(param instanceof BLSPrivateKeyParameters))
            {
                throw new IllegalArgumentException("signing requires a BLSPrivateKeyParameters");
            }
            this.privateKey = (BLSPrivateKeyParameters)param;
            this.publicKey = null;
        }
        else
        {
            if (!(param instanceof BLSPublicKeyParameters))
            {
                throw new IllegalArgumentException("verification requires a BLSPublicKeyParameters");
            }
            this.privateKey = null;
            this.publicKey = (BLSPublicKeyParameters)param;
        }
        reset();
    }

    public void update(byte b)
    {
        buffer.write(b);
    }

    public void update(byte[] in, int off, int len)
    {
        if (in == null)
        {
            throw new NullPointerException("input must not be null");
        }
        buffer.write(in, off, len);
    }

    public byte[] generateSignature()
        throws CryptoException
    {
        if (!forSigning || privateKey == null)
        {
            throw new IllegalStateException("BLSSigner not initialised for signing");
        }
        byte[] msg = buffer.snapshot();
        try
        {
            BLS12_381G2HashToCurve h = new BLS12_381G2HashToCurve(dst);
            BLS12_381G2Point q = h.hashToCurve(msg);
            BLS12_381G2Point sig = q.constantTimeMultiply(privateKey.getSecret());
            return BLS12_381Serialization.compressG2(sig);
        }
        finally
        {
            // Wipe the snapshot copy in addition to the resetting the
            // backing buffer — hashToCurve has already read every byte
            // through the SHA-256 expand_message_xmd, so the array is
            // safe to zero at this point. See WipingBuffer's doc for
            // why the snapshot is needed at all.
            Arrays.fill(msg, (byte)0);
            reset();
        }
    }

    public boolean verifySignature(byte[] signature)
    {
        if (forSigning || publicKey == null)
        {
            throw new IllegalStateException("BLSSigner not initialised for verification");
        }
        try
        {
            BLS12_381G2Point sig;
            try
            {
                sig = BLS12_381Serialization.decompressG2(signature);
            }
            catch (IllegalArgumentException malformed)
            {
                return false;
            }

            ECPoint pk = publicKey.getPublicPoint();
            if (sig.isInfinity() || !BLS12_381SubgroupCheck.isInG2Subgroup(sig))
            {
                return false;
            }
            byte[] msg = buffer.snapshot();
            try
            {
                BLS12_381G2HashToCurve h = new BLS12_381G2HashToCurve(dst);
                BLS12_381G2Point q = h.hashToCurve(msg);
                ECCurve curve = BLS12_381G1.createCurve();
                ECPoint g1 = BLS12_381G1.getGenerator(curve);
                // e(g1, sig) == e(pk, H(msg))   <=>   e(g1, sig) * e(-pk, H(msg)) == 1
                Fp12Element acc = BLS12_381Pairing.multiPair(
                    new ECPoint[]{g1, pk.negate()},
                    new BLS12_381G2Point[]{sig, q});
                return Fp12Element.ONE.equals(acc);
            }
            finally
            {
                Arrays.fill(msg, (byte)0);
            }
        }
        finally
        {
            reset();
        }
    }

    public void reset()
    {
        buffer.wipeAndReset();
    }

    /**
     * Wipe-aware byte buffer backing the {@link Signer#update update}
     * contract — bytes accumulate here between {@link #init} /
     * {@link #reset} cycles.
     * <p>
     * <b>Wipe scope</b> (W3 in the review):
     * <ul>
     *   <li>On {@link #wipeAndReset}: zero positions {@code 0..count} of
     *       the current backing array, then reset {@code count}. Called
     *       from the signer's {@code reset()}.</li>
     *   <li>On internal capacity growth: zero the old backing array
     *       before releasing it to GC, so the doubling-resize pattern
     *       doesn't leave a chain of obsolete buffers each holding a
     *       prefix of the message.</li>
     *   <li>On {@link #snapshot}: returns a fresh defensive copy that
     *       the signer's {@code finally} block zeroes after the
     *       hash-to-curve consumes it. The copy is unavoidable because
     *       {@code hashToCurve} takes a {@code byte[]}, not a
     *       {@code (byte[], offset, length)} triple.</li>
     * </ul>
     * <p>
     * <b>What this does NOT cover.</b> The wipe is best-effort. Message
     * bytes still flow through the SHA-256 block buffer inside
     * {@code expand_message_xmd}; the JVM may relocate arrays during GC,
     * leaving spectral copies behind; and reflection / native debuggers
     * can observe live bytes anyway. The replacement of the previous
     * {@link java.io.ByteArrayOutputStream}-derived buffer was driven by
     * the doubling-resize gap above — the prior class overstated wipe
     * coverage in its docstring. In typical BLS use the message is not
     * secret (consensus signing roots, transaction bodies), so a strict
     * wipe is not load-bearing for the signer; this class minimises
     * residence as a defence-in-depth measure for callers who choose to
     * sign sensitive data.
     * <p>
     * Not thread-safe — the BC {@link Signer} contract is per-instance,
     * per-thread.
     */
    private static final class WipingBuffer
    {
        private byte[] buf = new byte[64];
        private int count;

        void write(byte b)
        {
            ensureCapacity(longSize(count, 1));
            buf[count++] = b;
        }

        void write(byte[] in, int off, int len)
        {
            if (in == null)
            {
                throw new NullPointerException("input array must not be null");
            }
            if (off < 0 || len < 0 || ((long)off + (long)len) > (long)in.length)
            {
                throw new IndexOutOfBoundsException(
                    "off=" + off + " len=" + len + " in.length=" + in.length);
            }
            ensureCapacity(longSize(count, len));
            System.arraycopy(in, off, buf, count, len);
            count += len;
        }

        /**
         * @return a fresh copy of bytes {@code 0..count}. The caller is
         * responsible for wiping the returned array once consumed.
         */
        byte[] snapshot()
        {
            byte[] out = new byte[count];
            System.arraycopy(buf, 0, out, 0, count);
            return out;
        }

        void wipeAndReset()
        {
            Arrays.fill(buf, 0, count, (byte)0);
            count = 0;
        }

        /**
         * Compute {@code current + delta} as a {@code long} to detect
         * {@code int} overflow at the {@code count + len} boundary.
         * Casting through {@code long} avoids the silent wrap-around
         * that {@code int + int} would produce for ~2GB messages, which
         * would translate to negative-capacity arguments later.
         */
        private static long longSize(int current, int delta)
        {
            return (long)current + (long)delta;
        }

        private void ensureCapacity(long needed)
        {
            if (needed <= buf.length)
            {
                return;
            }
            if (needed > (long)(Integer.MAX_VALUE - 8))
            {
                throw new OutOfMemoryError(
                    "BLSSigner buffer would exceed maximum array size");
            }
            int newCap = buf.length;
            while ((long)newCap < needed)
            {
                long doubled = (long)newCap << 1;
                if (doubled > (long)(Integer.MAX_VALUE - 8))
                {
                    newCap = Integer.MAX_VALUE - 8;
                    break;
                }
                newCap = (int)doubled;
            }
            byte[] grown = new byte[newCap];
            System.arraycopy(buf, 0, grown, 0, count);
            // Wipe BEFORE releasing the old buffer to GC: this is the
            // load-bearing part of W3. Without it, every doubling-grow
            // leaves another stale buffer in the heap.
            Arrays.fill(buf, 0, count, (byte)0);
            buf = grown;
        }
    }
}
