package org.bouncycastle.crypto.signers;

import java.io.ByteArrayOutputStream;

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
        buffer.write(in, off, len);
    }

    public byte[] generateSignature()
        throws CryptoException
    {
        if (!forSigning || privateKey == null)
        {
            throw new IllegalStateException("BLSSigner not initialised for signing");
        }
        try
        {
            BLS12_381G2HashToCurve h = new BLS12_381G2HashToCurve(dst);
            BLS12_381G2Point q = h.hashToCurve(buffer.toByteArray());
            BLS12_381G2Point sig = q.constantTimeMultiply(privateKey.getSecret());
            return BLS12_381Serialization.compressG2(sig);
        }
        finally
        {
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
            if (!BLS12_381BasicScheme.keyValidate(pk))
            {
                return false;
            }
            if (sig.isInfinity() || !BLS12_381SubgroupCheck.isInG2Subgroup(sig))
            {
                return false;
            }
            BLS12_381G2HashToCurve h = new BLS12_381G2HashToCurve(dst);
            BLS12_381G2Point q = h.hashToCurve(buffer.toByteArray());
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
            reset();
        }
    }

    public void reset()
    {
        buffer.wipeAndReset();
    }

    /**
     * ByteArrayOutputStream subclass that wipes its internal byte storage
     * before resetting the count, so message bytes don't linger in the
     * heap between {@code reset()} and the next GC.
     */
    private static final class WipingBuffer
        extends ByteArrayOutputStream
    {
        synchronized void wipeAndReset()
        {
            Arrays.fill(buf, 0, count, (byte)0);
            this.count = 0;
        }
    }
}
