package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.bls.BLS12_381BasicScheme;
import org.bouncycastle.crypto.bls.BLS12_381Serialization;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Public-key parameters for a BLS signature scheme. The underlying point
 * lives on the suite-specific G1 curve (BLS12-381 G1 today; further BLS
 * families add curves in the future).
 * <p>
 * <b>Constructor invariant.</b> Construction runs the full
 * draft-irtf-cfrg-bls-signature sec. 2.5 {@code KeyValidate} (on-curve +
 * prime-order subgroup + non-identity) on the supplied point and rejects
 * anything that fails. Callers and downstream consumers can therefore
 * rely on the type itself as the validation boundary — once an instance
 * exists, the point is a valid BLS public key, and verify-time code
 * (e.g. {@link org.bouncycastle.crypto.signers.BLSSigner#verifySignature
 * BLSSigner.verifySignature}) does not need to redo the ~128-bit
 * GLV-shortened subgroup-membership scalar multiplication on every call.
 * <p>
 * The validation cost is the same as a single verify call's previous
 * pre-pairing keyValidate step, paid once at construction instead of N
 * times for N verifies under the same key. Callers that deserialize
 * public keys from untrusted bytes typically run
 * {@link BLS12_381Serialization#decompressG1 decompressG1} immediately
 * before constructing this object; that decompression does not subgroup
 * check, so the constructor is the place where the prime-order check
 * happens.
 */
public class BLSPublicKeyParameters
    extends BLSKeyParameters
{
    private final ECPoint publicPoint;

    public BLSPublicKeyParameters(BLSParameters params, ECPoint publicPoint)
    {
        super(false, params);
        if (publicPoint == null)
        {
            throw new IllegalArgumentException("publicPoint must not be null");
        }
        ECPoint normalised = publicPoint.normalize();
        // KeyValidate per draft-irtf-cfrg-bls-signature sec. 2.5: rejects
        // identity, off-curve points (curve equation), and points in
        // E(Fp) \ G1 (subgroup check). This is the invariant the class
        // promises downstream — see the class javadoc.
        if (!BLS12_381BasicScheme.keyValidate(normalised))
        {
            throw new IllegalArgumentException(
                "invalid BLS public key: must be a non-identity point in the prime-order G1 subgroup");
        }
        this.publicPoint = normalised;
    }

    /**
     * @return the G1 public-key point.
     */
    public ECPoint getPublicPoint()
    {
        return publicPoint;
    }

    /**
     * @return the Zcash-format compressed G1 encoding (48 bytes), matching
     * the {@code point_to_pubkey} encoding used by Eth2 and IETF
     * draft-irtf-cfrg-bls-signature.
     */
    public byte[] getEncoded()
    {
        return BLS12_381Serialization.compressG1(publicPoint);
    }
}
