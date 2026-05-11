package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.bls.BLS12_381Serialization;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Public-key parameters for a BLS signature scheme. The underlying point
 * lives on the suite-specific G1 curve (BLS12-381 G1 today; further BLS
 * families add curves in the future).
 */
public class BLSPublicKeyParameters
    extends BLSKeyParameters
{
    private final ECPoint publicPoint;

    public BLSPublicKeyParameters(BLSParameters params, ECPoint publicPoint)
    {
        super(false, params);
        this.publicPoint = publicPoint.normalize();
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
