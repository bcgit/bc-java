package org.bouncycastle.crypto.hash2curve.impl;

import org.bouncycastle.crypto.bls.BLS12_381G1;
import org.bouncycastle.crypto.hash2curve.CurveProcessor;
import org.bouncycastle.crypto.hash2curve.data.AffineXY;
import org.bouncycastle.math.ec.ECPoint;

/**
 * CurveProcessor for the BLS12381G1_XMD:SHA-256_SSWU_RO_ hash-to-curve suite.
 * Cofactor clearing is done by scalar-multiplication by
 * {@link BLS12_381G1#H_EFF} (Bowe's fast cofactor clear), as mandated by
 * RFC 9380 sec. 8.8.1.
 */
public class BLS12_381G1CurveProcessor
    implements CurveProcessor
{
    public BLS12_381G1CurveProcessor()
    {
    }

    public ECPoint add(ECPoint p, ECPoint q)
    {
        return p.add(q);
    }

    public ECPoint clearCofactor(ECPoint ecPoint)
    {
        return ecPoint.multiply(BLS12_381G1.H_EFF).normalize();
    }

    public AffineXY mapToAffineXY(ECPoint p)
    {
        return new AffineXY(p);
    }
}
