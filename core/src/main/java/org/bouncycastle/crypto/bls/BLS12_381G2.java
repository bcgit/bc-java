package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

/**
 * Curve parameters for BLS12-381 G2, the prime-order subgroup of
 * {@code E(Fp^2)} defined by {@code y^2 = x^3 + 4 * (1 + I)} over Fp^2.
 */
public class BLS12_381G2
{
    /**
     * G2 prime-order subgroup order — identical to G1's, since pairing-friendly
     * curves have G1 and G2 share the same scalar field.
     */
    public static final BigInteger ORDER = BLS12_381G1.ORDER;

    /** G2 cofactor. */
    public static final BigInteger COFACTOR = new BigInteger(
        "5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21437425da9678", 16);

    /**
     * Effective cofactor for hash-to-curve (RFC 9380 sec. 8.8.2). Multiplying
     * any point on E(Fp^2) by h_eff lands in the prime-order subgroup; the
     * value is chosen for compatibility with the Budroni-Pintore optimised
     * cofactor clearing.
     */
    public static final BigInteger H_EFF = new BigInteger(
        "bc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551",
        16);

    /** Generator x-coordinate (real part). */
    private static final BigInteger GX_C0 = new BigInteger(
        "24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
        16);

    /** Generator x-coordinate (imaginary part). */
    private static final BigInteger GX_C1 = new BigInteger(
        "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e",
        16);

    /** Generator y-coordinate (real part). */
    private static final BigInteger GY_C0 = new BigInteger(
        "ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801",
        16);

    /** Generator y-coordinate (imaginary part). */
    private static final BigInteger GY_C1 = new BigInteger(
        "606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be",
        16);

    private BLS12_381G2()
    {
    }

    /**
     * @return the standard generator G2 of the prime-order subgroup, as a
     * fresh affine point. The returned point is verified against the curve
     * equation.
     */
    public static BLS12_381G2Point getGenerator()
    {
        return BLS12_381G2Point.of(
            Fp2Element.of(GX_C0, GX_C1),
            Fp2Element.of(GY_C0, GY_C1));
    }
}
