package org.bouncycastle.crypto.hash2curve.impl;

import java.math.BigInteger;

import org.bouncycastle.crypto.bls.BLS12_381G1;
import org.bouncycastle.crypto.hash2curve.MapToCurve;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Map-to-curve implementation for the BLS12381G1_XMD:SHA-256_SSWU_RO_ suite
 * (RFC 9380 sec. 8.8.1).
 * <p>
 * BLS12-381 G1 has {@code A == 0}, so the simplified SWU map cannot be
 * applied to E directly. Instead the suite specifies an 11-isogenous curve
 * E' (RFC 9380 App. E.2) with non-zero A' / B', SSWU is run on E', and the
 * resulting point is mapped back to E by the {@code iso_11} rational map.
 * </p>
 */
public class BLS12_381G1MapToCurve
    implements MapToCurve
{
    /** SSWU Z parameter (RFC 9380 sec. 8.8.1). */
    private static final BigInteger Z = BigInteger.valueOf(11);

    /** A' coefficient of the 11-isogenous SSWU curve E' (RFC 9380 App. E.2). */
    private static final BigInteger A_PRIME = new BigInteger(
        "144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d",
        16);

    /** B' coefficient of the 11-isogenous SSWU curve E'. */
    private static final BigInteger B_PRIME = new BigInteger(
        "12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0",
        16);

    /** k_(1, 0) .. k_(1, 11): coefficients of x_num polynomial in iso_11 (RFC 9380 App. E.2). */
    private static final BigInteger[] K1 = {
        new BigInteger("11a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7", 16),
        new BigInteger("17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bb", 16),
        new BigInteger("d54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0", 16),
        new BigInteger("1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289f1b330835336e25ce3107193c5b388641d9b6861", 16),
        new BigInteger("e99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb65982fac18985a286f301e77c451154ce9ac8895d9", 16),
        new BigInteger("1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983", 16),
        new BigInteger("d6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84", 16),
        new BigInteger("17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88e", 16),
        new BigInteger("80d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c928c5d1de4fa295f296b74e956d71986a8497e317", 16),
        new BigInteger("169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314baf4bb1b7fa3190b2edc0327797f241067be390c9e", 16),
        new BigInteger("10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af36003b14866f69b771f8c285decca67df3f1605fb7b", 16),
        new BigInteger("6e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229", 16),
    };

    /**
     * k_(2, 0) .. k_(2, 9): coefficients of x_den polynomial in iso_11. The
     * leading coefficient k_(2, 10) is implicitly 1 per RFC 9380 App. E.2.
     */
    private static final BigInteger[] K2 = {
        new BigInteger("8ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1c", 16),
        new BigInteger("12561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bff", 16),
        new BigInteger("b2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19", 16),
        new BigInteger("3425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8", 16),
        new BigInteger("13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e833b306da9bd29ba81f35781d539d395b3532a21e", 16),
        new BigInteger("e7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5", 16),
        new BigInteger("772caacf16936190f3e0c63e0596721570f5799af53a1894e2e073062aede9cea73b3538f0de06cec2574496ee84a3a", 16),
        new BigInteger("14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5e", 16),
        new BigInteger("a10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67f39883503826692abba43704776ec3a79a1d641", 16),
        new BigInteger("95fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df533978f31c1593174e4b4b7865002d6384d168ecdd0a", 16),
    };

    /** k_(3, 0) .. k_(3, 15): coefficients of y_num polynomial in iso_11. */
    private static final BigInteger[] K3 = {
        new BigInteger("90d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33", 16),
        new BigInteger("134996a104ee5811d51036d776fb46831223e96c254f383d0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696", 16),
        new BigInteger("cc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91400da7d26d521628b00523b8dfe240c72de1f6", 16),
        new BigInteger("1f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cb", 16),
        new BigInteger("8cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd221351adc2ee7f8dc099040a841b6daecf2e8fedb", 16),
        new BigInteger("16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0", 16),
        new BigInteger("4ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2", 16),
        new BigInteger("987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c26c842642f64550fedfe935a15e4ca31870fb29", 16),
        new BigInteger("9fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587", 16),
        new BigInteger("e1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30", 16),
        new BigInteger("19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e416389e61031bf3a5cce3fbafce813711ad011c132", 16),
        new BigInteger("18b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8e", 16),
        new BigInteger("b182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e807b4633f06c851c1919211f20d4c04f00b971ef8", 16),
        new BigInteger("245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133", 16),
        new BigInteger("5c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224b", 16),
        new BigInteger("15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa95af01b2b665027efec01c7704b456be69c8b604", 16),
    };

    /**
     * k_(4, 0) .. k_(4, 14): coefficients of y_den polynomial in iso_11. The
     * leading coefficient k_(4, 15) is implicitly 1 per RFC 9380 App. E.2.
     */
    private static final BigInteger[] K4 = {
        new BigInteger("16112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b5be72e7a07f3688ef60c206d01479253b03663c1", 16),
        new BigInteger("1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03d", 16),
        new BigInteger("58df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2", 16),
        new BigInteger("16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489e726af41727364f2c28297ada8d26d98445f5416", 16),
        new BigInteger("be0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc9dec916a20b15dc0fd2ededda39142311a5001d", 16),
        new BigInteger("8d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7ac", 16),
        new BigInteger("166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775c", 16),
        new BigInteger("16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd206357132b920f5b00801dee460ee415a15812ed9", 16),
        new BigInteger("1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4a", 16),
        new BigInteger("167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55", 16),
        new BigInteger("4d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8", 16),
        new BigInteger("accbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88cea7913516f968986f7ebbea9684b529e2561092", 16),
        new BigInteger("ad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a00d9b8693000763e3b90ac11e99b138573345cc", 16),
        new BigInteger("2660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27942480e420517bd8714cc80d1fadc1326ed06f7", 16),
        new BigInteger("e0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd6356caa205ca2f570f13497804415473a1d634b8f", 16),
    };

    private final ECCurve curveE;
    private final BigInteger p;
    private final SimplifiedShallueVanDeWoestijneMapToCurve sswuOnEPrime;

    public BLS12_381G1MapToCurve(ECCurve curveE)
    {
        this.curveE = curveE;
        this.p = curveE.getField().getCharacteristic();
        ECCurve curveEPrime = new ECCurve.Fp(p, A_PRIME, B_PRIME, BLS12_381G1.ORDER, BLS12_381G1.COFACTOR);
        this.sswuOnEPrime = new SimplifiedShallueVanDeWoestijneMapToCurve(curveEPrime, Z);
    }

    public ECPoint process(BigInteger u)
    {
        ECPoint pointOnEPrime = sswuOnEPrime.process(u);
        ECPoint normalised = pointOnEPrime.normalize();
        BigInteger xPrime = normalised.getAffineXCoord().toBigInteger();
        BigInteger yPrime = normalised.getAffineYCoord().toBigInteger();

        BigInteger xNum = horner(K1, K1.length - 1, xPrime);
        BigInteger xDen = horner(K2, K2.length - 1, xPrime).add(power(xPrime, K2.length)).mod(p);
        BigInteger yNum = horner(K3, K3.length - 1, xPrime);
        BigInteger yDen = horner(K4, K4.length - 1, xPrime).add(power(xPrime, K4.length)).mod(p);

        BigInteger x = xNum.multiply(xDen.modInverse(p)).mod(p);
        BigInteger y = yPrime.multiply(yNum).mod(p)
            .multiply(yDen.modInverse(p)).mod(p);

        return curveE.createPoint(x, y);
    }

    private BigInteger horner(BigInteger[] coeffs, int topIndex, BigInteger x)
    {
        BigInteger acc = coeffs[topIndex];
        for (int i = topIndex - 1; i >= 0; --i)
        {
            acc = acc.multiply(x).add(coeffs[i]).mod(p);
        }
        return acc;
    }

    private BigInteger power(BigInteger base, int exponent)
    {
        return base.modPow(BigInteger.valueOf(exponent), p);
    }
}
