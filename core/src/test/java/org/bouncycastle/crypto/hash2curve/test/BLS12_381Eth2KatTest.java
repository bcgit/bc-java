package org.bouncycastle.crypto.hash2curve.test;

import java.math.BigInteger;

import junit.framework.TestCase;
import org.bouncycastle.crypto.bls.BLS12_381BasicScheme;
import org.bouncycastle.crypto.bls.BLS12_381G1;
import org.bouncycastle.crypto.bls.BLS12_381G2Point;
import org.bouncycastle.crypto.bls.BLS12_381ProofOfPossession;
import org.bouncycastle.crypto.bls.BLS12_381Serialization;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Cross-implementation conformance tests for BLS12-381 against the
 * Ethereum BLS test vectors at github.com/ethereum/bls12-381-tests
 * (release v0.1.2). These vectors are the same ones used by the Eth2
 * consensus client implementations (Lighthouse, Prysm, Teku, Nimbus,
 * Lodestar) so a passing test here is direct evidence of byte-level
 * interoperability.
 * <p>
 * The Eth2 BLS suite is the ProofOfPossession variant
 * {@code BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_}, with public keys
 * in G1 and signatures in G2, both encoded in Zcash compressed format.
 */
public class BLS12_381Eth2KatTest
    extends TestCase
{
    /**
     * Sign vectors: rows are {sk_hex, msg_hex, expected_sig_hex}. From
     * github.com/ethereum/bls12-381-tests v0.1.2, sign/ subdirectory.
     */
    private static final String[][] SIGN_VECTORS = {
        {
            "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "b23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9"
        },
        {
            "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
            "5656565656565656565656565656565656565656565656565656565656565656",
            "af1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe"
        },
        {
            "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
            "abababababababababababababababababababababababababababababababab",
            "9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df"
        },
        {
            "328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219fabb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075ea21be115"
        },
        {
            "328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216",
            "abababababababababababababababababababababababababababababababab",
            "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9"
        },
        {
            "328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216",
            "5656565656565656565656565656565656565656565656565656565656565656",
            "a4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffe47bb6"
        },
        {
            "263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55"
        },
        {
            "263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
            "5656565656565656565656565656565656565656565656565656565656565656",
            "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb"
        },
        {
            "263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
            "abababababababababababababababababababababababababababababababab",
            "91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121"
        },
    };

    /**
     * Run all valid Eth2 sign vectors. For each (sk, msg, expected_sig)
     * triple this asserts that
     * {@code compress(BLS12_381ProofOfPossession.sign(sk, msg)) == expected_sig}
     * byte-for-byte. A pass is direct interoperability evidence with
     * Lighthouse / Prysm / Teku / Nimbus / Lodestar and any other Eth2
     * BLS implementation that uses these vectors.
     */
    public void testSignByteCompatibilityWithEth2()
    {
        for (int i = 0; i < SIGN_VECTORS.length; ++i)
        {
            String[] v = SIGN_VECTORS[i];
            BigInteger sk = new BigInteger(1, Hex.decode(v[0]));
            byte[] msg = Hex.decode(v[1]);
            byte[] expectedSig = Hex.decode(v[2]);

            BLS12_381G2Point sig = BLS12_381ProofOfPossession.sign(sk, msg);
            byte[] actualSig = BLS12_381Serialization.compressG2(sig);

            assertTrue("Eth2 sign vector " + i + " (sk=" + v[0].substring(0, 16)
                + "..., msg=" + v[1].substring(0, 16) + "...): sign output must byte-match Eth2",
                Arrays.areEqual(expectedSig, actualSig));
        }
    }

    /**
     * Eth2 zero-privkey sign vector: the spec mandates that signing with
     * sk = 0 must fail. Our implementation rejects sk &lt;= 0 in
     * {@link BLS12_381BasicScheme#skToPk} and the underlying scheme
     * helpers, so we expect an exception.
     */
    public void testZeroPrivkeyRejected()
    {
        BigInteger zeroSk = BigInteger.ZERO;
        byte[] msg = Hex.decode("abababababababababababababababababababababababababababababababab");
        try
        {
            BLS12_381ProofOfPossession.sign(zeroSk, msg);
            fail("Eth2 expects sign(sk=0, msg) to fail");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    /**
     * Cross-derived sanity: sign with a vector's sk, then derive the
     * matching pk via {@code skToPk}, then verify the resulting
     * signature using the public-key API. Confirms the sign / skToPk /
     * verify trio is internally consistent with the byte-level Eth2
     * vectors above.
     */
    /**
     * Eth2 aggregate vector: aggregating three published Eth2 signatures
     * must produce a specific compressed G2 byte string.
     */
    public void testAggregateByteCompatibilityWithEth2()
    {
        BLS12_381G2Point sig0 = BLS12_381Serialization.decompressG2(Hex.decode(
            "91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2"
                + "677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346"
                + "da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121"));
        BLS12_381G2Point sig1 = BLS12_381Serialization.decompressG2(Hex.decode(
            "9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665a"
                + "a635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea"
                + "1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df"));
        BLS12_381G2Point sig2 = BLS12_381Serialization.decompressG2(Hex.decode(
            "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8"
                + "638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0"
                + "559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9"));
        byte[] expected = Hex.decode(
            "9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf"
                + "842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e66478"
                + "5a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfc4ff1d930");

        BLS12_381G2Point agg = org.bouncycastle.crypto.bls.BLS12_381Aggregation.aggregate(
            new BLS12_381G2Point[]{sig0, sig1, sig2});
        byte[] actual = BLS12_381Serialization.compressG2(agg);
        assertTrue("aggregate output must byte-match Eth2",
            Arrays.areEqual(expected, actual));
    }

    /**
     * Eth2 fast_aggregate_verify valid case: three pubkeys and one
     * aggregated signature over the same message must verify.
     */
    public void testFastAggregateVerifyValid()
    {
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint pk0 = BLS12_381Serialization.decompressG1(Hex.decode(
            "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20f"
                + "d6e10c1b77654d067c0618f6e5a7f79a"), curve);
        ECPoint pk1 = BLS12_381Serialization.decompressG1(Hex.decode(
            "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491"
                + "af75d0707adab3b70c6a6a580217bf81"), curve);
        ECPoint pk2 = BLS12_381Serialization.decompressG1(Hex.decode(
            "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9"
                + "f829fdd7963afdf972e5e77854051f6f"), curve);
        byte[] msg = Hex.decode("abababababababababababababababababababababababababababababababab");
        BLS12_381G2Point sig = BLS12_381Serialization.decompressG2(Hex.decode(
            "9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf"
                + "842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e66478"
                + "5a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfc4ff1d930"));
        assertTrue(BLS12_381ProofOfPossession.fastAggregateVerify(
            new ECPoint[]{pk0, pk1, pk2}, msg, sig));
    }

    /**
     * Eth2 fast_aggregate_verify tampered case: same pubkeys / message but
     * with the trailing bytes of the signature flipped — verify must reject.
     */
    public void testFastAggregateVerifyTamperedRejected()
    {
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint pk0 = BLS12_381Serialization.decompressG1(Hex.decode(
            "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20f"
                + "d6e10c1b77654d067c0618f6e5a7f79a"), curve);
        ECPoint pk1 = BLS12_381Serialization.decompressG1(Hex.decode(
            "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491"
                + "af75d0707adab3b70c6a6a580217bf81"), curve);
        ECPoint pk2 = BLS12_381Serialization.decompressG1(Hex.decode(
            "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9"
                + "f829fdd7963afdf972e5e77854051f6f"), curve);
        byte[] msg = Hex.decode("abababababababababababababababababababababababababababababababab");
        BLS12_381G2Point tampered;
        try
        {
            tampered = BLS12_381Serialization.decompressG2(Hex.decode(
                "9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf"
                    + "842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e66478"
                    + "5a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfcffffffff"));
        }
        catch (IllegalArgumentException e)
        {
            // The tampered byte string may not even be a valid G2 point on
            // the curve. Either way, fast_aggregate_verify must not accept
            // the original aggregate; the test passes by virtue of the
            // tamper being structurally rejected.
            return;
        }
        assertFalse(BLS12_381ProofOfPossession.fastAggregateVerify(
            new ECPoint[]{pk0, pk1, pk2}, msg, tampered));
    }

    public void testEth2VectorRoundTripVerify()
    {
        ECCurve curve = BLS12_381G1.createCurve();
        for (int i = 0; i < SIGN_VECTORS.length; ++i)
        {
            String[] v = SIGN_VECTORS[i];
            BigInteger sk = new BigInteger(1, Hex.decode(v[0]));
            byte[] msg = Hex.decode(v[1]);
            byte[] sigBytes = Hex.decode(v[2]);

            ECPoint pk = BLS12_381BasicScheme.skToPk(sk);
            BLS12_381G2Point sig = BLS12_381Serialization.decompressG2(sigBytes);
            assertTrue("Eth2 sign-vector " + i + " signature must verify under derived pk",
                BLS12_381ProofOfPossession.verify(pk, msg, sig));
        }
    }
}
