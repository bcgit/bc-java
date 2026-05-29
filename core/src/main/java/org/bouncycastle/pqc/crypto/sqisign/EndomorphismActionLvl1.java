package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;


/**
 * Java mirror of {@code CURVES_WITH_ENDOMORPHISMS[7]} from
 * {@code src/precomp/ref/lvl1/endomorphism_action.c}.
 *
 * <p>The C reference stores 7 entries (primary curve E₀ at index 0 plus 6
 * alternate starting curves). Each entry holds Montgomery-form curve
 * coefficients, a precomputed 2-power basis, and six 2×2 integer matrices
 * (the action of the endomorphism ring on the basis: i, j, k, and the
 * three order generators).</p>
 *
 * <p>Limb constants are mechanically extracted from the C reference via
 * {@code core/src/tools/python/extract_sqisign_precomp.py}. The
 * Montgomery 5-limb 51-bit fp values are converted to canonical
 * {@link BigInteger} via {@link MontgomeryLvl1#fromMontgomery5x51}; the
 * GMP-64 mp_t ibz values via {@link Ibz#fromMpLimbs}.</p>
 */
final class EndomorphismActionLvl1
{
    /** Number of curves in the table (1 primary + 6 alternates). */
    public static final int NUM_CURVES = 7;

    /**
     * The seven curves with their endomorphism rings. Index 0 is the primary
     * E₀; indices 1..6 are alternate starting curves.
     */
    public static final CurveWithEndomorphismRing[] CURVES_WITH_ENDOMORPHISMS;

    static
    {
        CURVES_WITH_ENDOMORPHISMS = new CurveWithEndomorphismRing[NUM_CURVES];
        for (int i = 0; i < NUM_CURVES; i++)
        {
            CURVES_WITH_ENDOMORPHISMS[i] = new CurveWithEndomorphismRing();
        }
        populateEntry0();
        populateAlternates();
    }

    /** Write a 2×2 ibz matrix into a target via per-entry {@link Ibz} values. */
    private static void setMatrix(Ibz[][] dst, Ibz m00, Ibz m01, Ibz m10, Ibz m11)
    {
        Ibz.copy(dst[0][0], m00);
        Ibz.copy(dst[0][1], m01);
        Ibz.copy(dst[1][0], m10);
        Ibz.copy(dst[1][1], m11);
    }

    /**
     * Populate an {@link EcCurve} from its four Montgomery-form 5-limb
     * fp components: {@code A.re}, {@code A.im}, {@code C.re}, {@code C.im}.
     * The A24 cache is not populated here — call
     * {@link org.bouncycastle.pqc.crypto.sqisign.EcOps#normalizeCurveAndA24}
     * before use.
     */
    private static void setCurveFromLimbs(EcCurve curve,
                                          long[] aRe, long[] aIm,
                                          long[] cRe, long[] cIm)
    {
        BigInteger[] a = MontgomeryLvl1.fp2FromMontgomery5x51(aRe, aIm);
        BigInteger[] c = MontgomeryLvl1.fp2FromMontgomery5x51(cRe, cIm);
        Fp2.copy(curve.A, new Fp2(new Fp(a[0]), new Fp(a[1])));
        Fp2.copy(curve.C, new Fp2(new Fp(c[0]), new Fp(c[1])));
        curve.isA24ComputedAndNormalized = false;
    }

    /**
     * Populate an {@link EcPoint} from four Montgomery 5-limb fp
     * components: {@code x.re}, {@code x.im}, {@code z.re}, {@code z.im}.
     */
    private static void setPointFromLimbs(EcPoint p,
                                          long[] xRe, long[] xIm,
                                          long[] zRe, long[] zIm)
    {
        BigInteger[] x = MontgomeryLvl1.fp2FromMontgomery5x51(xRe, xIm);
        BigInteger[] z = MontgomeryLvl1.fp2FromMontgomery5x51(zRe, zIm);
        Fp2.copy(p.x, new Fp2(new Fp(x[0]), new Fp(x[1])));
        Fp2.copy(p.z, new Fp2(new Fp(z[0]), new Fp(z[1])));
    }

    /** Entry 0 = the primary E₀ (curve y²=x³+x, j=1728). */
    private static void populateEntry0()
    {
        // E₀: A = 0, C = 1.
        Fp2.setZero(CURVES_WITH_ENDOMORPHISMS[0].curve.A);
        Fp2.setOne(CURVES_WITH_ENDOMORPHISMS[0].curve.C);
        CURVES_WITH_ENDOMORPHISMS[0].curve.isA24ComputedAndNormalized = false;

        // 2^TORSION_EVEN_POWER torsion basis on E₀: P, Q, and P-Q from
        // E0Basis with z = 1. PmQ comes from the C precomp table (the
        // differencePoint runtime computation can pick the opposite of x(P-Q)
        // vs x(P+Q), which downstream theta-isogeny code rejects).
        Fp2.copy(CURVES_WITH_ENDOMORPHISMS[0].basisEven.P.x, E0BasisLvl1.BASIS_E0_PX);
        Fp2.setOne(CURVES_WITH_ENDOMORPHISMS[0].basisEven.P.z);
        Fp2.copy(CURVES_WITH_ENDOMORPHISMS[0].basisEven.Q.x, E0BasisLvl1.BASIS_E0_QX);
        Fp2.setOne(CURVES_WITH_ENDOMORPHISMS[0].basisEven.Q.z);
        Fp2.copy(CURVES_WITH_ENDOMORPHISMS[0].basisEven.PmQ.x, E0BasisLvl1.BASIS_E0_PmQX);
        Fp2.setOne(CURVES_WITH_ENDOMORPHISMS[0].basisEven.PmQ.z);

        // Action matrices for E₀'s endomorphism ring are populated via
        // setMatrix below — using the extracted values matching the C
        // ACTION_I/J/K/GEN2/3/4 macros at index 0.
        setMatrix(CURVES_WITH_ENDOMORPHISMS[0].actionI,
            Ibz.fromMpLimbs(4, new long[]{ 0xc5d3bda21b5456dbL, 0x74759780861ddd06L, 0x7f9d34b241af33d1L, 0x00cab471aa8c7f8cL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x7bfb7d32048b7d7aL, 0xa955918263d89bd3L, 0x76bf6861034403e1L, 0x00574ae3eeb45cd0L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x856fd6493698444fL, 0x189cafdf498f41dbL, 0xf7e00bffe50bcb5bL, 0x001535daa88b47f9L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x3a2c425de4aba925L, 0x8b8a687f79e222f9L, 0x8062cb4dbe50cc2eL, 0x00354b8e55738073L }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[0].actionJ,
            Ibz.fromMpLimbs(4, new long[]{ 0x36bad5fd54900abfL, 0x00d14eea4a59da0fL, 0x914606f6a7aea3f0L, 0x007da2d2cde65004L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x611dbde3b7878680L, 0x0819c9ec8b68a95fL, 0xbd7b5e31f73e2361L, 0x0068240040d72b45L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x1f0c9e126d204277L, 0x563f9d1cf854977fL, 0xe829af54c2ed00dbL, 0x00ca7be80d8304fbL }),
            Ibz.fromMpLimbs(4, new long[]{ 0xc9452a02ab6ff541L, 0xff2eb115b5a625f0L, 0x6eb9f90958515c0fL, 0x00825d2d3219affbL }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[0].actionK,
            Ibz.fromMpLimbs(4, new long[]{ 0xb19c16401af2231bL, 0xf39a683ee470f713L, 0x904ec26e7a543289L, 0x004455fc6a0cd5a6L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x55d2de69b685ad7aL, 0x925f591684e85675L, 0x83917c511cb68c0aL, 0x00cd96ce11d1ffceL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x959b1b9279bd3724L, 0x64a727d46f18b3ecL, 0x664bade78c7e9b4bL, 0x00486a1da287a6d9L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x4e63e9bfe50ddce5L, 0x0c6597c11b8f08ecL, 0x6fb13d9185abcd76L, 0x00bbaa0395f32a59L }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[0].actionGen2,
            Ibz.fromMpLimbs(4, new long[]{ 0xc5d3bda21b5456dbL, 0x74759780861ddd06L, 0x7f9d34b241af33d1L, 0x00cab471aa8c7f8cL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x7bfb7d32048b7d7aL, 0xa955918263d89bd3L, 0x76bf6861034403e1L, 0x00574ae3eeb45cd0L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x856fd6493698444fL, 0x189cafdf498f41dbL, 0xf7e00bffe50bcb5bL, 0x001535daa88b47f9L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x3a2c425de4aba925L, 0x8b8a687f79e222f9L, 0x8062cb4dbe50cc2eL, 0x00354b8e55738073L }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[0].actionGen3,
            Ibz.fromMpLimbs(4, new long[]{ 0xfe4749cfb7f230cdL, 0xbaa37335683bdb8aL, 0x88719dd474aeebe0L, 0x00242ba23c3967c8L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x6e8c9d8ade0981fdL, 0x58b7adb777a0a299L, 0x1a1d63497d4113a1L, 0x00dfb77217c5c40bL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x523e3a2dd1dc4363L, 0x376e267e20f1ecadL, 0xf004ddaa53fc661bL, 0x006fd8e15b07267aL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x01b8b630480dcf33L, 0x455c8cca97c42475L, 0x778e622b8b51141fL, 0x00dbd45dc3c69837L }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[0].actionGen4,
            Ibz.fromMpLimbs(4, new long[]{ 0xd8ce0b200d79118eL, 0xf9cd341f72387b89L, 0x482761373d2a1944L, 0x00222afe35066ad3L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xaae96f34db42d6bdL, 0x492fac8b42742b3aL, 0x41c8be288e5b4605L, 0x0066cb6708e8ffe7L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x4acd8dc93cde9b92L, 0xb25393ea378c59f6L, 0xb325d6f3c63f4da5L, 0x0024350ed143d36cL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x2731f4dff286ee73L, 0x0632cbe08dc78476L, 0xb7d89ec8c2d5e6bbL, 0x00ddd501caf9952cL }));
    }

    private static void populateAlternates()
    {
        // CURVES_WITH_ENDOMORPHISMS[1]
        setCurveFromLimbs(CURVES_WITH_ENDOMORPHISMS[1].curve,
            new long[]{ 0x000177f3bd3d98cfL, 0x000568291dbf7092L, 0x000755dcb3de2190L, 0x000423388f314fe4L, 0x000002a6f0241fb7L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setPointFromLimbs(CURVES_WITH_ENDOMORPHISMS[1].basisEven.P,
            new long[]{ 0x0005f6259b797b43L, 0x000157f63b3af2f9L, 0x0007a3f4ea01dfa8L, 0x0001dbb73e23680aL, 0x000018914dc770b9L },
            new long[]{ 0x00008cb6e0ced492L, 0x00005f20ac237154L, 0x0007d25b71e8f3ddL, 0x0004bf5fc15b1e6eL, 0x00001dc3d80fa781L },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setPointFromLimbs(CURVES_WITH_ENDOMORPHISMS[1].basisEven.Q,
            new long[]{ 0x000567ae7b4d67f3L, 0x0005ccb6e9fa4f37L, 0x000176489cb8f4eaL, 0x0006a1c3c481062bL, 0x00002c142d4feffeL },
            new long[]{ 0x0004c1bfcd30a39fL, 0x00021b126ab96a61L, 0x000060add76bd4a7L, 0x0004a6a3d02240a9L, 0x00001f52f1a6e758L },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setPointFromLimbs(CURVES_WITH_ENDOMORPHISMS[1].basisEven.PmQ,
            new long[]{ 0x000023fad1a2013bL, 0x0005e4194af99678L, 0x00034468fab3bf1bL, 0x00076e4e3f5b18c0L, 0x0000432503da9000L },
            new long[]{ 0x00034c912d2b3900L, 0x000014d40850dcbeL, 0x000672a3eab48ffeL, 0x0002b790affecf8cL, 0x000002ba92928eabL },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setMatrix(CURVES_WITH_ENDOMORPHISMS[1].actionI,
            Ibz.fromMpLimbs(4, new long[]{ 0xe4058ceba8dcef13L, 0x3bbe28acfda5e2f5L, 0x5f5cb0ffee9141e5L, 0x0095ef671e331920L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xb1b6fbce9e936b6eL, 0x6bcd20ae14b880bbL, 0xceb3c4a7feffb7f4L, 0x00e9e00365bfd874L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x523646b6c98847ffL, 0x7d56d563ec049694L, 0xe1958b0ac48f6833L, 0x00db58b2e957b64eL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x1bfa7314572310edL, 0xc441d753025a1d0aL, 0xa0a34f00116ebe1aL, 0x006a1098e1cce6dfL }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[1].actionJ,
            Ibz.fromMpLimbs(4, new long[]{ 0xb19c16401af2231bL, 0xf39a683ee470f713L, 0x904ec26e7a543289L, 0x004455fc6a0cd5a6L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x55d2de69b685ad7aL, 0x925f591684e85675L, 0x83917c511cb68c0aL, 0x00cd96ce11d1ffceL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x959b1b9279bd3724L, 0x64a727d46f18b3ecL, 0x664bade78c7e9b4bL, 0x00486a1da287a6d9L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x4e63e9bfe50ddce5L, 0x0c6597c11b8f08ecL, 0x6fb13d9185abcd76L, 0x00bbaa0395f32a59L }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[1].actionK,
            Ibz.fromMpLimbs(4, new long[]{ 0xe776f94c38f88d79L, 0x867742422d2e2bdfL, 0x8ee7a2e31736ddf0L, 0x00a4bb554bb152acL }),
            Ibz.fromMpLimbs(4, new long[]{ 0xd49dc0b8e2806774L, 0x7a5dc53f25773b88L, 0x3ed5d6b24cfb3032L, 0x00fc85b1584c27b8L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xadb9d25b25cfc139L, 0x4e7a8867aa20bd39L, 0xacfc412aa81f8b24L, 0x00201d50ab0cee2dL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x188906b3c7077287L, 0x7988bdbdd2d1d420L, 0x71185d1ce8c9220fL, 0x005b44aab44ead53L }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[1].actionGen2,
            Ibz.fromMpLimbs(4, new long[]{ 0xe4058ceba8dcef13L, 0x3bbe28acfda5e2f5L, 0x5f5cb0ffee9141e5L, 0x0095ef671e331920L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xb1b6fbce9e936b6eL, 0x6bcd20ae14b880bbL, 0xceb3c4a7feffb7f4L, 0x00e9e00365bfd874L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x523646b6c98847ffL, 0x7d56d563ec049694L, 0xe1958b0ac48f6833L, 0x00db58b2e957b64eL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x1bfa7314572310edL, 0xc441d753025a1d0aL, 0xa0a34f00116ebe1aL, 0x006a1098e1cce6dfL }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[1].actionGen3,
            Ibz.fromMpLimbs(4, new long[]{ 0xd8ce0b200d79118eL, 0xf9cd341f72387b89L, 0x482761373d2a1944L, 0x00222afe35066ad3L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xaae96f34db42d6bdL, 0x492fac8b42742b3aL, 0x41c8be288e5b4605L, 0x0066cb6708e8ffe7L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x4acd8dc93cde9b92L, 0xb25393ea378c59f6L, 0xb325d6f3c63f4da5L, 0x0024350ed143d36cL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x2731f4dff286ee73L, 0x0632cbe08dc78476L, 0xb7d89ec8c2d5e6bbL, 0x00ddd501caf9952cL }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[1].actionGen4,
            Ibz.fromMpLimbs(4, new long[]{ 0x994175298b307029L, 0x4553e3d77b3f2be8L, 0xc80bb49c7bef7065L, 0x00181ece950cfa3eL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x7c8285e892ceb399L, 0x64f18924b18686ebL, 0x419631655e9a0d93L, 0x003155d501585e79L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xaa0c720929f8da47L, 0x517c6e1939c9fc22L, 0x1edc20fccfa4c94eL, 0x00df85f0396de0d0L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x66be8ad674cf8fd7L, 0xbaac1c2884c0d417L, 0x37f44b6384108f9aL, 0x00e7e1316af305c1L }));

        // CURVES_WITH_ENDOMORPHISMS[2]
        setCurveFromLimbs(CURVES_WITH_ENDOMORPHISMS[2].curve,
            new long[]{ 0x0004d12b0e68b79fL, 0x000337935267f3a8L, 0x000380bf65840877L, 0x0004bcc119304135L, 0x000035da6e9613a8L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setPointFromLimbs(CURVES_WITH_ENDOMORPHISMS[2].basisEven.P,
            new long[]{ 0x00011012b71d2d54L, 0x00076efaa195f3a3L, 0x0006a89621403297L, 0x0000f05f07417877L, 0x0000058bafba5332L },
            new long[]{ 0x0003f3eaf5646a2dL, 0x0006a0f369773854L, 0x00015a15657d2442L, 0x000667ba47d7dbf8L, 0x000002d784590c43L },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setPointFromLimbs(CURVES_WITH_ENDOMORPHISMS[2].basisEven.Q,
            new long[]{ 0x0003f45882691098L, 0x0006a82534f3934fL, 0x0006c6ead870b0eeL, 0x0005669ed2bbb8daL, 0x00002b9a1f281940L },
            new long[]{ 0x00041be7c586d896L, 0x00022c68cb09ca5eL, 0x00003c045adbe77bL, 0x000506845058c043L, 0x00002d2b7e8d71dbL },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setPointFromLimbs(CURVES_WITH_ENDOMORPHISMS[2].basisEven.PmQ,
            new long[]{ 0x00042b9c93c44402L, 0x000461426db46e24L, 0x0006d7aab066dc8cL, 0x0000bf26f540d0b8L, 0x00004f6e2764cc0cL },
            new long[]{ 0x000072f03d7912cdL, 0x00043aa6e7af9e21L, 0x000679aa18a05871L, 0x00014c0756affa95L, 0x00002abcbd62f832L },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setMatrix(CURVES_WITH_ENDOMORPHISMS[2].actionI,
            Ibz.fromMpLimbs(4, new long[]{ 0xe75d52b3a5945ff1L, 0xd9767d25d267dd09L, 0x10bf9aaec1a80bc5L, 0x0070ae848de3e894L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xa6d796c0b9e011e6L, 0xf4c52f4404b6ee81L, 0xebb65b93e75d4597L, 0x00163084c08e59c6L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x479f60313463f41dL, 0x404e1e6b159f6fe7L, 0xad84c1f788a8e302L, 0x00ab3d6631758b50L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x18a2ad4c5a6ba00fL, 0x268982da2d9822f6L, 0xef4065513e57f43aL, 0x008f517b721c176bL }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[2].actionJ,
            Ibz.fromMpLimbs(4, new long[]{ 0xb19c16401af2231bL, 0xf39a683ee470f713L, 0x904ec26e7a543289L, 0x004455fc6a0cd5a6L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x55d2de69b685ad7aL, 0x925f591684e85675L, 0x83917c511cb68c0aL, 0x00cd96ce11d1ffceL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x959b1b9279bd3724L, 0x64a727d46f18b3ecL, 0x664bade78c7e9b4bL, 0x00486a1da287a6d9L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x4e63e9bfe50ddce5L, 0x0c6597c11b8f08ecL, 0x6fb13d9185abcd76L, 0x00bbaa0395f32a59L }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[2].actionK,
            Ibz.fromMpLimbs(4, new long[]{ 0x56c4c7ef1fbeffc3L, 0x1ced36aafa5c2834L, 0x0e528890a31d9076L, 0x00c298bcef6887d2L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x8109b5c6d7404098L, 0xc0d081c23a8c0299L, 0x656a89969243e848L, 0x004cb9f56c998c87L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xc5fe55b5feed712bL, 0x7814177577a9e867L, 0x397386b173b14780L, 0x00b001fa7f0b797aL }),
            Ibz.fromMpLimbs(4, new long[]{ 0xa93b3810e041003dL, 0xe312c95505a3d7cbL, 0xf1ad776f5ce26f89L, 0x003d67431097782dL }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[2].actionGen2,
            Ibz.fromMpLimbs(4, new long[]{ 0xe75d52b3a5945ff1L, 0xd9767d25d267dd09L, 0x10bf9aaec1a80bc5L, 0x0070ae848de3e894L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xa6d796c0b9e011e6L, 0xf4c52f4404b6ee81L, 0xebb65b93e75d4597L, 0x00163084c08e59c6L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x479f60313463f41dL, 0x404e1e6b159f6fe7L, 0xad84c1f788a8e302L, 0x00ab3d6631758b50L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x18a2ad4c5a6ba00fL, 0x268982da2d9822f6L, 0xef4065513e57f43aL, 0x008f517b721c176bL }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[2].actionGen3,
            Ibz.fromMpLimbs(4, new long[]{ 0xd8ce0b200d79118eL, 0xf9cd341f72387b89L, 0x482761373d2a1944L, 0x00222afe35066ad3L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xaae96f34db42d6bdL, 0x492fac8b42742b3aL, 0x41c8be288e5b4605L, 0x0066cb6708e8ffe7L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x4acd8dc93cde9b92L, 0xb25393ea378c59f6L, 0xb325d6f3c63f4da5L, 0x0024350ed143d36cL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x2731f4dff286ee73L, 0x0632cbe08dc78476L, 0xb7d89ec8c2d5e6bbL, 0x00ddd501caf9952cL }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[2].actionGen4,
            Ibz.fromMpLimbs(4, new long[]{ 0x7e74cc3f1bd65d2bL, 0xd6d49f84fba04feaL, 0x4f4e68b188d142a1L, 0x002eb13ba60c13ecL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x649aaa1694487b4fL, 0x8df1d3fd3bc2e4b4L, 0xe8968caa4078931eL, 0x007c166ebed5deecL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x2b40d32d51aa101dL, 0xb323257ac5f807baL, 0x2c3ddc8f20c59bdeL, 0x009917b954a64e7bL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x818b33c0e429a2d5L, 0x292b607b045fb015L, 0xb0b1974e772ebd5eL, 0x00d14ec459f3ec13L }));

        // CURVES_WITH_ENDOMORPHISMS[3]
        setCurveFromLimbs(CURVES_WITH_ENDOMORPHISMS[3].curve,
            new long[]{ 0x0000c17103986f53L, 0x0006268ee5a8a215L, 0x00011304cb0efe57L, 0x0003846c2af6c518L, 0x00002f57c43f40f7L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setPointFromLimbs(CURVES_WITH_ENDOMORPHISMS[3].basisEven.P,
            new long[]{ 0x0005b79ca4d5d6e0L, 0x00039395e18e3349L, 0x00075887ba6eb031L, 0x0007d3b20412639bL, 0x000013cf1bccb9ddL },
            new long[]{ 0x00076561c962386eL, 0x0006f0884ce0b2e6L, 0x00020dd8220aacb5L, 0x00019375e2d543a7L, 0x00004da1583c8553L },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setPointFromLimbs(CURVES_WITH_ENDOMORPHISMS[3].basisEven.Q,
            new long[]{ 0x0004854b149c6d0cL, 0x0007904efa1d89aaL, 0x000343394a9e5c0fL, 0x00068d9d640ad69dL, 0x00002d711f0af96fL },
            new long[]{ 0x0003bcab7a6e1d94L, 0x0006c35a91df0293L, 0x0001b51f6ef1b777L, 0x00006e9f0bb3d284L, 0x0000464e4d547390L },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setPointFromLimbs(CURVES_WITH_ENDOMORPHISMS[3].basisEven.PmQ,
            new long[]{ 0x000376c342849596L, 0x000657b69dced4b6L, 0x00044b159aeb5ecaL, 0x00054b8abf1bdbfeL, 0x0000202393a746e4L },
            new long[]{ 0x000260478ad25e9bL, 0x00021652ecc55014L, 0x000728048f1594daL, 0x00006b5eb728d6d3L, 0x00003f305db59a7fL },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setMatrix(CURVES_WITH_ENDOMORPHISMS[3].actionI,
            Ibz.fromMpLimbs(4, new long[]{ 0x415c44557ed2323fL, 0xcc1176ef42825876L, 0x340547291142bdabL, 0x00c57c1f17791155L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x8a694faca958c9ceL, 0x8c191a17999731e1L, 0x8113c0eb68c7d118L, 0x003fc94ef8c862fdL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x127c8ea0ed4741cbL, 0x3826ce8cf74c69d5L, 0xe695056b6bf33da2L, 0x00d0581784acc45cL }),
            Ibz.fromMpLimbs(4, new long[]{ 0xbea3bbaa812dcdc1L, 0x33ee8910bd7da789L, 0xcbfab8d6eebd4254L, 0x003a83e0e886eeaaL }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[3].actionJ,
            Ibz.fromMpLimbs(4, new long[]{ 0x4e63e9bfe50ddce5L, 0x0c6597c11b8f08ecL, 0x6fb13d9185abcd76L, 0x00bbaa0395f32a59L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xaa2d2196497a5286L, 0x6da0a6e97b17a98aL, 0x7c6e83aee34973f5L, 0x00326931ee2e0031L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x6a64e46d8642c8dcL, 0x9b58d82b90e74c13L, 0x99b45218738164b4L, 0x00b795e25d785926L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xb19c16401af2231bL, 0xf39a683ee470f713L, 0x904ec26e7a543289L, 0x004455fc6a0cd5a6L }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[3].actionK,
            Ibz.fromMpLimbs(4, new long[]{ 0xb6e0c901be7a7363L, 0xd659bc42779d6a56L, 0x923a12f438683476L, 0x0003d5f954126fa8L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x014b5c144fd4edb4L, 0x04bb9c11d6bef702L, 0x5085b159de259f10L, 0x001dc4d36f42b0a9L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x6b01c7ed4974e873L, 0x20d6c641f3d4affbL, 0x451e9f012d69ca22L, 0x00deb43bef65fa05L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x491f36fe41858c9dL, 0x29a643bd886295a9L, 0x6dc5ed0bc797cb89L, 0x00fc2a06abed9057L }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[3].actionGen2,
            Ibz.fromMpLimbs(4, new long[]{ 0x415c44557ed2323fL, 0xcc1176ef42825876L, 0x340547291142bdabL, 0x00c57c1f17791155L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x8a694faca958c9ceL, 0x8c191a17999731e1L, 0x8113c0eb68c7d118L, 0x003fc94ef8c862fdL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x127c8ea0ed4741cbL, 0x3826ce8cf74c69d5L, 0xe695056b6bf33da2L, 0x00d0581784acc45cL }),
            Ibz.fromMpLimbs(4, new long[]{ 0xbea3bbaa812dcdc1L, 0x33ee8910bd7da789L, 0xcbfab8d6eebd4254L, 0x003a83e0e886eeaaL }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[3].actionGen3,
            Ibz.fromMpLimbs(4, new long[]{ 0x2731f4dff286ee73L, 0x0632cbe08dc78476L, 0xb7d89ec8c2d5e6bbL, 0x00ddd501caf9952cL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x551690cb24bd2943L, 0xb6d05374bd8bd4c5L, 0xbe3741d771a4b9faL, 0x00993498f7170018L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xb5327236c321646eL, 0x4dac6c15c873a609L, 0x4cda290c39c0b25aL, 0x00dbcaf12ebc2c93L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xd8ce0b200d79118eL, 0xf9cd341f72387b89L, 0x482761373d2a1944L, 0x00222afe35066ad3L }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[3].actionGen4,
            Ibz.fromMpLimbs(4, new long[]{ 0x490c34a61036ca5bL, 0x1c171590771bc0edL, 0xdb988054977e4855L, 0x00fe77221175b26fL }),
            Ibz.fromMpLimbs(4, new long[]{ 0xb0cbae0a821cf543L, 0x2340d2bf5a80642dL, 0xdace4e38e1ce0c8fL, 0x00059bc4807e3445L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x39a70fd4c3dc6e85L, 0xb0fe0b83777b5158L, 0x53dc103f45b355deL, 0x00012b18b6cb27e2L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xb6f3cb59efc935a5L, 0xe3e8ea6f88e43f12L, 0x24677fab6881b7aaL, 0x000188ddee8a4d90L }));

        // CURVES_WITH_ENDOMORPHISMS[4]
        setCurveFromLimbs(CURVES_WITH_ENDOMORPHISMS[4].curve,
            new long[]{ 0x00014612b0c4c481L, 0x0007219e19939ca1L, 0x0002bc69d2a0a8bdL, 0x0005f4b0bcbad964L, 0x000025664a8d484eL },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setPointFromLimbs(CURVES_WITH_ENDOMORPHISMS[4].basisEven.P,
            new long[]{ 0x00058c095baf6adaL, 0x0000741ce646cd96L, 0x0005007b4e8336a8L, 0x0005010ebbfe93f9L, 0x00001b2013c1eb92L },
            new long[]{ 0x00075c0724e94e91L, 0x00077664d380f258L, 0x0000fb261c9ef941L, 0x000749554a3cd77cL, 0x00001b77c23de11fL },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setPointFromLimbs(CURVES_WITH_ENDOMORPHISMS[4].basisEven.Q,
            new long[]{ 0x00071850cee2e1caL, 0x0001826b78a3cc19L, 0x00000ddebf5154aaL, 0x000696aeeba62d78L, 0x000008953ba03b47L },
            new long[]{ 0x0002dc44634da928L, 0x0004ea539513e1b6L, 0x0005728c1bb241c3L, 0x0003686f2152057eL, 0x00002f6351277b8bL },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setPointFromLimbs(CURVES_WITH_ENDOMORPHISMS[4].basisEven.PmQ,
            new long[]{ 0x0004c38023ba1341L, 0x0000ee167e7a402bL, 0x0007cbae09cd7aeeL, 0x000442bf312e4537L, 0x00000658d9f7ab76L },
            new long[]{ 0x000370f1db4d5016L, 0x0004e773feecb28aL, 0x0000427c305ffbe2L, 0x000687ab9f2e04cbL, 0x00001feaa39f031cL },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setMatrix(CURVES_WITH_ENDOMORPHISMS[4].actionI,
            Ibz.fromMpLimbs(4, new long[]{ 0x206ab453d052900dL, 0xfb21c57931f2e61dL, 0xf9c1f38f02bbc870L, 0x00eb58d147f183aaL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x9e04ebc3a5e8727eL, 0x8ea968e038d7f1ebL, 0x82c048eb83318f77L, 0x0054f2213583b0a3L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x34e9c9b349e4dba9L, 0xcfb0cae0d8767ab9L, 0x1e302c9826b36177L, 0x00713bdc53cc4a38L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xdf954bac2fad6ff3L, 0x04de3a86ce0d19e2L, 0x063e0c70fd44378fL, 0x0014a72eb80e7c55L }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[4].actionJ,
            Ibz.fromMpLimbs(4, new long[]{ 0xb19c16401af2231bL, 0xf39a683ee470f713L, 0x904ec26e7a543289L, 0x004455fc6a0cd5a6L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x55d2de69b685ad7aL, 0x925f591684e85675L, 0x83917c511cb68c0aL, 0x00cd96ce11d1ffceL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x959b1b9279bd3724L, 0x64a727d46f18b3ecL, 0x664bade78c7e9b4bL, 0x00486a1da287a6d9L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x4e63e9bfe50ddce5L, 0x0c6597c11b8f08ecL, 0x6fb13d9185abcd76L, 0x00bbaa0395f32a59L }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[4].actionK,
            Ibz.fromMpLimbs(4, new long[]{ 0x89600cfe1b002417L, 0x222cc00f42d2662eL, 0xbcac863f278b7671L, 0x001b4c5a6e5edb9cL }),
            Ibz.fromMpLimbs(4, new long[]{ 0xef865a2dd92b21e8L, 0x6b378ae01483f492L, 0xf4ec69c57b907f78L, 0x00f8829616602fb9L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xbc0e9aea5dc538ffL, 0xc311447b775dbea5L, 0x162a15fdb63af01cL, 0x00c52a0d9defab76L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x769ff301e4ffdbe9L, 0xddd33ff0bd2d99d1L, 0x435379c0d874898eL, 0x00e4b3a591a12463L }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[4].actionGen2,
            Ibz.fromMpLimbs(4, new long[]{ 0x206ab453d052900dL, 0xfb21c57931f2e61dL, 0xf9c1f38f02bbc870L, 0x00eb58d147f183aaL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x9e04ebc3a5e8727eL, 0x8ea968e038d7f1ebL, 0x82c048eb83318f77L, 0x0054f2213583b0a3L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x34e9c9b349e4dba9L, 0xcfb0cae0d8767ab9L, 0x1e302c9826b36177L, 0x00713bdc53cc4a38L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xdf954bac2fad6ff3L, 0x04de3a86ce0d19e2L, 0x063e0c70fd44378fL, 0x0014a72eb80e7c55L }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[4].actionGen3,
            Ibz.fromMpLimbs(4, new long[]{ 0xd8ce0b200d79118eL, 0xf9cd341f72387b89L, 0x482761373d2a1944L, 0x00222afe35066ad3L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xaae96f34db42d6bdL, 0x492fac8b42742b3aL, 0x41c8be288e5b4605L, 0x0066cb6708e8ffe7L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x4acd8dc93cde9b92L, 0xb25393ea378c59f6L, 0xb325d6f3c63f4da5L, 0x0024350ed143d36cL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x2731f4dff286ee73L, 0x0632cbe08dc78476L, 0xb7d89ec8c2d5e6bbL, 0x00ddd501caf9952cL }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[4].actionGen4,
            Ibz.fromMpLimbs(4, new long[]{ 0x731aacbf269320f0L, 0xf8361bcdd8ceb0f3L, 0xd3aad60444d58469L, 0x003f9086cdc34aa8L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x9534932fe55acc11L, 0x614f2956af432895L, 0x025560c6e4b24e84L, 0x0013c61ed70dbb14L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x54e4d24f450d28d6L, 0xadbe9b71081d6e67L, 0x4b684ebf61481088L, 0x00e5e1a665c8829eL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x8ce55340d96cdf10L, 0x07c9e43227314f0cL, 0x2c5529fbbb2a7b96L, 0x00c06f79323cb557L }));

        // CURVES_WITH_ENDOMORPHISMS[5]
        setCurveFromLimbs(CURVES_WITH_ENDOMORPHISMS[5].curve,
            new long[]{ 0x00027e67b1ad4c35L, 0x0004c9b9707ea7beL, 0x00054e830f39a013L, 0x00002661741eb0d4L, 0x000040d297b19c53L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setPointFromLimbs(CURVES_WITH_ENDOMORPHISMS[5].basisEven.P,
            new long[]{ 0x0006292649ab6ec5L, 0x000514c3aa63eaa8L, 0x00042b95b0dce14aL, 0x00005617e6b3d022L, 0x0000262a0b6ad948L },
            new long[]{ 0x0000296936f8959cL, 0x0007829b486d8303L, 0x00051e4d11693064L, 0x0003559dbc9d0daeL, 0x0000282ba45c8a46L },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setPointFromLimbs(CURVES_WITH_ENDOMORPHISMS[5].basisEven.Q,
            new long[]{ 0x0000bd0e9751b3dfL, 0x00029bd7a6842bbdL, 0x00061480930054f6L, 0x0007c90f1cdb870aL, 0x000010fc8988a92cL },
            new long[]{ 0x0006ee415f437e26L, 0x0002244aa9d1a613L, 0x000437f0b45ef3a9L, 0x000749d8893337b5L, 0x00000e5a6eeb752bL },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setPointFromLimbs(CURVES_WITH_ENDOMORPHISMS[5].basisEven.PmQ,
            new long[]{ 0x000085579e1b8722L, 0x000632525e90080bL, 0x00035539378e8d10L, 0x00047389416f49d3L, 0x000011c1e7bbb047L },
            new long[]{ 0x000367f0f2e5527cL, 0x000763bfb94f5016L, 0x00070df1a057bfdcL, 0x00042460f20b8757L, 0x00004a07f8d23dd8L },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setMatrix(CURVES_WITH_ENDOMORPHISMS[5].actionI,
            Ibz.fromMpLimbs(4, new long[]{ 0xcd7513e0493127cbL, 0x9ff95a913de76846L, 0xb97226eca6d6a270L, 0x003f52fce4b80b44L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x1d16ca745a382d7eL, 0xafc28c2916742547L, 0x79572c7348562349L, 0x00ad04d33c3e67e1L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xcf15321e27fbd8d7L, 0x7ed75fbd6f8efbd3L, 0xb73c593758d6f394L, 0x002264ace0270bfbL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x328aec1fb6ced835L, 0x6006a56ec21897b9L, 0x468dd91359295d8fL, 0x00c0ad031b47f4bbL }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[5].actionJ,
            Ibz.fromMpLimbs(4, new long[]{ 0x4e63e9bfe50ddce5L, 0x0c6597c11b8f08ecL, 0x6fb13d9185abcd76L, 0x00bbaa0395f32a59L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xaa2d2196497a5286L, 0x6da0a6e97b17a98aL, 0x7c6e83aee34973f5L, 0x00326931ee2e0031L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x6a64e46d8642c8dcL, 0x9b58d82b90e74c13L, 0x99b45218738164b4L, 0x00b795e25d785926L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xb19c16401af2231bL, 0xf39a683ee470f713L, 0x904ec26e7a543289L, 0x004455fc6a0cd5a6L }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[5].actionK,
            Ibz.fromMpLimbs(4, new long[]{ 0xebb2cd7f6dc794dfL, 0x0c882825811db290L, 0xc8c37d64959ad514L, 0x00321eea106a16a9L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x19fe1464e778e08cL, 0x4af0a98f1d24ef25L, 0x95ea2b828e4d70d3L, 0x000f1695c2673277L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x4bc9e2a4b6e1f1dfL, 0x9a383fca6365dc85L, 0x1984ca7fed030ee2L, 0x008bc1731efee709L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x144d328092386b21L, 0xf377d7da7ee24d6fL, 0x373c829b6a652aebL, 0x00cde115ef95e956L }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[5].actionGen2,
            Ibz.fromMpLimbs(4, new long[]{ 0xcd7513e0493127cbL, 0x9ff95a913de76846L, 0xb97226eca6d6a270L, 0x003f52fce4b80b44L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x1d16ca745a382d7eL, 0xafc28c2916742547L, 0x79572c7348562349L, 0x00ad04d33c3e67e1L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xcf15321e27fbd8d7L, 0x7ed75fbd6f8efbd3L, 0xb73c593758d6f394L, 0x002264ace0270bfbL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x328aec1fb6ced835L, 0x6006a56ec21897b9L, 0x468dd91359295d8fL, 0x00c0ad031b47f4bbL }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[5].actionGen3,
            Ibz.fromMpLimbs(4, new long[]{ 0x2731f4dff286ee73L, 0x0632cbe08dc78476L, 0xb7d89ec8c2d5e6bbL, 0x00ddd501caf9952cL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x551690cb24bd2943L, 0xb6d05374bd8bd4c5L, 0xbe3741d771a4b9faL, 0x00993498f7170018L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xb5327236c321646eL, 0x4dac6c15c873a609L, 0x4cda290c39c0b25aL, 0x00dbcaf12ebc2c93L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xd8ce0b200d79118eL, 0xf9cd341f72387b89L, 0x482761373d2a1944L, 0x00222afe35066ad3L }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[5].actionGen4,
            Ibz.fromMpLimbs(4, new long[]{ 0x01ee9a31f187d647L, 0x9418bfedeec2193bL, 0xae854c740e9a15b6L, 0x00423f1226773ebeL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x7bbf416c99be68ffL, 0xa8ff7682609fd44fL, 0xc0768e77ec03a6bbL, 0x00f5a15296767873L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xa38ebd23f7da3739L, 0x01a76b0e76908cf9L, 0x51015ac7a2bd77f0L, 0x00952d3aa9223aaeL }),
            Ibz.fromMpLimbs(4, new long[]{ 0xfe1165ce0e7829b9L, 0x6be74012113de6c4L, 0x517ab38bf165ea49L, 0x00bdc0edd988c141L }));

        // CURVES_WITH_ENDOMORPHISMS[6]
        setCurveFromLimbs(CURVES_WITH_ENDOMORPHISMS[6].curve,
            new long[]{ 0x0001fd635b4f2c83L, 0x0003ddd0240b9934L, 0x00053881afe8d4a1L, 0x000723f462627973L, 0x0000147962843332L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setPointFromLimbs(CURVES_WITH_ENDOMORPHISMS[6].basisEven.P,
            new long[]{ 0x000472a0432a50a5L, 0x0002584ec65ccf85L, 0x0005a5586ba27effL, 0x000248f2f0f9bd37L, 0x000042892709fd53L },
            new long[]{ 0x00003727bdaab80dL, 0x000229e05a5546f4L, 0x0004bad4d3212000L, 0x00079e6087aee2dfL, 0x000042f9bfaf2bc8L },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setPointFromLimbs(CURVES_WITH_ENDOMORPHISMS[6].basisEven.Q,
            new long[]{ 0x000140e00d2ad002L, 0x0003235e1c701b8dL, 0x000272d7237bc84dL, 0x00044426d7ad2303L, 0x0000459a7fa89b08L },
            new long[]{ 0x0004246142cac789L, 0x0001a160f97cc85dL, 0x00043707cb72dff1L, 0x00030e5aa57a2936L, 0x00002c228ad830feL },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setPointFromLimbs(CURVES_WITH_ENDOMORPHISMS[6].basisEven.PmQ,
            new long[]{ 0x000519b1a003883dL, 0x000356e25ed579a9L, 0x0006b2a143d80555L, 0x0001039d06c01eadL, 0x00000a3c331e0448L },
            new long[]{ 0x00045ddc052cdef3L, 0x00020a40813439efL, 0x00052630baf0e697L, 0x0004b49649819137L, 0x000014d0e0cfb056L },
            new long[]{ 0x0000000000000019L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000300000000000L },
            new long[]{ 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L });
        setMatrix(CURVES_WITH_ENDOMORPHISMS[6].actionI,
            Ibz.fromMpLimbs(4, new long[]{ 0xc57273deb1867177L, 0xfe177031c0ee9802L, 0xed41e2a741c5bc2eL, 0x001ef5bc9ff91cbfL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x75c232b6bae3726aL, 0x382ad1726e79e003L, 0x6a39a56379628a51L, 0x00a0f6f0c9109cddL }),
            Ibz.fromMpLimbs(4, new long[]{ 0xbd8754e69fa9246bL, 0x25fa64701c7015b5L, 0x7eb5a6e989403f5cL, 0x0016a8df54a16109L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x3a8d8c214e798e89L, 0x01e88fce3f1167fdL, 0x12be1d58be3a43d1L, 0x00e10a436006e340L }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[6].actionJ,
            Ibz.fromMpLimbs(4, new long[]{ 0xb19c16401af2231bL, 0xf39a683ee470f713L, 0x904ec26e7a543289L, 0x004455fc6a0cd5a6L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x55d2de69b685ad7aL, 0x925f591684e85675L, 0x83917c511cb68c0aL, 0x00cd96ce11d1ffceL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x959b1b9279bd3724L, 0x64a727d46f18b3ecL, 0x664bade78c7e9b4bL, 0x00486a1da287a6d9L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x4e63e9bfe50ddce5L, 0x0c6597c11b8f08ecL, 0x6fb13d9185abcd76L, 0x00bbaa0395f32a59L }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[6].actionK,
            Ibz.fromMpLimbs(4, new long[]{ 0x9cbe086c2b021975L, 0x737ed9a7b1c37576L, 0xf9bf7652a2454de1L, 0x0008eaa1dc2c4bf8L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x337c717746bcee88L, 0x3366b65740dc92b6L, 0x114640eb2b986c8aL, 0x00e3a22fb00ae116L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x40b9e24864d3f28dL, 0xcf3582ea82bb5141L, 0x6e88d71f0003faf0L, 0x00cc6b9ef4c97ac9L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x6341f793d4fde68bL, 0x8c8126584e3c8a89L, 0x064089ad5dbab21eL, 0x00f7155e23d3b407L }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[6].actionGen2,
            Ibz.fromMpLimbs(4, new long[]{ 0xc57273deb1867177L, 0xfe177031c0ee9802L, 0xed41e2a741c5bc2eL, 0x001ef5bc9ff91cbfL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x75c232b6bae3726aL, 0x382ad1726e79e003L, 0x6a39a56379628a51L, 0x00a0f6f0c9109cddL }),
            Ibz.fromMpLimbs(4, new long[]{ 0xbd8754e69fa9246bL, 0x25fa64701c7015b5L, 0x7eb5a6e989403f5cL, 0x0016a8df54a16109L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x3a8d8c214e798e89L, 0x01e88fce3f1167fdL, 0x12be1d58be3a43d1L, 0x00e10a436006e340L }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[6].actionGen3,
            Ibz.fromMpLimbs(4, new long[]{ 0xd8ce0b200d79118eL, 0xf9cd341f72387b89L, 0x482761373d2a1944L, 0x00222afe35066ad3L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xaae96f34db42d6bdL, 0x492fac8b42742b3aL, 0x41c8be288e5b4605L, 0x0066cb6708e8ffe7L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x4acd8dc93cde9b92L, 0xb25393ea378c59f6L, 0xb325d6f3c63f4da5L, 0x0024350ed143d36cL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x2731f4dff286ee73L, 0x0632cbe08dc78476L, 0xb7d89ec8c2d5e6bbL, 0x00ddd501caf9952cL }));
        setMatrix(CURVES_WITH_ENDOMORPHISMS[6].actionGen4,
            Ibz.fromMpLimbs(4, new long[]{ 0xc440bcc48ad184a0L, 0x784e15c646ea94e1L, 0x2bee0630d26f0190L, 0x003ce06193ce74b1L }),
            Ibz.fromMpLimbs(4, new long[]{ 0xa69bfa45dafe1e2bL, 0xa0f9927df670b77eL, 0x5f229607c897ccb5L, 0x00d9f781086747bfL }),
            Ibz.fromMpLimbs(4, new long[]{ 0x19bd02adbd3f2aa2L, 0xd17e3fff3b95e6f0L, 0x3b21da467888f3a6L, 0x00c43e505301cc57L }),
            Ibz.fromMpLimbs(4, new long[]{ 0x3bbf433b752e7b60L, 0x87b1ea39b9156b1eL, 0xd411f9cf2d90fe6fL, 0x00c31f9e6c318b4eL }));

    }

    private EndomorphismActionLvl1()
    {
    }
}
