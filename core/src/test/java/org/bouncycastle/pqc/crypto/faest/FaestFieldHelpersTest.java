package org.bouncycastle.pqc.crypto.faest;

import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Algebraic tests for the FAEST proof-helpers added to BF8 and BF128/192/256.
 * <p>
 * Two layers:
 * <ol>
 *   <li><b>Algebraic invariants:</b> {@code bits_sq} matches {@link BF8#square},
 *       {@code byteCombineBits} is GF(2)-linear, {@code byteCombine} on bit-valued
 *       inputs agrees with {@code byteCombineBits}, {@code byteCombineBitsSq} is
 *       {@code byteCombineBits} composed with {@code bits_sq}, and the trivial
 *       {@code mulBit}/{@code fromBit} identities hold.</li>
 *   <li><b>Upstream KAT byte vectors:</b> a sample of {@code byteCombineBits(b)}
 *       results from faest-ref {@code tests/fields.cpp} ({@code poly{128,192,256}_from_8_poly1}).
 *       These catch transcription errors in the {@code ALPHA[7]} tables that
 *       internal self-consistency could not (a typoed alpha entry would be
 *       returned unchanged by a unit-bit input).</li>
 * </ol>
 * <p>
 * Note on power basis. For BF128 and BF192 the upstream alpha tables happen to
 * be the power basis {@code alpha^1..alpha^7} where {@code alpha} satisfies
 * the AES Rijndael polynomial {@code x^8 + x^4 + x^3 + x + 1} in the host
 * field; for BF256 they do not (verified against the upstream C code: alpha[0]^2
 * differs from alpha[1] in the actual GF(2^256) ring). The FAEST proof system
 * uses {@code byteCombineBits} as a fixed GF(2)-linear lift, not a multiplicative
 * homomorphism, so the power-basis property is not required for soundness.
 */
public class FaestFieldHelpersTest
    extends SimpleTest
{
    public String getName()
    {
        return "FaestFieldHelpers";
    }

    public void performTest()
        throws Exception
    {
        bits_sq_matches_bf8_square();
        bf128_helpers();
        bf192_helpers();
        bf256_helpers();
    }

    /**
     * For every byte {@code b in 0..255}: build its bit-vector representation,
     * apply {@code bits_sq}, repack into a byte; the result must equal
     * {@code BF8.square(b)}.
     */
    private void bits_sq_matches_bf8_square()
    {
        for (int b = 0; b < 256; b++)
        {
            byte[] bits = new byte[8];
            for (int i = 0; i < 8; i++)
            {
                bits[i] = (byte)((b >>> i) & 1);
            }
            BF8.bits_sq(bits);
            int repacked = 0;
            for (int i = 0; i < 8; i++)
            {
                repacked |= (bits[i] & 1) << i;
            }
            int expected = BF8.square(b);
            if (repacked != expected)
            {
                fail("bits_sq disagrees with BF8.square at b=0x" + Integer.toHexString(b)
                    + ": expected 0x" + Integer.toHexString(expected)
                    + ", got 0x" + Integer.toHexString(repacked));
            }
        }
    }

    // ===== BF128 =====

    /** Upstream {@code poly128_from_8_poly1_input}, fields.cpp:653. */
    private static final byte[] BF128_KAT_IN = Hex.decode("c1a3c022e718935f46630386afa3d3f2");

    /** Upstream {@code poly128_from_8_poly1_output} (16 vectors of 16 bytes each), fields.cpp:657. */
    private static final String[] BF128_KAT_OUT = {
        "9f0617c47b7c51bd9590bb237294d1df",
        "04b54dcf1f2f6efe59cba8fcaea4f558",
        "9e0617c47b7c51bd9590bb237294d1df",
        "b94c7b2e8ba11484b9441fb3b495a551",
        "c7e4e4de3a8432d5a86f1b0c85b680c2",
        "e1de170ae6324cd438f0f33d09566638",
        "f9af78887056c6b0023782a60982a601",
        "2e41de4e6f712f5ed5ced76477c12ea7",
        "ce9fc9448943638aed3e24597e97489f",
        "9ab35a0b64533f43cc5b13dfdc302487",
        "0cce6055ace83fa11c9a97a955853d05",
        "5099de80f23f323778ae9f7a0c039940",
        "4d5dfccd7b74d6ad1ba2461da273ac21",
        "04b54dcf1f2f6efe59cba8fcaea4f558",
        "db5059ad9fa4ed7777288eca612727d7",
        "6ed242d6b8edc652d2f606d08037bf83",
    };

    private void bf128_helpers()
    {
        // ----- algebraic invariants -----
        long[] one = new long[BF128.LIMBS]; BF128.one(one, 0);
        long[] zero = new long[BF128.LIMBS];

        long[] z = new long[BF128.LIMBS]; BF128.fromBit(z, 0, 0);
        isTrue("BF128 fromBit(0)==0", BF128.equals(z, 0, zero, 0));
        BF128.fromBit(z, 0, 1);
        isTrue("BF128 fromBit(1)==1", BF128.equals(z, 0, one, 0));

        long[] a = BF128.ALPHA[3];
        long[] zM = new long[BF128.LIMBS];
        BF128.mulBit(zM, 0, a, 0, 0);
        isTrue("BF128 mulBit(a,0)==0", BF128.equals(zM, 0, zero, 0));
        BF128.mulBit(zM, 0, a, 0, 1);
        isTrue("BF128 mulBit(a,1)==a", BF128.equals(zM, 0, a, 0));

        // byteCombineBits unit-bit recovers each alpha power (internal self-consistency).
        for (int i = 0; i < 8; i++)
        {
            byte[] bits = new byte[8]; bits[i] = 1;
            long[] out = new long[BF128.LIMBS];
            BF128.byteCombineBits(out, 0, bits, 0);
            long[] expected = (i == 0) ? one : BF128.ALPHA[i - 1];
            isTrue("BF128 byteCombineBits(e" + i + ")", BF128.equals(out, 0, expected, 0));
        }

        // GF(2)-linearity: f(a xor b) = f(a) + f(b).
        byte[] aa = {1, 0, 1, 0, 1, 1, 0, 1};
        byte[] bb = {0, 1, 1, 1, 0, 1, 1, 0};
        byte[] xorAB = new byte[8];
        for (int i = 0; i < 8; i++)
        {
            xorAB[i] = (byte)(aa[i] ^ bb[i]);
        }
        long[] fA = new long[BF128.LIMBS];   BF128.byteCombineBits(fA, 0, aa, 0);
        long[] fB = new long[BF128.LIMBS];   BF128.byteCombineBits(fB, 0, bb, 0);
        long[] fXor = new long[BF128.LIMBS]; BF128.byteCombineBits(fXor, 0, xorAB, 0);
        long[] sumAB = new long[BF128.LIMBS]; BF128.add(sumAB, 0, fA, 0, fB, 0);
        isTrue("BF128 byteCombineBits linearity", BF128.equals(fXor, 0, sumAB, 0));

        // byteCombine on bit-valued field elements agrees with byteCombineBits.
        long[] x = new long[8 * BF128.LIMBS];
        for (int i = 0; i < 8; i++)
        {
            BF128.fromBit(x, i * BF128.LIMBS, aa[i]);
        }
        long[] combine = new long[BF128.LIMBS];
        BF128.byteCombine(combine, 0, x, 0);
        isTrue("BF128 byteCombine == byteCombineBits on bit inputs",
            BF128.equals(combine, 0, fA, 0));

        // byteCombineBitsSq == byteCombineBits ∘ bits_sq (by definition).
        byte[] copy = aa.clone();
        BF8.bits_sq(copy);
        long[] expectedSq = new long[BF128.LIMBS];
        BF128.byteCombineBits(expectedSq, 0, copy, 0);
        long[] gotSq = new long[BF128.LIMBS];
        BF128.byteCombineBitsSq(gotSq, 0, aa, 0);
        isTrue("BF128 byteCombineBitsSq definition", BF128.equals(expectedSq, 0, gotSq, 0));

        // ----- upstream KAT -----
        for (int idx = 0; idx < BF128_KAT_IN.length; idx++)
        {
            byte[] bits = new byte[8];
            int b = BF128_KAT_IN[idx] & 0xff;
            for (int i = 0; i < 8; i++)
            {
                bits[i] = (byte)((b >>> i) & 1);
            }
            long[] out = new long[BF128.LIMBS];
            BF128.byteCombineBits(out, 0, bits, 0);
            byte[] gotBytes = new byte[BF128.BYTES];
            BF128.store(gotBytes, 0, out, 0);
            byte[] expectedBytes = Hex.decode(BF128_KAT_OUT[idx]);
            if (!java.util.Arrays.equals(gotBytes, expectedBytes))
            {
                fail("BF128 byteCombineBits KAT[" + idx + "] (b=0x" + Integer.toHexString(b)
                    + "): got " + Hex.toHexString(gotBytes)
                    + ", expected " + Hex.toHexString(expectedBytes));
            }
        }
    }

    // ===== BF192 =====

    /** Upstream {@code poly192_from_8_poly1_input}, fields.cpp:692. */
    private static final byte[] BF192_KAT_IN = Hex.decode("c0720b10bf266c1924188772c51fbe52");

    /** Upstream {@code poly192_from_8_poly1_output}, fields.cpp:696. */
    private static final String[] BF192_KAT_OUT = {
        "cb64d38bb4c19b629bc9d166cc0af393f32eeb660bebdaee",
        "7caa08b63d47325e08f13faedeeecc6735be1db8bd303c8b",
        "6f1d019ac68fa550f3305c901b34576494781e3264c5303d",
        "5df72bbd7c7420dd2ed25800ab42557a5112bc949c51ec45",
        "001416b404cbf712ac8abf1b7c18fb0d04051236e0e14eb3",
        "20ec0299a9ce2ea6483cd324c2448595139d5c9158ebe53d",
        "f410d6ed19dd8461f32c58eb77873802c40f2eca63937329",
        "517d12486f584d41375f6a06dca167f8a75cc9a8ec5cd749",
        "437b3af67c6de66aa281bdb2ae93e07371ab379f4c23ee0c",
        "507d12486f584d41375f6a06dca167f8a75cc9a8ec5cd749",
        "a842ca76899f6f8b1f6b0b7a17358afde6297dd566a9e42c",
        "7caa08b63d47325e08f13faedeeecc6735be1db8bd303c8b",
        "713427f72aa0a8d0bdf6b2b3d51505e8c7f57ab22ddc4934",
        "89bade5b249ab63ffbdd6745a969f465f1b13372dea34fa2",
        "011416b404cbf712ac8abf1b7c18fb0d04051236e0e14eb3",
        "8481c63cdf4be7868c4fe1c96962da6f70cebbf3d724415d",
    };

    private void bf192_helpers()
    {
        long[] one = new long[BF192.LIMBS]; BF192.one(one, 0);
        long[] zero = new long[BF192.LIMBS];

        long[] z = new long[BF192.LIMBS]; BF192.fromBit(z, 0, 0);
        isTrue("BF192 fromBit(0)==0", BF192.equals(z, 0, zero, 0));
        BF192.fromBit(z, 0, 1);
        isTrue("BF192 fromBit(1)==1", BF192.equals(z, 0, one, 0));

        long[] a = BF192.ALPHA[3];
        long[] zM = new long[BF192.LIMBS];
        BF192.mulBit(zM, 0, a, 0, 0);
        isTrue("BF192 mulBit(a,0)==0", BF192.equals(zM, 0, zero, 0));
        BF192.mulBit(zM, 0, a, 0, 1);
        isTrue("BF192 mulBit(a,1)==a", BF192.equals(zM, 0, a, 0));

        for (int i = 0; i < 8; i++)
        {
            byte[] bits = new byte[8]; bits[i] = 1;
            long[] out = new long[BF192.LIMBS];
            BF192.byteCombineBits(out, 0, bits, 0);
            long[] expected = (i == 0) ? one : BF192.ALPHA[i - 1];
            isTrue("BF192 byteCombineBits(e" + i + ")", BF192.equals(out, 0, expected, 0));
        }

        byte[] aa = {1, 0, 1, 0, 1, 1, 0, 1};
        byte[] bb = {0, 1, 1, 1, 0, 1, 1, 0};
        byte[] xorAB = new byte[8];
        for (int i = 0; i < 8; i++)
        {
            xorAB[i] = (byte)(aa[i] ^ bb[i]);
        }
        long[] fA = new long[BF192.LIMBS];   BF192.byteCombineBits(fA, 0, aa, 0);
        long[] fB = new long[BF192.LIMBS];   BF192.byteCombineBits(fB, 0, bb, 0);
        long[] fXor = new long[BF192.LIMBS]; BF192.byteCombineBits(fXor, 0, xorAB, 0);
        long[] sumAB = new long[BF192.LIMBS]; BF192.add(sumAB, 0, fA, 0, fB, 0);
        isTrue("BF192 byteCombineBits linearity", BF192.equals(fXor, 0, sumAB, 0));

        long[] x = new long[8 * BF192.LIMBS];
        for (int i = 0; i < 8; i++)
        {
            BF192.fromBit(x, i * BF192.LIMBS, aa[i]);
        }
        long[] combine = new long[BF192.LIMBS];
        BF192.byteCombine(combine, 0, x, 0);
        isTrue("BF192 byteCombine == byteCombineBits on bit inputs",
            BF192.equals(combine, 0, fA, 0));

        byte[] copy = aa.clone();
        BF8.bits_sq(copy);
        long[] expectedSq = new long[BF192.LIMBS];
        BF192.byteCombineBits(expectedSq, 0, copy, 0);
        long[] gotSq = new long[BF192.LIMBS];
        BF192.byteCombineBitsSq(gotSq, 0, aa, 0);
        isTrue("BF192 byteCombineBitsSq definition", BF192.equals(expectedSq, 0, gotSq, 0));

        for (int idx = 0; idx < BF192_KAT_IN.length; idx++)
        {
            byte[] bits = new byte[8];
            int b = BF192_KAT_IN[idx] & 0xff;
            for (int i = 0; i < 8; i++)
            {
                bits[i] = (byte)((b >>> i) & 1);
            }
            long[] out = new long[BF192.LIMBS];
            BF192.byteCombineBits(out, 0, bits, 0);
            byte[] gotBytes = new byte[BF192.BYTES];
            BF192.store(gotBytes, 0, out, 0);
            byte[] expectedBytes = Hex.decode(BF192_KAT_OUT[idx]);
            if (!java.util.Arrays.equals(gotBytes, expectedBytes))
            {
                fail("BF192 byteCombineBits KAT[" + idx + "] (b=0x" + Integer.toHexString(b)
                    + "): got " + Hex.toHexString(gotBytes)
                    + ", expected " + Hex.toHexString(expectedBytes));
            }
        }
    }

    // ===== BF256 =====

    /** Upstream {@code poly256_from_8_poly1_input}, fields.cpp:731. */
    private static final byte[] BF256_KAT_IN = Hex.decode("c0cd0bedbe6a4c04b375897d369b7e62");

    /** Upstream {@code poly256_from_8_poly1_output}, fields.cpp:735. */
    private static final String[] BF256_KAT_OUT = {
        "808f766d21193624b1c0494310a2dafe3b0a7106150e64df4b52910326dd03d3",
        "5d9bd487885fb6d8c9c8303c83e50ec2c1164ec71d54b8f537eedbef9473d8b4",
        "fb635e34c13b4dc330417cf3260ea7a97a4dce557acfb424beaed850144b5c65",
        "ebab5e6ea1aa74404b4cc17c573ecad940bf07ba895d06dacba18c9ef978ff96",
        "d3ffdf0b43889796664e47a0388dd6be6be1f1f8459822df3358c920cfa8c904",
        "473490035161fac50e6a7cd534b38e1e85fb1edad1e30bfbb1c875f056774687",
        "d773e63410e9f562c4a78819552139908403a633377fddda8f95b03d9d99e6a7",
        "c18922d52af55aa92f07422c8dc4a52beab0006c370d4ad1f14a5b9c694d4e06",
        "0eeb7de1eace176a1e463edfabca028291fdce394dc2fef54fe483cc7d061263",
        "a813f752a3aaec71e7cf72100e21abe92aa64eab2a59f224c6a48073fd3e96b2",
        "9775b28c1b0599ef5a608376c847464555b9d759157cf3d4358d7aa2d209ab72",
        "b58e776d20193624b0c0494310a2dafe3a0a7106150e64df4b52910326dd03d3",
        "458a6d87588d0e793c2ec4d6f0ca90fb3e5826a150e4d10b06d5b3821da16276",
        "a546773740880fa7cbcdf4cc6192b78e00f8b8e9e69cd6213e5dc5cdcbeea020",
        "5370a9666291a1b2d78e0ee3282f0c4050eb80fe50964600780a5823e975cad7",
        "5aa9103cd2d22090596547862a30ff0995572177eeb49d003c3e64808d94d3e6",
    };

    private void bf256_helpers()
    {
        long[] one = new long[BF256.LIMBS]; BF256.one(one, 0);
        long[] zero = new long[BF256.LIMBS];

        long[] z = new long[BF256.LIMBS]; BF256.fromBit(z, 0, 0);
        isTrue("BF256 fromBit(0)==0", BF256.equals(z, 0, zero, 0));
        BF256.fromBit(z, 0, 1);
        isTrue("BF256 fromBit(1)==1", BF256.equals(z, 0, one, 0));

        long[] a = BF256.ALPHA[3];
        long[] zM = new long[BF256.LIMBS];
        BF256.mulBit(zM, 0, a, 0, 0);
        isTrue("BF256 mulBit(a,0)==0", BF256.equals(zM, 0, zero, 0));
        BF256.mulBit(zM, 0, a, 0, 1);
        isTrue("BF256 mulBit(a,1)==a", BF256.equals(zM, 0, a, 0));

        for (int i = 0; i < 8; i++)
        {
            byte[] bits = new byte[8]; bits[i] = 1;
            long[] out = new long[BF256.LIMBS];
            BF256.byteCombineBits(out, 0, bits, 0);
            long[] expected = (i == 0) ? one : BF256.ALPHA[i - 1];
            isTrue("BF256 byteCombineBits(e" + i + ")", BF256.equals(out, 0, expected, 0));
        }

        byte[] aa = {1, 0, 1, 0, 1, 1, 0, 1};
        byte[] bb = {0, 1, 1, 1, 0, 1, 1, 0};
        byte[] xorAB = new byte[8];
        for (int i = 0; i < 8; i++)
        {
            xorAB[i] = (byte)(aa[i] ^ bb[i]);
        }
        long[] fA = new long[BF256.LIMBS];   BF256.byteCombineBits(fA, 0, aa, 0);
        long[] fB = new long[BF256.LIMBS];   BF256.byteCombineBits(fB, 0, bb, 0);
        long[] fXor = new long[BF256.LIMBS]; BF256.byteCombineBits(fXor, 0, xorAB, 0);
        long[] sumAB = new long[BF256.LIMBS]; BF256.add(sumAB, 0, fA, 0, fB, 0);
        isTrue("BF256 byteCombineBits linearity", BF256.equals(fXor, 0, sumAB, 0));

        long[] x = new long[8 * BF256.LIMBS];
        for (int i = 0; i < 8; i++)
        {
            BF256.fromBit(x, i * BF256.LIMBS, aa[i]);
        }
        long[] combine = new long[BF256.LIMBS];
        BF256.byteCombine(combine, 0, x, 0);
        isTrue("BF256 byteCombine == byteCombineBits on bit inputs",
            BF256.equals(combine, 0, fA, 0));

        byte[] copy = aa.clone();
        BF8.bits_sq(copy);
        long[] expectedSq = new long[BF256.LIMBS];
        BF256.byteCombineBits(expectedSq, 0, copy, 0);
        long[] gotSq = new long[BF256.LIMBS];
        BF256.byteCombineBitsSq(gotSq, 0, aa, 0);
        isTrue("BF256 byteCombineBitsSq definition", BF256.equals(expectedSq, 0, gotSq, 0));

        for (int idx = 0; idx < BF256_KAT_IN.length; idx++)
        {
            byte[] bits = new byte[8];
            int b = BF256_KAT_IN[idx] & 0xff;
            for (int i = 0; i < 8; i++)
            {
                bits[i] = (byte)((b >>> i) & 1);
            }
            long[] out = new long[BF256.LIMBS];
            BF256.byteCombineBits(out, 0, bits, 0);
            byte[] gotBytes = new byte[BF256.BYTES];
            BF256.store(gotBytes, 0, out, 0);
            byte[] expectedBytes = Hex.decode(BF256_KAT_OUT[idx]);
            if (!java.util.Arrays.equals(gotBytes, expectedBytes))
            {
                fail("BF256 byteCombineBits KAT[" + idx + "] (b=0x" + Integer.toHexString(b)
                    + "): got " + Hex.toHexString(gotBytes)
                    + ", expected " + Hex.toHexString(expectedBytes));
            }
        }
    }

    public static void main(String[] args)
    {
        runTest(new FaestFieldHelpersTest());
    }
}
