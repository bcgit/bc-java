package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.OneStepKDFBytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.macs.KMAC;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * SP 800-56C Rev. 2 Section 4.1 one-step KDF: the hash option against ConcatenationKDFGenerator, the HMAC
 * option against values computed independently (Python hmac: HMAC(salt, counter || Z || FixedInfo) for
 * counter 1, 2, ...), and the KMAC option against a direct KMAC computation with the standard's single
 * invocation and default salt.
 */
public class OneStepKDFTest
    extends SimpleTest
{
    private static final byte[] Z = Hex.decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    private static final byte[] SALT = Hex.decode("000102030405060708090a0b0c0d0e0f");
    private static final byte[] INFO = Strings.toByteArray("ONESTEP-HMAC test fixed info");

    private static final byte[] HMAC_SHA256 = Hex.decode("24bc85145ba62bec777fc9a700e424d284e090b7dbee40a2a4041f11ef0d73d82e9eca8093eb6ffed2861e4a4c9678cf038024607c4dfe0d5e6824717d45a5017f3a6a0a029c03fef1cfd5f12ccaceb5");
    private static final byte[] HMAC_SHA384 = Hex.decode("fbc8983c68d755a513e7007edb9b8991e0c1039d65d1ff926a260f51ea7599db857d619286c478d2c6e26afef7e92542e0b8c67eff9ee9e09212551f86acbea93b94c344776e667439dfe00dae008f99");
    private static final byte[] HMAC_SHA512 = Hex.decode("34006a6bc2f593e5beefb2c79015a3fe465bcf3b4eaaca318d86c744f91d7ad78d38b445295f2b08da210788fae4eebc667b2f801f69faf81619bc36d8e437b7a98b0cd01beaeadfd762afcb5ad9d973");
    private static final byte[] HMAC_SHA256_NO_SALT = Hex.decode("3de80767ff8a7287ec5110d11862cbcaa1dd6a56806f802e3e9a14d50f7908096053e9e8eb10b5e327b1");
    private static final byte[] HASH_SHA256 = Hex.decode("71156349bad7af2f1890a3b350cec4d54a53f438518b755a219dd258c57022fe82371bf374324fe8f46c505f00d9b4fb");
    private static final byte[] HASH_SHA512 = Hex.decode("d1bb4796ff535e390ff9c3b054317f4383e91327da899b706b9ba865a50cd44e8af451b01f5f6c7dc28311007cd5bf59aa6bd5cc539d0a1d2f2f8c8c05498e8c9d32079a829aca3201f0a178c7eb57cdf01e33d5bd2058607ca25095a9383c93753a4eb5");

    public String getName()
    {
        return "OneStepKDF";
    }

    public void performTest()
        throws Exception
    {
        testHash(new SHA256Digest(), 48, HASH_SHA256);
        testHash(new SHA512Digest(), 100, HASH_SHA512);
        testHash(new SHA384Digest(), 33, null);

        testHmac(new SHA256Digest(), SALT, 80, HMAC_SHA256);
        testHmac(new SHA384Digest(), SALT, 80, HMAC_SHA384);
        testHmac(new SHA512Digest(), SALT, 80, HMAC_SHA512);
        testHmac(new SHA256Digest(), null, 42, HMAC_SHA256_NO_SALT);

        testKmac(128, SALT, 70);
        testKmac(256, SALT, 17);
        testKmac(128, null, 64);
        testKmac(256, null, 64);
    }

    private void testHash(Digest digest, int len, byte[] expected)
    {
        OneStepKDFBytesGenerator kdf = new OneStepKDFBytesGenerator(digest);
        kdf.init(new KDFParameters(Z, INFO));
        byte[] out = new byte[len];
        kdf.generateBytes(out, 0, len);

        ConcatenationKDFGenerator ref = new ConcatenationKDFGenerator(digest);
        ref.init(new KDFParameters(Z, INFO));
        byte[] refOut = new byte[len];
        ref.generateBytes(refOut, 0, len);

        isTrue("hash option differs from ConcatenationKDFGenerator", areEqual(refOut, out));
        if (expected != null)
        {
            isTrue("hash option differs from reference", areEqual(expected, out));
        }
    }

    private void testHmac(Digest digest, byte[] salt, int len, byte[] expected)
    {
        OneStepKDFBytesGenerator kdf = new OneStepKDFBytesGenerator(new HMac(digest), salt);
        kdf.init(new KDFParameters(Z, INFO));
        byte[] out = new byte[len];
        kdf.generateBytes(out, 0, len);

        isTrue("HMAC option differs from reference", areEqual(expected, out));

        // a second call from the same generator gives the same result
        byte[] again = new byte[len];
        kdf.generateBytes(again, 0, len);
        isTrue("HMAC option not repeatable", areEqual(out, again));
    }

    private void testKmac(int bits, byte[] salt, int len)
    {
        OneStepKDFBytesGenerator kdf = new OneStepKDFBytesGenerator(new KMAC(bits, Strings.toByteArray("KDF")), salt);
        kdf.init(new KDFParameters(Z, INFO));
        byte[] out = new byte[len];
        kdf.generateBytes(out, 0, len);

        // SP 800-56C 4.1 Option 3: one KMAC call, counter 1, output length L, default salt of zero bytes
        KMAC ref = new KMAC(bits, Strings.toByteArray("KDF"));
        ref.init(new KeyParameter(salt != null ? salt : new byte[bits == 128 ? 164 : 132]));
        byte[] counter = Pack.intToBigEndian(1);
        ref.update(counter, 0, 4);
        ref.update(Z, 0, Z.length);
        ref.update(INFO, 0, INFO.length);
        byte[] refOut = new byte[len];
        ref.doFinal(refOut, 0, len);

        isTrue("KMAC option differs from direct KMAC", areEqual(refOut, out));

        // the default salt is not the empty key
        if (salt == null)
        {
            KMAC empty = new KMAC(bits, Strings.toByteArray("KDF"));
            empty.init(new KeyParameter(new byte[0]));
            empty.update(counter, 0, 4);
            empty.update(Z, 0, Z.length);
            empty.update(INFO, 0, INFO.length);
            byte[] emptyOut = new byte[len];
            empty.doFinal(emptyOut, 0, len);
            isTrue("default KMAC salt must not be the empty key", !areEqual(emptyOut, out));
        }
    }

    public static void main(String[] args)
    {
        runTest(new OneStepKDFTest());
    }
}
