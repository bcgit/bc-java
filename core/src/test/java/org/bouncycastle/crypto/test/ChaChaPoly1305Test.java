package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.ChaChaPoly1305Engine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class ChaChaPoly1305Test
    extends SimpleTest
{
    // Test vector from https://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-04#section-2.8.2
    private byte[] K1 = Hex.decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    private byte[] N1 = Hex.decode("070000004041424344454647");
    private byte[] A1 = Hex.decode("50515253c0c1c2c3c4c5c6c7");
    private byte[] P1 = Hex.decode("4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
        + "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
        + "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
        + "637265656e20776f756c642062652069742e");
    private byte[] C1 = Hex.decode("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        + "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        + "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        + "3ff4def08e4b7a9de576d26586cec64b6116"
        + "1ae10b594f09e26a7e902ecbd0600691");
    private byte[] T1 = Hex.decode("1ae10b594f09e26a7e902ecbd0600691");

    // Additional vector from https://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-04#appendix-A.5
    private byte[] K2 = Hex.decode("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0");
    private byte[] N2 = Hex.decode("000000000102030405060708");
    private byte[] A2 = Hex.decode("f33388860000000000004e91");
    private byte[] P2 = Hex.decode("496e7465726e65742d4472616674732061726520647261667420646f63756d65" +
            "6e74732076616c696420666f722061206d6178696d756d206f6620736978206d" +
            "6f6e74687320616e64206d617920626520757064617465642c207265706c6163" +
            "65642c206f72206f62736f6c65746564206279206f7468657220646f63756d65" +
            "6e747320617420616e792074696d652e20497420697320696e617070726f7072" +
            "6961746520746f2075736520496e7465726e65742d4472616674732061732072" +
            "65666572656e6365206d6174657269616c206f7220746f206369746520746865" +
            "6d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67" +
            "726573732e2fe2809d");
    private byte[] C2 = Hex.decode("64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2" +
            "4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf" +
            "332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855" +
            "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4" +
            "b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e" +
            "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a" +
            "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10" +
            "49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29" +
            "a6ad5cb4022b02709b" + "eead9d67890cbb22392336fea1851f38");
    private byte[] T2 = Hex.decode("eead9d67890cbb22392336fea1851f38");


    private static final int NONCE_LEN = 12;
    private static final int MAC_LEN = 16;
    private static final int AUTHEN_LEN = 20;

    public String getName()
    {
        return "ChaChaPoly1305";
    }

    public void performTest()
        throws Exception
    {
        checkVectors(1, K1, 128, N1, A1, P1, T1, C1);
        checkVectors(2, K2, 128, N2, A2, P2, T2, C2);

        ivParamTest(1, new ChaChaPoly1305Engine(), K1, N1);

        randomTests();
        AEADTestUtil.testReset(this, new ChaChaPoly1305Engine(), new ChaChaPoly1305Engine(), new AEADParameters(new KeyParameter(K1), 128, N1));
        AEADTestUtil.testTampering(this, new ChaChaPoly1305Engine(), new AEADParameters(new KeyParameter(K1), 128, N1));
        AEADTestUtil.testOutputSizes(this, new ChaChaPoly1305Engine(), new AEADParameters(new KeyParameter(K1), 128, N1));
        AEADTestUtil.testBufferSizeChecks(this, new ChaChaPoly1305Engine(), new AEADParameters(new KeyParameter(K1), 128, N1));
    }

    private void checkVectors(
        int count,
        byte[] k,
        int macSize,
        byte[] n,
        byte[] a,
        byte[] p,
        byte[] t,
        byte[] c)
        throws InvalidCipherTextException
    {
        byte[] fa = new byte[a.length / 2];
        byte[] la = new byte[a.length - (a.length / 2)];
        System.arraycopy(a, 0, fa, 0, fa.length);
        System.arraycopy(a, fa.length, la, 0, la.length);

        checkVectors(count, "all initial associated data", k, macSize, n, a, null, p, t, c);
        checkVectors(count, "subsequent associated data", k, macSize, n, null, a, p, t, c);
        checkVectors(count, "split associated data", k, macSize, n, fa, la, p, t, c);
    }

    private void checkVectors(
        int count,
        String additionalDataType,
        byte[] k,
        int macSize,
        byte[] n,
        byte[] a,
        byte[] sa,
        byte[] p,
        byte[] t,
        byte[] c)
        throws InvalidCipherTextException
    {
        ChaChaPoly1305Engine enc = new ChaChaPoly1305Engine();
        ChaChaPoly1305Engine dec = new ChaChaPoly1305Engine();

        AEADParameters parameters = new AEADParameters(new KeyParameter(k), macSize, n, a);
        enc.init(true, parameters);
        dec.init(false, parameters);

        runCheckVectors(count, enc, dec, additionalDataType, sa, p, t, c);
        runCheckVectors(count, enc, dec, additionalDataType, sa, p, t, c);

        // key reuse test
        parameters = new AEADParameters(null, macSize, n, a);
        enc.init(true, parameters);
        dec.init(false, parameters);

        runCheckVectors(count, enc, dec, additionalDataType, sa, p, t, c);
        runCheckVectors(count, enc, dec, additionalDataType, sa, p, t, c);
    }

    private void runCheckVectors(
        int count,
        ChaChaPoly1305Engine encCipher,
        ChaChaPoly1305Engine decCipher,
        String additionalDataType,
        byte[] sa,
        byte[] p,
        byte[] t,
        byte[] c)
        throws InvalidCipherTextException
    {
        byte[] enc = new byte[encCipher.getOutputSize(p.length)];

        if (sa != null)
        {
            encCipher.processAADBytes(sa, 0, sa.length);
        }

        int len = encCipher.processBytes(p, 0, p.length, enc, 0);

        len += encCipher.doFinal(enc, len);

        if (!areEqual(c, enc))
        {
            fail("encrypted stream fails to match in test " + count + " with " + additionalDataType,
                    new String(Hex.encode(c)), new String(Hex.encode(enc)));
        }

        byte[] tmp = new byte[enc.length];

        if (sa != null)
        {
            decCipher.processAADBytes(sa, 0, sa.length);
        }

        len = decCipher.processBytes(enc, 0, enc.length, tmp, 0);

        len += decCipher.doFinal(tmp, len);

        byte[] dec = new byte[len];

        System.arraycopy(tmp, 0, dec, 0, len);

        if (!areEqual(p, dec))
        {
            fail("decrypted stream fails to match in test " + count + " with " + additionalDataType);
        }

        if (!areEqual(t, decCipher.getMac()))
        {
            fail("MAC fails to match in test " + count + " with " + additionalDataType);
        }
    }

    private void ivParamTest(
        int count,
        AEADBlockCipher c,
        byte[] k,
        byte[] n)
        throws InvalidCipherTextException
    {
        byte[] p = Strings.toByteArray("hello world!!");

        c.init(true, new ParametersWithIV(new KeyParameter(k), n));

        byte[] enc = new byte[c.getOutputSize(p.length)];

        int len = c.processBytes(p, 0, p.length, enc, 0);

        len += c.doFinal(enc, len);

        c.init(false, new ParametersWithIV(new KeyParameter(k), n));

        byte[] tmp = new byte[enc.length];

        len = c.processBytes(enc, 0, enc.length, tmp, 0);

        len += c.doFinal(tmp, len);

        byte[] dec = new byte[len];

        System.arraycopy(tmp, 0, dec, 0, len);

        if (!areEqual(p, dec))
        {
            fail("decrypted stream fails to match in test " + count);
        }
    }

    private void randomTests()
        throws InvalidCipherTextException
    {
        SecureRandom srng = new SecureRandom();
        for (int i = 0; i < 10; ++i)
        {
            randomTest(srng);
        }
    }

    private void randomTest(
        SecureRandom srng)
        throws InvalidCipherTextException
    {
        int DAT_LEN = srng.nextInt() >>> 22; // Note: JDK1.0 compatibility
        byte[] nonce = new byte[NONCE_LEN];
        byte[] authen = new byte[AUTHEN_LEN];
        byte[] datIn = new byte[DAT_LEN];
        byte[] key = new byte[32];
        srng.nextBytes(nonce);
        srng.nextBytes(authen);
        srng.nextBytes(datIn);
        srng.nextBytes(key);

        KeyParameter sessKey = new KeyParameter(key);
        ChaChaPoly1305Engine c = new ChaChaPoly1305Engine();

        AEADParameters params = new AEADParameters(sessKey, MAC_LEN * 8, nonce, authen);
        c.init(true, params);

        byte[] intrDat = new byte[c.getOutputSize(datIn.length)];
        int outOff = c.processBytes(datIn, 0, DAT_LEN, intrDat, 0);
        outOff += c.doFinal(intrDat, outOff);

        c.init(false, params);
        byte[] datOut = new byte[c.getOutputSize(outOff)];
        int resultLen = c.processBytes(intrDat, 0, outOff, datOut, 0);
        c.doFinal(datOut, resultLen);

        if (!areEqual(datIn, datOut))
        {
            fail("ChaChaPoly1305 roundtrip failed to match");
        }
    }

    public static void main(String[] args)
    {
        runTest(new ChaChaPoly1305Test());
    }
}
