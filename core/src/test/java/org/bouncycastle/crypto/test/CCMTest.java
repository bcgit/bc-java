package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.CCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * First four test vectors from
 * NIST Special Publication 800-38C.
 */
public class CCMTest
    extends SimpleTest
{
    private byte[] K1 = Hex.decode("404142434445464748494a4b4c4d4e4f");
    private byte[] N1 = Hex.decode("10111213141516");
    private byte[] A1 = Hex.decode("0001020304050607");
    private byte[] P1 = Hex.decode("20212223");
    private byte[] C1 = Hex.decode("7162015b4dac255d");
    private byte[] T1 = Hex.decode("6084341b");

    private byte[] K2 = Hex.decode("404142434445464748494a4b4c4d4e4f");
    private byte[] N2 = Hex.decode("1011121314151617");
    private byte[] A2 = Hex.decode("000102030405060708090a0b0c0d0e0f");
    private byte[] P2 = Hex.decode("202122232425262728292a2b2c2d2e2f");
    private byte[] C2 = Hex.decode("d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd");
    private byte[] T2 = Hex.decode("7f479ffca464");

    private byte[] K3 = Hex.decode("404142434445464748494a4b4c4d4e4f");
    private byte[] N3 = Hex.decode("101112131415161718191a1b");
    private byte[] A3 = Hex.decode("000102030405060708090a0b0c0d0e0f10111213");
    private byte[] P3 = Hex.decode("202122232425262728292a2b2c2d2e2f3031323334353637");
    private byte[] C3 = Hex.decode("e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951");
    private byte[] T3 = Hex.decode("67c99240c7d51048");

    private byte[] K4 = Hex.decode("404142434445464748494a4b4c4d4e4f");
    private byte[] N4 = Hex.decode("101112131415161718191a1b1c");
    private byte[] A4 = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    private byte[] P4 = Hex.decode("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    private byte[] C4 = Hex.decode("69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72b4ac6bec93e8598e7f0dadbcea5b");
    private byte[] T4 = Hex.decode("f4dd5d0ee404617225ffe34fce91");

    //
    // long data vector
    //
    private byte[] C5 = Hex.decode("49b17d8d3ea4e6174a48e2b65e6d8b417ac0dd3f8ee46ce4a4a2a509661cef52528c1cd9805333a5cfd482fa3f095a3c2fdd1cc47771c5e55fddd60b5c8d6d3fa5c8dd79d08b16242b6642106e7c0c28bd1064b31e6d7c9800c8397dbc3fa8071e6a38278b386c18d65d39c6ad1ef9501a5c8f68d38eb6474799f3cc898b4b9b97e87f9c95ce5c51bc9d758f17119586663a5684e0a0daf6520ec572b87473eb141d10471e4799ded9e607655402eca5176bbf792ef39dd135ac8d710da8e9e854fd3b95c681023f36b5ebe2fb213d0b62dd6e9e3cfe190b792ccb20c53423b2dca128f861a61d306910e1af418839467e466f0ec361d2539eedd99d4724f1b51c07beb40e875a87491ec8b27cd1");
    private byte[] T5 = Hex.decode("5c768856796b627b13ec8641581b");

    public void performTest()
        throws Exception
    {
        // TODO Need to resolve dependency on processPacket methods (add them to CCMModeCipher?)
//        CCMModeCipher ccm = CCMBlockCipher.newInstance(AESEngine.newInstance());
        CCMBlockCipher ccm = new CCMBlockCipher(AESEngine.newInstance());

        checkVectors(0, K1, 32, N1, A1, P1, T1, C1);
        checkVectors(1, K2, 48, N2, A2, P2, T2, C2);
        checkVectors(2, K3, 64, N3, A3, P3, T3, C3);

        ivParamTest(0, ccm, K1, N1);

        //
        // 4 has a reduced associated text which needs to be replicated
        //
        byte[] a4 = new byte[65536]; // 524288 / 8

        for (int i = 0; i < a4.length; i += A4.length)
        {
            System.arraycopy(A4, 0, a4, i, A4.length);
        }

        checkVectors(3, K4, 112, N4, a4, P4, T4, C4);

        //
        // long data test
        //
        checkVectors(4, K4, 112, N4, A4, A4, T5, C5);

        // decryption with output specified, non-zero offset.
        ccm.init(false, new AEADParameters(new KeyParameter(K2), 48, N2, A2));

        byte[] inBuf = new byte[C2.length + 10];
        byte[] outBuf = new byte[ccm.getOutputSize(C2.length) + 10];

        System.arraycopy(C2, 0, inBuf, 10, C2.length);

        int len = ccm.processPacket(inBuf, 10, C2.length, outBuf, 10);
        byte[] out = ccm.processPacket(C2, 0, C2.length);

        if (len != out.length || !isEqual(out, outBuf, 10))
        {
            fail("decryption output incorrect");
        }

        // encryption with output specified, non-zero offset. A fresh instance is used because
        // re-initialising the decryption cipher above for encryption with the same key+nonce is
        // now rejected by the nonce-reuse guard.
        CCMBlockCipher encCcm = new CCMBlockCipher(AESEngine.newInstance());
        encCcm.init(true, new AEADParameters(new KeyParameter(K2), 48, N2, A2));

        int inLen = len;
        inBuf = outBuf;
        outBuf = new byte[encCcm.getOutputSize(inLen) + 10];

        len = encCcm.processPacket(inBuf, 10, inLen, outBuf, 10);
        out = encCcm.processPacket(inBuf, 10, inLen);

        if (len != out.length || !isEqual(out, outBuf, 10))
        {
            fail("encryption output incorrect");
        }

        //
        // exception tests
        //

        try
        {
            ccm.init(false, new AEADParameters(new KeyParameter(K1), 32, N2, A2));

            ccm.processPacket(C2, 0, C2.length);

            fail("invalid cipher text not picked up");
        }
        catch (InvalidCipherTextException e)
        {
            // expected
        }

        try
        {
            // TODO Need to resolve dependency on processPacket methods (add them to CCMModeCipher?)
//            ccm = CCMBlockCipher.newInstance(new DESEngine());
            ccm = new CCMBlockCipher(new DESEngine());

            fail("incorrect block size not picked up");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        try
        {
            ccm.init(false, new KeyParameter(K1));

            fail("illegal argument not picked up");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        // For small number of allowed blocks, validate boundary
        // conditions are properly handled. Zero and greater will
        // fail as size bound is a strict inequality.
        int[] offsets = new int[]{-10, -2, -1, 0, 1, 10};
        int[] ns = new int[]{13, 12};
        for (int i = 0; i != ns.length; i++)
        {
            int n_len = ns[i];
            for (int j = 0; j != offsets.length; j++)
            {
                int offset = offsets[j];
                try
                {
                    // A fresh cipher per iteration: re-initialising one instance for encryption
                    // with the same key+nonce is now rejected by the nonce-reuse guard.
                    CCMBlockCipher bccm = new CCMBlockCipher(AESEngine.newInstance());
                    bccm.init(true, new AEADParameters(new KeyParameter(K1), 128, new byte[n_len]));

                    // Encrypt up to 2^(8q) + offset. Note that message length
                    // must be strictly less than 2^(8q) so offset=0 will not
                    // work (per SP 800-38C Section A.1 Length Requirements).
                    int q = 15 - n_len;
                    int size = 1 << (8*q);
                    inBuf = new byte[size + offset];

                    outBuf = new byte[bccm.getOutputSize(inBuf.length)];
                    len = bccm.processPacket(inBuf, 0, inBuf.length, outBuf, 0);

                    if (offset >= 0) {
                        fail("expected to fail to encrypt boundary bytes n=" + n_len + "size=" + size + " offset=" + offset);
                    } else {
                        // Decrypt should also succeed if encryption succeeded.
                        bccm.init(false, new AEADParameters(new KeyParameter(K1), 128, new byte[n_len]));
                        out = bccm.processPacket(outBuf, 0, outBuf.length);

                        if (out.length != inBuf.length || !Arrays.areEqual(inBuf, out))
                        {
                            fail("encryption output incorrect");
                        }
                    }
                }
                catch (Exception e)
                {
                    if (offset < 0) {
                        fail("unexpected failure to encrypt boundary bytes n=" + n_len + " offset=" + offset + " msg=" + e.getMessage());
                    }
                }
            }
        }

        AEADTestUtil.testReset(this, CCMBlockCipher.newInstance(AESEngine.newInstance()),
            CCMBlockCipher.newInstance(AESEngine.newInstance()), new AEADParameters(new KeyParameter(K1), 32, N2));
        AEADTestUtil.testTampering(this, CCMBlockCipher.newInstance(AESEngine.newInstance()), new AEADParameters(new KeyParameter(K1), 32, N2));
        AEADTestUtil.testOutputSizes(this, CCMBlockCipher.newInstance(AESEngine.newInstance()),
            new AEADParameters(new KeyParameter(K1), 32, N2));
        AEADTestUtil.testBufferSizeChecks(this, CCMBlockCipher.newInstance(AESEngine.newInstance()),
            new AEADParameters(new KeyParameter(K1), 32, N2));

        invalidTagLengthTest();
        validTagLengthTest();

        noUnverifiedPlaintextOnFailure();
    }

    private void noUnverifiedPlaintextOnFailure()
        throws Exception
    {
        CCMBlockCipher ccm = new CCMBlockCipher(AESEngine.newInstance());
        ccm.init(false, new AEADParameters(new KeyParameter(K2), 48, N2, A2));

        // Corrupt the authentication tag so verification fails; the ciphertext body is unchanged.
        byte[] tampered = Arrays.clone(C2);
        tampered[tampered.length - 1] ^= 0x01;

        byte[] output = new byte[ccm.getOutputSize(tampered.length)];
        Arrays.fill(output, (byte)0x55);

        try
        {
            ccm.processPacket(tampered, 0, tampered.length, output, 0);
            fail("tampered CCM ciphertext must not verify");
        }
        catch (InvalidCipherTextException e)
        {
            // On a tag-check failure the caller's output buffer must not be left holding the
            // unverified CTR plaintext.
            for (int i = 0; i != output.length; i++)
            {
                if (output[i] != (byte)0x55)
                {
                    fail("CCM left unverified plaintext in the output buffer on tag failure");
                }
            }
        }
    }

    private boolean isEqual(byte[] exp, byte[] other, int off)
    {
        for (int i = 0; i != exp.length; i++)
        {
            if (exp[i] != other[off + i])
            {
                return false;
            }
        }

        return true;
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

        // A fresh cipher per case: re-initialising one instance for encryption with the same
        // key+nonce is now rejected by the nonce-reuse guard.
        checkVectors(count, CCMBlockCipher.newInstance(AESEngine.newInstance()), "all initial associated data", k, macSize, n, a, null, p, t, c);
        checkVectors(count, CCMBlockCipher.newInstance(AESEngine.newInstance()), "subsequent associated data", k, macSize, n, null, a, p, t, c);
        checkVectors(count, CCMBlockCipher.newInstance(AESEngine.newInstance()), "split associated data", k, macSize, n, fa, la, p, t, c);

        // Key reuse: re-initialising the same instance for encryption with the same key+nonce (here
        // via a null key, i.e. key re-use) is now rejected (nonce reuse is catastrophic for CCM).
        CCMModeCipher reuse = CCMBlockCipher.newInstance(AESEngine.newInstance());
        reuse.init(true, new AEADParameters(new KeyParameter(k), macSize, n, a));
        byte[] enc = new byte[reuse.getOutputSize(p.length)];
        int len = reuse.processBytes(p, 0, p.length, enc, 0);
        reuse.doFinal(enc, len);
        try
        {
            reuse.init(true, new AEADParameters(null, macSize, n, a));
            fail("CCM nonce reuse not detected on re-init for encryption in test " + count);
        }
        catch (IllegalArgumentException e)
        {
            isTrue("wrong CCM nonce-reuse message: " + e.getMessage(),
                "cannot reuse nonce for CCM encryption".equals(e.getMessage()));
        }
    }

    private void checkVectors(
        int count,
        CCMModeCipher ccm,
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
        KeyParameter keyParam = (k == null) ? null : new KeyParameter(k);

        ccm.init(true, new AEADParameters(keyParam, macSize, n, a));

        byte[] enc = new byte[c.length];

        if (sa != null)
        {
            ccm.processAADBytes(sa, 0, sa.length);
        }

        int len = ccm.processBytes(p, 0, p.length, enc, 0);

        len += ccm.doFinal(enc, len);

        if (!areEqual(c, enc))
        {
            fail("encrypted stream fails to match in test " + count + " with " + additionalDataType);
        }

        ccm.init(false, new AEADParameters(keyParam, macSize, n, a));

        byte[] tmp = new byte[enc.length];

        if (sa != null)
        {
            ccm.processAADBytes(sa, 0, sa.length);
        }

        len = ccm.processBytes(enc, 0, enc.length, tmp, 0);

        len += ccm.doFinal(tmp, len);

        byte[] dec = new byte[len];

        System.arraycopy(tmp, 0, dec, 0, len);

        if (!areEqual(p, dec))
        {
            fail("decrypted stream fails to match in test " + count + " with " + additionalDataType,
                    new String(Hex.encode(p)), new String(Hex.encode(dec)));
        }

        if (!areEqual(t, ccm.getMac()))
        {
            fail("MAC fails to match in test " + count + " with " + additionalDataType);
        }
    }

    private void ivParamTest(
        int count,
        CCMModeCipher ccm,
        byte[] k,
        byte[] n)
        throws InvalidCipherTextException
    {
        byte[] p = Strings.toByteArray("hello world!!");

        ccm.init(true, new ParametersWithIV(new KeyParameter(k), n));

        byte[] enc = new byte[p.length + 8];

        int len = ccm.processBytes(p, 0, p.length, enc, 0);

        len += ccm.doFinal(enc, len);

        ccm.init(false, new ParametersWithIV(new KeyParameter(k), n));

        byte[] tmp = new byte[enc.length];

        len = ccm.processBytes(enc, 0, enc.length, tmp, 0);

        len += ccm.doFinal(tmp, len);

        byte[] dec = new byte[len];

        System.arraycopy(tmp, 0, dec, 0, len);

        if (!areEqual(p, dec))
        {
            fail("decrypted stream fails to match in test " + count);
        }
    }

    private void invalidTagLengthTest()
    {
        int[] invalid = new int[]{ 0, 8, 24, 40, 56, 72, 88, 104, 120, 136 };
        for (int i = 0; i < invalid.length; ++i)
        {
            int macSizeBits = invalid[i];

            // Rejected on encryption...
            try
            {
                CCMBlockCipher.newInstance(AESEngine.newInstance()).init(true,
                    new AEADParameters(new KeyParameter(K1), macSizeBits, N1, A1));
                fail("invalid tag length accepted");
            }
            catch (IllegalArgumentException e)
            {
                // expected
            }

            // ...and decryption
            try
            {
                CCMBlockCipher.newInstance(AESEngine.newInstance()).init(false,
                    new AEADParameters(new KeyParameter(K1), macSizeBits, N1, A1));
                fail("invalid tag length accepted");
            }
            catch (IllegalArgumentException e)
            {
                // expected
            }
        }
    }

    private void validTagLengthTest() throws Exception
    {
        byte[] plaintext = Hex.decode("202122232425262728292a2b2c2d2e2f3031323334353637");

        for (int macSizeBits = 32; macSizeBits <= 128; macSizeBits += 16)
        {
            // TODO Need to resolve dependency on processPacket methods (add them to CCMModeCipher?)
//            CCMModeCipher enc = CCMBlockCipher.newInstance(AESEngine.newInstance());
            CCMBlockCipher enc = new CCMBlockCipher(AESEngine.newInstance());
            enc.init(true, new AEADParameters(new KeyParameter(K1), macSizeBits, N1, A1));
            byte[] ct = enc.processPacket(plaintext, 0, plaintext.length);

//            CCMModeCipher dec = CCMBlockCipher.newInstance(AESEngine.newInstance());
            CCMBlockCipher dec = new CCMBlockCipher(AESEngine.newInstance());
            dec.init(false, new AEADParameters(new KeyParameter(K1), macSizeBits, N1, A1));
            byte[] recovered = dec.processPacket(ct, 0, ct.length);

            isTrue(Arrays.areEqual(plaintext, recovered));
        }
    }

    public String getName()
    {
        return "CCM";
    }

    public static void main(
        String[]    args)
    {
        runTest(new CCMTest());
    }
}
