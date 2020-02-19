package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * SM4 tester, vectors from <a href="http://eprint.iacr.org/2008/329.pdf">http://eprint.iacr.org/2008/329.pdf</a>
 */
public class SM4Test
    extends CipherTest
{
    static SimpleTest[]  tests = {
        new BlockCipherVectorTest(0, new SM4Engine(),
            new KeyParameter(Hex.decode("0123456789abcdeffedcba9876543210")),
            "0123456789abcdeffedcba9876543210",
            "681edf34d206965e86b3e94f536e4246")
            };

    SM4Test()
    {
        super(tests, new SM4Engine(), new KeyParameter(new byte[16]));
    }

    public void performTest()
        throws Exception
    {
        super.performTest();

        test1000000();
        gcmTest();
        ccmTest();
    }

    private void test1000000()
    {
        byte[] plain = Hex.decode("0123456789abcdeffedcba9876543210");
        byte[] key = Hex.decode("0123456789abcdeffedcba9876543210");
        byte[] cipher = Hex.decode("595298c7c6fd271f0402f804c33d3f66");
        byte[] buf = new byte[16];

        BlockCipher engine = new SM4Engine();

        engine.init(true, new KeyParameter(key));

        System.arraycopy(plain, 0, buf, 0, buf.length);

        for (int i = 0; i != 1000000; i++)
        {
            engine.processBlock(buf, 0, buf, 0);
        }

        if (!areEqual(cipher, buf))
        {
            fail("1000000 encryption test failed");
        }

        engine.init(false, new KeyParameter(key));

        for (int i = 0; i != 1000000; i++)
        {
            engine.processBlock(buf, 0, buf, 0);
        }

        if (!areEqual(plain, buf))
        {
            fail("1000000 decryption test failed");
        }
    }

    private void gcmTest()
        throws Exception
    {
        byte[] iv = Hex.decode("00001234567800000000ABCD");
        byte[] key = Hex.decode("0123456789ABCDEFFEDCBA9876543210");
        byte[] pt = Hex.decode(  "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"
                               + "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD"
                               + "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF"
                               + "EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA");
        byte[] aad = Hex.decode("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2");
        byte[] ct = Hex.decode("17F399F08C67D5EE19D0DC9969C4BB7D"
                             + "5FD46FD3756489069157B282BB200735"
                             + "D82710CA5C22F0CCFA7CBF93D496AC15"
                             + "A56834CBCF98C397B4024A2691233B8D");
        byte[] tag = Hex.decode("83DE3541E4C2B58177E065A9BF7B62EC");

        GCMBlockCipher encCipher = new GCMBlockCipher(new SM4Engine());
        GCMBlockCipher  decCipher = new GCMBlockCipher(new SM4Engine());

        checkTestCase(encCipher, decCipher, "1", key, iv, aad, pt, ct, tag);
    }

    private void ccmTest()
        throws Exception
    {
        byte[] iv = Hex.decode("00001234567800000000ABCD");
        byte[] key = Hex.decode("0123456789ABCDEFFEDCBA9876543210");
        byte[] pt = Hex.decode(  "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"
                               + "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD"
                               + "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF"
                               + "EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA");
        byte[] aad = Hex.decode("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2");
        byte[] ct = Hex.decode("48AF93501FA62ADBCD414CCE6034D895"
                             + "DDA1BF8F132F042098661572E7483094"
                             + "FD12E518CE062C98ACEE28D95DF4416B"
                             + "ED31A2F04476C18BB40C84A74B97DC5B");
        byte[] tag = Hex.decode("fe26a58f94552a8d533b5b6b261c9cd8");

        CCMBlockCipher encCipher = new CCMBlockCipher(new SM4Engine());
        CCMBlockCipher  decCipher = new CCMBlockCipher(new SM4Engine());

        checkTestCase(encCipher, decCipher, "2", key, iv, aad, pt, ct, tag);
    }

    private void checkTestCase(
        AEADBlockCipher encCipher,
        AEADBlockCipher decCipher,
        String          testName,
        byte[]          K,
        byte[]          IV,
        byte[]          SA,
        byte[]          P,
        byte[]          C,
        byte[]          T)
        throws InvalidCipherTextException
    {
        encCipher.init(true, new AEADParameters(new KeyParameter(K), T.length * 8, IV));
        decCipher.init(false, new AEADParameters(new KeyParameter(K), T.length * 8, IV));
        
        byte[] enc = new byte[encCipher.getOutputSize(P.length)];
        if (SA != null)
        {
            encCipher.processAADBytes(SA, 0, SA.length);
        }
        int len = encCipher.processBytes(P, 0, P.length, enc, 0);
        len += encCipher.doFinal(enc, len);

        if (enc.length != len)
        {
//            System.out.println("" + enc.length + "/" + len);
            fail("encryption reported incorrect length: " + testName);
        }

        byte[] mac = encCipher.getMac();
//         System.err.println(Hex.toHexString(enc));
        byte[] data = new byte[P.length];
        System.arraycopy(enc, 0, data, 0, data.length);
        byte[] tail = new byte[enc.length - P.length];
        System.arraycopy(enc, P.length, tail, 0, tail.length);

        if (!areEqual(C, data))
        {
            fail("incorrect encrypt in: " + testName);
        }
  
        if (!areEqual(T, mac))
        {
            fail("getMac() returned wrong mac in: " + testName);
        }

        if (encCipher instanceof GCMBlockCipher)
        {
            if (!areEqual(T, tail))
            {
                fail("stream contained wrong mac in: " + testName);
            }
        }

        byte[] dec = new byte[decCipher.getOutputSize(enc.length)];
        if (SA != null)
        {
            decCipher.processAADBytes(SA, 0, SA.length);
        }
        len = decCipher.processBytes(enc, 0, enc.length, dec, 0);
        len += decCipher.doFinal(dec, len);
        mac = decCipher.getMac();
       
        data = new byte[C.length];
        System.arraycopy(dec, 0, data, 0, data.length);

        if (!areEqual(P, data))
        {
            fail("incorrect decrypt in: " + testName);
        }
    }

    public String getName()
    {
        return "SM4";
    }

    public static void main(
        String[]    args)
    {
        runTest(new SM4Test());
    }
}
