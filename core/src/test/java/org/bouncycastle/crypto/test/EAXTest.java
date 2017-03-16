package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class EAXTest
    extends SimpleTest
{
    private byte[] K1 = Hex.decode("233952DEE4D5ED5F9B9C6D6FF80FF478");
    private byte[] N1 = Hex.decode("62EC67F9C3A4A407FCB2A8C49031A8B3");
    private byte[] A1 = Hex.decode("6BFB914FD07EAE6B");
    private byte[] P1 = Hex.decode("");
    private byte[] C1 = Hex.decode("E037830E8389F27B025A2D6527E79D01");
    private byte[] T1 = Hex.decode("E037830E8389F27B025A2D6527E79D01");

    private byte[] K2 = Hex.decode("91945D3F4DCBEE0BF45EF52255F095A4");
    private byte[] N2 = Hex.decode("BECAF043B0A23D843194BA972C66DEBD");
    private byte[] A2 = Hex.decode("FA3BFD4806EB53FA");
    private byte[] P2 = Hex.decode("F7FB");
    private byte[] C2 = Hex.decode("19DD5C4C9331049D0BDAB0277408F67967E5");
    private byte[] T2 = Hex.decode("5C4C9331049D0BDAB0277408F67967E5");

    private byte[] K3 = Hex.decode("01F74AD64077F2E704C0F60ADA3DD523");
    private byte[] N3 = Hex.decode("70C3DB4F0D26368400A10ED05D2BFF5E");
    private byte[] A3 = Hex.decode("234A3463C1264AC6");
    private byte[] P3 = Hex.decode("1A47CB4933");
    private byte[] C3 = Hex.decode("D851D5BAE03A59F238A23E39199DC9266626C40F80");
    private byte[] T3 = Hex.decode("3A59F238A23E39199DC9266626C40F80");

    private byte[] K4 = Hex.decode("D07CF6CBB7F313BDDE66B727AFD3C5E8");
    private byte[] N4 = Hex.decode("8408DFFF3C1A2B1292DC199E46B7D617");
    private byte[] A4 = Hex.decode("33CCE2EABFF5A79D");
    private byte[] P4 = Hex.decode("481C9E39B1");
    private byte[] C4 = Hex.decode("632A9D131AD4C168A4225D8E1FF755939974A7BEDE");
    private byte[] T4 = Hex.decode("D4C168A4225D8E1FF755939974A7BEDE");

    private byte[] K5 = Hex.decode("35B6D0580005BBC12B0587124557D2C2");
    private byte[] N5 = Hex.decode("FDB6B06676EEDC5C61D74276E1F8E816");
    private byte[] A5 = Hex.decode("AEB96EAEBE2970E9");
    private byte[] P5 = Hex.decode("40D0C07DA5E4");
    private byte[] C5 = Hex.decode("071DFE16C675CB0677E536F73AFE6A14B74EE49844DD");
    private byte[] T5 = Hex.decode("CB0677E536F73AFE6A14B74EE49844DD");

    private byte[] K6 = Hex.decode("BD8E6E11475E60B268784C38C62FEB22");
    private byte[] N6 = Hex.decode("6EAC5C93072D8E8513F750935E46DA1B");
    private byte[] A6 = Hex.decode("D4482D1CA78DCE0F");
    private byte[] P6 = Hex.decode("4DE3B35C3FC039245BD1FB7D");
    private byte[] C6 = Hex.decode("835BB4F15D743E350E728414ABB8644FD6CCB86947C5E10590210A4F");
    private byte[] T6 = Hex.decode("ABB8644FD6CCB86947C5E10590210A4F");

    private byte[] K7 = Hex.decode("7C77D6E813BED5AC98BAA417477A2E7D");
    private byte[] N7 = Hex.decode("1A8C98DCD73D38393B2BF1569DEEFC19");
    private byte[] A7 = Hex.decode("65D2017990D62528");
    private byte[] P7 = Hex.decode("8B0A79306C9CE7ED99DAE4F87F8DD61636");
    private byte[] C7 = Hex.decode("02083E3979DA014812F59F11D52630DA30137327D10649B0AA6E1C181DB617D7F2");
    private byte[] T7 = Hex.decode("137327D10649B0AA6E1C181DB617D7F2");

    private byte[] K8 = Hex.decode("5FFF20CAFAB119CA2FC73549E20F5B0D");
    private byte[] N8 = Hex.decode("DDE59B97D722156D4D9AFF2BC7559826");
    private byte[] A8 = Hex.decode("54B9F04E6A09189A");
    private byte[] P8 = Hex.decode("1BDA122BCE8A8DBAF1877D962B8592DD2D56");
    private byte[] C8 = Hex.decode("2EC47B2C4954A489AFC7BA4897EDCDAE8CC33B60450599BD02C96382902AEF7F832A");
    private byte[] T8 = Hex.decode("3B60450599BD02C96382902AEF7F832A");

    private byte[] K9 = Hex.decode("A4A4782BCFFD3EC5E7EF6D8C34A56123");
    private byte[] N9 = Hex.decode("B781FCF2F75FA5A8DE97A9CA48E522EC");
    private byte[] A9 = Hex.decode("899A175897561D7E");
    private byte[] P9 = Hex.decode("6CF36720872B8513F6EAB1A8A44438D5EF11");
    private byte[] C9 = Hex.decode("0DE18FD0FDD91E7AF19F1D8EE8733938B1E8E7F6D2231618102FDB7FE55FF1991700");
    private byte[] T9 = Hex.decode("E7F6D2231618102FDB7FE55FF1991700");

    private byte[] K10 = Hex.decode("8395FCF1E95BEBD697BD010BC766AAC3");
    private byte[] N10 = Hex.decode("22E7ADD93CFC6393C57EC0B3C17D6B44");
    private byte[] A10 = Hex.decode("126735FCC320D25A");
    private byte[] P10 = Hex.decode("CA40D7446E545FFAED3BD12A740A659FFBBB3CEAB7");
    private byte[] C10 = Hex.decode("CB8920F87A6C75CFF39627B56E3ED197C552D295A7CFC46AFC253B4652B1AF3795B124AB6E");
    private byte[] T10 = Hex.decode("CFC46AFC253B4652B1AF3795B124AB6E");

    private byte[] K11 = Hex.decode("8395FCF1E95BEBD697BD010BC766AAC3");
    private byte[] N11 = Hex.decode("22E7ADD93CFC6393C57EC0B3C17D6B44");
    private byte[] A11 = Hex.decode("126735FCC320D25A");
    private byte[] P11 = Hex.decode("CA40D7446E545FFAED3BD12A740A659FFBBB3CEAB7");
    private byte[] C11 = Hex.decode("CB8920F87A6C75CFF39627B56E3ED197C552D295A7CFC46AFC");
    private byte[] T11 = Hex.decode("CFC46AFC");

    private static final int NONCE_LEN = 8;
    private static final int MAC_LEN = 8;
    private static final int AUTHEN_LEN = 20;

    public String getName()
    {
        return "EAX";
    }

    public void performTest()
        throws Exception
    {
        checkVectors(1, K1, 128, N1, A1, P1, T1, C1);
        checkVectors(2, K2, 128, N2, A2, P2, T2, C2);
        checkVectors(3, K3, 128, N3, A3, P3, T3, C3);
        checkVectors(4, K4, 128, N4, A4, P4, T4, C4);
        checkVectors(5, K5, 128, N5, A5, P5, T5, C5);
        checkVectors(6, K6, 128, N6, A6, P6, T6, C6);
        checkVectors(7, K7, 128, N7, A7, P7, T7, C7);
        checkVectors(8, K8, 128, N8, A8, P8, T8, C8);
        checkVectors(9, K9, 128, N9, A9, P9, T9, C9);
        checkVectors(10, K10, 128, N10, A10, P10, T10, C10);
        checkVectors(11, K11, 32, N11, A11, P11, T11, C11);

        EAXBlockCipher eax = new EAXBlockCipher(new AESEngine());
        ivParamTest(1, eax, K1, N1);

        //
        // exception tests
        //

        try
        {
            eax.init(false, new AEADParameters(new KeyParameter(K1), 32, N2, A2));

            byte[] enc = new byte[C2.length];
            int len = eax.processBytes(C2, 0, C2.length, enc, 0);

            len += eax.doFinal(enc, len);

            fail("invalid cipher text not picked up");
        }
        catch (InvalidCipherTextException e)
        {
            // expected
        }

        try
        {
            eax.init(false, new KeyParameter(K1));

            fail("illegal argument not picked up");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        randomTests();
        AEADTestUtil.testReset(this, new EAXBlockCipher(new AESEngine()), new EAXBlockCipher(new AESEngine()), new AEADParameters(new KeyParameter(K1), 32, N2));
        AEADTestUtil.testTampering(this, eax, new AEADParameters(new KeyParameter(K1), 32, N2));
        AEADTestUtil.testOutputSizes(this, new EAXBlockCipher(new AESEngine()), new AEADParameters(
                new KeyParameter(K1), 32, N2));
        AEADTestUtil.testBufferSizeChecks(this, new EAXBlockCipher(new AESEngine()), new AEADParameters(
                new KeyParameter(K1), 32, N2));
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
        EAXBlockCipher encEax = new EAXBlockCipher(new AESEngine());
        EAXBlockCipher decEax = new EAXBlockCipher(new AESEngine());

        AEADParameters parameters = new AEADParameters(new KeyParameter(k), macSize, n, a);
        encEax.init(true, parameters);
        decEax.init(false, parameters);

        runCheckVectors(count, encEax, decEax, additionalDataType, sa, p, t, c);
        runCheckVectors(count, encEax, decEax, additionalDataType, sa, p, t, c);

        // key reuse test
        parameters = new AEADParameters(null, macSize, n, a);
        encEax.init(true, parameters);
        decEax.init(false, parameters);

        runCheckVectors(count, encEax, decEax, additionalDataType, sa, p, t, c);
        runCheckVectors(count, encEax, decEax, additionalDataType, sa, p, t, c);
    }

    private void runCheckVectors(
        int count,
        EAXBlockCipher encEax,
        EAXBlockCipher decEax,
        String additionalDataType,
        byte[] sa,
        byte[] p,
        byte[] t,
        byte[] c)
        throws InvalidCipherTextException
    {
        byte[] enc = new byte[c.length];

        if (sa != null)
        {
            encEax.processAADBytes(sa, 0, sa.length);
        }

        int len = encEax.processBytes(p, 0, p.length, enc, 0);

        len += encEax.doFinal(enc, len);

        if (!areEqual(c, enc))
        {
            fail("encrypted stream fails to match in test " + count + " with " + additionalDataType);
        }

        byte[] tmp = new byte[enc.length];

        if (sa != null)
        {
            decEax.processAADBytes(sa, 0, sa.length);
        }

        len = decEax.processBytes(enc, 0, enc.length, tmp, 0);

        len += decEax.doFinal(tmp, len);

        byte[] dec = new byte[len];

        System.arraycopy(tmp, 0, dec, 0, len);

        if (!areEqual(p, dec))
        {
            fail("decrypted stream fails to match in test " + count + " with " + additionalDataType);
        }

        if (!areEqual(t, decEax.getMac()))
        {
            fail("MAC fails to match in test " + count + " with " + additionalDataType);
        }
    }

    private void ivParamTest(
        int count,
        AEADBlockCipher eax,
        byte[] k,
        byte[] n)
        throws InvalidCipherTextException
    {
        byte[] p = Strings.toByteArray("hello world!!");

        eax.init(true, new ParametersWithIV(new KeyParameter(k), n));

        byte[] enc = new byte[p.length + 8];

        int len = eax.processBytes(p, 0, p.length, enc, 0);

        len += eax.doFinal(enc, len);

        eax.init(false, new ParametersWithIV(new KeyParameter(k), n));

        byte[] tmp = new byte[enc.length];

        len = eax.processBytes(enc, 0, enc.length, tmp, 0);

        len += eax.doFinal(tmp, len);

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
        byte[] key = new byte[16];
        srng.nextBytes(nonce);
        srng.nextBytes(authen);
        srng.nextBytes(datIn);
        srng.nextBytes(key);

        AESEngine engine = new AESEngine();
        KeyParameter sessKey = new KeyParameter(key);
        EAXBlockCipher eaxCipher = new EAXBlockCipher(engine);

        AEADParameters params = new AEADParameters(sessKey, MAC_LEN * 8, nonce, authen);
        eaxCipher.init(true, params);

        byte[] intrDat = new byte[eaxCipher.getOutputSize(datIn.length)];
        int outOff = eaxCipher.processBytes(datIn, 0, DAT_LEN, intrDat, 0);
        outOff += eaxCipher.doFinal(intrDat, outOff);

        eaxCipher.init(false, params);
        byte[] datOut = new byte[eaxCipher.getOutputSize(outOff)];
        int resultLen = eaxCipher.processBytes(intrDat, 0, outOff, datOut, 0);
        eaxCipher.doFinal(datOut, resultLen);

        if (!areEqual(datIn, datOut))
        {
            fail("EAX roundtrip failed to match");
        }
    }

    public static void main(String[] args)
    {
        runTest(new EAXTest());
    }
}
