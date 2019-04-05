package org.bouncycastle.crypto.test;

import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

public class SM2EngineTest
    extends SimpleTest
{
    public String getName()
    {
        return "SM2Engine";
    }

    private void doEngineTestFp()
        throws Exception
    {
        BigInteger SM2_ECC_P = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16);
        BigInteger SM2_ECC_A = new BigInteger("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498", 16);
        BigInteger SM2_ECC_B = new BigInteger("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A", 16);
        BigInteger SM2_ECC_N = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7", 16);
        BigInteger SM2_ECC_H = ECConstants.ONE;
        BigInteger SM2_ECC_GX = new BigInteger("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D", 16);
        BigInteger SM2_ECC_GY = new BigInteger("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2", 16);

        ECCurve curve = new ECCurve.Fp(SM2_ECC_P, SM2_ECC_A, SM2_ECC_B, SM2_ECC_N, SM2_ECC_H);

        ECPoint g = curve.createPoint(SM2_ECC_GX, SM2_ECC_GY);
        ECDomainParameters domainParams = new ECDomainParameters(curve, g, SM2_ECC_N);

        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();

        ECKeyGenerationParameters aKeyGenParams = new ECKeyGenerationParameters(domainParams, new TestRandomBigInteger("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0", 16));

        keyPairGenerator.init(aKeyGenParams);

        AsymmetricCipherKeyPair aKp = keyPairGenerator.generateKeyPair();

        ECPublicKeyParameters aPub = (ECPublicKeyParameters)aKp.getPublic();
        ECPrivateKeyParameters aPriv = (ECPrivateKeyParameters)aKp.getPrivate();

        SM2Engine sm2Engine = new SM2Engine();

        byte[] m = Strings.toByteArray("encryption standard");

        sm2Engine.init(true, new ParametersWithRandom(aPub, new TestRandomBigInteger("4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F", 16)));

        byte[] enc = sm2Engine.processBlock(m, 0, m.length);

        isTrue("enc wrong", Arrays.areEqual(Hex.decode(
            "04245C26 FB68B1DD DDB12C4B 6BF9F2B6 D5FE60A3 83B0D18D 1C4144AB F17F6252" +
            "E776CB92 64C2A7E8 8E52B199 03FDC473 78F605E3 6811F5C0 7423A24B 84400F01" +
            "B8650053 A89B41C4 18B0C3AA D00D886C 00286467 9C3D7360 C30156FA B7C80A02" +
            "76712DA9 D8094A63 4B766D3A 285E0748 0653426D"), enc));

        sm2Engine.init(false, aPriv);

        byte[] dec = sm2Engine.processBlock(enc, 0, enc.length);

        isTrue("dec wrong", Arrays.areEqual(m, dec));

        enc[80] = (byte)(enc[80] + 1);

        try
        {
            sm2Engine.processBlock(enc, 0, enc.length);
            fail("no exception");
        }
        catch (InvalidCipherTextException e)
        {
            isTrue("wrong exception", "invalid cipher text".equals(e.getMessage()));
        }

        // long message
        sm2Engine = new SM2Engine();

        m = new byte[4097];
        for (int i = 0; i != m.length; i++)
        {
            m[i] = (byte)i;
        }

        sm2Engine.init(true, new ParametersWithRandom(aPub, new TestRandomBigInteger("4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F", 16)));

        enc = sm2Engine.processBlock(m, 0, m.length);

        sm2Engine.init(false, aPriv);

        dec = sm2Engine.processBlock(enc, 0, enc.length);

        isTrue("dec wrong", Arrays.areEqual(m, dec));
    }

    private void doEngineTestFpC1C3C2()
        throws Exception
    {
        BigInteger SM2_ECC_P = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16);
        BigInteger SM2_ECC_A = new BigInteger("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498", 16);
        BigInteger SM2_ECC_B = new BigInteger("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A", 16);
        BigInteger SM2_ECC_N = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7", 16);
        BigInteger SM2_ECC_H = ECConstants.ONE;
        BigInteger SM2_ECC_GX = new BigInteger("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D", 16);
        BigInteger SM2_ECC_GY = new BigInteger("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2", 16);

        ECCurve curve = new ECCurve.Fp(SM2_ECC_P, SM2_ECC_A, SM2_ECC_B, SM2_ECC_N, SM2_ECC_H);

        ECPoint g = curve.createPoint(SM2_ECC_GX, SM2_ECC_GY);
        ECDomainParameters domainParams = new ECDomainParameters(curve, g, SM2_ECC_N);

        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();

        ECKeyGenerationParameters aKeyGenParams = new ECKeyGenerationParameters(domainParams, new TestRandomBigInteger("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0", 16));

        keyPairGenerator.init(aKeyGenParams);

        AsymmetricCipherKeyPair aKp = keyPairGenerator.generateKeyPair();

        ECPublicKeyParameters aPub = (ECPublicKeyParameters)aKp.getPublic();
        ECPrivateKeyParameters aPriv = (ECPrivateKeyParameters)aKp.getPrivate();

        SM2Engine sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);

        byte[] m = Strings.toByteArray("encryption standard");

        sm2Engine.init(true, new ParametersWithRandom(aPub, new TestRandomBigInteger("4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F", 16)));

        byte[] enc = sm2Engine.processBlock(m, 0, m.length);

        isTrue("enc wrong", Arrays.areEqual(Hex.decode(
            "04245C26 FB68B1DD DDB12C4B 6BF9F2B6 D5FE60A3 83B0D18D 1C4144AB F17F6252" +
            "E776CB92 64C2A7E8 8E52B199 03FDC473 78F605E3 6811F5C0 7423A24B 84400F01" +
            "B8 9C3D7360 C30156FA B7C80A02" +
            "76712DA9 D8094A63 4B766D3A 285E0748 0653426D 650053 A89B41C4 18B0C3AA D00D886C 00286467"), enc));

        sm2Engine.init(false, aPriv);

        byte[] dec = sm2Engine.processBlock(enc, 0, enc.length);

        isTrue("dec wrong", Arrays.areEqual(m, dec));

        enc[80] = (byte)(enc[80] + 1);

        try
        {
            sm2Engine.processBlock(enc, 0, enc.length);
            fail("no exception");
        }
        catch (InvalidCipherTextException e)
        {
            isTrue("wrong exception", "invalid cipher text".equals(e.getMessage()));
        }

        // long message
        sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);

        m = new byte[4097];
        for (int i = 0; i != m.length; i++)
        {
            m[i] = (byte)i;
        }

        sm2Engine.init(true, new ParametersWithRandom(aPub, new TestRandomBigInteger("4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F", 16)));

        enc = sm2Engine.processBlock(m, 0, m.length);

        sm2Engine.init(false, aPriv);

        dec = sm2Engine.processBlock(enc, 0, enc.length);

        isTrue("dec wrong", Arrays.areEqual(m, dec));
    }

    private void doEngineTestF2m()
        throws Exception
    {
        BigInteger SM2_ECC_A = new BigInteger("00", 16);
        BigInteger SM2_ECC_B = new BigInteger("E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B", 16);
        BigInteger SM2_ECC_N = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBC972CF7E6B6F900945B3C6A0CF6161D", 16);
        BigInteger SM2_ECC_H = BigInteger.valueOf(4);
        BigInteger SM2_ECC_GX = new BigInteger("00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD", 16);
        BigInteger SM2_ECC_GY = new BigInteger("013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E", 16);

        ECCurve curve = new ECCurve.F2m(257, 12, SM2_ECC_A, SM2_ECC_B, SM2_ECC_N, SM2_ECC_H);

        ECPoint g = curve.createPoint(SM2_ECC_GX, SM2_ECC_GY);
        ECDomainParameters domainParams = new ECDomainParameters(curve, g, SM2_ECC_N, SM2_ECC_H);

        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();

        ECKeyGenerationParameters aKeyGenParams = new ECKeyGenerationParameters(domainParams, new TestRandomBigInteger("56A270D17377AA9A367CFA82E46FA5267713A9B91101D0777B07FCE018C757EB", 16));

        keyPairGenerator.init(aKeyGenParams);

        AsymmetricCipherKeyPair aKp = keyPairGenerator.generateKeyPair();

        ECPublicKeyParameters aPub = (ECPublicKeyParameters)aKp.getPublic();
        ECPrivateKeyParameters aPriv = (ECPrivateKeyParameters)aKp.getPrivate();

        SM2Engine sm2Engine = new SM2Engine();

        byte[] m = Strings.toByteArray("encryption standard");

        sm2Engine.init(true, new ParametersWithRandom(aPub, new TestRandomBigInteger("6D3B497153E3E92524E5C122682DBDC8705062E20B917A5F8FCDB8EE4C66663D", 16)));

        byte[] enc = sm2Engine.processBlock(m, 0, m.length);

        isTrue("f2m enc wrong", Arrays.areEqual(Hex.decode(
            "04019D23 6DDB3050 09AD52C5 1BB93270 9BD534D4 76FBB7B0 DF9542A8 A4D890A3" +
                "F2E100B2 3B938DC0 A94D1DF8 F42CF45D 2D6601BF 638C3D7D E75A29F0 2AFB7E45" +
                "E91771FD 55AC6213 C2A8A040 E4CAB5B2 6A9CFCDA 737373A4 8625D375 8FA37B3E" +
                "AB80E9CF CABA665E 3199EA15 A1FA8189 D96F5791 25E4"), enc));

        sm2Engine.init(false, aPriv);

        byte[] dec = sm2Engine.processBlock(enc, 0, enc.length);

        isTrue("f2m dec wrong", Arrays.areEqual(m, dec));
    }

    public void performTest()
        throws Exception
    {
        doEngineTestFp();
        doEngineTestF2m();
        doEngineTestFpC1C3C2();
    }

    public static void main(String[] args)
    {
        runTest(new SM2EngineTest());
    }
}
