package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

public class SM2CipherTest
    extends SimpleTest
{
    public String getName()
    {
        return "SM2Cipher";
    }

    public void performTest()
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

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");

        ECParameterSpec aKeyGenParams = new ECParameterSpec(domainParams.getCurve(), domainParams.getG(), domainParams.getN(), domainParams.getH());

        keyPairGenerator.initialize(aKeyGenParams, new TestRandomBigInteger("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0", 16));

        KeyPair aKp = keyPairGenerator.generateKeyPair();

        Cipher sm2Engine = Cipher.getInstance("SM2", "BC");

        byte[] m = Strings.toByteArray("encryption standard");

        sm2Engine.init(Cipher.ENCRYPT_MODE, aKp.getPublic(), new TestRandomBigInteger("4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F", 16));

        byte[] enc = sm2Engine.doFinal(m);

        isTrue("enc wrong", Arrays.areEqual(Hex.decode(
            "04245C26 FB68B1DD DDB12C4B 6BF9F2B6 D5FE60A3 83B0D18D 1C4144AB F17F6252" +
            "E776CB92 64C2A7E8 8E52B199 03FDC473 78F605E3 6811F5C0 7423A24B 84400F01" +
            "B8650053 A89B41C4 18B0C3AA D00D886C 00286467 9C3D7360 C30156FA B7C80A02" +
            "76712DA9 D8094A63 4B766D3A 285E0748 0653426D"), enc));

        sm2Engine.init(Cipher.DECRYPT_MODE, aKp.getPrivate());

        byte[] dec = sm2Engine.doFinal(enc);

        isTrue("dec wrong", Arrays.areEqual(m, dec));
        
        testAlgorithm(aKp, "SM2", GMObjectIdentifiers.sm2encrypt_with_sm3);
        testAlgorithm(aKp, "SM2withSM3", GMObjectIdentifiers.sm2encrypt_with_sm3);
        testAlgorithm(aKp, "SM2withBlake2b", GMObjectIdentifiers.sm2encrypt_with_blake2b512);
        testAlgorithm(aKp, "SM2withBlake2s", GMObjectIdentifiers.sm2encrypt_with_blake2s256);
        testAlgorithm(aKp, "SM2withMD5", GMObjectIdentifiers.sm2encrypt_with_md5);
        testAlgorithm(aKp, "SM2withRIPEMD160", GMObjectIdentifiers.sm2encrypt_with_rmd160);
        testAlgorithm(aKp, "SM2withWhirlpool", GMObjectIdentifiers.sm2encrypt_with_whirlpool);
        testAlgorithm(aKp, "SM2withSHA1", GMObjectIdentifiers.sm2encrypt_with_sha1);
        testAlgorithm(aKp, "SM2withSHA224", GMObjectIdentifiers.sm2encrypt_with_sha224);
        testAlgorithm(aKp, "SM2withSHA256", GMObjectIdentifiers.sm2encrypt_with_sha256);
        testAlgorithm(aKp, "SM2withSHA384", GMObjectIdentifiers.sm2encrypt_with_sha384);
        testAlgorithm(aKp, "SM2withSHA512", GMObjectIdentifiers.sm2encrypt_with_sha512);
    }

    private void testAlgorithm(KeyPair kp, String name, ASN1ObjectIdentifier oid)
        throws Exception
    {
        Cipher sm2Engine1 = Cipher.getInstance(name, "BC");
        Cipher sm2Engine2 = Cipher.getInstance(oid.getId(), "BC");
        
        byte[] m = Strings.toByteArray("encryption standard");

        sm2Engine1.init(Cipher.ENCRYPT_MODE, kp.getPublic(), new TestRandomBigInteger("4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F", 16));

        byte[] enc = sm2Engine1.doFinal(m);

        isTrue(enc.length == sm2Engine1.getOutputSize(m.length));

        sm2Engine2.init(Cipher.DECRYPT_MODE, kp.getPrivate());

        byte[] dec = sm2Engine2.doFinal(enc);

        isTrue("dec wrong", Arrays.areEqual(m, dec));
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new SM2CipherTest());
    }
}
