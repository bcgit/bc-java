package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.AsconHash256;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECCSIKeyPairGenerator;
import org.bouncycastle.crypto.params.ECCSIKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECCSIPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECCSIPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.ECCSISigner;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;

public class ECCSISignerTest
    extends SimpleTest
{
    String[] curveNames = {
        "curve25519",
        "secp128r1",
        "secp160k1",
        "secp160r1",
        "secp160r2",
        "secp192k1",
        "secp192r1",
        "secp224k1",
        "secp224r1",
        "secp256k1",
        "secp256r1",
        "secp384r1",
        "secp521r1",
        "sect113r1",
        "sect113r2",
        "sect131r1",
        "sect131r2",
        "sect163k1",
        "sect163r1",
        "sect163r2",
        "sect193r1",
        "sect193r2",
        "sect233k1",
        "sect233r1",
        "sect239k1",
        "sect283k1",
        "sect283r1",
        "sect409k1",
        "sect409r1",
        "sect571k1",
        "sect571r1",
        "sm2p256v1"
    };

    Digest[] digests = new Digest[]{
        new SHA256Digest(),
        new SHA3Digest(),
        new SHA3Digest(512),
        new SHA224Digest(),
        new SHA512Digest(),
        new AsconHash256(),
        new SHAKEDigest(256),
        new SHAKEDigest(128),
        new MD5Digest()
    };


    public static void main(String[] args)
        throws Exception
    {
        ECCSISignerTest test = new ECCSISignerTest();
        test.performTest();
    }

    @Override
    public String getName()
    {
        return "ECCSISigner Test";
    }

    @Override
    public void performTest()
        throws Exception
    {
        testTestVector();
        for (int i = 0; i < curveNames.length; ++i)
        {
            for (int j = 0; j < digests.length; ++j)
            {
                testRandom(curveNames[i], digests[j]);
            }
        }
    }

    private void testTestVector()
        throws Exception
    {
        BigInteger ksak = BigInteger.valueOf(0x12345);
        BigInteger v = BigInteger.valueOf(0x23456);
        BigInteger j = BigInteger.valueOf(0x34567);
        ECCSIKeyPairGenerator generator = new ECCSIKeyPairGenerator();
        SecureRandom random = new FixedSecureRandom(new FixedSecureRandom.Source[]{new FixedSecureRandom.Data(BigIntegers.asUnsignedByteArray(32, ksak)),
            new FixedSecureRandom.Data(BigIntegers.asUnsignedByteArray(32, v)),
            new FixedSecureRandom.Data(BigIntegers.asUnsignedByteArray(32, j))});
        ECCSIKeyGenerationParameters keyGenerationParameters = new ECCSIKeyGenerationParameters(random,
            CustomNamedCurves.getByName("secP256r1"), new SHA256Digest(), "2011-02\0tel:+447700900123\0".getBytes());
        generator.init(keyGenerationParameters);
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        ECCSIPublicKeyParameters pub = (ECCSIPublicKeyParameters)keyPair.getPublic();
        ECCSIPrivateKeyParameters priv = (ECCSIPrivateKeyParameters)keyPair.getPrivate();
//        System.out.println(new String(Hex.encode(pub.getPVT().getXCoord().toBigInteger().toByteArray())));
//        System.out.println(new String(Hex.encode(pub.getPVT().getYCoord().toBigInteger().toByteArray())));
//        System.out.println(new String(Hex.encode(priv.getSSK().toByteArray())));

        byte[] M = "message\0".getBytes();

        ECCSISigner signer = new ECCSISigner(keyGenerationParameters.getKPAK(), CustomNamedCurves.getByName("secP256r1"), new SHA256Digest(), keyGenerationParameters.getId());
        signer.init(true, new ParametersWithRandom(priv, random));
        signer.update(M, 0, M.length);
        byte[] sig = signer.generateSignature();
        isTrue(Arrays.areEqual(sig, Hex.decode("269D4C8F DEB66A74 E4EF8C0D 5DCC597D\n" +
            "                      DFE6029C 2AFFC493 6008CD2C C1045D81\n" +
            "                      E09B528D 0EF8D6DF 1AA3ECBF 80110CFC\n" +
            "                      EC9FC682 52CEBB67 9F413484 6940CCFD\n" +
            "                      04\n" +
            "\n" +
            "                      758A1427 79BE89E8 29E71984 CB40EF75\n" +
            "                      8CC4AD77 5FC5B9A3 E1C8ED52 F6FA36D9\n" +
            "                      A79D2476 92F4EDA3 A6BDAB77 D6AA6474\n" +
            "                      A464AE49 34663C52 65BA7018 BA091F79")));
//        System.out.println("sig: " + new String(Hex.encode(sig)));

        signer.init(false, pub);
        signer.update(M, 0, M.length);
        isTrue(signer.verifySignature(sig));
    }

    private void testRandom(String curveName, Digest digest)
        throws Exception
    {
        SecureRandom random = new SecureRandom();
        ECCSIKeyPairGenerator generator = new ECCSIKeyPairGenerator();
        byte[] id = new byte[16];
        random.nextBytes(id);
        X9ECParameters params = CustomNamedCurves.getByName(curveName);
        ECCSIKeyGenerationParameters keyGenerationParameters = new ECCSIKeyGenerationParameters(random,
            params, digest, id);
        generator.init(keyGenerationParameters);
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        ECCSIPublicKeyParameters pub = (ECCSIPublicKeyParameters)keyPair.getPublic();
        ECCSIPrivateKeyParameters priv = (ECCSIPrivateKeyParameters)keyPair.getPrivate();

        byte[] M = "message\0".getBytes();

        ECCSISigner signer = new ECCSISigner(keyGenerationParameters.getKPAK(), params, digest, keyGenerationParameters.getId());
        signer.init(true, new ParametersWithRandom(priv, random));
        signer.update(M, 0, M.length);
        signer.reset();
        signer.update(M, 0, M.length);
        byte[] sig = signer.generateSignature();
        signer = new ECCSISigner(keyGenerationParameters.getKPAK(), params, digest, keyGenerationParameters.getId());
        signer.init(false, pub);
        signer.update(M, 0, M.length);
        signer.reset();
        signer.update(M, 0, M.length);
        isTrue(signer.verifySignature(sig));
    }

}
