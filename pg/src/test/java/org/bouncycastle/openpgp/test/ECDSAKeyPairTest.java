package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPSecretKeyRing;
import org.bouncycastle.openpgp.jcajce.JcaPGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Date;

public class ECDSAKeyPairTest
        extends AbstractPgpKeyPairTest
{

    private static final String PRIME256v1 = "" +
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: BCPG v@RELEASE_NAME@\n" +
            "\n" +
            "lHcEZkH7VRMIKoZIzj0DAQcCAwQee5wkHVVrG7u7CcrHoZOaC+reK0wn2Y5XPJoU\n" +
            "O6geh1j2qXHj4+f+a6lav5hzKIJZHkgBYcS0aeABgWNjKsHbAAD/b4K93MJF7c2l\n" +
            "4Y7ojBqTuZAOOD0Dyqe8MTXXyDUWN/0R/w==\n" +
            "=mPB9\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    private static final String SECP384r1 = "" +
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: BCPG v@RELEASE_NAME@\n" +
            "\n" +
            "lKQEZkH7VhMFK4EEACIDAwQgkKs+EzJaFLgMZH5Fp1S8DCXZC0OildnuQX6F7Jzt\n" +
            "BgkYyfDZ/F2KNistCqfsmxWnwAxtdRuuY2PfehWktQBQaID0OfXUnOC2E5961b3/\n" +
            "7xoZU26T0npmTqX0P/wuXawAAX9S2V72/xeShrcIwIwy2QvCcsW9ATBSQ6U+T7KZ\n" +
            "zzFisUiqCgYa/9hoSNnu7iNrnrcYlQ==\n" +
            "=SyFg\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    private static final String SECP521r1 = "" +
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: BCPG v@RELEASE_NAME@\n" +
            "\n" +
            "lNkEZkH7VhMFK4EEACMEIwQBxt7DenSWrjuJGR0ouSwylW3ZC6mX4S+A5Cav7nz3\n" +
            "DninA8Rdt3Cd5sHQ1IWea+J05NUZDKbOL417lUSPkAVLot0B/Qis90wODcGnAXbc\n" +
            "m+m7rN2/Waryj/EsxLxub4UNtyZ405C8dDo9ch2JRfHiH6R1dwyqD9+yY2lOPYO+\n" +
            "tn5fx/4AAgIDG9+DPtDf91tBMhBKc0f++t6aV115HLlyIpnEipThSwMTgzWm0uPZ\n" +
            "KD3CifJeUU/TMk9IGFYvRlaWBQfrB3V/Ahz4\n" +
            "=DD95\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    private static final String BRAINPOOLP256r1 = "" +
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: BCPG v@RELEASE_NAME@\n" +
            "\n" +
            "lHgEZkH7VhMJKyQDAwIIAQEHAgMEj7YxVg4/2p4uuhcpRqGl2i+vDhjx8YhUUNJX\n" +
            "RNFozBuIWJ6zkW3wRKdD/7Y7tzKNwyHmZ4FBFCcUoLliLeD4SAABAIkEm4iT1g0B\n" +
            "Bo9vkUrUcP2b+vtOuwtmrvGrT0VzVXYlD5M=\n" +
            "=vZRh\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    private static final String BRAINPOOLP384r1 = "" +
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: BCPG v@RELEASE_NAME@\n" +
            "\n" +
            "lKgEZkH7VhMJKyQDAwIIAQELAwMEYm1fhilklF53Pj91awsoO0aZsppmPk9KNESD\n" +
            "H7/gSK86gl+yhf4/oKSxeOFDHCU2es6Iijq/TCIaAjeFH3ITEyQ4tPdnDqQSz2xq\n" +
            "o6wtRTW3cRD9oyoOT8bAMdm+RYpJAAF5AXAfxp3VtxqVVxnR1mC3Z3nL25zmvdu1\n" +
            "oPRvA9fenVxTOlyU6X9qCycSuxamkPO7Gic=\n" +
            "=2eJn\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    private static final String BRAINPOOLP521r1 = "" +
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: BCPG v@RELEASE_NAME@\n" +
            "\n" +
            "lNgEZkH7VhMJKyQDAwIIAQENBAMEbSjn4lQKNnC50PzeUtenikvF62KR7HfOLJTA\n" +
            "r/T17tFx3Qb6Ek/xQWIJ5nIHroOrduZjLigPOXqQ+GNhCgdNPGUqAWw1sfQ86nrx\n" +
            "jqlr67na3F3eaTJr9ajr2V37/5uHnuryJnkyy2laFdOGD0Ad9/bQkvXYoWVm0P07\n" +
            "uCPnexEAAgCSUoeS3c+DAZlWETdyuSDyvHK7GLO67+CgVsEyqBF/Kch/vhBZFWXA\n" +
            "Cs9lph8la5B0faKH5XSbeReudKGh/MjfIJo=\n" +
            "=MZeT\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    @Override
    public String getName()
    {
        return "ECDSAKeyPairTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testConversionOfFreshJcaKeyPair();
        testConversionOfParsedJcaKeyPair();
        testConversionOfParsedBcKeyPair();

    }

    private void testConversionOfParsedJcaKeyPair()
            throws PGPException, IOException
    {
        parseAndConvertJca(BRAINPOOLP256r1);
        parseAndConvertJca(BRAINPOOLP384r1);
        parseAndConvertJca(BRAINPOOLP521r1);
        parseAndConvertJca(PRIME256v1);
        parseAndConvertJca(SECP384r1);
        parseAndConvertJca(SECP521r1);
    }

    private void parseAndConvertJca(String curve)
            throws IOException, PGPException
    {
        JcaPGPKeyConverter c = new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider());
        PGPKeyPair parsed = parseJca(curve);
        byte[] pubEnc = parsed.getPublicKey().getEncoded();
        byte[] privEnc = parsed.getPrivateKey().getPrivateKeyDataPacket().getEncoded();

        JcaPGPKeyPair j1 = new JcaPGPKeyPair(
                parsed.getPublicKey().getAlgorithm(),
                new KeyPair(c.getPublicKey(parsed.getPublicKey()),
                        c.getPrivateKey(parsed.getPrivateKey())),
                parsed.getPublicKey().getCreationTime());
        isEncodingEqual("ECDSA Public key (" + curve + ") encoding mismatch", pubEnc, j1.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, j1.getPrivateKey().getPrivateKeyDataPacket().getEncoded());

        BcPGPKeyPair b1 = toBcKeyPair(j1);
        isEncodingEqual(pubEnc, b1.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, b1.getPrivateKey().getPrivateKeyDataPacket().getEncoded());

        JcaPGPKeyPair j2 = toJcaKeyPair(b1);
        isEncodingEqual(pubEnc, j2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, j2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());

        BcPGPKeyPair b2 = toBcKeyPair(j2);
        isEncodingEqual(pubEnc, b2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, b2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
    }

    private void testConversionOfParsedBcKeyPair()
            throws PGPException, IOException
    {
        parseAndConvertBc(BRAINPOOLP256r1);
        parseAndConvertBc(BRAINPOOLP384r1);
        parseAndConvertBc(BRAINPOOLP521r1);
        parseAndConvertBc(PRIME256v1);
        parseAndConvertBc(SECP384r1);
        parseAndConvertBc(SECP521r1);
    }

    private void parseAndConvertBc(String curve)
            throws IOException, PGPException
    {
        BcPGPKeyConverter c = new BcPGPKeyConverter();
        PGPKeyPair parsed = parseBc(curve);
        byte[] pubEnc = parsed.getPublicKey().getEncoded();
        byte[] privEnc = parsed.getPrivateKey().getPrivateKeyDataPacket().getEncoded();

        BcPGPKeyPair b1 = new BcPGPKeyPair(
                parsed.getPublicKey().getAlgorithm(),
                new AsymmetricCipherKeyPair(
                        c.getPublicKey(parsed.getPublicKey()),
                        c.getPrivateKey(parsed.getPrivateKey())),
                parsed.getPublicKey().getCreationTime());
        isEncodingEqual(pubEnc, b1.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, b1.getPrivateKey().getPrivateKeyDataPacket().getEncoded());

        JcaPGPKeyPair j1 = toJcaKeyPair(b1);
        isEncodingEqual(pubEnc, j1.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, j1.getPrivateKey().getPrivateKeyDataPacket().getEncoded());

        BcPGPKeyPair b2 = toBcKeyPair(j1);
        isEncodingEqual(pubEnc, b2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, b2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());

        JcaPGPKeyPair j2 = toJcaKeyPair(b2);
        isEncodingEqual(pubEnc, j2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, j2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());

    }

    private PGPKeyPair parseJca(String armored)
            throws IOException, PGPException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        JcaPGPSecretKeyRing ring = new JcaPGPSecretKeyRing(pIn);
        PGPSecretKey sk = ring.getSecretKey();
        return new PGPKeyPair(sk.getPublicKey(), sk.extractPrivateKey(null));
    }

    private PGPKeyPair parseBc(String armored)
            throws IOException, PGPException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        BcPGPSecretKeyRing ring = new BcPGPSecretKeyRing(pIn);
        PGPSecretKey sk = ring.getSecretKey();
        return new PGPKeyPair(sk.getPublicKey(), sk.extractPrivateKey(null));
    }

    private void testConversionOfFreshJcaKeyPair()
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, PGPException, IOException
    {
        for (String curve : new String[] {
                "prime256v1",
                "secp384r1",
                "secp521r1",
                "brainpoolP256r1",
                "brainpoolP384r1",
                "brainpoolP512r1"
        })
        {
            testConversionOfFreshJcaKeyPair(curve);
        }
    }

    private void testConversionOfFreshJcaKeyPair(String curve)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, PGPException
    {
        Date date = currentTimeRounded();
        KeyPairGenerator gen = KeyPairGenerator.getInstance("ECDSA", new BouncyCastleProvider());
        gen.initialize(new ECNamedCurveGenParameterSpec(curve));
        KeyPair kp = gen.generateKeyPair();

        JcaPGPKeyPair j1 = new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDSA, kp, date);
        byte[] pubEnc = j1.getPublicKey().getEncoded();
        byte[] privEnc = j1.getPrivateKey().getPrivateKeyDataPacket().getEncoded();
        isTrue("Legacy ECDSA public key MUST be instanceof ECDSAPublicBCPGKey",
                j1.getPublicKey().getPublicKeyPacket().getKey() instanceof ECDSAPublicBCPGKey);
        isTrue("Legacy ECDSA secret key MUST be instanceof ECSecretBCPGKey",
                j1.getPrivateKey().getPrivateKeyDataPacket() instanceof ECSecretBCPGKey);

        BcPGPKeyPair b1 = toBcKeyPair(j1);
        isEncodingEqual(pubEnc, b1.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, b1.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Legacy ECDSA public key MUST be instanceof ECDSAPublicBCPGKey",
                b1.getPublicKey().getPublicKeyPacket().getKey() instanceof ECDSAPublicBCPGKey);
        isTrue(" Legacy ECDSA secret key MUST be instanceof ECSecretBCPGKey",
                b1.getPrivateKey().getPrivateKeyDataPacket() instanceof ECSecretBCPGKey);

        JcaPGPKeyPair j2 = toJcaKeyPair(b1);
        isEncodingEqual(pubEnc, j2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, j2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Legacy ECDSA public key MUST be instanceof ECDSAPublicBCPGKey",
                j2.getPublicKey().getPublicKeyPacket().getKey() instanceof ECDSAPublicBCPGKey);
        isTrue("Legacy ECDSA secret key MUST be instanceof ECSecretBCPGKey",
                j2.getPrivateKey().getPrivateKeyDataPacket() instanceof ECSecretBCPGKey);

        BcPGPKeyPair b2 = toBcKeyPair(j2);
        isEncodingEqual(pubEnc, b2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, b2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Legacy ECDSA public key MUST be instanceof ECDSAPublicBCPGKey",
                b2.getPublicKey().getPublicKeyPacket().getKey() instanceof ECDSAPublicBCPGKey);
        isTrue("Legacy ECDSA secret key MUST be instanceof ECSecretBCPGKey",
                b2.getPrivateKey().getPrivateKeyDataPacket() instanceof ECSecretBCPGKey);

        isEquals("Creation time is preserved",
                date.getTime(), b2.getPublicKey().getCreationTime().getTime());
    }

    public static void main(String[] args)
    {
        runTest(new ECDSAKeyPairTest());
    }
}
