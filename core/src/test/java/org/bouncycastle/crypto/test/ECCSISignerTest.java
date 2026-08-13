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
import org.bouncycastle.math.ec.ECPoint;
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
    {
        runTest(new ECCSISignerTest());
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
        testConsecutiveSignatures();
        testSSKRange();
        testNoRandom();
        testUnreducedR();
        for (int i = 0; i < curveNames.length; ++i)
        {
            for (int j = 0; j < digests.length; ++j)
            {
                testRandom(curveNames[i], digests[j]);
            }
        }
    }

    /**
     * RFC 6507 sec. 5.2.1 draws j fresh per signature: two signatures formed over one j share
     * their r, and the pair of s' values then determines the SSK by linear algebra, so a signer
     * initialised once and asked for a second signature must draw a new pair rather than reuse
     * the first.
     */
    private void testConsecutiveSignatures()
        throws Exception
    {
        SecureRandom random = new SecureRandom();
        X9ECParameters params = CustomNamedCurves.getByName("secP256r1");
        ECCSIKeyPairGenerator generator = new ECCSIKeyPairGenerator();
        byte[] id = "2011-02\0tel:+447700900123\0".getBytes();
        ECCSIKeyGenerationParameters keyGenerationParameters = new ECCSIKeyGenerationParameters(random,
            params, new SHA256Digest(), id);
        generator.init(keyGenerationParameters);
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

        byte[] M1 = "message\0".getBytes();
        byte[] M2 = "message2\0".getBytes();

        ECCSISigner signer = new ECCSISigner(keyGenerationParameters.getKPAK(), params, new SHA256Digest(), id);
        signer.init(true, new ParametersWithRandom(keyPair.getPrivate(), random));
        signer.update(M1, 0, M1.length);
        byte[] sig1 = signer.generateSignature();
        signer.update(M2, 0, M2.length);
        byte[] sig2 = signer.generateSignature();

        // r is the first N bytes of each signature; a shared r is a reused nonce
        int n = 32;
        isTrue("nonce reused: consecutive signatures share r",
            !Arrays.areEqual(Arrays.copyOf(sig1, n), Arrays.copyOf(sig2, n)));

        ECCSISigner verifier = new ECCSISigner(keyGenerationParameters.getKPAK(), params, new SHA256Digest(), id);
        verifier.init(false, keyPair.getPublic());
        verifier.update(M1, 0, M1.length);
        isTrue("first consecutive signature did not verify", verifier.verifySignature(sig1));

        verifier = new ECCSISigner(keyGenerationParameters.getKPAK(), params, new SHA256Digest(), id);
        verifier.init(false, keyPair.getPublic());
        verifier.update(M2, 0, M2.length);
        isTrue("second consecutive signature did not verify", verifier.verifySignature(sig2));
    }

    /**
     * RFC 6507 sec. 5.1.2 derives the SSK modulo q, so one outside [1, q-1] is a malformed key,
     * rejected when the signer is initialised. The value congruent to a valid SSK modulo q is the
     * case worth covering: [ssk + q]G is still the point the KPAK consistency check expects, so
     * only the range check stands between it and the order arithmetic that requires it reduced.
     */
    private void testSSKRange()
    {
        SecureRandom random = new SecureRandom();
        X9ECParameters params = CustomNamedCurves.getByName("secP256r1");
        ECCSIKeyPairGenerator generator = new ECCSIKeyPairGenerator();
        byte[] id = "2011-02\0tel:+447700900123\0".getBytes();
        ECCSIKeyGenerationParameters keyGenerationParameters = new ECCSIKeyGenerationParameters(random,
            params, new SHA256Digest(), id);
        generator.init(keyGenerationParameters);
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        ECCSIPrivateKeyParameters priv = (ECCSIPrivateKeyParameters)keyPair.getPrivate();

        BigInteger q = params.getCurve().getOrder();
        BigInteger[] bad = new BigInteger[]{ priv.getSSK().add(q), BigIntegers.ZERO, q,
            BigIntegers.ONE.negate() };

        for (int i = 0; i != bad.length; i++)
        {
            ECCSISigner signer = new ECCSISigner(keyGenerationParameters.getKPAK(), params, new SHA256Digest(), id);
            try
            {
                signer.init(true, new ParametersWithRandom(
                    new ECCSIPrivateKeyParameters(bad[i], priv.getPublicKeyParameters()), random));

                fail("no exception thrown for SSK " + bad[i]);
            }
            catch (IllegalArgumentException e)
            {
                isTrue("wrong message: " + e.getMessage(), "SSK must be in [1, q-1]".equals(e.getMessage()));
            }
        }
    }

    /**
     * A signer initialised for signing with bare ECCSIPrivateKeyParameters rather than
     * ParametersWithRandom draws j from the default SecureRandom; the signature must round-trip.
     */
    private void testNoRandom()
        throws Exception
    {
        SecureRandom random = new SecureRandom();
        X9ECParameters params = CustomNamedCurves.getByName("secP256r1");
        ECCSIKeyPairGenerator generator = new ECCSIKeyPairGenerator();
        byte[] id = "2011-02\0tel:+447700900123\0".getBytes();
        ECCSIKeyGenerationParameters keyGenerationParameters = new ECCSIKeyGenerationParameters(random,
            params, new SHA256Digest(), id);
        generator.init(keyGenerationParameters);
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

        byte[] M = "message\0".getBytes();

        ECCSISigner signer = new ECCSISigner(keyGenerationParameters.getKPAK(), params, new SHA256Digest(), id);
        signer.init(true, keyPair.getPrivate());
        signer.update(M, 0, M.length);
        byte[] sig = signer.generateSignature();

        signer = new ECCSISigner(keyGenerationParameters.getKPAK(), params, new SHA256Digest(), id);
        signer.init(false, keyPair.getPublic());
        signer.update(M, 0, M.length);
        isTrue("signature from default SecureRandom did not verify", signer.verifySignature(sig));
    }

    /**
     * RFC 6507 sec. 5.2.1 assigns r the N-octet Jx itself, not Jx mod q - sec. 5.2.2 has the
     * verifier check Jx = r modulo p, so a reduced r fails a conforming external verifier. On
     * P-256 the two differ for about one signature in four billion; curve25519's order sits two
     * bits below its field size, so a nonce whose Jx exceeds q is found by a short search and
     * the emitted r can be checked against the unreduced Jx directly.
     */
    private void testUnreducedR()
        throws Exception
    {
        SecureRandom random = new SecureRandom();
        X9ECParameters params = CustomNamedCurves.getByName("curve25519");
        BigInteger q = params.getCurve().getOrder();
        int n = (params.getCurve().getFieldSize() + 7) / 8;

        // find a small nonce whose [j]G x-coordinate is at least q
        BigInteger j = BigIntegers.ONE;
        ECPoint J = params.getG().normalize();
        while (J.getAffineXCoord().toBigInteger().compareTo(q) < 0)
        {
            j = j.add(BigIntegers.ONE);
            J = J.add(params.getG()).normalize();
        }
        BigInteger jx = J.getAffineXCoord().toBigInteger();

        byte[] id = "2011-02\0tel:+447700900123\0".getBytes();
        ECCSIKeyPairGenerator generator = new ECCSIKeyPairGenerator();
        ECCSIKeyGenerationParameters keyGenerationParameters = new ECCSIKeyGenerationParameters(random,
            params, new SHA256Digest(), id);
        generator.init(keyGenerationParameters);
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

        byte[] M = "message\0".getBytes();

        ECCSISigner signer = new ECCSISigner(keyGenerationParameters.getKPAK(), params, new SHA256Digest(), id);
        signer.init(true, new ParametersWithRandom(keyPair.getPrivate(),
            new FixedSecureRandom(BigIntegers.asUnsignedByteArray((q.bitLength() + 7) / 8, j))));
        signer.update(M, 0, M.length);
        byte[] sig = signer.generateSignature();

        isTrue("r is not the unreduced Jx RFC 6507 sec. 5.2.1 assigns",
            Arrays.areEqual(BigIntegers.asUnsignedByteArray(n, jx), Arrays.copyOf(sig, n)));

        ECCSISigner verifier = new ECCSISigner(keyGenerationParameters.getKPAK(), params, new SHA256Digest(), id);
        verifier.init(false, keyPair.getPublic());
        verifier.update(M, 0, M.length);
        isTrue("unreduced-r signature did not verify", verifier.verifySignature(sig));
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
        isTrue("RFC 6507 appendix A signature", Arrays.areEqual(sig, Hex.decode("269D4C8F DEB66A74 E4EF8C0D 5DCC597D\n" +
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
        isTrue("RFC 6507 appendix A signature did not verify", signer.verifySignature(sig));
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
        isTrue("round trip failed for " + curveName + " with " + digest.getAlgorithmName(),
            signer.verifySignature(sig));
    }

}
