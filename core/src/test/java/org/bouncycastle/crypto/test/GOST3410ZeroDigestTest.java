package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.GOST3410KeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.GOST3410KeyGenerationParameters;
import org.bouncycastle.crypto.params.GOST3410Parameters;
import org.bouncycastle.crypto.params.GOST3410PrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.ECGOST3410Signer;
import org.bouncycastle.crypto.signers.GOST3410Signer;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.test.SimpleTest;

/**
 * RFC 7091 and RFC 5832 sec. 6.1 step 2 and sec. 6.2 step 3: a message representative e that is
 * 0 mod q is replaced by 1 before use, when signing and when verifying. Without it a signature over
 * such a digest is s = d * r mod q, which gives up the private key as s * r^-1, and GOST R 34.10-94
 * verification accepted r = 1 with any s.
 */
public class GOST3410ZeroDigestTest
    extends SimpleTest
{
    private static final SecureRandom random = new SecureRandom();

    public String getName()
    {
        return "GOST3410ZeroDigest";
    }

    public void performTest()
        throws Exception
    {
        testEC("GostR3410-2001-CryptoPro-A", 32);
        testEC("Tc26-Gost-3410-12-256-paramSetA", 32);
        testEC("Tc26-Gost-3410-12-512-paramSetA", 64);
        testGOST3410_94();
    }

    private void testEC(String curveName, int digestLength)
    {
        X9ECParameters x9 = ECGOST3410NamedCurves.getByNameX9(curveName);
        ECDomainParameters domain = new ECDomainParameters(x9);
        BigInteger n = domain.getN();

        ECKeyPairGenerator kpGen = new ECKeyPairGenerator();
        kpGen.init(new ECKeyGenerationParameters(domain, random));
        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
        BigInteger d = ((ECPrivateKeyParameters)kp.getPrivate()).getD();

        byte[] one = new byte[digestLength];
        one[0] = 1; // little-endian 1

        byte[][] zeroDigests = new byte[][]{
            new byte[digestLength],
            new byte[0],
            Arrays.reverse(BigIntegers.asUnsignedByteArray(digestLength, n)) // n, little-endian
        };

        for (int i = 0; i != zeroDigests.length; i++)
        {
            ECGOST3410Signer signer = new ECGOST3410Signer();
            signer.init(true, new ParametersWithRandom(kp.getPrivate(), random));
            BigInteger[] sig = signer.generateSignature(zeroDigests[i]);

            isTrue(curveName + " digest " + i + ": s * r^-1 is the private key",
                !sig[1].multiply(sig[0].modInverse(n)).mod(n).equals(d));

            ECGOST3410Signer verifier = new ECGOST3410Signer();
            verifier.init(false, kp.getPublic());
            // previously threw ArithmeticException ("BigInteger not invertible.")
            isTrue(curveName + " digest " + i + ": own signature does not verify",
                verifier.verifySignature(zeroDigests[i], sig[0], sig[1]));
            isTrue(curveName + " digest " + i + ": signature not formed over e = 1",
                verifier.verifySignature(one, sig[0], sig[1]));
        }
    }

    private void testGOST3410_94()
    {
        GOST3410Parameters params = new GOST3410Parameters(
            new BigInteger("EE8172AE8996608FB69359B89EB82A69854510E2977A4D63BC97322CE5DC3386"
                + "EA0A12B343E9190F23177539845839786BB0C345D165976EF2195EC9B1C379E3", 16),
            new BigInteger("98915E7EC8265EDFCDA31E88F24809DDB064BDC7285DD50D7289F0AC6F49DD2D", 16),
            new BigInteger("9E96031500C8774A869582D4AFDE2127AFAD2538B4B6270A6F7C8837B50D50F2"
                + "06755984A49E509304D648BE2AB5AAB18EBE2CD46AC3D8495B142AA6CE23E21C", 16));
        BigInteger q = params.getQ();

        GOST3410KeyPairGenerator kpGen = new GOST3410KeyPairGenerator();
        kpGen.init(new GOST3410KeyGenerationParameters(random, params));
        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
        BigInteger x = ((GOST3410PrivateKeyParameters)kp.getPrivate()).getX();

        byte[][] zeroDigests = new byte[][]{
            new byte[32],
            Arrays.reverse(BigIntegers.asUnsignedByteArray(32, q))
        };

        for (int i = 0; i != zeroDigests.length; i++)
        {
            GOST3410Signer signer = new GOST3410Signer();
            signer.init(true, new ParametersWithRandom(kp.getPrivate(), random));
            BigInteger[] sig = signer.generateSignature(zeroDigests[i]);

            isTrue("GOST3410-94 digest " + i + ": s * r^-1 is the private key",
                !sig[1].multiply(sig[0].modInverse(q)).mod(q).equals(x));

            GOST3410Signer verifier = new GOST3410Signer();
            verifier.init(false, kp.getPublic());
            isTrue("GOST3410-94 digest " + i + ": own signature does not verify",
                verifier.verifySignature(zeroDigests[i], sig[0], sig[1]));

            // with m = 0 left as 0, v = 0 and u = 1, so r = 1 verified for any s without the key
            BigInteger anyS = BigIntegers.createRandomInRange(BigIntegers.ONE, q.subtract(BigIntegers.ONE), random);
            isTrue("GOST3410-94 digest " + i + ": r = 1 with an arbitrary s verifies",
                !verifier.verifySignature(zeroDigests[i], BigIntegers.ONE, anyS));
        }
    }

    public static void main(String[] args)
    {
        runTest(new GOST3410ZeroDigestTest());
    }
}
