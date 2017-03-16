package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.ECNRSigner;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

/**
 * ECNR tests.
 */
public class ECNRTest
    extends SimpleTest
{
    /**
     * a basic regression test with 239 bit prime
     */
    BigInteger r = new BigInteger("308636143175167811492623515537541734843573549327605293463169625072911693");
    BigInteger s = new BigInteger("852401710738814635664888632022555967400445256405412579597015412971797143");

    byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("700000017569056646655505781757157107570501575775705779575555657156756655"));

    SecureRandom    k = new TestRandomBigInteger(kData);

    private void ecNR239bitPrime()
    {
        BigInteger n = new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307");

        ECCurve.Fp curve = new ECCurve.Fp(
            new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
            new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16), // b
            n, ECConstants.ONE);

        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
            n);

        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("876300101507107567501066130761671078357010671067781776716671676178726717"), // d
            params);

        ECNRSigner ecnr = new ECNRSigner();
        ParametersWithRandom param = new ParametersWithRandom(priKey, k);

        ecnr.init(true, param);

        byte[] message = new BigInteger("968236873715988614170569073515315707566766479517").toByteArray();
        BigInteger[] sig = ecnr.generateSignature(message);

        if (!r.equals(sig[0]))
        {
            fail("r component wrong.", r, sig[0]);
        }

        if (!s.equals(sig[1]))
        {
            fail("s component wrong.", s, sig[1]);
        }

        // Verify the signature
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            curve.decodePoint(Hex.decode("025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70")), // Q
            params);

        ecnr.init(false, pubKey);
        if (!ecnr.verifySignature(message, sig[0], sig[1]))
        {
            fail("signature fails");
        }
    }

    public String getName()
    {
        return "ECNR";
    }

    public void performTest()
    {
        ecNR239bitPrime();
    }

    public static void main(
        String[]    args)
    {
        runTest(new ECNRTest());
    }
}

