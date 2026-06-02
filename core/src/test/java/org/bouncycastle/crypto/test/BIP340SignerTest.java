package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.BIP340Signer;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Regression test for BIP-340 Schnorr signatures over secp256k1.
 * <p>
 * Drives the official test vectors from
 * <a href="https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv">bitcoin/bips</a>,
 * resolved through {@link TestResourceFinder} at {@code crypto/bip340/test-vectors.csv}. Each row exercises
 * verification; rows that carry a secret key additionally exercise deterministic signing (the {@code aux_rand}
 * column makes both signing and verification reproducible).
 */
public class BIP340SignerTest
    extends SimpleTest
{
    public String getName()
    {
        return "BIP340Signer";
    }

    public static void main(String[] args)
    {
        runTest(new BIP340SignerTest());
    }

    public void performTest()
        throws Exception
    {
        runOfficialVectors();
        roundTripWithAuxRand();
        deterministicMode();
        defaultModeSubstitutesSecureRandom();
    }

    private void runOfficialVectors()
        throws Exception
    {
        InputStream src = TestResourceFinder.findTestResource("crypto/bip340", "test-vectors.csv");
        BufferedReader reader = new BufferedReader(new InputStreamReader(src));
        try
        {
            String header = reader.readLine();
            isTrue("missing CSV header", header != null && header.startsWith("index,"));

            String line;
            while ((line = reader.readLine()) != null)
            {
                if (line.length() == 0)
                {
                    continue;
                }
                runVectorRow(splitCsv(line));
            }
        }
        finally
        {
            reader.close();
        }
    }

    private void runVectorRow(List<String> cols)
        throws Exception
    {
        String index = (String)cols.get(0);
        String secretHex = (String)cols.get(1);
        String publicHex = (String)cols.get(2);
        String auxRandHex = (String)cols.get(3);
        String messageHex = (String)cols.get(4);
        String signatureHex = (String)cols.get(5);
        boolean expected = "TRUE".equalsIgnoreCase((String)cols.get(6));

        byte[] pubX = Hex.decode(publicHex);
        byte[] message = Hex.decode(messageHex);
        byte[] signature = Hex.decode(signatureHex);

        ECPublicKeyParameters pub = BIP340Signer.decodePublicKey(pubX);

        if (secretHex.length() > 0)
        {
            byte[] auxRand = Hex.decode(auxRandHex);
            byte[] produced = sign(Hex.decode(secretHex), auxRand, message);
            if (!Arrays.areEqual(signature, produced))
            {
                fail("vector " + index + ": signing produced " + Hex.toHexString(produced)
                    + " expected " + Hex.toHexString(signature));
            }
        }

        boolean actual;
        if (pub == null)
        {
            // BIP-340 §3.1 rejects encodings outside [0,p) or with no curve point — caller can't construct a key.
            actual = false;
        }
        else
        {
            BIP340Signer verifier = new BIP340Signer();
            verifier.init(false, pub);
            verifier.update(message, 0, message.length);
            actual = verifier.verifySignature(signature);
        }

        if (actual != expected)
        {
            fail("vector " + index + ": verify returned " + actual + " expected " + expected);
        }
    }

    private byte[] sign(byte[] secret, byte[] auxRand, byte[] message)
    {
        BigInteger d = new BigInteger(1, secret);
        ECPrivateKeyParameters priv = new ECPrivateKeyParameters(d, BIP340Signer.getDomain());
        BIP340Signer signer = new BIP340Signer();
        signer.init(true, new ParametersWithRandom(priv, new FixedBytesRandom(auxRand)));
        signer.update(message, 0, message.length);
        return signer.generateSignature();
    }

    private void roundTripWithAuxRand()
    {
        BigInteger d = new BigInteger(
            "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF", 16);
        ECPrivateKeyParameters priv = new ECPrivateKeyParameters(d, BIP340Signer.getDomain());
        byte[] msg = Hex.decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");

        BIP340Signer signer = new BIP340Signer();
        signer.init(true, new ParametersWithRandom(priv, new SecureRandom()));
        signer.update(msg, 0, msg.length);
        byte[] sig = signer.generateSignature();
        isTrue("signature length", sig.length == 64);

        byte[] pubX = BigIntegers.asUnsignedByteArray(32,
            new FixedPointCombMultiplier()
                .multiply(BIP340Signer.getDomain().getG(), d).normalize()
                .getAffineXCoord().toBigInteger());

        ECPublicKeyParameters pub = BIP340Signer.decodePublicKey(pubX);
        isTrue("liftX produced a key", pub != null);

        BIP340Signer verifier = new BIP340Signer();
        verifier.init(false, pub);
        verifier.update(msg, 0, msg.length);
        isTrue("self-issued signature verifies", verifier.verifySignature(sig));

        // tampered message
        byte[] bad = Arrays.clone(msg);
        bad[0] ^= 0x01;
        verifier.init(false, pub);
        verifier.update(bad, 0, bad.length);
        isTrue("tampered message rejected", !verifier.verifySignature(sig));

        // tampered signature
        byte[] badSig = Arrays.clone(sig);
        badSig[0] ^= 0x01;
        verifier.init(false, pub);
        verifier.update(msg, 0, msg.length);
        isTrue("tampered signature rejected", !verifier.verifySignature(badSig));
    }

    // Deterministic mode (explicit constructor) with no supplied random reproduces vector 0 (aux_rand = 0^32).
    private void deterministicMode()
    {
        BigInteger d = new BigInteger(
            "0000000000000000000000000000000000000000000000000000000000000003", 16);
        ECPrivateKeyParameters priv = new ECPrivateKeyParameters(d, BIP340Signer.getDomain());
        byte[] msg = Hex.decode("0000000000000000000000000000000000000000000000000000000000000000");
        byte[] expected = Hex.decode(
            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                + "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0");

        BIP340Signer signer = new BIP340Signer(true);
        signer.init(true, priv);
        signer.update(msg, 0, msg.length);
        isTrue("deterministic mode matches aux_rand=0 vector", Arrays.areEqual(expected, signer.generateSignature()));
    }

    // Default (randomized) mode with no ParametersWithRandom substitutes a default SecureRandom rather than
    // signing deterministically: two signatures over the same message differ, and both verify.
    private void defaultModeSubstitutesSecureRandom()
    {
        BigInteger d = new BigInteger(
            "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF", 16);
        ECPrivateKeyParameters priv = new ECPrivateKeyParameters(d, BIP340Signer.getDomain());
        byte[] msg = Hex.decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");

        BIP340Signer signer = new BIP340Signer();
        signer.init(true, priv);
        signer.update(msg, 0, msg.length);
        byte[] sig1 = signer.generateSignature();

        signer.init(true, priv);
        signer.update(msg, 0, msg.length);
        byte[] sig2 = signer.generateSignature();

        isTrue("default mode is randomized (aux_rand drawn from substituted SecureRandom)",
            !Arrays.areEqual(sig1, sig2));

        byte[] pubX = BigIntegers.asUnsignedByteArray(32,
            new FixedPointCombMultiplier()
                .multiply(BIP340Signer.getDomain().getG(), d).normalize()
                .getAffineXCoord().toBigInteger());
        ECPublicKeyParameters pub = BIP340Signer.decodePublicKey(pubX);

        BIP340Signer verifier = new BIP340Signer();
        verifier.init(false, pub);
        verifier.update(msg, 0, msg.length);
        isTrue("randomized signature 1 verifies", verifier.verifySignature(sig1));
        verifier.init(false, pub);
        verifier.update(msg, 0, msg.length);
        isTrue("randomized signature 2 verifies", verifier.verifySignature(sig2));
    }

    private static List<String> splitCsv(String line)
    {
        List<String> cols = new ArrayList<String>(8);
        int start = 0;
        for (int i = 0; i < line.length(); i++)
        {
            if (line.charAt(i) == ',')
            {
                cols.add(line.substring(start, i));
                start = i + 1;
            }
        }
        cols.add(line.substring(start));
        return cols;
    }

    /**
     * Emits a fixed byte buffer once for the next {@code nextBytes} call — used to replay {@code aux_rand} from the
     * BIP-340 vectors. Vectors only sign once per row, so the single-shot behaviour is sufficient.
     */
    private static final class FixedBytesRandom
        extends SecureRandom
    {
        private static final long serialVersionUID = 1L;
        private final byte[] bytes;

        FixedBytesRandom(byte[] bytes)
        {
            this.bytes = Arrays.clone(bytes);
        }

        public void nextBytes(byte[] out)
        {
            if (out.length != bytes.length)
            {
                throw new IllegalStateException("FixedBytesRandom asked for " + out.length
                    + " bytes, held " + bytes.length);
            }
            System.arraycopy(bytes, 0, out, 0, out.length);
        }
    }
}
