package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.HashMap;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.hawk.HawkKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkKeyPairGenerator;
import org.bouncycastle.pqc.crypto.hawk.HawkParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkPublicKeyParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkSigner;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Tests {@link HawkSigner} against the NIST PQCsignKAT vectors for Hawk-256,
 * Hawk-512 and Hawk-1024.
 *
 * <p>The reference implementation's {@code crypto_sign} writes the signed
 * message as {@code msg || sig}; the KAT {@code sm} field carries that
 * concatenation. {@code HawkSigner.generateSignature(msg)} returns only the
 * signature bytes (per the BC {@code MessageSigner} contract), so we
 * reconstruct {@code expectedSm = msg || sig} here for the byte-equality
 * comparison against the KAT.</p>
 */
public class HawkTest
    extends TestCase
{
    private static final HawkParameters[] PARAMETER_SETS = new HawkParameters[]
    {
        HawkParameters.Hawk_256,
        HawkParameters.Hawk_512,
        HawkParameters.Hawk_1024,
    };

    private static final String[] FILES = new String[]{
        "PQCsignKAT_96.rsp",
        "PQCsignKAT_184.rsp",
        "PQCsignKAT_360.rsp",
    };

    public void testTestVectors()
        throws Exception
    {
        for (int fileIndex = 0; fileIndex < FILES.length; fileIndex++)
        {
            runKat(fileIndex);
        }
    }

    private void runKat(int fileIndex)
        throws IOException
    {
        HawkParameters parameters = PARAMETER_SETS[fileIndex];
        String name = FILES[fileIndex];

        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/hawk", name);
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));

        HashMap<String, String> buf = new HashMap<String, String>();
        String line;
        while ((line = bin.readLine()) != null)
        {
            line = line.trim();
            if (line.startsWith("#"))
            {
                continue;
            }
            if (line.length() == 0)
            {
                if (!buf.isEmpty())
                {
                    checkVector(name, parameters, buf);
                    buf.clear();
                }
                continue;
            }
            int eq = line.indexOf('=');
            if (eq > 0)
            {
                buf.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
            }
        }
        if (!buf.isEmpty())
        {
            checkVector(name, parameters, buf);
        }
    }

    private void checkVector(String name, HawkParameters parameters, HashMap<String, String> buf)
    {
        String count = buf.get("count");
        byte[] seed = Hex.decode(buf.get("seed"));
        byte[] pk = Hex.decode(buf.get("pk"));
        byte[] sk = Hex.decode(buf.get("sk"));
        byte[] message = Hex.decode(buf.get("msg"));
        byte[] sm = Hex.decode(buf.get("sm"));

        SecureRandom random = new NISTSecureRandom(seed, null);

        HawkKeyPairGenerator kpGen = new HawkKeyPairGenerator();
        kpGen.init(new HawkKeyGenerationParameters(random, parameters));
        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
        HawkPublicKeyParameters pub = (HawkPublicKeyParameters)kp.getPublic();
        HawkPrivateKeyParameters priv = (HawkPrivateKeyParameters)kp.getPrivate();

        assertTrue(name + " count=" + count + ": public key",
            Arrays.areEqual(pk, pub.getEncoded()));
        assertTrue(name + " count=" + count + ": secret key",
            Arrays.areEqual(sk, priv.getEncoded()));

        HawkSigner signer = new HawkSigner();
        signer.init(true, new ParametersWithRandom(priv, random));
        byte[] sig = signer.generateSignature(message);

        // The KAT sm field is the NIST signed-message form: msg || sig.
        assertEquals(name + " count=" + count + ": signature length",
            sm.length - message.length, sig.length);
        byte[] expectedSm = Arrays.concatenate(message, sig);
        assertTrue(name + " count=" + count + ": signed message",
            Arrays.areEqual(sm, expectedSm));

        HawkSigner verifier = new HawkSigner();
        verifier.init(false, pub);
        assertTrue(name + " count=" + count + ": verify",
            verifier.verifySignature(message, sig));

        // Tampering one byte must fail verification.
        sig[sig.length / 2] ^= 0x01;
        assertFalse(name + " count=" + count + ": tampered signature rejected",
            verifier.verifySignature(message, sig));
    }
}
