package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.faest.FaestKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.faest.FaestKeyPairGenerator;
import org.bouncycastle.pqc.crypto.faest.FaestParameters;
import org.bouncycastle.pqc.crypto.faest.FaestPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.faest.FaestPublicKeyParameters;
import org.bouncycastle.pqc.crypto.faest.FaestSigner;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.encoders.Hex;

/**
 * Byte-exact NIST KAT compatibility test against upstream FAEST.
 * <p>
 * For each {@code count} entry in {@code PQCsignKAT_*.rsp}:
 * <ol>
 *   <li>Seed a {@link NISTSecureRandom} (AES-256-CTR-DRBG) with the 48-byte
 *       KAT seed.</li>
 *   <li>Run {@link FaestKeyPairGenerator} against that DRBG; assert the
 *       resulting {@code pk}/{@code sk} match the KAT.</li>
 *   <li>Initialize a {@link FaestSigner} with the private key and the SAME
 *       DRBG (so it consumes {@code rho} from the correct position).</li>
 *   <li>Sign the KAT message; assert {@code msg || signature} matches the
 *       expected {@code sm} byte-exactly.</li>
 *   <li>Initialize a fresh {@code FaestSigner} for verify and assert the
 *       signature accepts.</li>
 * </ol>
 * <p>
 * KAT files live in {@code bc-test-data/pqc/crypto/faest/}; the test is
 * driven by {@code org.bouncycastle.test.TestResourceFinder}.
 */
public class FaestKatTest
    extends TestCase
{
    /** How many KAT entries to verify per parameter set. */
    private static final int MAX_ENTRIES = 3;

    public void testFaest128s() throws IOException { runKat("PQCsignKAT_faest_128s.rsp", FaestParameters.faest_128s); }
    public void testFaest128f() throws IOException { runKat("PQCsignKAT_faest_128f.rsp", FaestParameters.faest_128f); }
    public void testFaest192s() throws IOException { runKat("PQCsignKAT_faest_192s.rsp", FaestParameters.faest_192s); }
    public void testFaest192f() throws IOException { runKat("PQCsignKAT_faest_192f.rsp", FaestParameters.faest_192f); }
    public void testFaest256s() throws IOException { runKat("PQCsignKAT_faest_256s.rsp", FaestParameters.faest_256s); }
    public void testFaest256f() throws IOException { runKat("PQCsignKAT_faest_256f.rsp", FaestParameters.faest_256f); }
    public void testFaestEm128s() throws IOException { runKat("PQCsignKAT_faest_em_128s.rsp", FaestParameters.faest_em_128s); }
    public void testFaestEm128f() throws IOException { runKat("PQCsignKAT_faest_em_128f.rsp", FaestParameters.faest_em_128f); }
    public void testFaestEm192s() throws IOException { runKat("PQCsignKAT_faest_em_192s.rsp", FaestParameters.faest_em_192s); }
    public void testFaestEm192f() throws IOException { runKat("PQCsignKAT_faest_em_192f.rsp", FaestParameters.faest_em_192f); }
    public void testFaestEm256s() throws IOException { runKat("PQCsignKAT_faest_em_256s.rsp", FaestParameters.faest_em_256s); }
    public void testFaestEm256f() throws IOException { runKat("PQCsignKAT_faest_em_256f.rsp", FaestParameters.faest_em_256f); }

    private void runKat(String resource, FaestParameters p)
        throws IOException
    {
        InputStream is = TestResourceFinder.findTestResource("pqc/crypto/faest", resource);
        BufferedReader br = new BufferedReader(new InputStreamReader(is));
        Map<String, String> kv = new HashMap<String, String>();
        int entries = 0;
        String line;
        while ((line = br.readLine()) != null)
        {
            line = line.trim();
            if (line.length() == 0)
            {
                if (kv.containsKey("count") && kv.containsKey("sm"))
                {
                    runOne(p, kv);
                    entries++;
                    kv.clear();
                    if (entries >= MAX_ENTRIES)
                    {
                        break;
                    }
                }
                continue;
            }
            if (line.startsWith("#")) continue;
            int eq = line.indexOf('=');
            if (eq < 0)
            {
                continue;
            }
            kv.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
        }
        br.close();
        assertTrue(p.getName() + ": expected at least one KAT entry", entries > 0);
    }

    private void runOne(FaestParameters p, Map<String, String> kv)
    {
        byte[] seed = Hex.decode(kv.get("seed"));
        int mlen = Integer.parseInt(kv.get("mlen"));
        byte[] msg = Hex.decode(kv.get("msg"));
        byte[] expectedPk = Hex.decode(kv.get("pk"));
        byte[] expectedSk = Hex.decode(kv.get("sk"));
        byte[] expectedSm = Hex.decode(kv.get("sm"));

        // Seed the NIST DRBG and run the key-pair generator. The generator
        // consumes exactly the same bytes the upstream C keygen does (sk_key
        // with the bit-check reject loop, then sk_input), leaving the DRBG
        // state positioned for the signer to draw rho next.
        NISTSecureRandom drbg = new NISTSecureRandom(seed, null);

        FaestKeyPairGenerator kpg = new FaestKeyPairGenerator();
        kpg.init(new FaestKeyGenerationParameters(drbg, p));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        FaestPublicKeyParameters pub = (FaestPublicKeyParameters)kp.getPublic();
        FaestPrivateKeyParameters priv = (FaestPrivateKeyParameters)kp.getPrivate();

        assertEquals("sk mismatch count=" + kv.get("count"),
            Hex.toHexString(expectedSk), Hex.toHexString(priv.getEncoded()));
        assertEquals("pk mismatch count=" + kv.get("count"),
            Hex.toHexString(expectedPk), Hex.toHexString(pub.getEncoded()));

        // Sign. ParametersWithRandom binds the DRBG to FaestSigner so that
        // the signer's `random.nextBytes(rho)` consumes from the same stream
        // that just produced (sk_key, sk_input), exactly mirroring upstream.
        FaestSigner signer = new FaestSigner();
        signer.init(true, new ParametersWithRandom(priv, drbg));
        byte[] sig = signer.generateSignature(msg);

        // sm = msg || sig (NIST KAT convention).
        byte[] sm = new byte[mlen + p.getSigSize()];
        System.arraycopy(msg, 0, sm, 0, mlen);
        System.arraycopy(sig, 0, sm, mlen, p.getSigSize());
        assertEquals("sm mismatch count=" + kv.get("count"),
            Hex.toHexString(expectedSm), Hex.toHexString(sm));

        FaestSigner verifier = new FaestSigner();
        verifier.init(false, pub);
        assertTrue("verify count=" + kv.get("count"), verifier.verifySignature(msg, sig));
    }
}
