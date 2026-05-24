package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.mqom.MQOMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mqom.MQOMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mqom.MQOMParameters;
import org.bouncycastle.pqc.crypto.mqom.MQOMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mqom.MQOMPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mqom.MQOMSigner;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * KAT-driven validation of the MQOM engine. For each variant, the upstream
 * KAT generator submits a 48-byte seed to the NIST CTR-DRBG, draws a
 * key-pair seed and per-signature randomness from it, and records (pk, sk,
 * sm = msg || sig). This test replays the DRBG and asserts byte-identity
 * with the recorded outputs.
 *
 * <p>The KAT files under {@code core/src/test/data/pqc/crypto/mqom/kat/}
 * contain a small prefix (first three entries) of the upstream
 * {@code PQCsignKAT_*.rsp} stream — enough to exercise the deterministic
 * pipeline without bulking up the test data tree.
 */
public class MQOMKatTest
    extends TestCase
{
    private static final MQOMParameters[] ALL_VARIANTS = new MQOMParameters[]{
        MQOMParameters.mqom2_cat1_gf2_fast_r3, MQOMParameters.mqom2_cat1_gf2_fast_r5,
        MQOMParameters.mqom2_cat1_gf2_short_r3, MQOMParameters.mqom2_cat1_gf2_short_r5,
        MQOMParameters.mqom2_cat1_gf16_fast_r3, MQOMParameters.mqom2_cat1_gf16_fast_r5,
        MQOMParameters.mqom2_cat1_gf16_short_r3, MQOMParameters.mqom2_cat1_gf16_short_r5,
        MQOMParameters.mqom2_cat1_gf256_fast_r3, MQOMParameters.mqom2_cat1_gf256_fast_r5,
        MQOMParameters.mqom2_cat1_gf256_short_r3, MQOMParameters.mqom2_cat1_gf256_short_r5,
        MQOMParameters.mqom2_cat3_gf2_fast_r3, MQOMParameters.mqom2_cat3_gf2_fast_r5,
        MQOMParameters.mqom2_cat3_gf2_short_r3, MQOMParameters.mqom2_cat3_gf2_short_r5,
        MQOMParameters.mqom2_cat3_gf16_fast_r3, MQOMParameters.mqom2_cat3_gf16_fast_r5,
        MQOMParameters.mqom2_cat3_gf16_short_r3, MQOMParameters.mqom2_cat3_gf16_short_r5,
        MQOMParameters.mqom2_cat3_gf256_fast_r3, MQOMParameters.mqom2_cat3_gf256_fast_r5,
        MQOMParameters.mqom2_cat3_gf256_short_r3, MQOMParameters.mqom2_cat3_gf256_short_r5,
        MQOMParameters.mqom2_cat5_gf2_fast_r3, MQOMParameters.mqom2_cat5_gf2_fast_r5,
        MQOMParameters.mqom2_cat5_gf2_short_r3, MQOMParameters.mqom2_cat5_gf2_short_r5,
        MQOMParameters.mqom2_cat5_gf16_fast_r3, MQOMParameters.mqom2_cat5_gf16_fast_r5,
        MQOMParameters.mqom2_cat5_gf16_short_r3, MQOMParameters.mqom2_cat5_gf16_short_r5,
        MQOMParameters.mqom2_cat5_gf256_fast_r3, MQOMParameters.mqom2_cat5_gf256_fast_r5,
        MQOMParameters.mqom2_cat5_gf256_short_r3, MQOMParameters.mqom2_cat5_gf256_short_r5
    };

    public void testAllVariants()
        throws IOException
    {
        for (int i = 0; i < ALL_VARIANTS.length; i++)
        {
            MQOMParameters params = ALL_VARIANTS[i];
            String filename = params.getName() + ".rsp";
            InputStream in = TestResourceFinder.findTestResource("pqc/crypto/mqom/kat", filename);
            List<Map<String, String>> entries = parseKatFile(in);
            in.close();
            assertFalse("KAT file empty for " + params.getName(), entries.isEmpty());

            for (int k = 0; k < entries.size(); k++)
            {
                Map<String, String> e = entries.get(k);
                byte[] seed = Hex.decode(e.get("seed"));
                byte[] msg = Hex.decode(e.get("msg"));
                byte[] expectedPk = Hex.decode(e.get("pk"));
                byte[] expectedSk = Hex.decode(e.get("sk"));
                byte[] expectedSm = Hex.decode(e.get("sm"));

                // The KAT generator drives the NIST CTR-DRBG with the recorded
                // 48-byte seed, then reads (in order) 2*seedSize bytes for the
                // key generation seed, seedSize bytes for the message seed and
                // saltSize bytes for the salt. MQOMKeyPairGenerator and
                // MQOMSigner draw the same byte counts in the same order, so a
                // single shared DRBG drives the full pipeline through the
                // public API.
                NISTSecureRandom drbg = new NISTSecureRandom(seed, null);

                MQOMKeyPairGenerator kpg = new MQOMKeyPairGenerator();
                kpg.init(new MQOMKeyGenerationParameters(drbg, params));
                AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
                byte[] pk = ((MQOMPublicKeyParameters)kp.getPublic()).getEncoded();
                byte[] sk = ((MQOMPrivateKeyParameters)kp.getPrivate()).getEncoded();

                String tag = params.getName() + " #" + e.get("count");
                assertTrue(tag + " pk", Arrays.areEqual(expectedPk, pk));
                assertTrue(tag + " sk", Arrays.areEqual(expectedSk, sk));

                MQOMSigner signer = new MQOMSigner();
                signer.init(true, new ParametersWithRandom(kp.getPrivate(), drbg));
                byte[] sig = signer.generateSignature(msg);

                byte[] sm = new byte[msg.length + sig.length];
                System.arraycopy(msg, 0, sm, 0, msg.length);
                System.arraycopy(sig, 0, sm, msg.length, sig.length);
                assertTrue(tag + " sm", Arrays.areEqual(expectedSm, sm));

                MQOMSigner verifier = new MQOMSigner();
                verifier.init(false, kp.getPublic());
                assertTrue(tag + " verify", verifier.verifySignature(msg, sig));
            }
        }
    }

    static List<Map<String, String>> parseKatFile(InputStream in)
        throws IOException
    {
        List<Map<String, String>> out = new ArrayList<Map<String, String>>();
        BufferedReader br = new BufferedReader(new InputStreamReader(in));
        Map<String, String> cur = new LinkedHashMap<String, String>();
        String line;
        while ((line = br.readLine()) != null)
        {
            line = line.trim();
            if (line.startsWith("#") || line.length() == 0)
            {
                if (cur.size() > 0)
                {
                    out.add(cur);
                    cur = new LinkedHashMap<String, String>();
                }
                continue;
            }
            int eq = line.indexOf('=');
            if (eq < 0)
            {
                continue;
            }
            cur.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
        }
        if (cur.size() > 0)
        {
            out.add(cur);
        }
        return out;
    }
}
