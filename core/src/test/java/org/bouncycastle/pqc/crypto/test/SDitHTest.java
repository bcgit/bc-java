package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.sdith.SDitHKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sdith.SDitHKeyPairGenerator;
import org.bouncycastle.pqc.crypto.sdith.SDitHParameters;
import org.bouncycastle.pqc.crypto.sdith.SDitHPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sdith.SDitHPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sdith.SDitHSigner;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class SDitHTest
        extends TestCase
{
    public void testHypercubeCat1Gf256Kats()
            throws Exception
    {
        runKats("sdith_hypercube_cat1_gf256_KAT.rsp", SDitHParameters.sdith_hypercube_cat1_gf256);
    }

    public void testHypercubeCat3Gf256Kats()
            throws Exception
    {
        runKats("sdith_hypercube_cat3_gf256_KAT.rsp", SDitHParameters.sdith_hypercube_cat3_gf256);
    }

    public void testHypercubeCat5Gf256Kats()
            throws Exception
    {
        runKats("sdith_hypercube_cat5_gf256_KAT.rsp", SDitHParameters.sdith_hypercube_cat5_gf256);
    }

    public void testHypercubeCat1P251Kats()
            throws Exception
    {
        runKats("sdith_hypercube_cat1_p251_KAT.rsp", SDitHParameters.sdith_hypercube_cat1_p251);
    }

    public void testHypercubeCat3P251Kats()
            throws Exception
    {
        runKats("sdith_hypercube_cat3_p251_KAT.rsp", SDitHParameters.sdith_hypercube_cat3_p251);
    }

    public void testHypercubeCat5P251Kats()
            throws Exception
    {
        runKats("sdith_hypercube_cat5_p251_KAT.rsp", SDitHParameters.sdith_hypercube_cat5_p251);
    }

    public void testThresholdCat1Gf256Kats()
            throws Exception
    {
        runKats("sdith_threshold_cat1_gf256_KAT.rsp", SDitHParameters.sdith_threshold_cat1_gf256);
    }

    public void testThresholdCat3Gf256Kats()
            throws Exception
    {
        runKats("sdith_threshold_cat3_gf256_KAT.rsp", SDitHParameters.sdith_threshold_cat3_gf256);
    }

    public void testThresholdCat5Gf256Kats()
            throws Exception
    {
        runKats("sdith_threshold_cat5_gf256_KAT.rsp", SDitHParameters.sdith_threshold_cat5_gf256);
    }

    public void testThresholdCat1P251Kats()
            throws Exception
    {
        runKats("sdith_threshold_cat1_p251_KAT.rsp", SDitHParameters.sdith_threshold_cat1_p251);
    }

    public void testThresholdCat3P251Kats()
            throws Exception
    {
        runKats("sdith_threshold_cat3_p251_KAT.rsp", SDitHParameters.sdith_threshold_cat3_p251);
    }

    public void testThresholdCat5P251Kats()
            throws Exception
    {
        runKats("sdith_threshold_cat5_p251_KAT.rsp", SDitHParameters.sdith_threshold_cat5_p251);
    }

    private void runKats(String name, SDitHParameters parameters)
            throws Exception
    {
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/sdith", name);
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        try
        {
            HashMap<String, String> buf = new HashMap<String, String>();
            int processed = 0;
            String line;
            while ((line = bin.readLine()) != null)
            {
                line = line.trim();
                if (line.startsWith("#") || line.length() == 0)
                {
                    if (buf.size() > 0)
                    {
                        runOne(parameters, buf);
                        processed++;
                        if (processed >= 10)
                        {
                            // For routine CI: only exercise the first 10 counts. The full
                            // 100-count sweep matches but takes longer; raise this limit
                            // when adding new variants.
                            return;
                        }
                    }
                    buf.clear();
                    continue;
                }
                int eq = line.indexOf('=');
                if (eq > 0)
                {
                    buf.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
                }
            }
            if (buf.size() > 0)
            {
                runOne(parameters, buf);
            }
        }
        finally
        {
            bin.close();
        }
    }

    private void runOne(SDitHParameters parameters, HashMap<String, String> buf)
    {
        String count = (String) buf.get("count");
        byte[] seed = Hex.decode((String) buf.get("seed"));
        byte[] expectedPk = Hex.decode((String) buf.get("pk"));
        byte[] expectedSk = Hex.decode((String) buf.get("sk"));
        byte[] expectedSm = Hex.decode((String) buf.get("sm"));
        byte[] msg = Hex.decode((String) buf.get("msg"));
        int smlen = Integer.parseInt((String) buf.get("smlen"));

        NISTSecureRandom random = new NISTSecureRandom(seed, null);

        SDitHKeyPairGenerator kpg = new SDitHKeyPairGenerator();
        kpg.init(new SDitHKeyGenerationParameters(random, parameters));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

        SDitHPublicKeyParameters pub = (SDitHPublicKeyParameters) kp.getPublic();
        SDitHPrivateKeyParameters priv = (SDitHPrivateKeyParameters) kp.getPrivate();

        byte[] gotPk = pub.getEncoded();
        byte[] gotSk = priv.getEncoded();
        assertTrue("count " + count + " pk", Arrays.areEqual(expectedPk, gotPk));
        assertTrue("count " + count + " sk", Arrays.areEqual(expectedSk, gotSk));

        SDitHSigner signer = new SDitHSigner();
        signer.init(true, new ParametersWithRandom(priv, random));
        byte[] sig = signer.generateSignature(msg);

        // The reference NIST-KAT sm format differs between variants:
        //   hypercube : sm = sig || msg
        //   threshold : sm = LE32(siglen) || msg || sig
        // Build the expected sm in whichever form the variant uses.
        byte[] gotSm;
        if (parameters.getVariant() == SDitHParameters.VARIANT_THRESHOLD)
        {
            byte[] lenLe = new byte[4];
            int s = sig.length;
            lenLe[0] = (byte)(s & 0xff);
            lenLe[1] = (byte)((s >>> 8) & 0xff);
            lenLe[2] = (byte)((s >>> 16) & 0xff);
            lenLe[3] = (byte)((s >>> 24) & 0xff);
            gotSm = Arrays.concatenate(new byte[][]{lenLe, msg, sig});
        }
        else
        {
            gotSm = Arrays.concatenate(sig, msg);
        }
        assertEquals("count " + count + " smlen", smlen, gotSm.length);
        assertTrue("count " + count + " sm", Arrays.areEqual(expectedSm, gotSm));

        SDitHSigner verifier = new SDitHSigner();
        verifier.init(false, pub);
        assertTrue("count " + count + " verify", verifier.verifySignature(msg, sig));
        sig[0] ^= 0x01;
        assertFalse("count " + count + " tampered should not verify", verifier.verifySignature(msg, sig));
    }
}
