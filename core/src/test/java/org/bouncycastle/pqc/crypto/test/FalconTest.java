package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.HashMap;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyPairGenerator;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class FalconTest
    extends TestCase
{
    public void testVectors()
        throws Exception
    {
        String[] files = new String[]{
            "falcon512-KAT.rsp",
            "falcon1024-KAT.rsp"
        };
        FalconParameters[] parameters = new FalconParameters[]{
            FalconParameters.falcon_512,
            FalconParameters.falcon_1024
        };

        for (int fileindex = 0; fileindex < files.length; fileindex++)
        {
            String name = files[fileindex];

            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/falcon", name);
            BufferedReader bin = new BufferedReader(new InputStreamReader(src));

            String line = null;
            HashMap<String, String> buf = new HashMap<String, String>();
            TestSampler sampler = new TestSampler();
            while ((line = bin.readLine()) != null)
            {
                line = line.trim();

                if (line.startsWith("#"))
                {
                    continue;
                }
                if (line.length() == 0)
                {
                    if (buf.size() > 0)
                    {
                        String count = (String)buf.get("count");
                        if (sampler.skipTest(count))
                        {
                            continue;
                        }
                        // System.out.println("test case: " + count);

                        byte[] seed = Hex.decode((String)buf.get("seed")); // seed for Falcon secure random
                        byte[] pk = Hex.decode((String)buf.get("pk"));     // public key
                        byte[] sk = Hex.decode((String)buf.get("sk"));     // private key
                        byte[] sm = Hex.decode((String)buf.get("sm"));     // signed message
                        int sm_len = Integer.parseInt((String)buf.get("smlen"));
                        byte[] msg = Hex.decode((String)buf.get("msg")); // message
                        int m_len = Integer.parseInt((String)buf.get("mlen"));

                        NISTSecureRandom random = new NISTSecureRandom(seed, null);

                        // keygen
                        FalconKeyGenerationParameters kparam = new FalconKeyGenerationParameters(random, parameters[fileindex]);
                        FalconKeyPairGenerator kpg = new FalconKeyPairGenerator();
                        kpg.init(kparam);
                        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

                        FalconPublicKeyParameters pubParams = (FalconPublicKeyParameters)PublicKeyFactory.createKey(
                            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((FalconPublicKeyParameters)kp.getPublic()));
                        FalconPrivateKeyParameters privParams = (FalconPrivateKeyParameters)PrivateKeyFactory.createKey(
                            PrivateKeyInfoFactory.createPrivateKeyInfo((FalconPrivateKeyParameters)kp.getPrivate()));

                        byte[] respk = pubParams.getH();
                        byte[] ressk = privParams.getEncoded();

                        //keygen
                        assertTrue(name + " " + count + " public key", Arrays.areEqual(respk, 0, respk.length, pk, 1, pk.length));
                        assertTrue(name + " " + count + " secret key", Arrays.areEqual(ressk, 0, ressk.length, sk, 1, sk.length));

                        // sign
                        FalconSigner signer = new FalconSigner();
                        ParametersWithRandom skwrand = new ParametersWithRandom(kp.getPrivate(), random);
                        signer.init(true, skwrand);
                        byte[] sig = signer.generateSignature(msg);
                        // reconstruct test vector signature
                        byte[] ressm = new byte[2 + msg.length + sig.length];
                        ressm[0] = (byte)((sig.length - 40) >>> 8);
                        ressm[1] = (byte)(sig.length - 40);
                        System.arraycopy(sig, 1, ressm, 2, 40);
                        System.arraycopy(msg, 0, ressm, 2 + 40, msg.length);
                        ressm[2 + 40 + msg.length] = (byte)(0x20 + kparam.getParameters().getLogN());
                        System.arraycopy(sig, 40 + 1, ressm, 3 + 40 + msg.length, sig.length - 40 - 1);

                        // verify
                        FalconSigner verifier = new FalconSigner();
                        FalconPublicKeyParameters pkparam = (FalconPublicKeyParameters)kp.getPublic();
                        verifier.init(false, pkparam);
                        boolean vrfyrespass = verifier.verifySignature(msg, sig);
                        sig[11]++; // changing the signature by 1 byte should cause it to fail
                        boolean vrfyresfail = verifier.verifySignature(msg, sig);

                        //sign
                        assertTrue(name + " " + count + " signature", Arrays.areEqual(ressm, sm));
                        //verify
                        assertTrue(name + " " + count + " verify failed when should pass", vrfyrespass);
                        assertFalse(name + " " + count + " verify passed when should fail", vrfyresfail);

                    }
                    buf.clear();

                    continue;
                }

                int a = line.indexOf("=");
                if (a > -1)
                {
                    buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
                }


            }
            // System.out.println("testing successful!");
        }
    }

    public void testRandom()
        throws Exception
    {
        SecureRandom random = new SecureRandom();
        byte[] msg = Strings.toByteArray("Hello World!");

        FalconKeyPairGenerator keyGen = new FalconKeyPairGenerator();
        keyGen.init(new FalconKeyGenerationParameters(random, FalconParameters.falcon_512));

        for (int i = 0; i < 10; ++i)
        {
            AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();

            FalconPrivateKeyParameters privParams = (FalconPrivateKeyParameters)keyPair.getPrivate();
            FalconPublicKeyParameters pubParams = (FalconPublicKeyParameters)keyPair.getPublic();

            privParams = (FalconPrivateKeyParameters)PrivateKeyFactory.createKey(
                PrivateKeyInfoFactory.createPrivateKeyInfo(privParams));
            pubParams = (FalconPublicKeyParameters)PublicKeyFactory.createKey(
                SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pubParams));
            
            for (int j = 0; j < 10; ++j)
            {
                // sign
                FalconSigner signer = new FalconSigner();
                signer.init(true, new ParametersWithRandom(privParams, random));
                byte[] signature = signer.generateSignature(msg);
    
                // verify
                FalconSigner verifier = new FalconSigner();
                verifier.init(false, pubParams);
                boolean verified = verifier.verifySignature(msg, signature);

                assertTrue("count = " + i, verified);
            }
        }
    }

    /**
     * github #2297: FalconPrivateKeyParameters.getPublicKeyParameters()
     * should return a FalconPublicKeyParameters whose encoded form matches
     * the keypair's original public key, and a signature produced under
     * the private key must verify under the recovered public key.
     */
    public void testPublicKeyRecoveryFromPrivateKey()
        throws Exception
    {
        SecureRandom random = new SecureRandom();
        byte[] msg = Strings.toByteArray("recover me");

        FalconParameters[] parameters = new FalconParameters[]{
            FalconParameters.falcon_512,
            FalconParameters.falcon_1024
        };

        for (int p = 0; p < parameters.length; p++)
        {
            FalconKeyPairGenerator keyGen = new FalconKeyPairGenerator();
            keyGen.init(new FalconKeyGenerationParameters(random, parameters[p]));
            AsymmetricCipherKeyPair kp = keyGen.generateKeyPair();

            FalconPrivateKeyParameters priv = (FalconPrivateKeyParameters)kp.getPrivate();
            FalconPublicKeyParameters pubFromKpg = (FalconPublicKeyParameters)kp.getPublic();

            FalconPublicKeyParameters recovered = priv.getPublicKeyParameters();

            assertEquals("parameter set mismatch on recovered public key",
                priv.getParameters(), recovered.getParameters());
            assertTrue("recovered public-key bytes don't match keypair output for "
                + parameters[p].getName(),
                org.bouncycastle.util.Arrays.areEqual(pubFromKpg.getH(), recovered.getH()));

            FalconSigner signer = new FalconSigner();
            signer.init(true, new ParametersWithRandom(priv, random));
            byte[] signature = signer.generateSignature(msg);

            FalconSigner verifier = new FalconSigner();
            verifier.init(false, recovered);
            assertTrue("signature did not verify under recovered public key for "
                + parameters[p].getName(),
                verifier.verifySignature(msg, signature));
        }
    }

    /**
     * github #2297: when only the private encoding (f &#8214; g &#8214; F) was
     * persisted — no public key bytes, no key-generation seed — the public key
     * h must be recomputed from the private polynomials (h = g * f^-1 mod q)
     * by the {@code getPublicKeyParameters()} fall-back. The recovered h must
     * match the keypair's original public key and verify a signature made under
     * the reconstructed private key.
     */
    public void testPublicKeyDerivationWithoutStoredPublicKey()
        throws Exception
    {
        SecureRandom random = new SecureRandom();
        byte[] msg = Strings.toByteArray("no public key retained");

        FalconParameters[] parameters = new FalconParameters[]{
            FalconParameters.falcon_512,
            FalconParameters.falcon_1024
        };

        for (int p = 0; p < parameters.length; p++)
        {
            FalconKeyPairGenerator keyGen = new FalconKeyPairGenerator();
            keyGen.init(new FalconKeyGenerationParameters(random, parameters[p]));
            AsymmetricCipherKeyPair kp = keyGen.generateKeyPair();

            FalconPrivateKeyParameters orig = (FalconPrivateKeyParameters)kp.getPrivate();
            FalconPublicKeyParameters pubFromKpg = (FalconPublicKeyParameters)kp.getPublic();

            // Rebuild the private key from only its private encoding, as a
            // consumer that stored f || g || F and nothing else would.
            FalconPrivateKeyParameters stripped = new FalconPrivateKeyParameters(
                parameters[p], orig.getSpolyf(), orig.getG(), orig.getSpolyF(), new byte[0]);

            // getPublicKey() recomputes h from (f, g) when no public bytes are present
            assertTrue("getPublicKey() did not recompute h for " + parameters[p].getName(),
                org.bouncycastle.util.Arrays.areEqual(pubFromKpg.getH(), stripped.getPublicKey()));

            // getPublicKeyParameters() exposes the same recovered key
            FalconPublicKeyParameters recovered = stripped.getPublicKeyParameters();
            assertTrue("getPublicKeyParameters() did not recompute h for " + parameters[p].getName(),
                org.bouncycastle.util.Arrays.areEqual(pubFromKpg.getH(), recovered.getH()));

            // the reconstructed private key still signs, and the recomputed
            // public key verifies that signature
            FalconSigner signer = new FalconSigner();
            signer.init(true, new ParametersWithRandom(stripped, random));
            byte[] signature = signer.generateSignature(msg);

            FalconSigner verifier = new FalconSigner();
            verifier.init(false, recovered);
            assertTrue("signature did not verify under recomputed public key for "
                + parameters[p].getName(),
                verifier.verifySignature(msg, signature));
        }
    }
}
