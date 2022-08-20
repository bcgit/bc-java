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

        TestSampler sampler = new TestSampler();

        for (int fileindex = 0; fileindex < files.length; fileindex++)
        {
            String name = files[fileindex];
            System.out.println("testing: " + name);
            InputStream src = FalconTest.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/falcon/" + name);
            BufferedReader bin = new BufferedReader(new InputStreamReader(src));
            String line = null;
            HashMap<String, String> buf = new HashMap<String, String>();
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
                        String count = buf.get("count");
                        if (sampler.skipTest(count))
                        {
                            continue;
                        }
                        System.out.println("test case: " + count);

                        byte[] seed = Hex.decode(buf.get("seed")); // seed for Falcon secure random
                        byte[] pk = Hex.decode(buf.get("pk"));     // public key
                        byte[] sk = Hex.decode(buf.get("sk"));     // private key
                        byte[] sm = Hex.decode(buf.get("sm"));     // signed message
                        int sm_len = Integer.parseInt(buf.get("smlen"));
                        byte[] msg = Hex.decode(buf.get("msg")); // message
                        int m_len = Integer.parseInt(buf.get("mlen"));

                        NISTSecureRandom random = new NISTSecureRandom(seed, null);

                        // keygen
                        FalconKeyGenerationParameters kparam = new FalconKeyGenerationParameters(random, parameters[fileindex]);
                        FalconKeyPairGenerator kpg = new FalconKeyPairGenerator();
                        kpg.init(kparam);
                        AsymmetricCipherKeyPair ackp = kpg.generateKeyPair();
                        byte[] respk = ((FalconPublicKeyParameters)ackp.getPublic()).getEncoded();
                        byte[] ressk = ((FalconPrivateKeyParameters)ackp.getPrivate()).getEncoded();

                        // sign
                        FalconSigner signer = new FalconSigner();
                        FalconPrivateKeyParameters skparam = new FalconPrivateKeyParameters(parameters[fileindex], sk);
                        ParametersWithRandom skwrand = new ParametersWithRandom(skparam, random);
                        signer.init(true, skwrand);
                        byte[] sig = signer.generateSignature(msg);
                        byte[] ressm = new byte[2 + msg.length + sig.length - 1];
                        ressm[0] = (byte)((sig.length - 40 - 1) >>> 8);
                        ressm[1] = (byte)(sig.length - 40 - 1);
                        System.arraycopy(sig, 1, ressm, 2, 40);
                        System.arraycopy(msg, 0, ressm, 2 + 40, msg.length);
                        System.arraycopy(sig, 40 + 1, ressm, 2 + 40 + msg.length, sig.length - 40 - 1);

                        // verify
                        FalconSigner verifier = new FalconSigner();
                        FalconPublicKeyParameters pkparam = new FalconPublicKeyParameters(parameters[fileindex], pk);
                        verifier.init(false, pkparam);
                        byte[] noncesig = new byte[sm_len - m_len - 2 + 1];
                        noncesig[0] = (byte)(0x30 + parameters[fileindex].getLogN());
                        System.arraycopy(sm, 2, noncesig, 1, 40);
                        System.arraycopy(sm, 2 + 40 + m_len, noncesig, 40 + 1, sm_len - 2 - 40 - m_len);
                        boolean vrfyrespass = verifier.verifySignature(msg, noncesig);
                        noncesig[42]++; // changing the signature by 1 byte should cause it to fail
                        boolean vrfyresfail = verifier.verifySignature(msg, noncesig);

                        // print results
                        /*
                        System.out.println("--Keygen");
                        boolean kgenpass = true;
                        if (!Arrays.areEqual(respk, pk)) {
                            System.out.println("  == Keygen: pk do not match");
                            kgenpass = false;
                        }
                        if (!Arrays.areEqual(ressk, sk)) {
                            System.out.println("  == Keygen: sk do not match");
                            kgenpass = false;
                        }
                        if (kgenpass) {
                            System.out.println("  ++ Keygen pass");
                        } else {
                            System.out.println("  == Keygen failed");
                            return;
                        }

                        System.out.println("--Sign");
                        boolean spass = true;
                        if (!Arrays.areEqual(ressm, sm)) {
                            System.out.println("  == Sign: signature do not match");
                            spass = false;
                        }
                        if (spass) {
                            System.out.println("  ++ Sign pass");
                        } else {
                            System.out.println("  == Sign failed");
                            return;
                        }

                        System.out.println("--Verify");
                        if (vrfyrespass && !vrfyresfail) {
                            System.out.println("  ++ Verify pass");
                        } else {
                            System.out.println("  == Verify failed");
                            return;
                        }
                         */
                        // AssertTrue
                        //keygen
                        assertTrue(name + " " + count + " public key", Arrays.areEqual(respk, pk));
                        assertTrue(name + " " + count + " public key", Arrays.areEqual(ressk, sk));
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
            System.out.println("testing successful!");
        }
    }
    
    public void testFalconRandom()
    {
        byte[] msg = Strings.toByteArray("Hello World!");
        FalconKeyPairGenerator keyGen = new FalconKeyPairGenerator();

        SecureRandom random = new SecureRandom();

        keyGen.init(new FalconKeyGenerationParameters(random, FalconParameters.falcon_512));

        for (int i = 0; i != 100; i++)
        {
            AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();

            // sign
            FalconSigner signer = new FalconSigner();
            FalconPrivateKeyParameters skparam = (FalconPrivateKeyParameters)keyPair.getPrivate();
            ParametersWithRandom skwrand = new ParametersWithRandom(skparam, random);
            signer.init(true, skwrand);

            byte[] sigGenerated = signer.generateSignature(msg);

            // verify
            FalconSigner verifier = new FalconSigner();
            FalconPublicKeyParameters pkparam = (FalconPublicKeyParameters)keyPair.getPublic();
            verifier.init(false, pkparam);

            assertTrue("count = " + i, verifier.verifySignature(msg, sigGenerated));
        }
    }
}
