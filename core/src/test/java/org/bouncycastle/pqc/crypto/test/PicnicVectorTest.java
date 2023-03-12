package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.HashMap;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.picnic.PicnicKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicKeyPairGenerator;
import org.bouncycastle.pqc.crypto.picnic.PicnicParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicPublicKeyParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicSigner;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class PicnicVectorTest
    extends TestCase

{

    public void testParameters()
            throws Exception
    {
        //todo
    }


    public void testVectors()
        throws Exception
    {
        boolean full = System.getProperty("test.full", "false").equals("true");
        String[] files;
        PicnicParameters[] params;
        if (full)
        {
            files = new String[]{
                    "picnicl1fs.rsp",
                    "picnicl1ur.rsp",
                    "picnicl3fs.rsp",
                    "picnicl3ur.rsp",
                    "picnicl5fs.rsp",
                    "picnicl5ur.rsp",
                    "picnic3l1.rsp",
                    "picnic3l3.rsp",
                    "picnic3l5.rsp",
                    "picnicl1full.rsp",
                    "picnicl3full.rsp",
                    "picnicl5full.rsp",

            };
            params = new PicnicParameters[]{
                    PicnicParameters.picnicl1fs,
                    PicnicParameters.picnicl1ur,
                    PicnicParameters.picnicl3fs,
                    PicnicParameters.picnicl3ur,
                    PicnicParameters.picnicl5fs,
                    PicnicParameters.picnicl5ur,
                    PicnicParameters.picnic3l1,
                    PicnicParameters.picnic3l3,
                    PicnicParameters.picnic3l5,
                    PicnicParameters.picnicl1full,
                    PicnicParameters.picnicl3full,
                    PicnicParameters.picnicl5full
            };
        }
        else
        {
            files = new String[]{
                    "picnicl1fs.rsp",
                    "picnic3l1.rsp",
                    "picnicl3ur.rsp",
                    "picnicl1full.rsp",
            };
            params = new PicnicParameters[]{
                    PicnicParameters.picnicl1fs,
                    PicnicParameters.picnic3l1,
                    PicnicParameters.picnicl3ur,
                    PicnicParameters.picnicl1full,
            };
        }

        TestSampler sampler = new TestSampler();

        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/picnic", name);
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
                        String count = (String)buf.get("count");
                        if (sampler.skipTest(count))
                        {
                            continue;
                        }
                        System.out.println("test case: " + count);
                        byte[] seed = Hex.decode((String)buf.get("seed"));      // seed for picnic secure random
                        int mlen = Integer.parseInt((String)buf.get("mlen"));   // message length
                        byte[] msg = Hex.decode((String)buf.get("msg"));        // message
                        byte[] pk = Hex.decode((String)buf.get("pk"));          // public key
                        byte[] sk = Hex.decode((String)buf.get("sk"));          // private key
                        int smlen = Integer.parseInt((String)buf.get("smlen")); // signature length
                        byte[] sigExpected = Hex.decode((String)buf.get("sm"));          // signature

//                        System.out.println("message: " + Hex.toHexString(msg));
                        NISTSecureRandom random = new NISTSecureRandom(seed, null);
                        PicnicParameters parameters = params[fileIndex];


                        PicnicKeyPairGenerator kpGen = new PicnicKeyPairGenerator();
                        PicnicKeyGenerationParameters genParams = new PicnicKeyGenerationParameters(random, parameters);
                        //
                        // Generate keys and test.
                        //
                        kpGen.init(genParams);
                        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();


                        PicnicPublicKeyParameters pubParams = (PicnicPublicKeyParameters) PublicKeyFactory.createKey(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(kp.getPublic()));
                        PicnicPrivateKeyParameters privParams = (PicnicPrivateKeyParameters) PrivateKeyFactory.createKey(PrivateKeyInfoFactory.createPrivateKeyInfo(kp.getPrivate()));

//                        System.out.println("pk = " + Hex.toHexString(pubParams.getEncoded()).toUpperCase());
//                        System.out.println("sk = " + Hex.toHexString(privParams.getEncoded()).toUpperCase());

                        assertTrue(name + " " + count + ": public key", Arrays.areEqual(pk, pubParams.getEncoded()));
                        assertTrue(name + " " + count + ": secret key", Arrays.areEqual(sk, privParams.getEncoded()));


                        //
                        // Signature test
                        //
                        PicnicSigner signer = new PicnicSigner();

                        signer.init(true, privParams);

                        byte[] sigGenerated = signer.generateSignature(msg);
                        byte[] attachedSig = Arrays.concatenate(Pack.intToLittleEndian(sigGenerated.length), msg, sigGenerated);

//                        System.out.println("expected:\t" + Hex.toHexString(sigExpected));
//                        System.out.println("generated:\t" + Hex.toHexString(sigGenerated));
//                        System.out.println("attached:\t" + Hex.toHexString(attachedSig));

                        assertEquals(name + " " + count + ": signature length", smlen, attachedSig.length);

                        signer.init(false, pubParams);

                        assertTrue(name + " " + count + ": signature verify", signer.verifySignature(msg, sigGenerated));
                        assertTrue(name + " " + count + ": signature gen match", Arrays.areEqual(sigExpected, attachedSig));

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

    public void testPicnicRandom()
    {
        byte[] msg = Strings.toByteArray("Hello World!");
        PicnicKeyPairGenerator keyGen = new PicnicKeyPairGenerator();

        SecureRandom random = new SecureRandom();

        keyGen.init(new PicnicKeyGenerationParameters(random, PicnicParameters.picnic3l1));

        for (int i = 0; i != 100; i++)
        {
            AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();

            // sign
            PicnicSigner signer = new PicnicSigner();
            PicnicPrivateKeyParameters skparam = (PicnicPrivateKeyParameters)keyPair.getPrivate();
            signer.init(true, skparam);

            byte[] sigGenerated = signer.generateSignature(msg);

            // verify
            PicnicSigner verifier = new PicnicSigner();
            PicnicPublicKeyParameters pkparam = (PicnicPublicKeyParameters)keyPair.getPublic();
            verifier.init(false, pkparam);

            assertTrue("count = " + i, verifier.verifySignature(msg, sigGenerated));
        }
    }
}
