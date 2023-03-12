package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.gemss.GeMSSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.gemss.GeMSSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.gemss.GeMSSParameters;
import org.bouncycastle.pqc.crypto.gemss.GeMSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.gemss.GeMSSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.gemss.GeMSSSigner;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class GeMSSTest
    extends TestCase
{
    //TODO: MQSOFT_REF
    public void testVectors()
        throws Exception
    {

//        String testcipher = "fgemss256";//key generation fail

//        String testcipher = "dualmodems256";//key generation fail
        String files = "dualmodems256.rsp fgemss256.rsp dualmodems192.rsp fgemss192.rsp fgemss128.rsp dualmodems128.rsp " +
            "redgemss128.rsp bluegemss128.rsp gemss128.rsp cyangemss128.rsp whitegemss128.rsp magentagemss128.rsp " +
            "bluegemss192.rsp gemss192.rsp redgemss192.rsp whitegemss192.rsp cyangemss192.rsp magentagemss192.rsp " +
            "cyangemss256.rsp bluegemss256.rsp  whitegemss256.rsp redgemss256.rsp magentagemss256.rsp gemss256.rsp";

        TestSampler sampler = new TestSampler();

        String[] fileList = splitOn(files, ' ');
        for (int i = 0; i < fileList.length; i++)
        {
            String name = fileList[i];
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/gemss", name);
            BufferedReader bin = new BufferedReader(new InputStreamReader(src));
            String testcase = name.replace(".rsp", "");
            System.out.println("Testing on " + testcase);
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
                        byte[] sk = Hex.decode((String)buf.get("sk"));
                        byte[] pk = Hex.decode((String)buf.get("pk"));
                        byte[] msg = Hex.decode((String)buf.get("msg"));
                        byte[] sigExpected = Hex.decode((String)buf.get("sm"));
                        byte[] seed = Hex.decode((String)buf.get("seed"));

                        if (sampler.skipTest(count))
                        {
                            continue;
                        }

                        GeMSSKeyPairGenerator kpGen = new GeMSSKeyPairGenerator();
                        SecureRandom random = new NISTSecureRandom(seed, null);

                        GeMSSParameters parameters = (GeMSSParameters)GeMSSParameters.class.getField(testcase).get(null);//
//                        StringBuffer b = new StringBuffer();
//                        b.append("_");
                        //parameters = (GeMSSParameters)GeMSSParameters.class.getField(b.toString()).get(null);
                        //
                        // Generate keys and test.
                        //
                        kpGen.init(new GeMSSKeyGenerationParameters(random, parameters));
                        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
                        //System.out.println("Key generation complete for case " + buf.get("count"));
                        //GeMSSPublicKeyParameters pubParams =new GeMSSPublicKeyParameters(parameters, pk);
                        GeMSSPublicKeyParameters pubParams = (GeMSSPublicKeyParameters)kp.getPublic();
                        GeMSSPrivateKeyParameters privParams = (GeMSSPrivateKeyParameters)kp.getPrivate();

                        byte[] PK = pubParams.getPK();
                        byte[] SK = privParams.getEncoded();
//                        for (i = 0; i < sk.length; ++i)
//                        {
//                            if (sk[i] != SK[i])
//                            {
//                                System.out.println(i + " " + sk[i] + " " + SK[i]);
//                            }
//                        }
//                        for (i = 0; i < pk.length; ++i)
//                        {
//                            if (pk[i] != PK[i])
//                            {
//                                System.out.println(i + " " + pk[i] + " " + PK[i]);
//                            }
//                        }
                        assertTrue(name + " " + count + ": public key", Arrays.areEqual(pk, pubParams.getEncoded()));
                        assertTrue(name + " " + count + ": secret key", Arrays.areEqual(sk, privParams.getEncoded()));
//                        assertTrue(name + " " + count + ": public key", Arrays.areEqual(Arrays.concatenate(pubParams.getParameters().getEncoded(), pk), pubParams.getEncoded()));
//                        assertTrue(name + " " + count + ": secret key", Arrays.areEqual(Arrays.concatenate(privParams.getParameters().getEncoded(), sk), privParams.getEncoded()));
                        //
                        // Signature test
                        //
                        GeMSSSigner signer = new GeMSSSigner();
                        ParametersWithRandom skwrand = new ParametersWithRandom(kp.getPrivate(), random);
                        signer.init(true, skwrand);
                        byte[] sigGenerated = signer.generateSignature(msg);
                        //System.out.println("Sig generation complete for case " + buf.get("count"));
                        signer.init(false, pubParams);
//                        for (i = 0; i < sigGenerated.length; ++i)
//                        {
//                            if (sigExpected[i] != sigGenerated[i])
//                            {
//                                System.out.println(i + " " + sigExpected[i] + " " + sigGenerated[i]);
//                            }
//                        }
                        assertTrue(name + " " + count + ": signature verify", signer.verifySignature(msg, Arrays.copyOfRange(sigExpected, 0, sigGenerated.length)));
                        //assertTrue(name + " " + count + ": signature verify", signer.verifySignature(msg, sigExpected));
                        assertTrue(name + " " + count + ": signature gen match", Arrays.areEqual(sigExpected, sigGenerated));
                        System.out.println(testcase + " case " + buf.get("count") + " pass");
//                            System.err.println(Hex.toHexString(sigExpected));
//                            System.err.println(Hex.toHexString(attachedSig));
                        //assertTrue(name + " " + count + ": signature gen match", Arrays.areEqual(sigExpected, attachedSig));

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
            src.close();
        }
        //System.err.println(System.currentTimeMillis() - startTime);
    }

    private static String[] splitOn(String input, char c)
    {
        String s = input.trim();
        List l = new ArrayList();

        int idx = s.indexOf(c);
        while (idx > 0)
        {
            l.add(s.substring(0, idx));
            s = s.substring(idx + 1).trim();
            idx = s.indexOf(c);
        }

        if (s.length() > 0)
        {
            l.add(s);
        }

        return (String[])l.toArray(new String[0]);
    }
}
