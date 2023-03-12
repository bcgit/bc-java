package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.rainbow.RainbowKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowKeyPairGenerator;
import org.bouncycastle.pqc.crypto.rainbow.RainbowParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowPublicKeyParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowSigner;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class RainbowVectorTest
    extends TestCase
{
    public void testVectors()
        throws Exception
    {
        String[] files = new String[]{
                "rainbowIIIclassic.rsp",
                "rainbowIIIcircumzenithal.rsp",
                "rainbowIIIcompressed.rsp",
                "rainbowVclassic.rsp",
                "rainbowVcircumzenithal.rsp",
                "rainbowVcompressed.rsp"
        };
        RainbowParameters[] params = new RainbowParameters[]{
                RainbowParameters.rainbowIIIclassic,
                RainbowParameters.rainbowIIIcircumzenithal,
                RainbowParameters.rainbowIIIcompressed,
                RainbowParameters.rainbowVclassic,
                RainbowParameters.rainbowVcircumzenithal,
                RainbowParameters.rainbowVcompressed
        };

        TestSampler sampler = new TestSampler();

        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/rainbow", name);
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
                        byte[] seed = Hex.decode((String)buf.get("seed"));      // seed for Rainbow secure random
                        int mlen = Integer.parseInt((String)buf.get("mlen"));   // message length
                        byte[] msg = Hex.decode((String)buf.get("msg"));        // message
                        byte[] pk = Hex.decode((String)buf.get("pk"));          // public key
                        byte[] sk = Hex.decode((String)buf.get("sk"));          // private key
                        int smlen = Integer.parseInt((String)buf.get("smlen")); // signature length
                        byte[] sigExpected = Hex.decode((String)buf.get("sm")); // signature

                        NISTSecureRandom random = new NISTSecureRandom(seed, null);

                        RainbowParameters parameters = params[fileIndex];

                        RainbowKeyPairGenerator kpGen = new RainbowKeyPairGenerator();
                        RainbowKeyGenerationParameters genParams = new RainbowKeyGenerationParameters(random, parameters);
                        //
                        // Generate keys and test.
                        //
                        kpGen.init(genParams);
                        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

                        RainbowPublicKeyParameters pubParams = (RainbowPublicKeyParameters)kp.getPublic();
                        RainbowPrivateKeyParameters privParams = (RainbowPrivateKeyParameters)kp.getPrivate();
                        assertTrue(name + " " + count + ": public key", Arrays.areEqual(pk, pubParams.getEncoded()));
                        assertTrue(name + " " + count + ": secret key", Arrays.areEqual(sk, privParams.getPrivateKey()));

                        //
                        // Signature test
                        //
                        ParametersWithRandom param = new ParametersWithRandom(kp.getPrivate(), random);
                        MessageSigner signer = new RainbowSigner();

                        signer.init(true, param);

                        byte[] sigGenerated = signer.generateSignature(msg);
                        byte[] attachedSig = Arrays.concatenate(msg, sigGenerated);

                        //System.out.println("expected:\t" + Hex.toHexString(sigExpected).toUpperCase().substring(msg.length*2, sigExpected.length*2));
                        //System.out.println("generated:\t" + Hex.toHexString(sigGenerated).toUpperCase());
                        //System.out.println("attached:\t" + Hex.toHexString(attachedSig).toUpperCase());

                        signer.init(false, kp.getPublic());

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

}
