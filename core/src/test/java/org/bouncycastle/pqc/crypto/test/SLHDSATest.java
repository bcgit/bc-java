package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSASigner;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class SLHDSATest
    extends TestCase
{
    private static final Map<String, SLHDSAParameters> parametersMap = new HashMap<String, SLHDSAParameters>()
    {
        {
            put("SLH-DSA-SHA2-128s", SLHDSAParameters.sha2_128s);
            put("SLH-DSA-SHA2-128f", SLHDSAParameters.sha2_128f);
            put("SLH-DSA-SHA2-192s", SLHDSAParameters.sha2_192s);
            put("SLH-DSA-SHA2-192f", SLHDSAParameters.sha2_192f);
            put("SLH-DSA-SHA2-256s", SLHDSAParameters.sha2_256s);
            put("SLH-DSA-SHA2-256f", SLHDSAParameters.sha2_256f);

            put("SLH-DSA-SHAKE-128s", SLHDSAParameters.shake_128s);
            put("SLH-DSA-SHAKE-128f", SLHDSAParameters.shake_128f);
            put("SLH-DSA-SHAKE-192s", SLHDSAParameters.shake_192s);
            put("SLH-DSA-SHAKE-192f", SLHDSAParameters.shake_192f);
            put("SLH-DSA-SHAKE-256s", SLHDSAParameters.shake_256s);
            put("SLH-DSA-SHAKE-256f", SLHDSAParameters.shake_256f);
        }
    };

    SLHDSAParameters[] PARAMETER_SETS = new SLHDSAParameters[]
    {
        SLHDSAParameters.sha2_128f,
        SLHDSAParameters.sha2_128s,
        SLHDSAParameters.sha2_192f,
        SLHDSAParameters.sha2_192s,
        SLHDSAParameters.sha2_256f,
        SLHDSAParameters.sha2_256s,
        SLHDSAParameters.shake_128f,
        SLHDSAParameters.shake_128s,
        SLHDSAParameters.shake_192f,
        SLHDSAParameters.shake_192s,
        SLHDSAParameters.shake_256f,
        SLHDSAParameters.shake_256s,
    };

    public void testConsistency()
    {
        SecureRandom random = new SecureRandom();

        SLHDSAKeyPairGenerator kpg = new SLHDSAKeyPairGenerator();

        for (int idx = 0; idx != PARAMETER_SETS.length; idx++)
        {
            SLHDSAParameters parameters = PARAMETER_SETS[idx];
            kpg.init(new SLHDSAKeyGenerationParameters(random, parameters));

            {
                AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

                SLHDSASigner signer = new SLHDSASigner();

                {
                    int msgLen = random.nextInt(257);
                    byte[] msg = new byte[msgLen];
                    random.nextBytes(msg);
    
                    // sign
                    signer.init(true, new ParametersWithRandom(kp.getPrivate(), random));
                    byte[] signature = signer.generateSignature(msg);
    
                    // verify
                    signer.init(false, kp.getPublic());
                    boolean shouldVerify = signer.verifySignature(msg, signature);
    
                    assertTrue(shouldVerify);
                }
            }
        }
    }

    public void testKeyGenSingleFile() throws IOException
    {
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/slhdsa/", "SLH-DSA-keyGen.txt");
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
                    byte[] skSeed = Hex.decode((String)buf.get("skSeed"));
                    byte[] skPrf = Hex.decode((String)buf.get("skPrf"));
                    byte[] pkSeed = Hex.decode((String)buf.get("pkSeed"));
                    byte[] pk = Hex.decode((String)buf.get("pk"));
                    byte[] sk = Hex.decode((String)buf.get("sk"));

                    SLHDSAParameters parameters = (SLHDSAParameters)parametersMap.get((String)buf.get("parameterSet"));

                    SLHDSAKeyPairGenerator kpGen = new SLHDSAKeyPairGenerator();
                    SLHDSAKeyGenerationParameters genParam = new SLHDSAKeyGenerationParameters(new SecureRandom(), parameters);

                    //
                    // Generate keys and test.
                    //
                    kpGen.init(genParam);
                    AsymmetricCipherKeyPair kp = kpGen.internalGenerateKeyPair(skSeed, skPrf, pkSeed);

                    SLHDSAPublicKeyParameters pubParams = (SLHDSAPublicKeyParameters) PublicKeyFactory.createKey(
                        SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((SLHDSAPublicKeyParameters) kp.getPublic()));
                    SLHDSAPrivateKeyParameters privParams = (SLHDSAPrivateKeyParameters) PrivateKeyFactory.createKey(
                        PrivateKeyInfoFactory.createPrivateKeyInfo((SLHDSAPrivateKeyParameters) kp.getPrivate()));

                    assertTrue("public key", Arrays.areEqual(pk, pubParams.getEncoded()));
                    assertTrue("secret key", Arrays.areEqual(sk, privParams.getEncoded()));

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
    }

    public void testSigGenSingleFile() throws IOException
    {
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/slhdsa", "SLH-DSA-sigGen.txt");
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
                    boolean deterministic = !buf.containsKey("additionalRandomness");
                    byte[] sk = Hex.decode((String)buf.get("sk"));
//                    int messageLength = Integer.parseInt((String)buf.get("messageLength"));
                    byte[] message = Hex.decode((String)buf.get("message"));
                    byte[] signature = Hex.decode((String)buf.get("signature"));
                    byte[] rnd = null;

                    SLHDSAParameters parameters = (SLHDSAParameters)parametersMap.get((String)buf.get("parameterSet"));

                    SLHDSAPrivateKeyParameters privParams = new SLHDSAPrivateKeyParameters(parameters, sk);

                    if (!deterministic)
                    {
                        rnd = Hex.decode((String)buf.get("additionalRandomness"));
                    }
                    else
                    {
                        rnd = privParams.getPublicSeed();
                    }

                    // sign
                    InternalSLHDSASigner signer = new InternalSLHDSASigner();

                    signer.init(true, privParams);
                    byte[] sigGenerated = signer.internalGenerateSignature(message, rnd);
                    assertTrue(Arrays.areEqual(sigGenerated, signature));
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
    }

    public void testSigVerSingleFile() throws IOException
    {
        String name ="SLH-DSA-sigVer.txt";
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/slhdsa", name);
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
                    boolean testPassed = TestUtils.parseBoolean((String)buf.get("testPassed"));
//                    boolean deterministic = !buf.containsKey("additionalRandomness");
                    String reason = (String)buf.get("reason");

                    byte[] pk = Hex.decode((String)buf.get("pk"));
                    byte[] message = Hex.decode((String)buf.get("message"));
                    byte[] signature = Hex.decode((String)buf.get("signature"));

//                    byte[] rnd = null;
//                    if (!deterministic)
//                    {
//                        rnd = Hex.decode((String)buf.get("additionalRandomness"));
//                    }

                    SLHDSAParameters parameters = (SLHDSAParameters)parametersMap.get((String)buf.get("parameterSet"));

                    SLHDSAPublicKeyParameters pubParams = new SLHDSAPublicKeyParameters(parameters, pk);

                    InternalSLHDSASigner verifier = new InternalSLHDSASigner();
                    verifier.init(false, pubParams);
                    boolean ver = verifier.internalVerifySignature(message, signature);
                    assertEquals("expected " + testPassed + " " + reason, ver, testPassed);
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
    }

    public void testKeyGen() throws IOException
    {
        String[] files = new String[]{
            "keyGen_SLH-DSA-SHA2-128s.txt",
            "keyGen_SLH-DSA-SHA2-192f.txt",
            "keyGen_SLH-DSA-SHAKE-192s.txt",
            "keyGen_SLH-DSA-SHAKE-256f.txt",
        };

        SLHDSAParameters[] params = new SLHDSAParameters[]{
            SLHDSAParameters.sha2_128s,
            SLHDSAParameters.sha2_192f,
            SLHDSAParameters.shake_192s,
            SLHDSAParameters.shake_256f,
        };

        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/slhdsa/acvp", name);
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
                        byte[] skSeed = Hex.decode((String)buf.get("skSeed"));
                        byte[] skPrf = Hex.decode((String)buf.get("skPrf"));
                        byte[] pkSeed = Hex.decode((String)buf.get("pkSeed"));
                        byte[] pk = Hex.decode((String)buf.get("pk"));
                        byte[] sk = Hex.decode((String)buf.get("sk"));

                        SLHDSAParameters parameters = params[fileIndex];

                        SLHDSAKeyPairGenerator kpGen = new SLHDSAKeyPairGenerator();
                        SLHDSAKeyGenerationParameters genParam = new SLHDSAKeyGenerationParameters(new SecureRandom(), parameters);
                        //
                        // Generate keys and test.
                        //
                        kpGen.init(genParam);
                        AsymmetricCipherKeyPair kp = kpGen.internalGenerateKeyPair(skSeed, skPrf, pkSeed);

                        SLHDSAPublicKeyParameters pubParams = (SLHDSAPublicKeyParameters) PublicKeyFactory.createKey(
                            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((SLHDSAPublicKeyParameters) kp.getPublic()));
                        SLHDSAPrivateKeyParameters privParams = (SLHDSAPrivateKeyParameters) PrivateKeyFactory.createKey(
                            PrivateKeyInfoFactory.createPrivateKeyInfo((SLHDSAPrivateKeyParameters) kp.getPrivate()));

                        assertTrue(name + ": public key", Arrays.areEqual(pk, pubParams.getEncoded()));
                        assertTrue(name + ": secret key", Arrays.areEqual(sk, privParams.getEncoded()));
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
        }
    }

    public void testSigGen() throws IOException
    {
        String[] files = new String[]{
            "sigGen_SLH-DSA-SHA2-192s.txt",
            "sigGen_SLH-DSA-SHA2-256f.txt",
            "sigGen_SLH-DSA-SHAKE-128f.txt",
            "sigGen_SLH-DSA-SHAKE-192s.txt",
            "sigGen_SLH-DSA-SHAKE-256f.txt",
        };

        SLHDSAParameters[] params = new SLHDSAParameters[]{
            SLHDSAParameters.sha2_192s,
            SLHDSAParameters.sha2_256f,
            SLHDSAParameters.shake_128f,
            SLHDSAParameters.shake_192s,
            SLHDSAParameters.shake_256f,
        };

        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/slhdsa/acvp", name);
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
                        boolean deterministic = !buf.containsKey("additionalRandomness");
                        byte[] sk = Hex.decode((String)buf.get("sk"));
//                        int messageLength = Integer.parseInt((String)buf.get("messageLength"));
                        byte[] message = Hex.decode((String)buf.get("message"));
                        byte[] signature = Hex.decode((String)buf.get("signature"));
                        byte[] rnd = null;

                        SLHDSAParameters parameters = params[fileIndex];

                        SLHDSAPrivateKeyParameters privParams = new SLHDSAPrivateKeyParameters(parameters, sk);

                        if (!deterministic)
                        {
                            rnd = Hex.decode((String)buf.get("additionalRandomness"));
                        }
                        else
                        {
                            rnd = privParams.getPublicSeed();
                        }

                        // sign
                        InternalSLHDSASigner signer = new InternalSLHDSASigner();

                        signer.init(true, privParams);
                        byte[] sigGenerated = signer.internalGenerateSignature(message, rnd);
                        assertTrue(Arrays.areEqual(sigGenerated, signature));
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
        }
    }

    public void testSigVer() throws IOException
    {
        String[] files = new String[]{
            "sigVer_SLH-DSA-SHA2-192s.txt",
            "sigVer_SLH-DSA-SHA2-256f.txt",
            "sigVer_SLH-DSA-SHAKE-128f.txt",
            "sigVer_SLH-DSA-SHAKE-192s.txt",
            "sigVer_SLH-DSA-SHAKE-256f.txt",
        };

        SLHDSAParameters[] params = new SLHDSAParameters[]{
            SLHDSAParameters.sha2_192s,
            SLHDSAParameters.sha2_256f,
            SLHDSAParameters.shake_128f,
            SLHDSAParameters.shake_192s,
            SLHDSAParameters.shake_256f,
        };

        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/slhdsa/acvp", name);
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
                        boolean testPassed = TestUtils.parseBoolean((String)buf.get("testPassed"));
//                        boolean deterministic = !buf.containsKey("additionalRandomness");
                        String reason = (String)buf.get("reason");

                        byte[] pk = Hex.decode((String)buf.get("pk"));
//                        byte[] sk = Hex.decode((String)buf.get("sk"));
                        byte[] message = Hex.decode((String)buf.get("message"));
                        byte[] signature = Hex.decode((String)buf.get("signature"));

//                        byte[] rnd = null;
//                        if (!deterministic)
//                        {
//                            rnd = Hex.decode((String)buf.get("additionalRandomness"));
//                        }

                        SLHDSAParameters parameters = params[fileIndex];

                        SLHDSAPublicKeyParameters pubParams = new SLHDSAPublicKeyParameters(parameters, pk);
//                        SLHDSAPrivateKeyParameters privParams = new SLHDSAPrivateKeyParameters(parameters, sk);

                        InternalSLHDSASigner verifier = new InternalSLHDSASigner();
                        verifier.init(false, pubParams);
                        boolean ver = verifier.internalVerifySignature(message, signature);
                        assertEquals("expected " + testPassed + " " + reason, ver, testPassed);
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
        }
    }

//    public void testVectors()
//        throws Exception
//    {
//        String files =
//            " sha2-128f-simple.rsp sha2-192f-simple.rsp sha2-256f-simple.rsp shake-128f-simple.rsp" +
//            " shake-192f-simple.rsp shake-256f-simple.rsp " +
//            " sha2-128s-simple.rsp sha2-192s-simple.rsp" +
//            " sha2-256s-simple.rsp shake-128s-simple.rsp shake-192s-simple.rsp shake-256s-simple.rsp";
//
//        TestSampler sampler = new TestSampler();
//
//        String[] fileList = splitOn(files, ' ');
//        for (int i = 0; i != fileList.length; i++)
//        {
//            String name = fileList[i];
//            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/slhdsa", "subset_" + name);
//            BufferedReader bin = new BufferedReader(new InputStreamReader(src));
//            String line = null;
//            HashMap<String, String> buf = new HashMap<String, String>();
//            while ((line = bin.readLine()) != null)
//            {
//                line = line.trim();
//
//                if (line.startsWith("#"))
//                {
//                    continue;
//                }
//                if (line.length() == 0)
//                {
//                    if (buf.size() > 0)
//                    {
//                        String count = (String)buf.get("count");
//                        byte[] sk = Hex.decode((String)buf.get("sk"));
//                        byte[] pk = Hex.decode((String)buf.get("pk"));
//                        byte[] msg = Hex.decode((String)buf.get("msg"));
//                        byte[] sigExpected = Hex.decode((String)buf.get("sm"));
//                        byte[] oprR = Hex.decode((String)buf.get("optrand"));
//
//                        if (sampler.skipTest(count))
//                        {
//                            continue;
//                        }
//
//                        SLHDSAKeyPairGenerator kpGen = new SLHDSAKeyPairGenerator();
//                        SecureRandom random = new FixedSecureRandom(sk);
//
//                        SLHDSAParameters parameters;
//
//                        String[] nameParts = splitOn(name, '-');
//                        boolean sha2 = nameParts[0].equals("sha2");
//                        boolean shake = nameParts[0].equals("shake");
//                        boolean haraka = nameParts[0].equals("haraka");
//                        int size = Integer.parseInt(nameParts[1].substring(0, 3));
//                        boolean fast = nameParts[1].endsWith("f");
//                        boolean slow = nameParts[1].endsWith("s");
//                        boolean simple = nameParts[2].equals("simple.rsp");
//                        boolean robust = nameParts[2].equals("robust.rsp");
//                        if (robust)
//                        {
//                            continue;
//                        }
//                        if (haraka)
//                        {
//                            continue;
//                        }
//
//                        StringBuffer b = new StringBuffer();
//                        if (sha2)
//                        {
//                            b.append("sha2");
//                        }
//                        else if (shake)
//                        {
//                            b.append("shake");
//                        }
//                        else
//                        {
//                            throw new IllegalArgumentException("unknown digest");
//                        }
//
//                        b.append("_");
//                        b.append(size);
//
//                        if (fast)
//                        {
//                            b.append("f");
//                        }
//                        else if (slow)
//                        {
//                            b.append("s");
//                        }
//                        else
//                        {
//                            throw new IllegalArgumentException("unknown speed");
//                        }
//
//                        if (robust)
//                        {
//                            if (b.indexOf("haraka") < 0)
//                            {
//                                b.append("_robust");
//                            }
//                        }
//                        else if (simple)
//                        {
//                            if (b.indexOf("haraka") >= 0)
//                            {
//                                b.append("_simple");
//                            }
//                        }
//                        else
//                        {
//                            throw new IllegalArgumentException("unknown complexity");
//                        }
//
//
//                        parameters = (SLHDSAParameters)SLHDSAParameters.class.getField(b.toString()).get(null);
//
//                        //
//                        // Generate keys and test.
//                        //
//                        kpGen.init(new SLHDSAKeyGenerationParameters(random, parameters));
//                        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
//
//                        SLHDSAPublicKeyParameters pubParams = (SLHDSAPublicKeyParameters)kp.getPublic();
//                        SLHDSAPrivateKeyParameters privParams = (SLHDSAPrivateKeyParameters)kp.getPrivate();
//
//                        // FIXME No OIDs for simple variants of SPHINCS+
//                        if (name.indexOf("-simple") < 0)
//                        {
//                            pubParams = (SLHDSAPublicKeyParameters)PublicKeyFactory.createKey(
//                                SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pubParams));
//                            privParams = (SLHDSAPrivateKeyParameters)PrivateKeyFactory.createKey(
//                                PrivateKeyInfoFactory.createPrivateKeyInfo(privParams));
//                        }
//
//                        assertTrue(name + " " + count + ": public key", Arrays.areEqual(pk, pubParams.getEncoded()));
//                        assertTrue(name + " " + count + ": secret key", Arrays.areEqual(sk, privParams.getEncoded()));
//
//                        //
//                        // Signature test
//                        //
//
//                        SLHDSASigner signer = new SLHDSASigner();
//
//                        signer.init(true, new ParametersWithRandom(privParams, new FixedSecureRandom(oprR)));
//
//                        byte[] sigGenerated = signer.generateSignature(msg);
//                        byte[] attachedSig = Arrays.concatenate(sigGenerated, msg);
//
//
//                        signer.init(false, pubParams);
//
//                        assertTrue(name + " " + count + ": signature verify", signer.verifySignature(msg, Arrays.copyOfRange(sigExpected, 0, sigGenerated.length)));
//
//                        assertTrue(name + " " + count + ": signature gen match", Arrays.areEqual(sigExpected, attachedSig));
//
//                    }
//                    buf.clear();
//
//                    continue;
//                }
//
//                int a = line.indexOf("=");
//                if (a > -1)
//                {
//                    buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
//                }
//            }
//            src.close();
//        }
//    }

    public void testBasicKeyGenerationSha2128sSimple()
    {
        byte[] skSeed = Hex.decode("2F896D61D9CD9038CA303394FADAA22A");
        byte[] skPrf = Hex.decode("24AC5EC1D86A989CA2196C3C8632419C");
        byte[] pkSeed = Hex.decode("1A05A42FE300E87B16AEE116CB2E2363");
        byte[] pk = Hex.decode("1A05A42FE300E87B16AEE116CB2E236358E2C3E62632C9DE03D08A535A0EB7E7");
        byte[] sk = Hex.decode("2F896D61D9CD9038CA303394FADAA22A24AC5EC1D86A989CA2196C3C8632419C1A05A42FE300E87B16AEE116CB2E236358E2C3E62632C9DE03D08A535A0EB7E7");

        SLHDSAParameters parameters = SLHDSAParameters.sha2_128s;

        SLHDSAKeyPairGenerator kpGen = new SLHDSAKeyPairGenerator();
        SLHDSAKeyGenerationParameters genParam = new SLHDSAKeyGenerationParameters(new SecureRandom(), parameters);
        //
        // Generate keys and test.
        //
        kpGen.init(genParam);
        AsymmetricCipherKeyPair kp = kpGen.internalGenerateKeyPair(skSeed, skPrf, pkSeed);

        SLHDSAPublicKeyParameters pubParams = (SLHDSAPublicKeyParameters) kp.getPublic();
        SLHDSAPrivateKeyParameters privParams = (SLHDSAPrivateKeyParameters) kp.getPrivate();

        assertTrue("public key", Arrays.areEqual(pk, pubParams.getEncoded()));
        assertTrue("secret key", Arrays.areEqual(sk, privParams.getEncoded()));
    }

    public void testBasicKeyGenerationShake256128fSimpleSign()
    {
        byte[] sk = Hex.decode("DADB023900B157BAEDFF38B4BDE4B308C83A26A11170274E7E35CD3935AEAF07119231DA3849A12477373395D264043DA6CECC80D20A2E15A3622ABFFC221FC8");
        byte[] message = Hex.decode("3048BDE7F28C0414CC318C90048F23AFECF079866C34858521192E1684F37F0BC5D2C8585E9BF753626F6E853779D41C15BDA83DEF79DBF8A11B82EAE066833AB6C409D8AC386C942D69FF482D26A1A4030F7C082E36CFCEAA7491CB2F25BD61B79BACD91DD72C91C5D673BE48866D33E6B20F9DC83BD5639D27B0D8CA326AA1");
        byte[] signature = Hex.decode("EA52B3F889F36866D485BE712C5A7EE6FB696EFA6F5BBCB9E4FF1820FE0C580BE5786FE8A773E1AFCD353B106EECD84D65C3BF4259089B54DCC0557911FDCA8323AF0839686975D2D6AD148572D173E8D8EE8DE5E8A709D11B29E84C8ADD4E373985310F4C09F346086765B90888B94704014171AE30F65CCEE69DBC2603C0FF3D662DD0E18E0B0C69A457C5B46B3062B1A5F690EA5AA84D33C92C571D5C4156C2A96F07E66816F8453697381C93571BF7072F697152F191482CD1C73C41F2C190B59C06EFF4F4E806E832FE18F3D298F8CFBFC5E7529D3E35187289DAC000EAC6C563E456A6CFF491D90778E577476B34ECEB3193BDCEAF720E368E4D56A88634AD6FA3FA25CC09194D53AA00F9044B087727F99B4FFE61C6171CBCB424AF6DF373C58F73FF229D8DC557CBED5C6E8EF908A9DC07D2D62FFBF791B689D5356ECF67F3658A8EF845A4E8F6275B7FE44555742C2BAD4ED740D10186DE0E6CE9FC75144599F070C8F8704ECB99CA9DA9ECAC449E0170A8FD1B48DA791DE2D376CCD3C13B99FDBDE0495AAD3B4D3D6F955D51917A649262810E80467D177B29CA85FC96B93CEBC78A4E318DAA1EF00CE6D5B73BF41196CC7AA8B4D247CD1B0CA2C494DCC8591EFBFD18F5FACFC765CDA4EF6990AA7FD26696A440F992774DD952E144D3E349CDA3312E2D4A60AAE010743023AFFB20C0CAF9F4DF9697D20341B46EEB60F3C5993794E8D443C3457DA31E6F37DB4C7CCBEE86C491250AF781F81F3247CF94EE61B6EC9C493B6501AFAF2A1A41F776D4C74F2ED7F17DA149B540322D38EDF6214BF9D1575957A2ED1D0C54A20F661BA39CE2658223422A8AA5A8B6078A226C9E68C5A43674918A067A1103CAD71A9899B53B398358FD076DCA90251CC28977827FBFBBE71D9CCF0D333D95BA1F270CED5676648F5E19800622E1A0E893F9FCFE9065F216C7ED9A17F6320F866F3A95979DE3285E294987BC65D3A099E978E29C9F72ECC14020A228E587D3569D8454F3BCC8E5DBE8EA6062D4A24B1A9DCC20BB34BE1EF6C25F77E9EED6334CF6F4763CBAF5819C145D8326E558447768B7895A7F4C4CA5647A112AF1292F6F46DF796573AD3B76C2062921C252B7979119BE9309E104BAD3F643DC1433DCA48E3FF43C49B95ACC4E9941448892BB2BFC61A22F7EE5D29C9789F69612B1B3503CB324587D4CF882F40F20A46598C636D75327DD35E7132C88B91EBDD44F511E360EF6D086613F383CA4F70914E09CDFA544413A95159B3AE724FB2017F2F3ABE8AD4E64926AE797533931AF66C91DAAA46AA9AA9B331EE116EBFC57E7AF4D4466AEC4785FB72D1692E149C8EBB35140F1BD61A78495D85E5DF64EA74134E941310C59E51506408F74F1435B67701A7A76F472309A6F0B0097C8BAE4F86368CC7A93B66B8CDDF893EF10201A246D1C6E4F386FE727E27495A9735B667FFC5752818030E51250D1646AD69EC8D46628BDCF450F1165CC60211A439C8CACB48F9309FC1C992385343D821FE68BED569A972676128D338956578DF73A9186238F3FB8B1DFCC2357C3444EE25756DFC2B39135117B63D6CA4113FAD133913DB7924A7BDBD417F42D3B61BE442C451BE0B6B7BC58AB8A2A2738D1679E3B6E0F25DE923B242EADC95525D71672D527BE64BFE88956DDBAE1EE124056332AB20F8806C2F3A3F1292B099C7502CE94AEE45BFC85410CF68EF739A34565E6D337F4240C265A006CE8FE77FA10FB795155B31CBDBB22647E3F71D1EE798C3D7713652EDE11C9425E5EC06BA430A58FE95C14F08A87D0DC5E654F69A306FDA04FEE8B8162190517CAA7DDD644B6F5BD55F3670678E0CC8232F436A965EBD4FE7487E58CBD61E38DB2A31A95A9605DD40371D3D4F4C3F056E86145061B91A98F20C57EA2D38C9B332538B3E0F9C2BB204FCE003A79F09B71BF9B51D18D566C47B6A4150B974138C440DFB2F994E138A0F41F3BD3D4F2CB61A27CA36531E858968A851513946C00287C1369024AC4E3C46888EB97F7208FFB0CF0B7EE6D808AA09D7BC21300F300CCC2D75592F331A97DD69DBF3B58AFD9ACAD269C3829D8E77A4ABB0020FDD37A2CAA2BAF71584B1AD79BF8DEAE8D2ED1BFB38D04C437A83BDA779C2ECB3D2FB2DEEBBE1D6FFA1F7C524642997F482A3AE472EA925D11E7A06DEEBD272F3D16658B810124DC45DFAD77C3350901E571FE138869883716A4D1EC4A44CCA76EA6A5C1A72972751992C39A5A3EEC5C0E148FC0130C104F7B5DAC8340A88E6D371023237B64B203EB03DE0F91DA7EB0612D2C185C3F33D6678B25C39FD459DFA0B3B96D7BADFA2984B73E164AC507C898FAA55ECC3D086FA6FD28D9C93EEB053F5AF51A6A261EBF50ED3729FEEABA7178313FBD39EC1D010F4A831D088214D50262AC5975F1F34DBF791E9C72C48B6C7E9FB841579211007C336DAA46DE84954CD99E1B97CBE5CE34889ACC6861EBF2A63FB7745DAC42E0EAB5A7C7AB95B1C9D1BAB6D7AE20037988D65F973884E0816151392691405D5E52197438C39AFDA66532C7279F5B9B58B85112BF2C03A76FB54FE5EACFC5F12C3C47820E99647CDCDBBACEBC200B28B4D707EA257F37F1CE5047D2AB0E02948E1BDF126866D76EC48DD6271A2ECFB68040B31BFE6563AC34456BC66C10CEACDA74F3F92983AC1F8250B87D2D925592E3280C46A71CF16E4FEEEDBD53C240164943794F9D9471EAC03D15A5EE0DC1914A9D5C50E3D2AA165513C9BFA1560F04E06EBDE94C22E62932588A68C7A8B65223BC55B6FE75DA29874E4673AA3CA66217B1284AE0CD9C1C605556CB68156B833549146E98D76E0725A41F44B13F8249A19C169FC6F396F0152129A2C2ECC6609653644C4731E92B4AFA4516676D22A5BF0F263CB8430D40015046C41444380F80C2371E4F6EC825E19E5EB0FD2D2F07975687ED64C16684AC969D446F925689D468347DC3B96A6C5F715B8A69D60705E22ED45FF8598D3185DDAAF0F0E611A9337CA54B5C822F785E06A2BBB48ED9EBA9B39B7BB91482F27CF22781695754733278058E682D0BA140C0830902E7A12D6AE7C2FE603816DD1AF08CADB1D18C2FB3BBE22121F74898AEB1D55B04F300E8396519A41DA60259DDEB533E8EC3712B8FD07DA650E819E8EE0CB165863175E3FC70E81EF729F839769BC34727F5354395A479886B1B2D446DCB48EC2384EAEDFB9023B5C29FB8ADDB416EDF03DA9BF50CE8397DFF31EE52EAC25F482CD28C84A4B430654590BBB9401539302F23B914C62203BBB7AB7C709A08F8C707D2F9ADC49EAD6A0C6A1997F2818534248AF1FC0BFBBA33729675EDA0B0709CC1F6187EAE1F599E025966905F1D357FF7ABF118B1E7FF2186AA724869535AFA8AED869FD0F929C8AD3B73F01571C614E4CFEB80A9132F8ED8F65C67A6DF8685F1D2F457A9E40D0CDF005D7A6BF4560308A342E933B05549E40BA87E2A4559D4123C45E3238F40A91726B3018A59DE1CB116BF1B99E56FC42EA720A9276D42078F18C98BBBC2DB597B852542C8ABBB14CFCAC2E56D82BC403F321FEA9F60DF76B0FD5CC2F49AA3FF99DC46432EFD2DFE33DC6287BB140AEA5C3C582B9E4A7DA0A1FEF384A568AB86FF624086BD22CAE972580208B73AC88DE300A5792DFDB9516C113D42996DBA0A925B67774CE060D334239605F4E9F616619959568C7325AEBC8BB0CD5A60D312E130C33372760C2820192D87FC2AF2FB151FF63D2819FE51916916A13B883C478FBF6A33D1EAFEF08402F80E6E6D2F88001F96FF84E5CB81E4CB61AC804D733179175706FDD637925B6764001ADB6616A1F8D83262CDD40B505679699D85EC960E136D3D0DB3EA6FE22D38994D3ECCCC974982EC868066D98798551EB7E42825684AFB2AF7190E81BAD9F6CB426DBBBC0BE7231DCC9D3BFF065AF0BE5772FEB8A9FB1AC87AAC2EE9B0ADC2E86EF239E208D58B36DCA7A6F13B79363B5E5891A11927C5B7925F4157D28F27E59AF3F24373734EB10EC734F57624810B81E8A77C48546E8485E08274451AFB84A58F1B0F13B5DCA38DB9037F37870657E1379C26F47D4D45C80513069F0C08585F9778700F88D8EEADA57B4D3EF3DB100D889CCCD9433561F7A05FCCE05220509253C42E1710F08ECDE1AD49584B07F9A1FD17B11ED48E8900BF00FFCC1822A68336914F223DD80449DD980D74DD1BF5EA269A4725D549E249ED5604BE51F7369EE3366C65EF5F0311683CD5652583B5B9552472F1146BDD2DE068BA5D4C1702185CD34450F3B015C5952C8458C4D5345C9081CB1044B76EC63EBD725D38FAB0E111A11FC7CC130CBF3E9BC97FAE14F78BA4C97F60879660788DAE01A394372B2CFF17C93F3DA92B213C4BD00084602E7AFB11CAB263979B4CE9EAE5BB03C89EE41D546266BC371BE33E28AC3E43C52F66F823BB31DF5C97EAB4584B31D9CC2F662B78DD387811B90D3577CAB2DF90CA1AE12C20B8DFA7958C8FDA63AA6EBCF5E27492FD2219CA016ECEAE59095C9ED097BBFE985E3A6AAD24A0A8BC1D5D1E85FBB3F87944F6BC3010F39ED5062290FC826DBD5EF8592EFC084B7B45C17BE0A22792E48577D14335DD17F88BAD9D50F3B83D4373F37BDC88ED5D39FBF2B807AB33A05B229DECACA01269CDCA999AE5E5ECF4E6D18B5AE41201FEF3B83EB64358670C981F8B1D0F33930CF62F907C761103C6A5B0AB19524EF0EFC74837A1EDF14657E31929BC63DCC07EEE1581B47A790C86542EBB3D04A091C59E5636ED8CFDFBC3631819CE9915245815E2D3E127EBABECC5E4DA38F4CEA5CC9968A3D23A95970FEB49FC74C4B0C1B85BADBCA2827F55A556D6EFA23B5DE174567456984690CE9235012D13355F2CA9C43CD5E59A84400321E299D6507B90496C52D8DC48A2166B00E2726AD75090B74F288B2704C52E7A197DF10A3D4AC8292694C83DB9DA54415A98AF542C7C299572661EBF426DF387473B877CA2A71993F3F682AE25C13901B048395E66F09C69C43E3990668682EC4424497422D38E79B617F806F22B0E393007D9586D3CCA274F750E2D5ACBF5245972AC34A40787730FAF2BF004BE36AB098C5486EFD95A977A8675A9A904FE79CE8810A3D1A629BE0B51CD8ED3C72019081988FB22FC8B2311D0F91C37883378EFF1D8786846931D96EBC29CE0D2DE42EBCF20AB46CE9259C83BB86997B5E7275B8A9A5A81E65E4D6BC19D6E9C7806E2D15E5EC7BC6026295D52AC66D183099D8543CDD50FB5614BBFFD99ECAC7B5019C4D94F8EDB1BEB4343D1A22C898CF2132C897A669F255DB9884374451D4A29F0F92791D2229BC29230906120A98EF5484D55440243E1DBE547AA96BC0F578444FEB41620935E276B58A46B2A96049BCBE2AAAEC8C23578C8A0903BDFAB0EE272CBB59315E06201C3D633AB6F974E779D68AC4F35BE9C1F02624EEB780681BECD1BEC79F9480D1FEC5780DF79DB98FC392403AA4BDC47FD71DC3E76FDEBF58CD3B0472A96927F25922138C7C5DBC56CBD16744BA9FF8046BAD134AD90416263B52C3B61C3781981E35AE6E5000FC715093A34DF7C4A06987F87B4304E98222613BB5812DF652C0CFD8421B21567ADC5FDE09D3FE88AE109CFA32647680A6EEE3B5E2DA4054B61FA7ECBA7F94322514F71432BFDDD4ACB92E578BC2656AC7C0C8BCE6FD9C88144842545A6C56EF91DEE1EE62A70996CE2090F8D1665A9AE4DE52BB1E803FFFF708F551BAF664A6AB44DB8ACAF1740AF077A34EB02401286B67F31D89B17D40A1FD2CA38E197276039A64FBA2F5833108D587715ADD5285EC0914EE382042402B2C2E884873EE1DE429025683D512545047DA3AE7B36B4D1E96EE93DC1544B25A8AA7319697A653258642D22151AA37CE86D88CA85644A42457794DB0012A851194B94D58681261BF84819DD7CD3B71D85A0A407C8385A4A854610D882793C93C30526D67420B28B17E998473C3769E442D13B9B664DEC623AAD0DB5BDBB606F8E123B4B8AE037242EEAFEE8D94594761A85851AF740E3F4DAC75FD35D5FDA1B50D591BCF7C22FFB190497AF417F6A0E406EC22CCAFF1D1369F54B8193C93182A738ED6EF261779B785258F65BF093DB76190DD01C5D9A5F59BE7B1F93A34E86EB44B664F6063B7B08D53CA0B0D5CA926D449E1895D576F9955E215413456B5A02AFB7C14D56666298A2EA581576B8D275C3D02BB57D8C4FB3C71AEA31786E3948D0039DF67473A1135B94AEEAFA47FED3590AFBFE67854113D396A577C01128E91EB55028FD0C46724A6BE94F2472A37417A9DC44EBE7A5859E3FAB39AD38BD8BB5C462A0E57CEB14D3C8499B343B2ACF2AE1D003A32E99328D0689D787D4E067660A16E6A2C3022BECFC5885F85757230641AF0428006C1B2EC617DF866487022B356474959F2771C3053D9B6F56FFAEC6D970EEF014B427D5CB4F3F852BE64F8F54364DD82FFF47B13763ED931949731D6757EC1AC30C004A343EDBD6C5E48A7F311E40AC9FF9BB3DECB12F7AA5396EF949EF98275E624CB4ACEE6184D13D80A96D535B21FC59C9616E0E9E34E6858DD8DCCE39ACF505836462A255E2D58B0534BBD5B0A8BCD45226C178A70909C7A1EE44A003C733469103E6A114581250E8B823DE56FC9A08B4A54A28F572E3AAF59E6FDB3E6DBDB59553CC5B5E2E3094BDA6C8C97A58DCDE2B5AB6C1318AC6C796F31CE5CC1427F245572B730C26C993D8E3550F954869D82871DC8A3E903B7747ACC6D476EA7501D7973171DFFE8EFEA2345D7C9ED011F09BA6D2E8B992EE3D67439154699597627ACE5CB65B471F24D38673DC452E909D855C803C6923E0EC11E1F2A06C2A975C4B539FEF387AF7AF427B5A9501162EAAC8D2B55760FCD9FAAD2A4642BB42B85E7C58971B7F1DFE2B82D794DDE694C094B31717D90ACF61060B8B5F293B7CE68EC0CD2EB10FA43AEC8E604FDF3B0465A79F007D9DA481BF9590840EE0EE30D1A1687150E799459D1B8DE5A7FF92F43E0A298529797C4EBC7AB4320A87BAA208CC6E0A622AB9B67F9014F132B2D4A59E2729F218A8DBDF9147335336FB7A973A506133DEF843AD600533B325F5BF06095E49B00CFB078096E2D931F9541F18CF7F5B4AA716BF40F870AFFCC4EC2C64A073C6A7F8BE0A1969DA10173085384A484253AE426C46D42A14FDD8A0D555204A05A44845F6066715EFE2BA1C7B30CF95C60179986952DFB8094289C0977C7B737C7A1FA3945DC457EFF5961768E61D745F9CA4AB78FE5ADF254521B3149FE985D869E2AD7724D2AD9861175138E6853881A39A8EC1673849059F30A4DDAF671C537F296729ADA9CF7D86171C6C797FA6EB4D23F659BAB36D67F9FAA8505F26DE850FB97445C5670863BCFDE31F466E61ECF2FFE9E6314688F91D9F97D6641414A7908925EB4DF057E96133CB8E2C49E055E5137442A8F87AAF32E7F77034F438F1EC849A1549BF4E22155EACB038BBF3F6458EDDBEFEE5BF3D89975BF1A329B975F6E8CB9ED8020A19CFC57D527589219F4344E1619A1C85DD6E67DE3DF935E6FEE20FDC4579BD303E5D95EE5B509B58A3D6899B7397C2AF3E45D52FBFED35D8AD82B1FCC5EF76264453F64D8153994B05DA5B0AE4D428335F34AFA2C5AE108ACA9D50E78DB42D972A7C87EC8FE8BF524806232C1559596539C9416DCE518F96DF5649F7807448C53D927E0B02F880BFC9714C4C0438B95AE79645B209A2EC117387B83BC429EFDCD4BD41EDABE0E1D2B1BBA7B0932C234B3D3FE30E948684049CB197D82C035ED3A1D60579C3F9DB849A68CBC2968D7114D7F7CBF58E7E02D6C1633BBEDFC53C960E52B6136AD5620C25D2F898FE5F367B00720FD3D718EBA657666787F50CFF06725D4545C8E9C5686A57C0B6AD672088CCA2F4864951B164514082D5BBBDD3390C26206B4403BFD98365D4912751EEE910B75FAE27C4D5334B69E3C4618165CB68E45DC92F8906052FBE511EBD577B30FFFD48E1E9522D10C9D4C2B796F66363C621456A168866517E55A077833844DBFB1D6AEF0DED29BF88F9F76D22E71703F193057DE08C4A3DD711324CD6F886845E730C55E6829BCFEA1F97BF3CAE94D1552044F11ACCBACDA4A34941E012E0C67D4348B25C20474D04BBAC4B6396CA3DAAFD45D00A8905F9124DD0729BE16864A6DB768A28893F4EC57683C4A49173D0049FC915A8577DB9EABBC7172469775478A2E973F90086E363986703692BB416CBE0B422A9BD4E21DF8B105C97FA01EDF7E735A56C5928301D4EEC1C85A59A0DB6AB6886E1726B7AA4884A807230B4CA2DBB45EA7F1512AE9F53FBFAED6930D3A38F430E3115E277F41D4AA0F4DBBE84B0412C3C962C8AE43D74C07E1F35527DC8431CF67098527317A4F205FDCDD2C5B6F8462A93455310EB5C8B5E6FCFCFD4E6AFD0D4A7381B955CAFA1CE2CC87FAFD939B4C87B75EFFC1EA171EA07A275DC23327E1EB972AE3A42EEAE319595F3DEC76F097FB91EDCEEA10CE82554FA69E4D72BC5C408056018CC421DBF252905B89DAC81E4827F1EECDE696C465201CA1E7FCB6E84F645128A743552647D1E524E79EE09CC9806C027048C7BDAF7C5D033D1AF1F2F832520E4599FFFDE257E46F606B6A96D762E93CE9F29ADFD0067CBD454C170224BC19E164972A08D6BFD3EABBD92A9ACD009E13E70F194FE8E16761DDA54F7B2319335F7B11513159CC13D699A256A236431D02F19A554E24635928AEB0C06AAA03DC40C863D6D9483A6CDD22CBB79F82A78E581941D143AA02F8316B06A3526CF62BDB5B0084AFB00642DB9EF335C32D90709440631DA39AB38193EFC4A091AFE7EEE2A3AD4C7284388553B4A388B8BEE6144C1C32190F1BA3E5181B029036BA23D632C90E0662438CFB26696BFE0DE8517A77E3321818CD97F8B89C0F52646EA58A17E044BE611D7A8378083B8D5EBBA5D4DAA8114F0673FF60388FBCD98F3D302385E760073B5E30AD141504CCC9CBCB91304BF02917FD1B5B0EB68D1D85B559A26F9A585B16A0E8FED0C000272E2487D8D21332F55B5FDA26D35C34C8E702410728139FA558A79D4FB2841509890B73AF96B993D4873D0121053AA2208A22DEDFEE805C4EAB14DF41489A74E42E1B6DC4693AD13553B3993731DB74188C50CEC97C488410E6355733F17CD0F611D6EA991C69F53AA65B43EDE46447669E630F9AD8B643BE8020949554A2C04844D9CB085981FAFAEDA58402359C10CCB103C6662C6DFF41C451EDBE3DC741DC46846AAB0A3FD27D92425D41B5305ECD8D7BC8F623710A43372515BFBD02F1805F96C3492D8744DA31B00F8C4277E2F65AC664C926D6DB00ADE6DB114DBF7CD580FDC371921ACA774B284AE968836056609199F38EA68C626C07CFE19B7BA2397D863083FAFE9E81BA5E4CEAFCB4B283CD1B4982B98791AAAEF031C9FB8D65DC242050D9A133B64DB5E57C3BD8842D3ECB1B50019D3FEF411613C1D5199F2A00990A3C6AAF0A343F0F30A5AAAFA0E1DDD37CB684288DF1410112174B0B137A4B9B6026F0BE67B8ECE5A7D4344C7C333A60405978710A2F95E34FC4C2FD4ECDE5422D5392512E7B04F27D8A5BA2DA7FF837484BEC3C17E26E5DC3DC6C9D16A03141F41C1E87F358AD555E50A366FE7F6A661ECBA6405CD82744A5F658A31D88C3D73303F0541CB2014622CEC76543BB292D07A9FE683158D2D6251FAB3B6A43F7F34BADDD285EF76B2EB51E80A6BCF6ACC767695FD3E1A4F33BADCF8F09D9F205D2555BC3D4333CB16B0FDA573A390E78C05E7ECF0170204099F8E8A0DE58F9EBFF7ACBE5339C7FB01803CF1ECC3C023D6DA93DAE2C0307A7055CE5570A6A1E76D24E4313CFE81C7EECB6746544AC159241D464747502D6347D8553FC39485FD027659EFDC34AE3420C6F55F6E8A58F97703241F42EF87F9C8C3C26C46F97F50B9AD368439B2AA7EA6F92241601253E792A9F4F9869D3F66812F920C8090975398D723DFDF12075743146694C54A65EA381161C6712082E4D9107B7DC74A3AA02A3851B2285595F637CB65FC613086831A0F526FDC793F675693E225CCF3FBEE7F483E85ECD8FF9A5D290FDD24294F6A113D4070FDA80C4E05DEF2DAD2888699A6B091075D9DDF1DDE3D8E02A22651FD829582CA3B69098ED42A81BACD9AD5FE12177B52A165E72D85F4E1AE5D5A8F3337039E8CAE5FDDFEFF0247F8ED66FC8D54B05ACC5B11E4988A0C9A98FD41C34D64B3D2DEDBEF8D8435411F81DA7CD8BEEE8845417F5608B78E017800EFAFD22D38B60E133616DEBC47386D8B64A3D5D72530CA31B8B28C78FEBD37107BA9E9B15E1DCFB6B31A38BF9687C094E3C9937080DA337DC12A60CFABBEE179F8C0D19780CBE6DFC7A205F42096589E851BFADCBAAF020E569D0BD56282B5F6E1B776E66FEFCF11A29363F6A32B8E11BA54F044FFC450F24C14FA6CCB4656AD8C82B8D105B83E31EA8D5C9F0FAD6B82554EBDCECDA6D8BD7D7B6B00D28E8E4D16849490A446880D4DBE7BC709C7CF034C72F3CB1A8DCD11CDD18C1C58DF373C10F30AF7C8B3496C455A68E89223FEEDE94427EA777741C5240035F8C94633438BC020495012F414A3D61F69C4CD0184A70D199F761EA9C6CA86275C4BBB635477D420A49F516182E21ECCC927D68D3BA8C2C1BF0857426F217A5CAE3838858D80EE875FC381EEC855AD6741DF673F487A960CCF8B9522B2A85C696E63904078FE2B37D0AF5DD2FEADC37F71206AF58D3A2F5831EB78B48049A0BB69913D8F2F1BC1D1684CFFD088ABE0B87405612F98BC085FBA626C553187ED83D9758F68C4E8D122AFE832CB1BF75F4B9E5705A68A5AE91C5C78C61E4BDF607D933312AC3DF74E01D5A9E2AAFF3043AACD7EE898B2149B758CC2323CABA9A976E65DCCD56F7C39B13AEBED82AE2F93C1478AB1C649041E2DD32ECD8A8D0FBA92AF72A6A9B9749D13CF534A539311CB7E10A93F065CF4880526129F01034A962FFD20FB76245F79088B015ABABB0AE7E29A222CE2AFC046AC1EDDFE0AFA5983A4A3688ACA58D9B333493328BA4E093617ABD338954205B2D067770B91D18D64821E87D8781D52F20E096B44505E4F2823C364BEB696FCD6CF8A5F607862DF370FDBF502801984FAE20CB0AD4C2844E6E6EF5BF6DC33918810A30E10072BA5F51F933ED174E20FC1D810958A4ABEC116265C0BEF2E5888EE43CBB34D2117848BCD07C08F5D4B09CA16212741F2D43D2558F19A3019519082B4DC39F37AAA278439C3E5C44894965CB34EA5B4D16C90A4291F5114488B5643F7A906B175D3C153620DC6126210C600A0974469573B891CEB02B374B71D3BA534006F9CB891C49EDD0CE2E311FDB9DE14B770AD5FCFC85681A0B3992EC20DC7F81E61DE318EBC66DB2EDD42B2B540F91EF0689C5E02C5E5A1E0F113E435F30B61CBED530E82B9B46F8F6A28F14E6D9C0BD17B3DB9AFD2273500EDA1531D854D88981FF88EC342DE7FCEE9B7206EB34213F42FD4C254F49C90E47EE413B698CCACD02882DCB955E0C08CA4936A3BA3CC07A03A29C9D5A1C43D8FC6840C53ECB80F17F3BCEA0B298B81806B732F917CD6A6135C0DB7848F0C2BF46EFA4FE7381BBC47A32F7CF02C46B02BC11BDE7F18FDDA7AC854994C4D8FB8F6FF4F8F4EBC1B4E4FA511F6C78AA5C367B91236B92F7AE47B85A6DD7CAE2826C26D79403B29921BDDABA218BF9331188C2D6212E8BDEAD88EB9797F5916D492F098C6B24AF4022EDF6DD12306EC8B2F9FAF6979DB1D805FF54B2DC161CA3E3A1DEC12A35D65DC055941A3F76CCAD59E5593C0A69F56EC3C34461D9BE3823CA52C3808AE4A0CF5A40B8B0E99E89893794AFC7E1A020DD3B7370655265BD601ADE1EAEA97F24DA21C8CEFFE3C270888C78A03CF5288943EA38927DBF090588E59D3A44E49D70E0634D8E70BA03CE28D0B234F07F3E0C94FB4F40129B1D2261ADCF2F001BDA749AEEA9D07A156E8DF29D734D17FEA92A6A6F13AC58C927EBA415F5794F24FA5540175F74D879A2E0F38F89B660BE5BB4FAE56C7E44494C7F69804DE20F48FC51DCED12C82143CF491117B7097E3F897AF4BAE2AD3C3E8A38DF9B9569DB4D67E3C20F4FB5BAC779414384E8D91341D8A23F75E93F9B635D095E60E6E9496CADC878A3A887D22032D712517995E5FE71FF804FAFC9C74FAA7E2412192CE27B25DA96926A17B844B32BFC59D17154C1032532CEA955CCD00208CD729B78223AFAF986E8D26DD99E2D59F27C81C9DC85E613CA934EC8B996FA214F94920E3FEB5C495F5C715C11FDD97A6A4DF73D4D99E1102F0A044E27A49489B910043FAA71EF985405A110869202682284216D86A1401EE029ECF0D85E4779D744E06974D989BD562593FF6DCB8A00F73ECA411D98C0ACADFA02EFEA493A0B80F09F0A727C2BB5186B84264C6FB60C59D37660F16FC4C721CD19CB81A3ED62CC73EA382CEE9ADCDB8AAEB6C1B95F0B536161A16FB41797BABBAB6186579CB8A10F7594A2E071232632619D290B40EF5000F5606A525E5E9DDA2FDFE0E660BC17DBD2E4936468DBD52EA7DC5A05BE1979D5CE884D7B0AF950E519A5BE92552A61601DD2913E01F6BE8D3D7BA8F586D7D1362B9CE757FE2F926C09A2EFB81B3E114905B0A0A20468204806208C3424E6AD9BAA8BA3371BFBE1BEECDD061E1E0A13934410A471B4B4BCBFB41C7871801CFD3463B8EA5ED697720A54DA04ED22F9248D74E3C110095698CB564D9F3CDE75A93359F52BEFE94E0A7FAF1FAED01AF84F4302007AE04835E326DADFABAF6235A8CBE1CF41E31D6D6D7D6D360516EF9795F2E03F3911A161CE3E8EB5E9E904671F00C8A3B852A4498CBEA83D6285A4FB414D628B123C84E95DA3DAB4BE232173065771F1647390AE3C5938E955F93562A9B7AF67E2F6E8754840D1649DA13C752887F26BC68E7B30C69F5BBC66B8D43F70B4C81BF678FE83E1E893B3B0A2363A86F808C85CDBAED1733A85132BFE5E175F87B4091578B08F980077E58DE792DF9005834359139FB085FB1BF92956B3A2D76D905599AE00CD1E97599A6D2F05C722BB5F13DC581DAB6A41899D68DD7A6B315DB21B6BB890EE26C45EF980C2AAA5D75D56A0EC0B73A77EFB883F4E62A6E5E7CF58ABF11C59D76E38B4ED61619007A9DC18F21CD977D2B157AE9B22481C586801BC3F92D1493E8C501A6555648D278B12ADA547263025FA95A93B34015F04EA8B37BD39783E1B9567FF484FF5E719D42904D0299D613B93DBC8B99218626BBF52C4E4D68E4F65125A8491E59A461331E1B404F7BF879B13B70FF726BB80E7832ABA8E072F1437EC4E5CA106C6863D063FA9B7BACFFB24BD32AA6D624F30A5A2943AC7A085069137D3F62BA22962D9D9AAE00D2BBFF35F723B3EA698A2AC3692C48A4130697952EF8691CCEBE20A9EE6B33648186B45C1E9EC5D26B456B78E37E18007C14478CB46AB05176FED3B6CAA8F129E5D92A15522AE226CDD335FBBC32C4F6E40B2CA71B4ADFBA1D62BD5ED5FBBA50E0D8F4EC21D22555CA7866A9E504147A802823CADFC900AA92A6B94DCEF9A32A868446D5567F331EC8D3B9B855794134D367A1EF978CD079FB7214DABCF8F78310F7A3145FD7374D5931858970830C350686E9C4BC93432E26A86A576B526CAF28BFFEDA36A4A5B016BAC3FF4B68D09B881F4E6BE62FDDE77517FCAB64DA19339AD97BC7082F037697660D25BDA758E6B3911F830C1EAA8577445948431A0B4F055CC3EBA94C8B6B4E1178FF80FACFD5D949304D56F3ACCD35DECE845C824833BE7E3CB2403F3C74602CC90396542A0269127DFB739A318C606258D943C5DEC6B1F1CE3ACF0CD948D9F17AA2C0C3C7542ABFFA36C3CC46FA44397646C468737955B3EF20436CA9103E7D0FEBDD42133A1E0CA779E9A90C61009324B2480DA8C2ADB1D031D6A1E916F115B6125F7E6D0EC1C0DA7A18ADB8328F492E05C081FA9D423E962C1154A430196B22D155005CBB3C915B5A8909902E09BC1A7229AC7A901E032033BCF8F482D3128F1D55363234AB6840110D3F755995F428D97A4FEE849537AF2F8026489010FBAD6892561DDC452C15420AEF20998CD6FF379646AB6A2C0A0302ABB294EF252D6CD051CDDBD15514A98B576FEE4BAD5ECF207B99198ABE05563A4BE3693CA7A87C3468666FF174C55E82D8EE5266E51B6AAEDF06AEFE78CDC6DB7F2332E0749FC23E2BB08F975A63A404592F88CA0B4D988A30CBA49B323CAB8C1059DCCCBFE5422C8E68889762C1ED645891AFDD3150DFE89E13BF851008ED32F356B97CF846C86FA52D16293A6CDDEC8923D5D4E9F6CC0B311147BF18A5C612D4B318AEC20F6C4686D7930E932C758ECE9051021AAD99085758459DFED5CD9C1DB2E531B6E6265BC4463A96E56E275AB466BF5E13CA5B3470AE225AE8FB2CAD575F3753CB248DD2F06F7D22A50CF52F351138B1C08E9BFD71FDF1D576C2BE12C7C6143DEB38121E76883CB63AAA310EA3D82F5B221C3EBCEDE0EF870569FF52FDF1EAD73068DB36C1888D98AC03D085CAEF954DA724AA94DC4091BC90C014D5AD24580B8FE4B0FF16E8D21B17441B1395A15D7C18855F5778F448E0C87F83FE55282629754186BA12E6352B7BC9BD3AF81896BDD768EDA2BF8CE5FA3B265434BC56B76833386E0D1ABEB6EBE505125771D52632CE44A1B75D0069E864F806E2D94C60FDD78E518F1764E5F5CEC2F42CA796B88834B0C66C683529371D307DCFF220C27DCE8D38B94DE7EA17C80B66946F18160E5CBAC59594A8FE4542B7F06121810E3D06C468D167F93D698A5763B242B14A5B2DCA11AF7292E1D061B5C444BD34158125440314E11FCE408704F408C73D3B16D2FF57A7D4F975EC8F1C4D0709CB670FE42D075E6DAB45C00BB7C39CADDB4809BCDE731AB578A6EDC4E896D409FE3FF067DB341615B82A786516DC6CAB0AA5DD259946B40F00B865333D6AE0FAC263F32E947180942E2282A5868CC297BF0079632DBD2886795162ABDD153F1DD2F4B411BA2EC90FC968BDD73DBEAECB3FBBA04ACC9E6FD3FE9DB8654076A0450A0EE05479F82C8A82F5034D0D36D634292C6904AFC589ACF55F9A4B2837234156D9DD4E33AF4C93EC34C73F97E9AE1D6FB6386A55DA95916D8AA7461FAA2C90D512A168E19F99CF22438F0513EE97761AC759FFE5F739E2048DBA4C39E63365B1FA95904F78EF9175EAB9696316B153D1B98AE51442C05500AE2B9B6C82729D06398B39EF7A0101AD4D606E713AEC004EA270FE6519EA9472B9EC6D7FE5DCA5B34C233D12057FA7715BE8AF1C7AE4D929E1766B25928989057524898469D55A368F4B1004784382F17BA0720F56AC818C8DEAF6DF2BEBFC5BAF51B5FAE1DC77FBCFCE778E63820E029C48DF80FE6D8942874C82597750FD8BA00868E317DC40FBF6894935154C566526FA5E4BC6B2BBEA71C7494A50389A33DDCBBB890FFB878B887DA1F0F17848AD4CB0C68E95D7A4A66F22511CBFE54E2DE4D7DFC1129F4808BC155A7FD6A8011B2C43A89CDE183EC441D631A9EAD43460B2B69FA6BDD5AB32B5FDAF128567AC5BD4807F610637CFA667E375D912F26911C3B586AA2866B150EE05B93566EB4EE2E853504D18F023706D038618A341812FAE1634B70BAA33C9040BB877F4CF07BA7A49D6D96E9ABC0D1C9E8DC9F4946B008355737D7DDA12EC6C8E1A9CB45CA66DF94B61BDCD12C49E6E6BA51516D875C49911A231EEC5BE6EAEB4244359D4B7C9447964B2053658E916CD9538B21A3EA00F287A985ADC5114A0CCB15ABC46C854CEF0BCE191CB525C3C282391F2E9149636D602EBBF884E097F9BB90C5331D12DB7F0FD40CB699D89FECCDC7410C7E2B6C7AE95C119A0CDF8AF8F384BE13C23DEB2598A06B054394267D61D891C02BA6612959A0EA3D1A28F85312E379A0367C95F0E24615154227FA2500BA3548BBBA46F81A740D23944213F4F48D654C6F6AF41ECF4796515AE92CEA08D80CF2DA7C70B3413C451825E2F7B83D0EA99C3A4979688E223971D8C8B9A8F8228520B113D9F6137C0DE9CA060B3189E699E088FB8AE9FBCA602FDE791347F5E29A71D3BD5FB290EA42F5AC8F0528C65D53A0EE7EBCDB93DE18C6CF427BE8DD392AB146CC46E04028507D9F666903A836947E6F2B0206AF6E4E618F133683E977EEC6D929798A3ABF18C38E6A28FC1581DA524D5F6EA9BF7BE47AA785090979A12D4E965F40E2D3A568E768D7AC02879DF2B0B0176ECBDED2D2F3227355C125CDECDD61C91282FBB2F5B76404E8D73AE05F74B9B7B9FCAF8020AA53688FB99727A64A39292B06F4115DD64AC8BB2DD8584B4A42CFC94A13D4592180621D89855318FB9C47E7B556EC6DEFEF1D6D7A86607F2AB676BDFA8B8C03D0A892E5A9898FA94FA5B2386649EE75491414455A0FF1078320593CE6CCC8F087ED6EFD0997698852804AC62647DB4E01881453C056A91AB77439DEF983574DB19C96CD404FF23ED0D87DE78452FFBDEA9DD0648FE7A32EB3CA85122FCBC8D309E0B6AE349A56AAF04314373D870DF994D733D9137BCDF3517314E7F282A709C4CE8893C695832BE19AD83779C0622EF4E525A991E8E1F0F1FB339E6314318FCFBDE16A1EF5BFC32B51D8EC9F7071C83EEBE4E6081DC20441DA02F718976B4B5DDDAB192D6962CF92DC3F31EF59FAD3EB803CE2F875457A4496D0896DC385811540E44230EC05BF2B3E33BB88EB4BDE7D3FC7EB1F62FB54D3C642E2D1E8308A24C2324C18F27C0E00BECB195A1CBF15A32C4172D6A48DD7A72677BBC0695583E12AF7A4E6499A43904715CCEDD7761C6E999F422C88753671C355A9EDF273D3EF9149C64B5109A551476174C6EE74D1FC43C511FB5DE28CBB13FDAC58AB50DC98A9A0EC0F373BC381F5A6226DFE4C56F68063B59C7F3A36EE2EDE311A0ADBA653A51313A06C3B78C36EF0E82CEE7DBE2C68397E3A1F9DFF85E7DD89C95FF300C8951351DB52E17F3E449D2236D6687BEF754948E50845B05D033684663A432734807D594C080ADD589832CA0D6E51BBFB624A903D13B68703831238C94464F5E1C1D9720F0E56DC2358763C3191EC86C97357A4FD94CD5C0BAA6D144090DE4D37D1A89CD8BBB7B1BE9AB0F774F1024E64C46943BEDEA1B5D6403F2324158B158614C33B277D92277DF64E45F4896B5C880B91B3371F679257A0FD29B583FBCC758B77902A8A97E245B57FF05C1DEB84D17F49447958BF92202710B8F3AF33D39EE01784F6B7757D321CC8F4951231FB0A435958494B7869C5F387F3EF17807F90706D20A194C5F69C3783678B92BFBE92F52093BB2E88C04DCCBE300E78F0C8730E12A1EC5C44BFF9D1DEEA05C33DC80BE1669CD4C8E65891641258F61D390140724DE13C62B1C8660D070EA7C2BE929489D0B3260EE359E3D346745862B565CF03FA43A85B49A1D0A1A9EA43BD6D1A3F4495442504D4249195CCDD107769ACC5D73FA0299D4E0873A15596E5D01DF624BFC9C11166148C727AA2B1CD50C497E085858AD6BE8E3CBE9D11859CF70B237D90B2231D47A55485ECBBD5FF2C32F1FF8636452B1774C068C7AC5C891A671E6686B29B696CECA78A261F20CD88EB41F7E8F64EFAF7E108EBAE4EFDF02EABB7D6C0ADBDBAB27E3180EC19B95015F362DB1FE92BEB5F225D632B92006719900B7EA8C4C75DB970ADE06906C0BABCE5E1955CCABA581F96B870A5F05D4A8CCE7F620F79EFF9B7FEB471688F571D059B36B93F0C74CCF67948326B14160830F5C402108067D7B5A02C23EA2DCB4A42DA29DED563384EE91A22F364D4E49B58A08570B7C9D20F380349005968D8CBD8FE1208F124AFCE3BC0540994AA8ABB777C4F8FFC80B22FEEB888F9D089178D71F836E0253CB75A3575031A098ADA28597F597C8DF5C7C57F1654606C043C7654CD8621BA14BA09E71EAAD10FE8BA1DE3E7AC177BBB0CF48169E02FC84A4BBC4BC3DA9033C3B54AEFDC2F85B437B631E0CF2642EECAC95617F1EBBF4B5DA1CE90F4D8DC28B09A06970749A20E8248AFFB376D1F9AF7C0319C8A3C141BBFD3EB002A66F5A5869A0B8F371AFC89320A9F34F3FBE2B523D347D257B7DDA78C27479D2E297FD0D79D4DD0B59001C1D3460D7E2EEF2394A6CD98116FFE326BA575732DF12497249B3D43FAB93D145B41F2A5C557C0BB66BF9D5B50DD44CAA61EBE2C6BDDC15E1677B43F472501E8210E6DCE0292746E2AE2CD299F75CB222C39193588862332F77831943D9609857241F5722E52E55CB64AE57FD2C4DAB0A40BB23B28E8607AABFDF43328F7C91C1E205D41B0E6C9798A4F491F94E056D324A19ADEE1FEEDFFA68F49CC33AB97985CF9CC56EB88538943580338022EBD5341D4B7BA131B29B5E6A1348598F3983000D32EACF6354AC20D9E6E5FD3219AAE1B79585F9C1150DCDC97D1E42D493D167E7A31581C01CDCB237ECC1317FFF8EC02414FF29980C2943611FC5F64F0B797DFC0B3C000B0C25A28E6A1882F45892C3428196E5195EF6CF44446E921C6619A4494FE00FF96CBC83B048691D288362DFED850B01AC3B2651EEFC45EBFB741C87A98EAD95F1A3281EB20B52EFC5EF26CC38361D9F078B4DA27FF711342DF984B1F932A67819580051A6DEB3B55CFF0835C4648B8EA22B8962D22D1D5F2F72B77BB39312C0AD0381BBB81F6BF874D6A34F1FE0B01AD1D5D8BBA8EB537DBBBB14E9650A414AB0E0C7AD9526880E2127898FFD626C14E0F3DF32D111CA19133E3675DF7E8B96A6D8FB50AC32400AA6AB8148E92D4EC5FA01EB53049084AB73F0F47814738CE60400CB9F4CAA4E20427B791EB3EAF976053DA0958E10DEF7499D58A1337AC6318A3B969EFA175FD88C8F9E18BCC6C489A09B8FFF8035E8B2A4152CD464A5DF52EC0595D2A51B466DADBD444974B96075D954DA46885890DA5F182120B9F8A80F43AB072A3FDE7270E1A2050B6676139EE1110E73834AC98CC3E83964281B25526BD2D58A2BE80FB4872B4851128CF2DA8BA9464C353109194ED0CF7BDC851C06AF96E7DCA691C84FDFB86971DDCBB8E7C4CD2DD3AAB23B5D324926DA586E63DD8E830E86B2F13E054CA0A1BBE5527C233F0B5FE597659919157826D2456A1153C97B9C4B75A8EA8255609BE21FE12CBD4B71E5AB6DB9E233EB8D38139857C5F46E9C593B0E976152A6F5E8AD838028E5960A4A80B284DDFD83E9A4ABCA646DDFAA7F2D40C5DBA2B1EE5167A7D1603FCA615C2EA96AF6E3FD35F8901CF7E0DB719AEC247AE020F380B5114EA497141CB91E46F666EB3495F89F255FA2025B42FDC9A6962611D97C23EB46BDA45F2688FCCDED26AD52ECC6F0EF31AECDE9BE3B8B0CB7891B28083DB4B1640B9B9FDE964E766806554E19AF0CBF4BB81AB2E867C5B3686AD5DEFA1A7416054681F5D721BC0EB26CA87DB7BDB36FC132411EC385224FB22CF781D9E2A98C8C376FC543C87A0A052528D7C015AB320A46FC8036F8DE22AC778A9367A8157DC5C0B6D33562A01A427D1AEF7936BDF5FB44E6DCA3418FC5A3F335C784C856C6DC9FF9990C04C506E33EA2DDA0B38331A38DEF0B8DE5FC81E426736E5D1D27B5203EB8FE4FF13F037BB9C19133E1D530DF0CDF661AE7E0572F0EE8624DC00C5C75BE6E7C62F459378F9E598D6C79B825796FF90E3B900F1508583161EA030212591A60F6D12F6B0B4DBF0FFB772FFD6B79B9EDB5FB80404E7504766B8AE5E6C373D7490932F4FBBB94CAB3B30521A4E3C9FA2FF600343CFE3FC718978383A0511DE4B63BFC6037440AC11A90D0B4B8DCB30472975695BCC3BADAA4DF99D2182A76C87EE3895408BC29E528D1D970915950B1DC068000AE2519758C0C1908463D60A531B6855AFFFFFDE6DEAF67DE484C582773C542C08EC75D87A29208AD23722709D6F3BB61477FD1651E064A4CBB8EDFB5C1C2F15B31E770B99CDEE5D0EC1B4EBE79DBAFB96B8B3136C17B0211CAE9829A49EDD689FB39D986D5B5C35021EB5E36241FC3AA3C8AD0B67090C05819C2FB5AA74E6C2745E989EAFB9F64519ED4C77A3117F5ABC2C8FD5288EE3D55AD5136A6FD9D38EA12BAA4C576BB87C15AD0E238ADFA626CBAED74B40A5FC81988134B28E190E5C04977A02A9FED86BA505984A19C61BE03A49AB2AD28572A9A196611E03D21F445A6F690DC8358F5D4CEC7E42FE9BEBD071FC198F61A8F7E85349DBCA130EAF138787FFBF92844C1D8CD736760C54886B3781E8C683F54FCD7C1CA75C0567A9FDED4D64EC98AE9FABF0D41DD3094CF714F4F8D0F3CE6F1B0ED651784B18FC0BDC87AEDF24CE6B9702A3F78BE6A2CD2E5010108BCF5C7FBACAFE05D9A0407FCA1D95C6CE262CE70FE3923D35D59B29E27EF412DB81976234BA75BF5BFF81471A69839AD6D2B6CDB1470DD4A90E6798F4E464606B777C506B5B74348CE957F878D8985C24D64DE28088DEC4ED9DE68B01D7786539973AB526EAC403AEA89D2E400CDE608669B4CAA6005F56FB07D9E95FFCEDAD0FF933759D8386082B9499BB9FC10537856B51D747355637C6D29E6DFC8F223A007314F1183D7F9D0516FF4B1BF6DC9A2C6F20D7772392D83E9795B6CD82A45DE10C952D684EBAA828046437A814470044E139BF505E76CBE98C1623E15B9A28944474AD07932F057E22B3F1B2A98BE4A101D082886C4D2B757C6A62D26340662812A4C690B11AACB3F09F358815F1E977A1A24A575A76EDD235129F97917A70D26BCC2A61F5262374F647D913DDBD14C3AA1840C42AB2F562F5CE944D2CDE53F9482F5620360DAC190CB763F434548C51D9510C640927E89C461C9E7BBB0B55510BA4593F059182A7FB391E1E417413E54ED632002B5D8C05CEBB142EE6D31C88BA2B0F87E61462393EC3D568B1B6B3661FB8F610E694AB324387CBAD03AF8EB2A353042F5B97838EB1313939D319566CBD33B721559747407B7F6EB1CB60083D22AFA548A2C3843D3952905FADE717348DE4A32B8A004AF6396B1D4E1187527AB259775EB17E142C40A326474953C135799C5DA28D683F7BB328D101706862B50407A0651C21A1F07A7D79D275B3D8D46B32AAF28ABF5E92829ED713F004702C91BA035D369AA860892E54D01AFBCB86B23C01636648828A9D3C42FDF699CAA8AED7A87606FA31FAE021AA8CD6213FD331A6492A57F790F8C4D8652BC097C868A61685232C1FD00BA3230D1C19C0773C7BF9C1FA22DE0F8E036923F58403BED7E9E8CC209166C1CC53FB8D147E17E384808AF2C9E9BF91398EFBAA83BB6A40BF41D1BD8938684E804845D00B8F031D02F00717C6AC9EE7D56F3233C2CA3F096C88F13A87ECB67D406A8A99443EF8CCB1C9E1FE15A0AF367B95D89E7F71520BBF9BA4AAA530CAC03A1148D3EE7168E4E91AA9E6D12FC53C0BE2C3B9396A5A386F8ECEBC4C6C16384CF89F1E934D9FC17553638C3DB09486AC7600054A4A227C0FBE8C1D26A9347253447B9A982BC842F7D6DA56F296BECE64D2DEB4ED2F2DE79E19D44429A7EEB0B6B2C8E9CB90ADA3A569F75A74F91A0C4E5242020F03F372BCB5CCFB555BDAEFD2B34657F45FD24C9E062113C9E9D6290799EE2ABAFB9243F6EF4F548DB65B223508CA4A7C54EB81D9C49539A1BCC9589490B5421F0FACD38B8EC0F529556A292A4D608B28306DC465804DF6E8D7A7EE5BCD5561B068951F156F3C0D7015493EABD1B32B917D16FED4352DEB23F9BAAC0E3576550C347178C95BC5362E0657F80E36E5BFB4A416E4D6B8E6BEFD285B21C44C6F1EAD2DD59BE34F7AA479014BA1903732EAF7361BADFD2FA49BEB13F43D209778D5A1DF220B6029D038BB971497D89C205C25188C79D4A96ADA64B84929EEFD221B75908CFBC8D55696B0EC64BC154CFFC3361E68F0AC5918DA9B4F61D411CDC1282F64E2B6CA6FF86DB7492B18FABC2DB37F8DAD83C2B68E884A862B0F925E92FFD7937C404BFB60B16728DBD494059A4757759F452BACB4AF094B4EDC3057DCC214DD6482D44859383A5A2A878C72E60EC22BDFB07F84E735C56571F13258FE26AFB2C62014183ECCC7593B62069D129FD00EE94207BF14A18EE1CE2F736DE6C5EBA8D520EAC681156CFEBE3BED052DFCBBCB42D7A51D5C2A172E2EE3925EC94D59374BF4B0AAB6629745BDF27568F5DFF954B36FE9232BCB75A59B67D11E37BA87A6F7FF346A446C3AD3060D2CF299F05D3D52ABAFE61C1F4D1FB1B912F784ECC290CFB371F19E5D647A7A62C16D7412875B346322D30969945E6A215AB1F62D6998D1A3724D725ADB797EF5CA441F5E2BAC539D35AB3E645720105D8B565CD0CE83AEA6D60016A61141FF30938F24682A74961C9119FBBEB6C7CA95DA9163A3331B29AE63D76A22584449732FEDCA022C5A2AA87AE66F67AEAD257D4DC8F7F37881872211E97EE4A42BAD633F56E31EC3BF7C94011ECE846D804EA1AC7B3121960DC84C6A42D921A2A2DFE9FDDFA7A70F241412AAC4066747FCD008B21A9127075C256EF29658D2DBDBE8C0DF52C82B34992F8B49391DEA0A18B4DFE8CAAAD9C99CBD06FC60DD990402F2F4B07BA2FAABDC135B866E5E3BD32D3E0EB104E4A757142F43A80847FB563BB80FB84DBA2CC3BDC0393AAE483AC6A2A5E4E0CB19A1D3C8E49077045B0622F671D6E70717BF15BF4E915C7650F95CF15B524E1CA071A2A51D8801BF75A805CC04A724092E2BE55F9D8039CFB2E6D6AF800CDDBF7F8CCB9938F927086A7625D6903364A2B84F37D85BF6AD16559A3C8B187239B13030442287EC2A1AC3A0D2DA3AB0EBF37D62E00C42D98270DFC43E917A74BC201C60D94DE904F8A625D0178359EBE711556F3670806F8D07D8D05129748C28CBF4F117AD30094197527E00320D325DD4CB3C351A4BF33E5D8576B744AD59E722606D38509B395F2B6A2A03792551C1C0F9E5F26116C2D4268B1DBB750DC114787BDE9E1174D8C3F8999C4EFAF84F253D1B9AACCA6CBE1DAD25C861208180836FA572F324A899DDE228BCCADB545B644FB288717954EFF6CCD0260162101047564F6BEF5BB2843FEB8C280C5CD99C7D951052B102CEF3F136868809BC1E634DCE9F67D8CF6A6E86A0690696C3096858395CB10143579E35B81E18BA7D712E3D4A398BF14E534087142FCDD39773402D0943B97E9F8C4E214D53DC37A9D5F25DFF856BF9165C964619F278E591E67C418A6785FB9EBB5D19C67156520F5D6636B47D3F83808829AEB2A02CCFCEB0EC4B4D7DAD2A84D7028A926856CDAA9D6111BBB53EA997D023B1E019268E9D9D9BB1BBCC352D86DB733387683F383B6FF3E45357C49CF5013EDEB94A950923FFF3177B82BDFABBC6959E590020654E1A71918E14B490E18495FA6C86AE5BA8D4B148A34B5158531B4EF78BE7F8509EB008A6B1DE3C69D90BE27471D1D57272152EE892B28114A6A80BDAE2F3683C0A842D2DD12335BCD72F4C63CF89C787D4F8A676AC91E27E19E20F01CFA02274E7EEE466558974F0691BA1B17C8D8EE210CBC309595E5A6BF2E289016AC4672D320C81EC79C35E8C20A93C95F09D9FEEC643F040E044784248238E081A48DC56A5BD7F64D1875976897F058157D70BEE8DAE543FD8F354D9C8DF1F9DE9FC519039892A88F7D3833C45086CB726F979E9728F82AC196E3790F3F6B8D4F251E6934603DFCE34159EEBE64BA6D30BF1B58F213ECF55775A9FE4E17E67A4295D567DEDDEA81CD775014E4D503ACE722FF885DDE34CDA4944CF9E035586B3F2C5A00BFA26FD640CAF364D32FBBE37814F808C0D727D85DC444388BE6DD1181B952DE85D8F2EF4B147631CA55740A20FE7E4BDB5DCBB141C29D6DE17F0B67F42BF8C14F13E2B7E51234EBF26091627CB4E8F65D536CCC98A08121C770DDFEB41C08FEFDEEC559815732A586AB079D43343D8BF7706B7F86A48A6AFEF04F72DADB42FAD88FFE9A02183532758AE2309892E93F699C6C2B0AE17E7EA414BE39FCF3C9CF20275F408486815F7F47811B4561D094F10057C8D2F56C73BE80530B72E2C4F1D9C3E21E35EB5FC7FBEBD2F8C0CE722A3E010B39EFB3C62730C6C7FDCA0B310716E0B39312621147C1CE9FF21E80A8E696AA0283A6159D29B6CADDB903FAA63B0E067F87C66609D06DCCA80DEBB814AC211748D5C7C4");
        byte[] rnd = Hex.decode("934CEDC78C6F657E3BF6120E38EBB228");

        SLHDSAParameters parameters = SLHDSAParameters.shake_128f;

        SLHDSAPrivateKeyParameters privParams = new SLHDSAPrivateKeyParameters(parameters, sk);

        // sign
        InternalSLHDSASigner signer = new InternalSLHDSASigner();

        signer.init(true, privParams);
        byte[] sigGenerated = signer.internalGenerateSignature(message, rnd);
        assertTrue(Arrays.areEqual(sigGenerated, signature));
    }

//    private static String[] splitOn(String input, char c)
//    {
//        String s = input.trim();
//        List l = new ArrayList();
//
//        int idx = s.indexOf(c);
//        while (idx > 0)
//        {
//            l.add(s.substring(0, idx));
//            s = s.substring(idx + 1).trim();
//            idx = s.indexOf(c);
//        }
//
//        if (s.length() > 0)
//        {
//            l.add(s);
//        }
//
//        return (String[]) l.toArray(new String[0]);
//    }

    private class InternalSLHDSASigner
        extends SLHDSASigner
    {
        public byte[] internalGenerateSignature(byte[] message, byte[] optRand)
        {
            return super.internalGenerateSignature(message, optRand);
        }

        public boolean internalVerifySignature(byte[] message, byte[] signature)
        {
            return super.internalVerifySignature(message, signature);
        }
    }
}
