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
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

public class MLDSATest
    extends TestCase
{
    private static final Map<String, MLDSAParameters> PARAMETERS_MAP = new HashMap<String, MLDSAParameters>()
    {
        {
            put("ML-DSA-44", MLDSAParameters.ml_dsa_44);
            put("ML-DSA-65", MLDSAParameters.ml_dsa_65);
            put("ML-DSA-87", MLDSAParameters.ml_dsa_87);
        }
    };

    private static final MLDSAParameters[] PARAMETER_SETS = new MLDSAParameters[]
    {
        MLDSAParameters.ml_dsa_44,
        MLDSAParameters.ml_dsa_65,
        MLDSAParameters.ml_dsa_87,
    };

    public void testConsistency() throws Exception
    {
        SecureRandom random = new SecureRandom();

        MLDSAKeyPairGenerator kpg = new MLDSAKeyPairGenerator();

        for (int idx = 0; idx != PARAMETER_SETS.length; idx++)
        {
            MLDSAParameters parameters = PARAMETER_SETS[idx];
            kpg.init(new MLDSAKeyGenerationParameters(random, parameters));

            int msgSize = 0;
            do
            {
                byte[] msg = new byte[msgSize];

                for (int i = 0; i < 2; ++i)
                {
                    AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

                    MLDSASigner signer = new MLDSASigner();

                    for (int j = 0; j < 2; ++j)
                    {
                        random.nextBytes(msg);

                        // sign
                        signer.init(true, new ParametersWithRandom(kp.getPrivate(), random));
                        signer.update(msg, 0, msg.length);
                        byte[] signature = signer.generateSignature();

                        // verify
                        signer.init(false, kp.getPublic());
                        signer.update(msg, 0, msg.length);
                        boolean shouldVerify = signer.verifySignature(signature);

                        assertTrue("count = " + i, shouldVerify);
                    }
                }

                msgSize += msgSize < 128 ? 1 : 17;
            }
            while (msgSize <= 2048);
        }
    }

    public void testKeyGen()
        throws IOException
    {
        String[] files = new String[]{
            "keyGen_ML-DSA-44.txt",
            "keyGen_ML-DSA-65.txt",
            "keyGen_ML-DSA-87.txt",
        };

        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/dilithium/acvp", name);
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
                        byte[] seed = Hex.decode((String)buf.get("seed"));
                        byte[] pk = Hex.decode((String)buf.get("pk"));
                        byte[] sk = Hex.decode((String)buf.get("sk"));

                        FixedSecureRandom random = new FixedSecureRandom(seed);
                        MLDSAParameters parameters = PARAMETER_SETS[fileIndex];

                        MLDSAKeyPairGenerator kpGen = new MLDSAKeyPairGenerator();
                        kpGen.init(new MLDSAKeyGenerationParameters(random, parameters));

                        //
                        // Generate keys and test.
                        //
                        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

                        MLDSAPublicKeyParameters pubParams = (MLDSAPublicKeyParameters)PublicKeyFactory.createKey(
                            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(kp.getPublic()));
                        MLDSAPrivateKeyParameters privParams = (MLDSAPrivateKeyParameters)PrivateKeyFactory.createKey(
                            PrivateKeyInfoFactory.createPrivateKeyInfo(kp.getPrivate()));

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

    public void testSigGen()
        throws IOException
    {
        String[] files = new String[]{
            "sigGen_ML-DSA-44.txt",
            "sigGen_ML-DSA-65.txt",
            "sigGen_ML-DSA-87.txt",
        };

        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/dilithium/acvp", name);
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
                        boolean deterministic = !buf.containsKey("rnd");
                        byte[] sk = Hex.decode((String)buf.get("sk"));
                        byte[] message = Hex.decode((String)buf.get("message"));
                        byte[] signature = Hex.decode((String)buf.get("signature"));
                        byte[] rnd = new byte[32];
                        if (!deterministic)
                        {
                            rnd = Hex.decode((String)buf.get("rnd"));
                        }

                        MLDSAParameters parameters = PARAMETER_SETS[fileIndex];

                        MLDSAPrivateKeyParameters privParams = new MLDSAPrivateKeyParameters(parameters, sk, null);

                        // sign
                        InternalMLDSASigner signer = new InternalMLDSASigner();

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

    public void testSigVer()
        throws IOException
    {
        String[] files = new String[]{
            "sigVer_ML-DSA-44.txt",
            "sigVer_ML-DSA-65.txt",
            "sigVer_ML-DSA-87.txt",
        };

        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/dilithium/acvp", name);
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
                        String reason = (String)buf.get("reason");
                        byte[] pk = Hex.decode((String)buf.get("pk"));
                        byte[] message = Hex.decode((String)buf.get("message"));
                        byte[] signature = Hex.decode((String)buf.get("signature"));

                        MLDSAParameters parameters = PARAMETER_SETS[fileIndex];

                        MLDSAPublicKeyParameters pubParams = new MLDSAPublicKeyParameters(parameters, pk);

                        InternalMLDSASigner verifier = new InternalMLDSASigner();
                        verifier.init(false, pubParams);

                        boolean ver = verifier.internalVerifySignature(message, signature);
                        assertEquals("expected " + testPassed + " " + reason, testPassed, ver);
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

    public void testRNG()
    {
        String temp = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
        byte[] seed = Hex.decode(temp);

        NISTSecureRandom r = new NISTSecureRandom(seed, null);

        String testBytesString = "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D";
        byte[] testBytes = Hex.decode(testBytesString);

        byte[] randBytes = new byte[testBytes.length];
        r.nextBytes(randBytes);

        assertTrue(Arrays.areEqual(randBytes, testBytes));
    }

    public void testKeyGenCombinedVectorSet()
        throws IOException
    {
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/mldsa", "ML-DSA-keyGen.txt");
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
                    byte[] seed = Hex.decode((String)buf.get("seed"));
                    byte[] pk = Hex.decode((String)buf.get("pk"));
                    byte[] sk = Hex.decode((String)buf.get("sk"));

                    FixedSecureRandom random = new FixedSecureRandom(seed);
                    MLDSAParameters parameters = (MLDSAParameters)PARAMETERS_MAP.get((String)buf.get("parameterSet"));

                    MLDSAKeyPairGenerator kpGen = new MLDSAKeyPairGenerator();
                    kpGen.init(new MLDSAKeyGenerationParameters(random, parameters));

                    //
                    // Generate keys and test.
                    //
                    AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

                    MLDSAPublicKeyParameters pubParams = (MLDSAPublicKeyParameters)PublicKeyFactory.createKey(
                        SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(kp.getPublic()));
                    MLDSAPrivateKeyParameters privParams = (MLDSAPrivateKeyParameters)PrivateKeyFactory.createKey(
                        PrivateKeyInfoFactory.createPrivateKeyInfo(kp.getPrivate()));

                    assertTrue(Arrays.areEqual(pk, pubParams.getEncoded()));
                    assertTrue(Arrays.areEqual(sk, privParams.getEncoded()));
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

    public void testSigGenCombinedVectorSet()
        throws IOException
    {
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/mldsa", "ML-DSA-sigGen.txt");
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
                    boolean deterministic = TestUtils.parseBoolean((String)buf.get("deterministic"));
                    byte[] sk = Hex.decode((String)buf.get("sk"));
                    byte[] message = Hex.decode((String)buf.get("message"));
                    byte[] signature = Hex.decode((String)buf.get("signature"));
                    byte[] rnd = null;
                    if (!deterministic)
                    {
                        rnd = Hex.decode((String)buf.get("rnd"));
                    }
                    else
                    {
                        rnd = new byte[32];
                    }

                    MLDSAParameters parameters = (MLDSAParameters)PARAMETERS_MAP.get((String)buf.get("parameterSet"));
                    MLDSAPrivateKeyParameters privParams = new MLDSAPrivateKeyParameters(parameters, sk, null);

                    // sign
                    InternalMLDSASigner signer = new InternalMLDSASigner();

                    signer.init(true, privParams);
                    byte[] sigGenerated;

                    sigGenerated = signer.internalGenerateSignature(message, rnd);
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

    public void testSigVerCombinedVectorSet()
        throws IOException
    {
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/mldsa", "ML-DSA-sigVer.txt");
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
                if (!buf.isEmpty())
                {
                    boolean expectedResult = TestUtils.parseBoolean((String)buf.get("testPassed"));

                    byte[] pk = Hex.decode((String)buf.get("pk"));
                    byte[] message = Hex.decode((String)buf.get("message"));
                    byte[] signature = Hex.decode((String)buf.get("signature"));

                    MLDSAParameters parameters = (MLDSAParameters)PARAMETERS_MAP.get((String)buf.get("parameterSet"));

                    MLDSAPublicKeyParameters pubParams = new MLDSAPublicKeyParameters(parameters, pk);

                    InternalMLDSASigner verifier = new InternalMLDSASigner();
                    verifier.init(false, pubParams);

                    boolean verifyResult = verifier.internalVerifySignature(message, signature);
                    assertEquals(expectedResult, verifyResult);
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

    private class InternalMLDSASigner
        extends MLDSASigner
    {
        public byte[] internalGenerateSignature(byte[] message, byte[] rnd)
        {
            return super.internalGenerateSignature(message, rnd);
        }

        public boolean internalVerifySignature(byte[] message, byte[] signature)
        {
            return super.internalVerifySignature(message, signature);
        }
    }
}
