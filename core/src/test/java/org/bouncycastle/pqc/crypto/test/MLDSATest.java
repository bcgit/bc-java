package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.mldsa.HashMLDSASigner;
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

    public void testConsistency()
        throws Exception
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

    public void testMLDSARejection()
        throws Exception
    {
        rejectionExternalMuTest(MLDSAParameters.ml_dsa_44, "dilithium_external_mu_rejection_vectors_44.h");
        rejectionExternalMuTest(MLDSAParameters.ml_dsa_65, "dilithium_external_mu_rejection_vectors_65.h");
        rejectionExternalMuTest(MLDSAParameters.ml_dsa_87, "dilithium_external_mu_rejection_vectors_87.h");
        // TODO: rejection vectors based on non-compliant hash - SHA-512 is currently the only one accepted
//        rejectionPrehashTest(MLDSAParameters.ml_dsa_44, "dilithium_prehash_rejection_vectors_44.h");
//        rejectionPrehashTest(MLDSAParameters.ml_dsa_65, "dilithium_prehash_rejection_vectors_65.h");
//        rejectionPrehashTest(MLDSAParameters.ml_dsa_87, "dilithium_prehash_rejection_vectors_87.h");
        rejectionTest(MLDSAParameters.ml_dsa_44, "dilithium_pure_rejection_vectors_44.h");
        rejectionTest(MLDSAParameters.ml_dsa_65, "dilithium_pure_rejection_vectors_65.h");
        rejectionTest(MLDSAParameters.ml_dsa_87, "dilithium_pure_rejection_vectors_87.h");
        rejectionUpStreamTest(MLDSAParameters.ml_dsa_44, "dilithium_rejection_upstream_vectors_44.h");
        rejectionUpStreamTest(MLDSAParameters.ml_dsa_65, "dilithium_rejection_upstream_vectors_65.h");
        rejectionUpStreamTest(MLDSAParameters.ml_dsa_87, "dilithium_rejection_upstream_vectors_87.h");
        rejectionUpStreamTest(MLDSAParameters.ml_dsa_44, "dilithium_rejection_vectors_44.h");
        rejectionUpStreamTest(MLDSAParameters.ml_dsa_65, "dilithium_rejection_vectors_65.h");
        rejectionUpStreamTest(MLDSAParameters.ml_dsa_87, "dilithium_rejection_vectors_87.h");
    }

    private interface RejectionOperation
    {
        byte[] processSign(MLDSAPrivateKeyParameters privParams, byte[] msg)
            throws CryptoException;
        boolean processVerify(MLDSAPublicKeyParameters pubParams, byte[] msg, byte[] sig);
    }

    private void rejectionTest(MLDSAParameters parameters, String filename, RejectionOperation operation)
        throws Exception
    {
        List<TestVector> testVectors = parseTestVectors(TestResourceFinder.findTestResource("pqc/crypto/mldsa", filename));
        for (int i = 0; i < testVectors.size(); ++i)
        {
            TestVector t = (TestVector)testVectors.get(i);
            FixedSecureRandom random = new FixedSecureRandom(t.seed);

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

            if (t.pk.length != 0)
            {
                assertTrue(Arrays.areEqual(t.pk, pubParams.getEncoded()));
            }
            if (t.sk.length != 0)
            {
                assertTrue(Arrays.areEqual(t.sk, privParams.getEncoded()));
            }
            byte[] signature = operation.processSign(privParams, t.msg);
            if (t.sig.length != 0)
            {
                assertTrue(Arrays.areEqual(t.sig, signature));
            }
            boolean shouldVerify = operation.processVerify(pubParams, t.msg, signature);
            assertTrue(shouldVerify);
        }
    }

    private void rejectionExternalMuTest(MLDSAParameters parameters, String filename)
        throws Exception
    {
        rejectionTest(parameters, filename, new RejectionOperation()
        {
            public byte[] processSign(MLDSAPrivateKeyParameters privParams, byte[] msg)
                throws CryptoException
            {
                InternalMLDSASigner signer = new InternalMLDSASigner();
                signer.init(true, privParams);
                return signer.generateMuSignature(msg);
            }

            public boolean processVerify(MLDSAPublicKeyParameters pubParams, byte[] msg, byte[] sig)
            {
                InternalMLDSASigner signer = new InternalMLDSASigner();
                signer.init(false, pubParams);
                return signer.verifyMuSignature(msg, sig);
            }
        });
    }

    private void rejectionPrehashTest(MLDSAParameters parameters, String filename)
        throws Exception
    {
        rejectionTest(parameters, filename, new RejectionOperation()
        {
            public byte[] processSign(MLDSAPrivateKeyParameters privParams, byte[] msg)
                throws CryptoException
            {
                HashMLDSASigner signer = new HashMLDSASigner();
                signer.init(true, privParams);
                signer.update(msg, 0, msg.length);
                return signer.generateSignature();
            }

            public boolean processVerify(MLDSAPublicKeyParameters pubParams, byte[] msg, byte[] sig)
            {
                HashMLDSASigner signer = new HashMLDSASigner();
                signer.init(false, pubParams);
                signer.update(msg, 0, msg.length);
                return signer.verifySignature(sig);
            }
        });
    }

    private void rejectionTest(MLDSAParameters parameters, String filename)
        throws Exception
    {
        rejectionTest(parameters, filename, new RejectionOperation()
        {
            public byte[] processSign(MLDSAPrivateKeyParameters privParams, byte[] msg)
                throws CryptoException
            {
                InternalMLDSASigner signer = new InternalMLDSASigner();

                signer.init(true, privParams);
                signer.update(msg, 0, msg.length);
                return signer.generateSignature();
            }

            public boolean processVerify(MLDSAPublicKeyParameters pubParams, byte[] msg, byte[] sig)
            {
                InternalMLDSASigner signer = new InternalMLDSASigner();
                signer.init(false, pubParams);
                signer.update(msg, 0, msg.length);
                return signer.verifySignature(sig);
            }
        });
    }

    private void rejectionUpStreamTest(MLDSAParameters parameters, String filename)
        throws Exception
    {
        rejectionTest(parameters, filename, new RejectionOperation()
        {
            public byte[] processSign(MLDSAPrivateKeyParameters privParams, byte[] msg)
                throws CryptoException
            {
                InternalMLDSASigner signer = new InternalMLDSASigner();
                signer.init(true, privParams);
                return signer.internalGenerateSignature(msg, new byte[32]);
            }

            public boolean processVerify(MLDSAPublicKeyParameters pubParams, byte[] msg, byte[] sig)
            {
                InternalMLDSASigner signer = new InternalMLDSASigner();
                signer.init(false, pubParams);
                signer.update(msg, 0, msg.length);
                return signer.internalVerifySignature(msg, sig);
            }
        });
    }

    private static List<TestVector> parseTestVectors(InputStream src)
        throws IOException
    {
        List<TestVector> vectors = new ArrayList<TestVector>();
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));

        TestVector currentVector = null;
        String currentField = null;
        List<Byte> currentBytes = null;
        Pattern fieldPattern = Pattern.compile("\\.(seed|pk|sk|msg|sig|key_hash|sig_hash)\\s*=\\s*\\{");
        Pattern hexPattern = Pattern.compile("0x([0-9a-fA-F]{2})");

        String line;
        while ((line = bin.readLine()) != null)
        {
            // Skip comments and empty lines
            line = line.split("//")[0].trim();
            if (line.length() == 0)
            {
                continue;
            }

            // Look for test vector array start
            if (line.indexOf("dilithium_rejection_testvectors[] = ") >= 0)
            {
                continue;
            }

            // Start new test vector
            if (line.startsWith("{") && currentVector == null)
            {
                currentVector = new TestVector();
                continue;
            }

            // Detect field start
            Matcher fieldMatcher = fieldPattern.matcher(line);
            if (fieldMatcher.find())
            {
                currentField = fieldMatcher.group(1);
                currentBytes = new ArrayList<Byte>();
                line = line.substring(fieldMatcher.end()).trim();
            }

            // Collect hex values if in field
            if (currentField != null)
            {
                Matcher hexMatcher = hexPattern.matcher(line);
                while (hexMatcher.find())
                {
                    String hex = hexMatcher.group(1);
                    currentBytes.add(new Byte((byte)Integer.parseInt(hex, 16)));
                }

                // Check for field end
                if (line.indexOf("},") >= 0)
                {
                    setField(currentVector, currentField, currentBytes);
                    currentField = null;
                    currentBytes = null;
                }
                continue;
            }

            // End of test vector
            if (line.startsWith("},") && currentVector != null)
            {
                vectors.add(currentVector);
                currentVector = null;
            }
        }

        return vectors;
    }

    private static void setField(TestVector vector, String field, List<Byte> bytes)
    {
        byte[] byteArray = new byte[bytes.size()];
        for (int i = 0; i < bytes.size(); i++)
        {
            byteArray[i] = ((Byte)bytes.get(i)).byteValue();
        }

        if ("seed".equals(field))
        {
            vector.seed = byteArray;
        }
        else if ("pk".equals(field))
        {
            vector.pk = byteArray;
        }
        else if ("sk".equals(field))
        {
            vector.sk = byteArray;
        }
        else if ("msg".equals(field))
        {
            vector.msg = byteArray;
        }
        else if ("sig".equals(field))
        {
            vector.sig = byteArray;
        }
        // else ignore
    }

    static class TestVector
    {
        byte[] seed = new byte[0];
        byte[] pk = new byte[0];
        byte[] sk = new byte[0];
        byte[] msg = new byte[0];
        byte[] sig = new byte[0];
    }

    private static class InternalMLDSASigner
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
