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
import org.bouncycastle.crypto.CryptoException;
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
    public void testKeyGen()
        throws IOException
    {
        String[] files = new String[]{
            "keyGen_ML-DSA-44.txt",
            "keyGen_ML-DSA-65.txt",
            "keyGen_ML-DSA-87.txt",
        };

        MLDSAParameters[] params = new MLDSAParameters[]{
            MLDSAParameters.ml_dsa_44,
            MLDSAParameters.ml_dsa_65,
            MLDSAParameters.ml_dsa_87,
        };

        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            // System.out.println("testing: " + name);
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
                        MLDSAParameters parameters = params[fileIndex];

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
            // System.out.println("testing successful!");
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

        MLDSAParameters[] params = new MLDSAParameters[]{
            MLDSAParameters.ml_dsa_44,
            MLDSAParameters.ml_dsa_65,
            MLDSAParameters.ml_dsa_87,
        };

        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            // System.out.println("testing: " + name);
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

                        MLDSAParameters parameters = params[fileIndex];

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

        MLDSAParameters[] params = new MLDSAParameters[]{
            MLDSAParameters.ml_dsa_44,
            MLDSAParameters.ml_dsa_65,
            MLDSAParameters.ml_dsa_87,
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
                        boolean testPassed = Boolean.parseBoolean((String)buf.get("testPassed"));
                        String reason = buf.get("reason");
                        byte[] pk = Hex.decode((String)buf.get("pk"));
                        byte[] message = Hex.decode((String)buf.get("message"));
                        byte[] signature = Hex.decode((String)buf.get("signature"));

                        MLDSAParameters parameters = params[fileIndex];

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
            // System.out.println("testing successful!");
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


    public void testMLDSARandom()
    {

        MLDSAKeyPairGenerator keyGen = new MLDSAKeyPairGenerator();

        SecureRandom random = new SecureRandom();

        for (MLDSAParameters param : new MLDSAParameters[]{MLDSAParameters.ml_dsa_44, MLDSAParameters.ml_dsa_65, MLDSAParameters.ml_dsa_87})
        {
            keyGen.init(new MLDSAKeyGenerationParameters(random, param));
            for (int msgSize = 0; msgSize < 2049; )
            {
                byte[] msg = new byte[msgSize];
                if (msgSize < 128)
                {
                    msgSize += 1;
                }
                else
                {
                    msgSize += 12;
                }
                for (int i = 0; i != 100; i++)
                {
                    random.nextBytes(msg);
                    AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();

                    // sign
                    MLDSASigner signer = new MLDSASigner();
                    MLDSAPrivateKeyParameters skparam = (MLDSAPrivateKeyParameters)keyPair.getPrivate();
                    ParametersWithRandom skwrand = new ParametersWithRandom(skparam, random);
                    signer.init(true, skwrand);

                    signer.update(msg, 0, msg.length);

                    byte[] sigGenerated;
                    try
                    {
                        sigGenerated = signer.generateSignature();
                    }
                    catch (CryptoException e)
                    {
                        throw new RuntimeException(e);
                    }

                    // verify
                    MLDSASigner verifier = new MLDSASigner();
                    MLDSAPublicKeyParameters pkparam = (MLDSAPublicKeyParameters)keyPair.getPublic();
                    verifier.init(false, pkparam);

                    verifier.update(msg, 0, msg.length);

                    boolean ok = verifier.verifySignature(sigGenerated);

                    if (!ok)
                    {
                        System.out.println("Verify failed");
                        System.out.println("MSG:" + Hex.toHexString(msg));
                        System.out.println("SIG: " + Hex.toHexString(sigGenerated));
                        System.out.println("PK: " + Hex.toHexString(pkparam.getEncoded()));
                        System.out.println("SK: " + Hex.toHexString(skparam.getEncoded()));
                    }

                    assertTrue("count = " + i, ok);
                }
            }
        }
    }

    public void testSigGenCombinedVectorSet()
        throws IOException
    {

        Map<String, MLDSAParameters> parametersMap = new HashMap<String, MLDSAParameters>()
        {
            {
                put("ML-DSA-44", MLDSAParameters.ml_dsa_44);
                put("ML-DSA-65", MLDSAParameters.ml_dsa_65);
                put("ML-DSA-87", MLDSAParameters.ml_dsa_87);
            }
        };


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
                    boolean deterministic = Boolean.valueOf(buf.get("deterministic"));
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

                    MLDSAParameters parameters = parametersMap.get(buf.get("parameterSet"));

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
        Map<String, MLDSAParameters> parametersMap = new HashMap<String, MLDSAParameters>()
        {
            {
                put("ML-DSA-44", MLDSAParameters.ml_dsa_44);
                put("ML-DSA-65", MLDSAParameters.ml_dsa_65);
                put("ML-DSA-87", MLDSAParameters.ml_dsa_87);
            }
        };


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
            if (line.isEmpty())
            {
                if (!buf.isEmpty())
                {
                    boolean expectedResult = Boolean.parseBoolean((String)buf.get("testPassed"));

                    byte[] pk = Hex.decode((String)buf.get("pk"));
                    byte[] message = Hex.decode((String)buf.get("message"));
                    byte[] signature = Hex.decode((String)buf.get("signature"));

                    MLDSAParameters parameters = parametersMap.get(buf.get("parameterSet"));

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
