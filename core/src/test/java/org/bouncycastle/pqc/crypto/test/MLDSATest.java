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
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
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
import org.bouncycastle.util.Strings;
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
            put("ML-DSA-44-WITH-SHA512", MLDSAParameters.ml_dsa_44_with_sha512);
            put("ML-DSA-65-WITH-SHA512", MLDSAParameters.ml_dsa_65_with_sha512);
            put("ML-DSA-87-WITH-SHA512", MLDSAParameters.ml_dsa_87_with_sha512);
        }
    };

    private static final MLDSAParameters[] PARAMETER_SETS = new MLDSAParameters[]
    {
        MLDSAParameters.ml_dsa_44,
        MLDSAParameters.ml_dsa_65,
        MLDSAParameters.ml_dsa_87,
        MLDSAParameters.ml_dsa_44_with_sha512,
        MLDSAParameters.ml_dsa_65_with_sha512,
        MLDSAParameters.ml_dsa_87_with_sha512,
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

                    Signer signer = parameters.isPreHash() ? (Signer)new HashMLDSASigner() : (Signer)new MLDSASigner();

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

    public void testQuickBrownFox()
        throws Exception
    {
        MLDSAKeyPairGenerator kpGen = new MLDSAKeyPairGenerator();

        kpGen.init(new MLDSAKeyGenerationParameters(new SecureRandom(), MLDSAParameters.ml_dsa_44));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
        MLDSAPublicKeyParameters pubKey = (MLDSAPublicKeyParameters)kp.getPublic();
        MLDSAPrivateKeyParameters privKey = (MLDSAPrivateKeyParameters)kp.getPrivate();

        byte[] msg = Strings.toByteArray("The quick brown fox");
        
        MLDSASigner signer = new MLDSASigner();

        // a "deterministic non-deterministic" signature initialisation.
        signer.init(true, new ParametersWithRandom(privKey, new FixedSecureRandom(Hex.decode("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"))));

        signer.update(msg, 0, msg.length);

        byte[] sig = signer.generateSignature();

        signer.init(false, pubKey);

        signer.update(msg, 0, msg.length);
        
        assertTrue("ML-DSA pubKey verification fails", signer.verifySignature(sig));

        PrivateKeyInfo privInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privKey);
        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pubKey);

        signer.init(true, PrivateKeyFactory.createKey(privInfo.getEncoded()));

        signer.update(msg, 0, msg.length);

        sig = signer.generateSignature();

        signer.init(false, PublicKeyFactory.createKey(pubInfo.getEncoded()));

        signer.update(msg, 0, msg.length);

        assertTrue("ML-DSA pubInfo verification fails", signer.verifySignature(sig));
    }

    public void testHashQuickBrownFox()
        throws Exception
    {
        byte[] expected = Hex.decode("8fbf0813a2bbe17e6a8bae1bbabc8704c59fe8910b8125426b6983eb50bb26c8b6249722fdea7c26" +
            "d731d7ca34ff100be306d6e7d11367e521e783eaf799cd8c235e45c663abf632aad1543c5faf13220af0eb06c7a0e7f0d1a6385db" +
            "c7fd10e58ed905850c9f9692ee8ca6642dcaa2bb1c6fea12bcbdc59d5a19c78ad1ec952dd4f22e651b2a42035b63cf5b510ab95cf" +
            "0c9a9fd77389d3fae9b42b123199c84a881ff30d7955c9841f5319d93a2c531d4d26bc6341f07c42acda0f5ec4cf70932dee57029" +
            "2699128d23f13ebc7d79bea2ff7ca352369e8b765e4e2fbcb2476f67b8cc8c84690be164e08c34be160806435993be3dce5455338" +
            "f14eb9f3918fd70b3753d374cdd84c350654d626881a0757a20244b86e7b5eba61a517e75f60e8658795133079e72b8bd4ce9fce5" +
            "c6af2a94988bb3141b38e8498d9f01a5cea3f2e24f5f4b6f64e2105010d9efe12693241149f115ca2a4086c456a9c852ade47f07f" +
            "0a78eaad4ed4a67a18ffb12f9f9eaa151b5973010f021c7f11a79df404b637fa4a777b3ef7dc724f191baac9dcf1a5e376978c146" +
            "c944c1f8f510412c05c872551e625b50426dc0433f89b89e67e6a6bcac4c1ab86c2da13cc0c52911319889cbecfde58c5af586ff0" +
            "b802aebc18b13014f5d189af1fe335a8fc3b37d90cbfaa89d7f6db2d9960787a49c7c632e339c75d3e618d55971885d4b45f58db4" +
            "c9a0fd50ababadde1ad2423178e0aa26e6f3d16f6b6f03f5dcb2e2eb54ca4aac44fabc92f6b4eea194174e15f5c26801cbb8519e0" +
            "4fc8bfbc8ddb63a3cfbe4ba2b92c7a38f3c64a1702ee785ccb745d3a6f5853521796526c1dfc2b0bfb774a2b1812524e6ab5f1513" +
            "7e22dcf70136274cb0181cb277303478d9a5153f56e9624ea9d2f838a9bc054e080973a86e174c72fa4bb78c01598ed3f5115939f" +
            "a172537d8799ada93af028b437048b0ae1b412fda490b3a5a292552927cf3ac540b1c67a97c2a7a94a6217a7a3fb7526c00a0d2a1" +
            "3e64aed1449c4029c4f9ef7b7c783929c37713c7cec1d55d1371dbe6ed00782e143e2ffb74cef8bec56c18e37e707e1a7e1fb04cc" +
            "0243f0002de7644e8780f215910754985ce1cf6b4e16c0656e2b9fe55fd4fa4340a4de5b01624afbc819902b90a17f0b8d55841f2" +
            "d3b41e43bc2727b3584ab49db5548169c5e207ace157469cc2d712e885e67735afbee9d5874b9bbac6a2d88cf8f957537c137e44b" +
            "105202942ecd3cfdd792b2657f025d48c4ea172052c7f33ef8f44e808b8888ca755414eb191a1c4cfed2ec6ab9dcf8aa1451b1640" +
            "b09f0022349091d19665fa3ca2d5f6ab9d883c0f03fabfe9565c7fc2a536ea73758fde6490f4de2e138f39a628175f2860e8694bd" +
            "b9c2045d218c78b29243ec2b40e5bebbe2688985e337b528df5549f4adc5a36dd04f7045bcc436676cc6c8b58b0e0205b7e1bea51" +
            "2749102883e4a65600dbc0744b03f2445950eeb536cdd8a88cb90d069c4205e4a0df830170c73779245729d896d14730dccce05a2" +
            "f1cab706e9929cc1ace014727d793b1f1f8b572bc7a760b15b325c5fa4b1511f253567caebaafe7acc0cc400e470cce9ed5121cab" +
            "a5371038906d8ee1643f336146ac6c743c2cc36912195da57aa1e557ee4040997583dfa77e0bbad48ff901ccf4f28b32b350f2383" +
            "812a5bb59211f8a90aefda3eef487de26746303676d5727a4ee39dd5a2d8e0072fcd4dab6e0af099aee6b379283272c3e56b5a55b" +
            "5b399832482ce311a3a629ea2e01cf4c236ca4bc807898fbce977521fb75ff02699f81a26bb69c7a69d46edbe4575ca2f11c361b2" +
            "69b918f7826c61496b815390efa51b92bc70b83c3fb1f311be5b23d7cf6fcf2d4877c3e7d439c4bac5aef81348688f97fd34b32c3" +
            "cb798feb38197c6754527a75cdb38e28647de8fec0d77cf3786cb5d339f6569ca879d941d88c8cc1194443c40c0ea86d5d4cad5f7" +
            "db683effde3339bfd63ad5cfb1caba26521e3c9c6d93d9c58e38431e40eab5f7cb2158c8f48e771f551e940a8607af3fd44aad01b" +
            "db9a04418aa03aefeceeef5bffed53cb37919d280f8f8d73965b02ca4515d26d33ae3afc97c779b72656ef34399e6508bdc9017bd" +
            "17d17ed675db7294fee98bf8fed1d84154949dfad1dba8168ee1f6d8828f80ad5a8c11aceffde97886fe2440f26b74436a8534f5a" +
            "c3de9fb61f3bd6c7ec5c761aaf0036be004a9d5d952b8719afd5cc6da5081632e1a10398fc7d7edabe522e75ea774819b1f2f558c" +
            "46c276eb6419504a4f9d1226544ebc4dccfa76cf26ad90661e9f78d563472e78cbed3833655983e9458aa71dcdb44fbe13295606b" +
            "fe7a02715044589652c641585e3950086e40e30885934b92e302ced1a94e95fffa9402afe1f359569a394019d5265862dce4b828b" +
            "657e43591d199b3500394f871155debc78922305c366350868bd81b06608a44ae383aacb8c0761bbf8bc7a1ee1b9bc7f5a9173544" +
            "f9987c9b15706a50a193c84dea3317b71e04369a52c32cc3d0eafa918eededa4dd321b1ba99a668c436f16f7f2f1a1ffe847f86a6" +
            "a1c39b857c118b848593265042eb4a1ba8a50303ad7034d2ab4960bdde975dbc3fa632777b8ff5c541af07e63ee05defa4aed3fda" +
            "7a69a67191617f92dac21e511db12fa95a5fe1ca37f184e02f58b835faa8ceadd8bfbd938626a7565007a5e022b97debe17328355" +
            "60e74bfd58c0eb0624fb36703d5aa05a71256cc432bc3850f7b982048c3329f717317e9a755440d1e6d3934dab952e23a993d15fa" +
            "d17534bc848060b51a15e670766c6bd3649957bf89e8fa34950fb1870089a5a9e82af440cd2571f2edaf68d4c1ff4a82c30d7e0b1" +
            "ee60483fbfc3eeff73c97c7ec9d07444d05624cebbe408f2d2fe6cb43c17d64f135b113538035d0ab73e9822b804b607e88ae999a" +
            "035ee22d7fda883c817ee5a027208bc22046585f24451f76dfc6e9da9e62085de03a323de7b7ba09cfe6bf1e3b1643dda9d1b798e" +
            "dc54741084595af65b36b9a323a90edefbd37e9038b68991846cb5ecc442785aa7fe6993cf3cda097c3417d234aeac8540e12f810" +
            "a07fd78548708a72092ff1c4b59f9f8c4023e89a344ded87915b65cfb5547a57cca97c33c861b04125550648434e960c144dc7cef" +
            "b12459b314da4d6cfdab29e2f4354dbe9ca93970964816c366924c84fd1e7f592cdd8fb37264d359d508bff7b2fd342d80375f87f" +
            "d76bdc5932517aebe6aed1a7e27632e980b63ec70af947130ab190de8bb309ad1528a51a5142215181b252b2f345f6a72aaabcaea" +
            "1114152f344c5764656a6c89a2a7b7b9badce5050a2661738f99b5babdbec4cccfdd35677b84b9c8d9deedf4f9fc0000000000000" +
            "0000000000000000000000000000e21303c");

        MLDSAKeyPairGenerator kpGen = new MLDSAKeyPairGenerator();

        kpGen.init(new MLDSAKeyGenerationParameters(new FixedSecureRandom(Hex.decode(
            "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")), MLDSAParameters.ml_dsa_44_with_sha512));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
        MLDSAPublicKeyParameters pubKey = (MLDSAPublicKeyParameters)kp.getPublic();
        MLDSAPrivateKeyParameters privKey = (MLDSAPrivateKeyParameters)kp.getPrivate();

        byte[] msg = Strings.toByteArray("The quick brown fox");

        HashMLDSASigner signer = new HashMLDSASigner();

        signer.init(true, new ParametersWithRandom(privKey, new FixedSecureRandom(Hex.decode("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"))));

        signer.update(msg, 0, msg.length);

        byte[] sig = signer.generateSignature();

        assertTrue("HashML-DSA sig mismatch", Arrays.areEqual(sig, expected));

        signer.init(false, pubKey);

        signer.update(msg, 0, msg.length);

        assertTrue("HashML-DSA pubKey verification fails", signer.verifySignature(sig));

        PrivateKeyInfo privInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privKey);
        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pubKey);

        signer.init(true, PrivateKeyFactory.createKey(privInfo.getEncoded()));

        signer.update(msg, 0, msg.length);

        sig = signer.generateSignature();

        signer.init(false, PublicKeyFactory.createKey(pubInfo.getEncoded()));

        signer.update(msg, 0, msg.length);

        assertTrue("HashML-DSA pubInfo verification fails", signer.verifySignature(sig));
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
