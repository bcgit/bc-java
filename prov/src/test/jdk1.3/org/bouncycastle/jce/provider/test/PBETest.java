package org.bouncycastle.jce.provider.test;

import java.security.AlgorithmParameters;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * test out the various PBE modes, making sure the JCE implementations
 * are compatible woth the light weight ones.
 */
public class PBETest implements Test
{
    private class OpenSSLTest
        implements Test
    {
        char[]    password;
        String    baseAlgorithm;
        String    algorithm;
        int       keySize;
        int       ivSize;
        
        OpenSSLTest(
            String    baseAlgorithm,
            String    algorithm,
            int       keySize,
            int       ivSize)
        {
            this.password = algorithm.toCharArray();
            this.baseAlgorithm = baseAlgorithm;
            this.algorithm = algorithm;
            this.keySize = keySize;
            this.ivSize = ivSize;
        }
        
        public String getName()
        {
            return "OpenSSLPBE";
        }
    
        public TestResult perform()
        {
            byte[] salt = new byte[16];
            int    iCount = 100;
            
            for (int i = 0; i != salt.length; i++)
            {
                salt[i] = (byte)i;
            }
            
            try
            {
                OpenSSLPBEParametersGenerator   pGen = new OpenSSLPBEParametersGenerator();
                
                pGen.init(
                        PBEParametersGenerator.PKCS5PasswordToBytes(password),
                        salt);
                
                ParametersWithIV params = (ParametersWithIV)pGen.generateDerivedParameters(keySize, ivSize);
                SecretKeySpec    encKey = new SecretKeySpec(((KeyParameter)params.getParameters()).getKey(), baseAlgorithm);
                
                Cipher          c;
                
                if (baseAlgorithm.equals("RC4"))
                {
                    c = Cipher.getInstance(baseAlgorithm, "BC");
                    
                    c.init(Cipher.ENCRYPT_MODE, encKey);
                }
                else
                {
                    c = Cipher.getInstance(baseAlgorithm + "/CBC/PKCS7Padding", "BC");
                    
                    c.init(Cipher.ENCRYPT_MODE, encKey, new IvParameterSpec(params.getIV()));
                }
                
                byte[]              enc = c.doFinal(salt);
                
                c = Cipher.getInstance(algorithm, "BC");
                
                PBEKeySpec          keySpec = new PBEKeySpec(password);
                SecretKeyFactory    fact = SecretKeyFactory.getInstance(algorithm, "BC");
                
                c.init(Cipher.DECRYPT_MODE, fact.generateSecret(keySpec), new PBEParameterSpec(salt, iCount));
                
                byte[]          dec = c.doFinal(enc);
                
                if (!arrayEquals(salt, dec))
                {
                    return new SimpleTestResult(false, getName() + ": " + algorithm + "failed encryption/decryption test");
                }
                
                return new SimpleTestResult(true, getName() + ": Okay");
            }
            catch (Exception e)
            {
                return new SimpleTestResult(false, getName() + ": " + algorithm + " failed - exception " + e, e);
            }
        }
    }

    private class PKCS12Test
        implements Test
    {
        char[]    password;
        String    baseAlgorithm;
        String    algorithm;
        Digest    digest;
        int       keySize;
        int       ivSize;
        
        PKCS12Test(
            String    baseAlgorithm,
            String    algorithm,
            Digest    digest,
            int       keySize,
            int       ivSize)
        {
            this.password = algorithm.toCharArray();
            this.baseAlgorithm = baseAlgorithm;
            this.algorithm = algorithm;
            this.digest = digest;
            this.keySize = keySize;
            this.ivSize = ivSize;
        }
        
        public String getName()
        {
            return "PKCS12PBE";
        }

        public TestResult perform()
        {
            byte[] salt = new byte[digest.getDigestSize()];
            int    iCount = 100;
            
            digest.doFinal(salt, 0);
            
            try
            {
                PKCS12ParametersGenerator   pGen = new PKCS12ParametersGenerator(digest);
                
                pGen.init(
                        PBEParametersGenerator.PKCS12PasswordToBytes(password),
                        salt,
                        iCount);
                
                ParametersWithIV params = (ParametersWithIV)pGen.generateDerivedParameters(keySize, ivSize);
                
                SecretKeySpec   encKey = new SecretKeySpec(((KeyParameter)params.getParameters()).getKey(), baseAlgorithm);
                
                Cipher          c;
                
                if (baseAlgorithm.equals("RC4"))
                {
                    c = Cipher.getInstance(baseAlgorithm, "BC");
                    
                    c.init(Cipher.ENCRYPT_MODE, encKey);
                }
                else
                {
                    c = Cipher.getInstance(baseAlgorithm + "/CBC/PKCS7Padding", "BC");
                    
                    c.init(Cipher.ENCRYPT_MODE, encKey, new IvParameterSpec(params.getIV()));
                }
                
                byte[]          enc = c.doFinal(salt);
                
                c = Cipher.getInstance(algorithm, "BC");
                
                PBEKeySpec          keySpec = new PBEKeySpec(password);
                SecretKeyFactory    fact = SecretKeyFactory.getInstance(algorithm, "BC");
                
                c.init(Cipher.DECRYPT_MODE, fact.generateSecret(keySpec), new PBEParameterSpec(salt, iCount));
                
                byte[]          dec = c.doFinal(enc);
                
                if (!arrayEquals(salt, dec))
                {
                    return new SimpleTestResult(false, getName() + ": " + algorithm + "failed encryption/decryption test");
                }
                
                //
                // get the parameters
                //
                AlgorithmParameters param = c.getParameters();
                PBEParameterSpec    spec = (PBEParameterSpec)param.getParameterSpec(PBEParameterSpec.class);
                
                if (!arrayEquals(salt, spec.getSalt()))
                {
                    return new SimpleTestResult(false, getName() + ": " + algorithm + "failed salt test");
                }
                
                if (iCount != spec.getIterationCount())
                {
                    return new SimpleTestResult(false, getName() + ": " + algorithm + "failed count test");
                }
                
                //
                // try using parameters
                //
                keySpec = new PBEKeySpec(password);
                
                c.init(Cipher.DECRYPT_MODE, fact.generateSecret(keySpec), param);
                
                dec = c.doFinal(enc);
                
                if (!arrayEquals(salt, dec))
                {
                    return new SimpleTestResult(false, getName() + ": " + algorithm + "failed encryption/decryption test");
                }
                
                return new SimpleTestResult(true, getName() + ": Okay");
            }
            catch (Exception e)
            {
                return new SimpleTestResult(false, getName() + ": " + algorithm + " failed - exception " + e, e);
            }
        }
    }
    
    private PKCS12Test[] pkcs12Tests = {
        new PKCS12Test("DESede", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC",  new SHA1Digest(),   192,  64),
        new PKCS12Test("DESede", "PBEWITHSHAAND2-KEYTRIPLEDES-CBC",  new SHA1Digest(),   128,  64),
        new PKCS12Test("RC4",    "PBEWITHSHAAND128BITRC4",           new SHA1Digest(),   128,   0),
        new PKCS12Test("RC4",    "PBEWITHSHAAND40BITRC4",            new SHA1Digest(),    40,   0),
        new PKCS12Test("RC2",    "PBEWITHSHAAND128BITRC2-CBC",       new SHA1Digest(),   128,  64),
        new PKCS12Test("RC2",    "PBEWITHSHAAND40BITRC2-CBC",        new SHA1Digest(),    40,  64),
        new PKCS12Test("AES",    "PBEWithSHA1And128BitAES-CBC-BC",   new SHA1Digest(),   128, 128),
        new PKCS12Test("AES",    "PBEWithSHA1And192BitAES-CBC-BC",   new SHA1Digest(),   192, 128),
        new PKCS12Test("AES",    "PBEWithSHA1And256BitAES-CBC-BC",   new SHA1Digest(),   256, 128),
        new PKCS12Test("AES",    "PBEWithSHA256And128BitAES-CBC-BC", new SHA256Digest(), 128, 128),
        new PKCS12Test("AES",    "PBEWithSHA256And192BitAES-CBC-BC", new SHA256Digest(), 192, 128),   
        new PKCS12Test("AES",    "PBEWithSHA256And256BitAES-CBC-BC", new SHA256Digest(), 256, 128)
    };
    
    private OpenSSLTest openSSLTests[] = {
        new OpenSSLTest("AES", "PBEWITHMD5AND128BITAES-CBC-OPENSSL", 128, 128),
        new OpenSSLTest("AES", "PBEWITHMD5AND192BITAES-CBC-OPENSSL", 192, 128),
        new OpenSSLTest("AES", "PBEWITHMD5AND256BITAES-CBC-OPENSSL", 256, 128)
    };

    static byte[]   message = Hex.decode("4869205468657265");
    
    private byte[] hMac1 = Hex.decode("bcc42174ccb04f425d9a5c8c4a95d6fd7c372911");
    private byte[] hMac2 = Hex.decode("cb1d8bdb6aca9e3fa8980d6eb41ab28a7eb2cfd6");
    
    private Cipher makePBECipher(
        String  algorithm,
        int     mode,
        char[]  password,
        byte[]  salt,
        int     iterationCount)
        throws Exception
    {
        PBEKeySpec          pbeSpec = new PBEKeySpec(password);
        SecretKeyFactory    keyFact = SecretKeyFactory.getInstance(algorithm, "BC");
        PBEParameterSpec    defParams = new PBEParameterSpec(salt, iterationCount);

        Cipher cipher = Cipher.getInstance(algorithm, "BC");

        cipher.init(mode, keyFact.generateSecret(pbeSpec), defParams);

        return cipher;
    }

    private boolean arrayEquals(
        byte[]  a,
        byte[]  b)
    {
        if (a.length != b.length)
        {
            return false;
        }

        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }
    
    public TestResult testPBEHMac(
        String  hmacName,
        byte[]  output)
    {
        SecretKey           key;
        byte[]              out;
        Mac                 mac;

        try
        {
            SecretKeyFactory    fact = SecretKeyFactory.getInstance(hmacName, "BC");

            key = fact.generateSecret(new PBEKeySpec("hello".toCharArray()));
            
            mac = Mac.getInstance(hmacName, "BC");
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": Failed - exception " + e.toString(), e);
        }

        try
        {
            mac.init(key, new PBEParameterSpec(new byte[20], 100));
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": Failed - exception " + e.toString(), e);
        }

        mac.reset();
        
        mac.update(message, 0, message.length);

        out = mac.doFinal();

        if (!arrayEquals(out, output))
        {
            return new SimpleTestResult(false, getName() + ": Failed - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(out)));
        }
        
        return new SimpleTestResult(true, getName() + ": Okay");
    }
    
    public TestResult perform()
    {
        byte[] input = Hex.decode("1234567890abcdefabcdef1234567890fedbca098765");

        try
        {
            //
            // DES
            //
            Cipher  cEnc = Cipher.getInstance("DES/CBC/PKCS7Padding", "BC");

            cEnc.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(Hex.decode("30e69252758e5346"), "DES"),
                new IvParameterSpec(Hex.decode("7c1c1ab9c454a688")));

            byte[]  out = cEnc.doFinal(input);

            char[]  password = { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };

            Cipher  cDec = makePBECipher(
                                "PBEWithSHA1AndDES",
                                Cipher.DECRYPT_MODE,
                                password,
                                Hex.decode("7d60435f02e9e0ae"),
                                2048);

            byte[]  in = cDec.doFinal(out);

            if (!arrayEquals(input, in))
            {
                return new SimpleTestResult(false, getName() + ": DES failed");
            }

            //
            // DESede
            //
            cEnc = Cipher.getInstance("DESede/CBC/PKCS7Padding", "BC");

            cEnc.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(Hex.decode("732f2d33c801732b7206756cbd44f9c1c103ddd97c7cbe8e"), "DES"),
                new IvParameterSpec(Hex.decode("b07bf522c8d608b8")));

            out = cEnc.doFinal(input);

            cDec = makePBECipher(
                                "PBEWithSHAAnd3-KeyTripleDES-CBC",
                                Cipher.DECRYPT_MODE,
                                password,
                                Hex.decode("7d60435f02e9e0ae"),
                                2048);

            in = cDec.doFinal(out);

            if (!arrayEquals(input, in))
            {
                return new SimpleTestResult(false, getName() + ": DESede failed");
            }

            //
            // 40Bit RC2
            //
            cEnc = Cipher.getInstance("RC2/CBC/PKCS7Padding", "BC");

            cEnc.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(Hex.decode("732f2d33c8"), "RC2"),
                new IvParameterSpec(Hex.decode("b07bf522c8d608b8")));

            out = cEnc.doFinal(input);

            cDec = makePBECipher(
                                "PBEWithSHAAnd40BitRC2-CBC",
                                Cipher.DECRYPT_MODE,
                                password,
                                Hex.decode("7d60435f02e9e0ae"),
                                2048);

            in = cDec.doFinal(out);

            if (!arrayEquals(input, in))
            {
                return new SimpleTestResult(false, getName() + ": RC2 failed");
            }

            //
            // 128bit RC4
            //
            cEnc = Cipher.getInstance("RC4", "BC");

            cEnc.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(Hex.decode("732f2d33c801732b7206756cbd44f9c1"), "RC4"));

            out = cEnc.doFinal(input);

            cDec = makePBECipher(
                                "PBEWithSHAAnd128BitRC4",
                                Cipher.DECRYPT_MODE,
                                password,
                                Hex.decode("7d60435f02e9e0ae"),
                                2048);

            in = cDec.doFinal(out);

            if (!arrayEquals(input, in))
            {
                return new SimpleTestResult(false, getName() + ": RC4 failed");
            }

            for (int i = 0; i != pkcs12Tests.length; i++)
            {
                TestResult  res = pkcs12Tests[i].perform();
                if (!res.isSuccessful())
                {
                    return res;
                }
            }
            
            for (int i = 0; i != openSSLTests.length; i++)
            {
                TestResult  res = openSSLTests[i].perform();
                if (!res.isSuccessful())
                {
                    return res;
                }
            }
            
            TestResult res = testPBEHMac("PBEWithHMacSHA1", hMac1);

            if (!res.isSuccessful())
            {
                return res;
            }
            
            res = testPBEHMac("PBEWithHMacRIPEMD160", hMac2);

            if (!res.isSuccessful())
            {
                return res;
            }
            
            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": exception - " + e.toString(), e);
        }
    }

    public String getName()
    {
        return "PBETest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new PBETest();
        TestResult      result = test.perform();
        
        System.out.println(result.toString());
    }
}
