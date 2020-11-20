package org.bouncycastle.crypto.test;

import java.io.ByteArrayInputStream;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RC2CBCParameter;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * A test class for PKCS5 PBES2 with PBKDF2 (PKCS5 v2.0) using
 * test vectors provider at 
 * <a href=https://www.rsasecurity.com/rsalabs/pkcs/pkcs-5/index.html>
 * RSA's PKCS5 Page</a>
 * <br>
 * The vectors are Base 64 encoded and encrypted using the password "password"
 * (without quotes). They should all yield the same PrivateKeyInfo object.
 */
public class PKCS5Test
    extends SimpleTest
{
    /**
     * encrypted using des-cbc.
     */
    static byte[] sample1 = Base64.decode(
        "MIIBozA9BgkqhkiG9w0BBQ0wMDAbBgkqhkiG9w0BBQwwDgQIfWBDXwLp4K4CAggA"
      + "MBEGBSsOAwIHBAiaCF/AvOgQ6QSCAWDWX4BdAzCRNSQSANSuNsT5X8mWYO27mr3Y"
      + "9c9LoBVXGNmYWKA77MI4967f7SmjNcgXj3xNE/jmnVz6hhsjS8E5VPT3kfyVkpdZ"
      + "0lr5e9Yk2m3JWpPU7++v5zBkZmC4V/MwV/XuIs6U+vykgzMgpxQg0oZKS9zgmiZo"
      + "f/4dOCL0UtCDnyOSvqT7mCVIcMDIEKu8QbVlgZYBop08l60EuEU3gARUo8WsYQmO"
      + "Dz/ldx0Z+znIT0SXVuOwc+RVItC5T/Qx+aijmmpt+9l14nmaGBrEkmuhmtdvU/4v"
      + "aptewGRgmjOfD6cqK+zs0O5NrrJ3P/6ZSxXj91CQgrThGfOv72bUncXEMNtc8pks"
      + "2jpHFjGMdKufnadAD7XuMgzkkaklEXZ4f5tU6heIIwr51g0GBEGF96gYPFnjnSQM"
      + "75JE02Clo+DfcfXpcybPTwwFg2jd6JTTOfkdf6OdSlA/1XNK43FA");

    /**
     * encrypted using des-ede3-cbc.
     */
    static byte[] sample2 = Base64.decode(
        "MIIBpjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIeFeOWl1jywYCAggA"
      + "MBQGCCqGSIb3DQMHBAjUJ5eGBhQGtQSCAWBrHrRgqO8UUMLcWzZEtpk1l3mjxiF/"
      + "koCMkHsFwowgyWhEbgIkTgbSViK54LVK8PskekcGNLph+rB6bGZ7pPbL5pbXASJ8"
      + "+MkQcG3FZdlS4Ek9tTJDApj3O1UubZGFG4uvTlJJFbF1BOJ3MkY3XQ9Gl1qwv7j5"
      + "6e103Da7Cq9+oIDKmznza78XXQYrUsPo8mJGjUxPskEYlzwvHjKubRnYm/K6RKhi"
      + "5f4zX4BQ/Dt3H812ZjRXrsjAJP0KrD/jyD/jCT7zNBVPH1izBds+RwizyQAHwfNJ"
      + "BFR78TH4cgzB619X47FDVOnT0LqQNVd0O3cSwnPrXE9XR3tPayE+iOB15llFSmi8"
      + "z0ByOXldEpkezCn92Umk++suzIVj1qfsK+bv2phZWJPbLEIWPDRHUbYf76q5ArAr"
      + "u4xtxT/hoK3krEs/IN3d70qjlUJ36SEw1UaZ82PWhakQbdtu39ZraMJB");

    /**
     * encrypted using rc2-cbc.
     */
    static byte[] sample3 = Base64.decode(
        "MIIBrjBIBgkqhkiG9w0BBQ0wOzAeBgkqhkiG9w0BBQwwEQQIrHyQPBZqWLUCAggA"
      + "AgEQMBkGCCqGSIb3DQMCMA0CAToECEhbh7YZKiPSBIIBYCT1zp6o5jpFlIkgwPop"
      + "7bW1+8ACr4exqzkeb3WflQ8cWJ4cURxzVdvxUnXeW1VJdaQZtjS/QHs5GhPTG/0f"
      + "wtvnaPfwrIJ3FeGaZfcg2CrYhalOFmEb4xrE4KyoEQmUN8tb/Cg94uzd16BOPw21"
      + "RDnE8bnPdIGY7TyL95kbkqH23mK53pi7h+xWIgduW+atIqDyyt55f7WMZcvDvlj6"
      + "VpN/V0h+qxBHL274WA4dj6GYgeyUFpi60HdGCK7By2TBy8h1ZvKGjmB9h8jZvkx1"
      + "MkbRumXxyFsowTZawyYvO8Um6lbfEDP9zIEUq0IV8RqH2MRyblsPNSikyYhxX/cz"
      + "tdDxRKhilySbSBg5Kr8OfcwKp9bpinN96nmG4xr3Tch1bnVvqJzOQ5+Vva2WwVvH"
      + "2JkWvYm5WaANg4Q6bRxu9vz7DuhbJjQdZbxFezIAgrJdSe92B00jO/0Kny1WjiVO"
      + "6DA=");

    static byte[] result = Hex.decode(
        "30820155020100300d06092a864886f70d01010105000482013f3082013b020100024100"
      + "debbfc2c09d61bada2a9462f24224e54cc6b3cc0755f15ce318ef57e79df17026b6a85cc"
      + "a12428027245045df2052a329a2f9ad3d17b78a10572ad9b22bf343b020301000102402d"
      + "90a96adcec472743527bc023153d8f0d6e96b40c8ed228276d467d843306429f8670559b"
      + "f376dd41857f6397c2fc8d95e0e53ed62de420b855430ee4a1b8a1022100ffcaf0838239"
      + "31e073ff534f06a5d415b3d414bc614a4544a3dff7ed271817eb022100deea30242117db"
      + "2d3b8837f58f1da530ff83cf9283680da33683ec4e583610f1022100e6026381adb0a683"
      + "f16a8f4c096b462979b9e4277cc89f3ed8a905b46fa9ff9f02210097c146d4d1d2b3dbaf"
      + "53a504ff51674c5c271800de84d003f4f10ac6ab36e38102202bfa141f10bda874e1017d"
      + "845e82767c1c38e82745daf421f0c8cd09d7652387");

    private class PBETest
        extends SimpleTest
    {
        int                 id;
        BufferedBlockCipher cipher;
        byte[]              sample;
        int                 keySize;

        PBETest(
            int                 id,
            BufferedBlockCipher cipher,
            byte[]              sample,
            int                 keySize)
        {
            this.id = id;
            this.cipher = cipher;
            this.sample = sample;
            this.keySize = keySize;
        }

        public String getName()
        {
            return cipher.getUnderlyingCipher().getAlgorithmName() + " PKCS5S2 Test " + id;
        }

        public void performTest()
        {
            char[]                  password = { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
            PBEParametersGenerator  generator = new PKCS5S2ParametersGenerator();
            ByteArrayInputStream    bIn = new ByteArrayInputStream(sample);
            ASN1InputStream         dIn = new ASN1InputStream(bIn);
            EncryptedPrivateKeyInfo info = null;

            try
            {
                info = EncryptedPrivateKeyInfo.getInstance(dIn.readObject());
            }
            catch (Exception e)
            {
                fail("failed construction - exception " + e.toString(), e);
            }

            PBES2Parameters         alg = PBES2Parameters.getInstance(info.getEncryptionAlgorithm().getParameters());
            PBKDF2Params            func = PBKDF2Params.getInstance(alg.getKeyDerivationFunc().getParameters());
            EncryptionScheme        scheme = alg.getEncryptionScheme();
    
            if (func.getKeyLength() != null)
            {
                keySize = func.getKeyLength().intValue() * 8;
            }
    
            int     iterationCount = func.getIterationCount().intValue();
            byte[]  salt = func.getSalt();
    
            generator.init(
                PBEParametersGenerator.PKCS5PasswordToBytes(password),
                salt,
                iterationCount);
    
            CipherParameters    param;
    
            if (scheme.getAlgorithm().equals(PKCSObjectIdentifiers.RC2_CBC))
            {
                RC2CBCParameter rc2Params = RC2CBCParameter.getInstance(scheme.getParameters());
                byte[]  iv = rc2Params.getIV();
    
                param = new ParametersWithIV(generator.generateDerivedParameters(keySize), iv);
            }
            else
            {
                byte[]  iv = ASN1OctetString.getInstance(scheme.getParameters()).getOctets();

                param = new ParametersWithIV(generator.generateDerivedParameters(keySize), iv);
            }
    
            cipher.init(false, param);
    
            byte[]  data = info.getEncryptedData();
            byte[]  out = new byte[cipher.getOutputSize(data.length)];
            int     len = cipher.processBytes(data, 0, data.length, out, 0);
        
            try
            {
                len += cipher.doFinal(out, len);
            }
            catch (Exception e)
            {
                fail("failed doFinal - exception " + e.toString());
            }

            if (result.length != len)
            {
                fail("failed length");
            }

            for (int i = 0; i != len; i++)
            {
                if (out[i] != result[i])
                {
                    fail("failed comparison");
                }
            }
        }
    }

    public String getName()
    {
        return "PKCS5S2";
    }

    public void performTest()
        throws Exception
    {
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESEngine()));
        SimpleTest          test = new PBETest(0, cipher, sample1, 64);

        test.performTest();

        cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESedeEngine()));
        test = new PBETest(1, cipher, sample2, 192);

        test.performTest();

        cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new RC2Engine()));
        test = new PBETest(2, cipher, sample3, 0);
        test.performTest();

        //
        // RFC 3211 tests
        //
        char[]                  password = { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
        PBEParametersGenerator  generator = new PKCS5S2ParametersGenerator();

        byte[]  salt = Hex.decode("1234567878563412");

        generator.init(
                PBEParametersGenerator.PKCS5PasswordToBytes(password),
                salt,
                5);

        if (!areEqual(((KeyParameter)generator.generateDerivedParameters(64)).getKey(), Hex.decode("d1daa78615f287e6")))
        {
            fail("64 test failed");
        }

        password = "All n-entities must communicate with other n-entities via n-1 entiteeheehees".toCharArray();

        generator.init(
                PBEParametersGenerator.PKCS5PasswordToBytes(password),
                salt,
                500);

        if (!areEqual(((KeyParameter)generator.generateDerivedParameters(192)).getKey(), Hex.decode("6a8970bf68c92caea84a8df28510858607126380cc47ab2d")))
        {
            fail("192 test failed");
        }

        generator.init(PBEParametersGenerator.PKCS5PasswordToBytes(password), salt, 60000);
        if (!areEqual(((KeyParameter)generator.generateDerivedParameters(192)).getKey(), Hex.decode("29aaef810c12ecd2236bbcfb55407f9852b5573dc1c095bb")))
        {
            fail("192 (60000) test failed");
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new PKCS5Test());
    }
}
