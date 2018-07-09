package org.bouncycastle.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ua.DSTU4145NamedCurves;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jcajce.spec.DSTU4145ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Base64;


public class GeneralKeyTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testDH()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DH", "BC");

        doBasicTest("DH", kpGen.generateKeyPair());

        byte[] encPub = Base64.decode("MIIDbzCCAmIGByqGSM4+AgEwggJVAoIBAQCVR1z12T5ZbD/NHZAq3QL0J/XzxyEDE7tF+01bsuX+HL1n" +
            "jNS73YTJg2vh8xwHd3Ja62wvw4uF9IB2+na82BRsyJpvsvcG3XGYmMIIPcjYlvhAYuLJyU0TewVKjYCWrbjVGVI5juyoUqCvEt+D5HWqZd" +
            "TsDDipVg1WYRhv+Yufyetg7uiwMDdrI2vHO+Os29dP1hwdJHX6MHe48IBGeIH/fhylb+4GbXlQat5R7btUQ6Vjkn28S6UgCGdGF1yIhZJe" +
            "vGTGFHkGdzSWmQy3FOxmcwTiYfruM7PL3wCODD+pBlDZfTkJySdb9KyG/8s9A+bfyK2lk0JC3W07zKKkBssLAoIBAELeu52ls9iMyVbgh4" +
            "fsPzoJu6X0i4iadKr1MXSqD75+PFuPzXpTvvVjsOmFYDKJYKlRf0AU0zJfx5Yr8eBJNw120TFKdhN+eS8/DbhZ0JXkpbkyAk8Hns8u8Jx5" +
            "dFKwdw4TUHgu1X3feUl53O8jy5bxgwYZZcTryTycccVrkllVp1+UzM8USaxD1YbQvu5DJRsLIoc0nWjeDRREA/E+gC9BRtiC4FevGbb2J1" +
            "xmdsj6DjyicToyV/0bJ9Bjn2leNH2NHPmsgZomypsEyw65t7A1mI0Vu6xlISpVI5z8flj6441yUKuZkf+8lxNAJf6M4ExDma2WVpvpGlRv" +
            "SXhpPHoCIQD4GDZoul/Fuwa1mB5ti3ldMLiXjUPKDsVy434Jk5qXczAnAyEAsLRBdgG1nLydisj5Ncra7E9fuy8jeFYJrkZnSNm1pTYCAg" +
            "HxA4IBBQACggEAQad+gehy9k1NNz8U5JHZIDvxm8v8RI9VLgggIr9nVs9Sxp5txpLNZ6SO0mh6U/BThwRXW1HvR6eR/WrtizfMQ/EZJdUT" +
            "8Tm5tEKEqA6gkTlyX/nLtsJWFuzLc6cYhdnCmP7tDWFBg7qhPqE6Aaj7E/IORPZXH/8NuE3XmhuRoba6x+u7wWMdEXhRYsIIH1xxCQuJCJ" +
            "/gIeDa+jtXckXQp/e4yUBB4yZ/GRxDiNfKP1A8m6Qqqf1g7zWN+r3gIEpB74pu6X4p/nyA3tqAI0rBao2rIPe7MaQtml6KsvH9MKaimGeC" +
            "BcmlncsqZZXbvFOYiu4fYKszqx+K7z8bWAuwzA==");
        byte[] encPriv = Base64.decode("MIIDcgIBADCCAmIGByqGSM4+AgEwggJVAoIBAQCVR1z12T5ZbD/NHZAq3QL0J/XzxyEDE7tF+01bsuX" +
            "+HL1njNS73YTJg2vh8xwHd3Ja62wvw4uF9IB2+na82BRsyJpvsvcG3XGYmMIIPcjYlvhAYuLJyU0TewVKjYCWrbjVGVI5juyoUqCvEt+D5" +
            "HWqZdTsDDipVg1WYRhv+Yufyetg7uiwMDdrI2vHO+Os29dP1hwdJHX6MHe48IBGeIH/fhylb+4GbXlQat5R7btUQ6Vjkn28S6UgCGdGF1y" +
            "IhZJevGTGFHkGdzSWmQy3FOxmcwTiYfruM7PL3wCODD+pBlDZfTkJySdb9KyG/8s9A+bfyK2lk0JC3W07zKKkBssLAoIBAELeu52ls9iMy" +
            "Vbgh4fsPzoJu6X0i4iadKr1MXSqD75+PFuPzXpTvvVjsOmFYDKJYKlRf0AU0zJfx5Yr8eBJNw120TFKdhN+eS8/DbhZ0JXkpbkyAk8Hns8" +
            "u8Jx5dFKwdw4TUHgu1X3feUl53O8jy5bxgwYZZcTryTycccVrkllVp1+UzM8USaxD1YbQvu5DJRsLIoc0nWjeDRREA/E+gC9BRtiC4FevG" +
            "bb2J1xmdsj6DjyicToyV/0bJ9Bjn2leNH2NHPmsgZomypsEyw65t7A1mI0Vu6xlISpVI5z8flj6441yUKuZkf+8lxNAJf6M4ExDma2WVpv" +
            "pGlRvSXhpPHoCIQD4GDZoul/Fuwa1mB5ti3ldMLiXjUPKDsVy434Jk5qXczAnAyEAsLRBdgG1nLydisj5Ncra7E9fuy8jeFYJrkZnSNm1p" +
            "TYCAgHxBIIBBQKCAQEA8o/I0VTKbn0VaBgiQwRgM3++T/2PxGJ8wQkQALnq4YSmd4QRDIlYXlaq4UxJgg3A/F/udNpSvmU7ecj/KjHvV8T" +
            "sLnGHY2oEKoE0feUgUmArcW5SbJ1Wj41QYBMjhTFNrqGdXUM8l8JA/pG+3QJrG0XcnaC0G25LlWTfEVJsKg2pJoVW2tVPAbUabi9jcbP7Q" +
            "Bgv5qELgBGOJ7V+jX5cxmReXEgOh+pyiBbN93KtRJA4EkyZgUzNs9AibqPnyb0cK54oJu8vVelUR1adtbBK9y/mwG3w1Vqh5UbylfT7wU7" +
            "YqXJL0kAwj7T4qQqb2aY1IjWfxCyxqMvHQw7VweFAcg==");

        KeyFactory keyFact = KeyFactory.getInstance("DH", "BC");

        PublicKey pub = keyFact.generatePublic(new X509EncodedKeySpec(encPub));
        PrivateKey priv = keyFact.generatePrivate(new PKCS8EncodedKeySpec(encPriv));
       
        assertTrue(pub.toString().startsWith("DH Public Key [2d:41:52:69:c3:c1:13:f1:18:69:f3:6e:49:6e:55:8a:d7:4e:67:54]"));
        assertTrue(pub.toString().contains("    Y: 41a77e81e872f64d4d373f14e491d9203bf19bcbfc448f552e082022bf6756cf52c69e6dc692cd67a48ed2687a53f0538704575b51ef47a791fd6aed8b37cc43f11925d513f139b9b44284a80ea09139725ff9cbb6c25616eccb73a71885d9c298feed0d614183baa13ea13a01a8fb13f20e44f6571fff0db84dd79a1b91a1b6bac7ebbbc1631d11785162c2081f5c71090b89089fe021e0dafa3b577245d0a7f7b8c94041e3267f191c4388d7ca3f503c9ba42aa9fd60ef358dfabde0204a41ef8a6ee97e29fe7c80deda80234ac16a8dab20f7bb31a42d9a5e8ab2f1fd30a6a298678205c9a59dcb2a6595dbbc53988aee1f60ab33ab1f8aef3f1b580bb0cc"));
        assertTrue(priv.toString().startsWith("DH Private Key [2d:41:52:69:c3:c1:13:f1:18:69:f3:6e:49:6e:55:8a:d7:4e:67:54]"));
        assertTrue(priv.toString().contains("    Y: 41a77e81e872f64d4d373f14e491d9203bf19bcbfc448f552e082022bf6756cf52c69e6dc692cd67a48ed2687a53f0538704575b51ef47a791fd6aed8b37cc43f11925d513f139b9b44284a80ea09139725ff9cbb6c25616eccb73a71885d9c298feed0d614183baa13ea13a01a8fb13f20e44f6571fff0db84dd79a1b91a1b6bac7ebbbc1631d11785162c2081f5c71090b89089fe021e0dafa3b577245d0a7f7b8c94041e3267f191c4388d7ca3f503c9ba42aa9fd60ef358dfabde0204a41ef8a6ee97e29fe7c80deda80234ac16a8dab20f7bb31a42d9a5e8ab2f1fd30a6a298678205c9a59dcb2a6595dbbc53988aee1f60ab33ab1f8aef3f1b580bb0cc"));
    }

    public void testDSA()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DSA", "BC");

        doBasicTest("DSA", kpGen.generateKeyPair());

        byte[] encPub = Base64.decode("MIIDRjCCAjkGByqGSM44BAEwggIsAoIBAQCVR1z12T5ZbD/NHZAq3QL0J/XzxyEDE7tF+01bsuX+HL1n" +
            "jNS73YTJg2vh8xwHd3Ja62wvw4uF9IB2+na82BRsyJpvsvcG3XGYmMIIPcjYlvhAYuLJyU0TewVKjYCWrbjVGVI5juyoUqCvEt+D5HWqZd" +
            "TsDDipVg1WYRhv+Yufyetg7uiwMDdrI2vHO+Os29dP1hwdJHX6MHe48IBGeIH/fhylb+4GbXlQat5R7btUQ6Vjkn28S6UgCGdGF1yIhZJe" +
            "vGTGFHkGdzSWmQy3FOxmcwTiYfruM7PL3wCODD+pBlDZfTkJySdb9KyG/8s9A+bfyK2lk0JC3W07zKKkBssLAiEA+Bg2aLpfxbsGtZgebY" +
            "t5XTC4l41Dyg7FcuN+CZOal3MCggEAQt67naWz2IzJVuCHh+w/Ogm7pfSLiJp0qvUxdKoPvn48W4/NelO+9WOw6YVgMolgqVF/QBTTMl/H" +
            "livx4Ek3DXbRMUp2E355Lz8NuFnQleSluTICTweezy7wnHl0UrB3DhNQeC7Vfd95SXnc7yPLlvGDBhllxOvJPJxxxWuSWVWnX5TMzxRJrE" +
            "PVhtC+7kMlGwsihzSdaN4NFEQD8T6AL0FG2ILgV68ZtvYnXGZ2yPoOPKJxOjJX/Rsn0GOfaV40fY0c+ayBmibKmwTLDrm3sDWYjRW7rGUh" +
            "KlUjnPx+WPrjjXJQq5mR/7yXE0Al/ozgTEOZrZZWm+kaVG9JeGk8egOCAQUAAoIBABu9EnYG2X4u8gzDH1bTzc05pK75MP4L+7YIJ7VwY0" +
            "+ufBxle9q9Jpl8fO8CDIv1H+Gj/+ZkdL8CejCpTwG0MQ5a+apGoQ9yw0qyaeaFEcXXhFSoLIBW4BXyoN2aBsksdBZET1JTwwWBfVq34LC0" +
            "l3I19ukASem4VPEbmzSgPyouDJ33gzUZJSzaeG2WFPxeMGc37S4XWu7XZLMtmNYye5rjyWl+A143uXtkyzpRNFcJByQjoDpAz132nnq2g1" +
            "OvPW+osjv/U8MAO2bwAXPGbcyuLKDj35vjm9x+Xuh4vfrzATIkF2uhRpdRO5O41oa3IaH3G54aSfJCLStr/8xHQPs=");
        byte[] encPriv = Base64.decode("MIICZQIBADCCAjkGByqGSM44BAEwggIsAoIBAQCVR1z12T5ZbD/NHZAq3QL0J/XzxyEDE7tF+01bsuX" +
            "+HL1njNS73YTJg2vh8xwHd3Ja62wvw4uF9IB2+na82BRsyJpvsvcG3XGYmMIIPcjYlvhAYuLJyU0TewVKjYCWrbjVGVI5juyoUqCvEt+D5" +
            "HWqZdTsDDipVg1WYRhv+Yufyetg7uiwMDdrI2vHO+Os29dP1hwdJHX6MHe48IBGeIH/fhylb+4GbXlQat5R7btUQ6Vjkn28S6UgCGdGF1y" +
            "IhZJevGTGFHkGdzSWmQy3FOxmcwTiYfruM7PL3wCODD+pBlDZfTkJySdb9KyG/8s9A+bfyK2lk0JC3W07zKKkBssLAiEA+Bg2aLpfxbsGt" +
            "ZgebYt5XTC4l41Dyg7FcuN+CZOal3MCggEAQt67naWz2IzJVuCHh+w/Ogm7pfSLiJp0qvUxdKoPvn48W4/NelO+9WOw6YVgMolgqVF/QBT" +
            "TMl/Hlivx4Ek3DXbRMUp2E355Lz8NuFnQleSluTICTweezy7wnHl0UrB3DhNQeC7Vfd95SXnc7yPLlvGDBhllxOvJPJxxxWuSWVWnX5TMz" +
            "xRJrEPVhtC+7kMlGwsihzSdaN4NFEQD8T6AL0FG2ILgV68ZtvYnXGZ2yPoOPKJxOjJX/Rsn0GOfaV40fY0c+ayBmibKmwTLDrm3sDWYjRW" +
            "7rGUhKlUjnPx+WPrjjXJQq5mR/7yXE0Al/ozgTEOZrZZWm+kaVG9JeGk8egQjAiEAlomaJBRJqjzpFwjSFMTXpEXpEcm2VmYhTGAHObt/L" +
            "+w=");

        KeyFactory keyFact = KeyFactory.getInstance("DSA", "BC");

        PublicKey pub = keyFact.generatePublic(new X509EncodedKeySpec(encPub));
        PrivateKey priv = keyFact.generatePrivate(new PKCS8EncodedKeySpec(encPriv));

        assertTrue(pub.toString().startsWith("DSA Public Key [0d:64:94:81:01:3d:2d:30:82:00:4b:67:a1:23:45:56:fe:52:11:18]"));
        assertTrue(pub.toString().contains("    Y: 1bbd127606d97e2ef20cc31f56d3cdcd39a4aef930fe0bfbb60827b570634fae7c1c657bdabd26997c7cef020c8bf51fe1a3ffe66474bf027a30a94f01b4310e5af9aa46a10f72c34ab269e68511c5d78454a82c8056e015f2a0dd9a06c92c7416444f5253c305817d5ab7e0b0b4977235f6e90049e9b854f11b9b34a03f2a2e0c9df7833519252cda786d9614fc5e306737ed2e175aeed764b32d98d6327b9ae3c9697e035e37b97b64cb3a51345709072423a03a40cf5df69e7ab68353af3d6fa8b23bff53c3003b66f00173c66dccae2ca0e3df9be39bdc7e5ee878bdfaf3013224176ba14697513b93b8d686b721a1f71b9e1a49f2422d2b6bffcc4740fb"));
        assertTrue(priv.toString().startsWith("DSA Private Key [0d:64:94:81:01:3d:2d:30:82:00:4b:67:a1:23:45:56:fe:52:11:18]"));
        assertTrue(priv.toString().contains("    Y: 1bbd127606d97e2ef20cc31f56d3cdcd39a4aef930fe0bfbb60827b570634fae7c1c657bdabd26997c7cef020c8bf51fe1a3ffe66474bf027a30a94f01b4310e5af9aa46a10f72c34ab269e68511c5d78454a82c8056e015f2a0dd9a06c92c7416444f5253c305817d5ab7e0b0b4977235f6e90049e9b854f11b9b34a03f2a2e0c9df7833519252cda786d9614fc5e306737ed2e175aeed764b32d98d6327b9ae3c9697e035e37b97b64cb3a51345709072423a03a40cf5df69e7ab68353af3d6fa8b23bff53c3003b66f00173c66dccae2ca0e3df9be39bdc7e5ee878bdfaf3013224176ba14697513b93b8d686b721a1f71b9e1a49f2422d2b6bffcc4740fb"));
    }

    public void testDstu4145()
        throws Exception
    {
        ECDomainParameters ecDP = DSTU4145NamedCurves.getByOID(UAObjectIdentifiers.dstu4145le.branch("2.2"));
        ECCurve curve = ecDP.getCurve();

        // NOTE: For some reason this test uses an alternate base-point to the registry curve
        ecDP = new ECDomainParameters(curve,
            curve.createPoint(new BigInteger("BE6628EC3E67A91A4E470894FBA72B52C515F8AEE9", 16), new BigInteger("D9DEEDF655CF5412313C11CA566CDC71F4DA57DB45C", 16)),
            ecDP.getN(), ecDP.getH(), ecDP.getSeed());

        DSTU4145ParameterSpec spec = new DSTU4145ParameterSpec(ecDP);

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DSTU4145", "BC");

        kpGen.initialize(spec);

        doBasicTest("DSTU4145", kpGen.generateKeyPair());

        byte[] encPub = Base64.decode("MIGMMG8GDSqGJAIBAQEBAwEBAQEwXjBcMA8CAgCtMAkCAQECAQICAQoCAQAEFhCFdsgEmdsvwW7d9oU7" +
            "uyePa2+0N9kCFggAAAAAAAAAAAAAGJtOZ2BuOCW7KDEEFgC+ZijsPmepGk5HCJT7pytSxRX4rukDGQAEFgojyiWbwNI5uQ/H6/7tj5c1iJ" +
            "6YMa4=");
        byte[] encPriv = Base64.decode("MIH1AgEAMG8GDSqGJAIBAQEBAwEBAQEwXjBcMA8CAgCtMAkCAQECAQICAQoCAQAEFhCFdsgEmdsvwW7" +
            "d9oU7uyePa2+0N9kCFggAAAAAAAAAAAAAGJtOZ2BuOCW7KDEEFgC+ZijsPmepGk5HCJT7pytSxRX4rukEfzB9AgEBBBYA8jtdMuBv99mSm" +
            "oocSNbxaJd+UvHioGAwXjBcMA8CAgCtMAkCAQECAQICAQoCAQAEFhCFdsgEmdsvwW7d9oU7uyePa2+0N9kCFggAAAAAAAAAAAAAGJtOZ2B" +
            "uOCW7KDEEFgC+ZijsPmepGk5HCJT7pytSxRX4ruk=");

        KeyFactory keyFact = KeyFactory.getInstance("DSTU4145", "BC");

        PublicKey pub = keyFact.generatePublic(new X509EncodedKeySpec(encPub));
        PrivateKey priv = keyFact.generatePrivate(new PKCS8EncodedKeySpec(encPriv));

        assertTrue(pub.toString().startsWith("DSTU4145 Public Key [9c:8e:34:24:8c:80:da:36:e1:e6:c1:39:70:97:c8:31:24:f7:69:7d]"));
        assertTrue(pub.toString().contains("    X: a23ca259bc0d239b90fc7ebfeed8f9735889e9831af"));
        assertTrue(pub.toString().contains("    Y: df30da8281430f4e17221ceea3e21ebe3644e7c9d05"));
        assertTrue(priv.toString().startsWith("DSTU4145 Private Key [88:51:e7:8d:42:e9:ca:b6:3d:a8:51:de:06:b6:73:f0:11:f7:2d:18]"));
        assertTrue(priv.toString().contains("    X: a23ca259bc0d239b90fc7ebfeed8f9735889e9831af"));
        assertTrue(priv.toString().contains("    Y: 7d0c78db3d4e2cd587de62514d3ae7cd6ecd0e4acaa"));
    }

    public void testGost3410()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("GOST3410", "BC");

        doBasicTest("GOST3410", kpGen.generateKeyPair());

        byte[] encPub = Base64.decode("MIGqMCMGBiqFAwICFDAZBgcqhQMCAiACBgYqhQMCAgkGBiqFAwICCQOBggAEf+wRHYrsehOZV7jOmTpLUXxv1ZK8EXXN3M3M4+rETmDVVHbj0AVrZi4DIqulBb97Vos4h90piPGiHrY0GPqJLjYa93Xwo9SSSzLoG/zl67tXNLTwNNBm6q7xpZTUskk5kHQcXDY8EC5m3bTCKQsFGXKB/BNoY7qYoT2mWv/StkY=");
        byte[] encPriv = Base64.decode("MEwCAQAwIwYGKoUDAgIUMBkGByqFAwICIAIGBiqFAwICCQYGKoUDAgIJBCIEIOjlYW+mRem+9wH6Y4rO5WW7C0KZlb36pW5P3uq24xBV");

        KeyFactory keyFact = KeyFactory.getInstance("GOST3410", "BC");

        PublicKey pub = keyFact.generatePublic(new X509EncodedKeySpec(encPub));
        PrivateKey priv = keyFact.generatePrivate(new PKCS8EncodedKeySpec(encPriv));
                  
        assertTrue(pub.toString().startsWith("GOST3410 Public Key [4f:4d:ab:ec:1d:f6:c6:aa:d2:f9:91:4d:44:3d:a7:d0:b9:77:e8:e0]"));
        assertTrue(pub.toString().contains(  "                 Y: 46b6d2ff5aa63da198ba636813fc817219050b29c2b4dd662e103c365c1c74903949b2d494a5f1aeea66d034f0b43457bbebe5fc1be8324b92d4a3f075f71a362e89fa1834b61ea2f18829dd87388b567bbf05a5ab22032e666b05d0e37654d5604ec4eae3cccddccd7511bc92d56f7c514b3a99ceb85799137aec8a1d11ec"));
        assertTrue(priv.toString().startsWith("GOST3410 Private Key [4f:4d:ab:ec:1d:f6:c6:aa:d2:f9:91:4d:44:3d:a7:d0:b9:77:e8:e0]"));
        assertTrue(priv.toString().contains(  "                  Y: 46b6d2ff5aa63da198ba636813fc817219050b29c2b4dd662e103c365c1c74903949b2d494a5f1aeea66d034f0b43457bbebe5fc1be8324b92d4a3f075f71a362e89fa1834b61ea2f18829dd87388b567bbf05a5ab22032e666b05d0e37654d5604ec4eae3cccddccd7511bc92d56f7c514b3a99ceb85799137aec8a1d11ec"));
    }

    public void testEC()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

        doBasicTest("EC", kpGen.generateKeyPair());

        byte[] encPub = Base64.decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEs/4/qXFF0Sq2es80Fp/O5EzzQM0tmr/OYI+zIh3QRdAY1iuvj3jn9Y9katnE6Ybp86w98xDVnU5sFeZryDwDtg==");
        byte[] encPriv = Base64.decode("MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgYNlelt3GClXy1el0MRSTgr9yIuTxk21K5mNlhLToxQ2gCgYIKoZIzj0DAQehRANCAASz/j+pcUXRKrZ6zzQWn87kTPNAzS2av85gj7MiHdBF0BjWK6+PeOf1j2Rq2cTphunzrD3zENWdTmwV5mvIPAO2");

        KeyFactory keyFact = KeyFactory.getInstance("EC", "BC");

        PublicKey pub = keyFact.generatePublic(new X509EncodedKeySpec(encPub));
        PrivateKey priv = keyFact.generatePrivate(new PKCS8EncodedKeySpec(encPriv));

        assertTrue(pub.toString().startsWith("EC Public Key [0c:c4:d5:d1:c6:1f:6a:b6:0c:14:17:03:d3:00:7d:5a:98:a6:5b:41]"));
        assertTrue(pub.toString().contains("    X: b3fe3fa97145d12ab67acf34169fcee44cf340cd2d9abfce608fb3221dd045d0"));
        assertTrue(pub.toString().contains("    Y: 18d62baf8f78e7f58f646ad9c4e986e9f3ac3df310d59d4e6c15e66bc83c03b6"));
        assertTrue(priv.toString().startsWith("EC Private Key [0c:c4:d5:d1:c6:1f:6a:b6:0c:14:17:03:d3:00:7d:5a:98:a6:5b:41]"));
        assertTrue(priv.toString().contains("    X: b3fe3fa97145d12ab67acf34169fcee44cf340cd2d9abfce608fb3221dd045d0"));
        assertTrue(priv.toString().contains("    Y: 18d62baf8f78e7f58f646ad9c4e986e9f3ac3df310d59d4e6c15e66bc83c03b6"));
    }

    public void testEcgost3410()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECGOST3410", "BC");

        kpGen.initialize(new ECGenParameterSpec("GostR3410-2001-CryptoPro-A"));

        doBasicTest("ECGOST3410", kpGen.generateKeyPair());

        byte[] encPub = Base64.decode("MGowIwYGKoUDAgITMBkGByqFAwICIwEGBiqFAwICCQYGKoUDAgIJA0MABEBzEeFGk8H7WMVf+6YsXqpKj1hzEybybIG09gaCrRX7pYr/4+yBNvYRIKll0GCdiKBNiHiT1Oce1KSk7rd6389l");
        byte[] encPriv = Base64.decode("MEwCAQAwIwYGKoUDAgITMBkGByqFAwICIwEGBiqFAwICCQYGKoUDAgIJBCIEIB+i3qfPM2W1SqbejFMmMfqpBW08ID+MU7OMtShKKgxb");

        KeyFactory keyFact = KeyFactory.getInstance("ECGOST3410", "BC");

        PublicKey pub = keyFact.generatePublic(new X509EncodedKeySpec(encPub));
        PrivateKey priv = keyFact.generatePrivate(new PKCS8EncodedKeySpec(encPriv));

        assertTrue(pub.toString().startsWith("ECGOST3410 Public Key [50:e7:1f:ce:03:88:cc:7a:6b:7b:3d:3a:72:89:62:23:76:c2:fa:e5]"));
        assertTrue(pub.toString().contains("    X: a5fb15ad8206f6b4816cf2261373588f4aaa5e2ca6fb5fc558fbc19346e11173"));
        assertTrue(pub.toString().contains("    Y: 65cfdf7ab7eea4a4d41ee7d49378884da0889d60d065a92011f63681ece3ff8a"));
        assertTrue(priv.toString().startsWith("ECGOST3410 Private Key [50:e7:1f:ce:03:88:cc:7a:6b:7b:3d:3a:72:89:62:23:76:c2:fa:e5]"));
        assertTrue(priv.toString().contains("    X: a5fb15ad8206f6b4816cf2261373588f4aaa5e2ca6fb5fc558fbc19346e11173"));
        assertTrue(priv.toString().contains("    Y: 65cfdf7ab7eea4a4d41ee7d49378884da0889d60d065a92011f63681ece3ff8a"));
    }

    public void testEcgost3410_2012()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECGOST3410-2012", "BC");

        kpGen.initialize(new ECGenParameterSpec("Tc26-Gost-3410-12-512-paramSetA"));
        
        doBasicTest("ECGOST3410-2012", kpGen.generateKeyPair());

        byte[] encPub = Base64.decode("MIGqMCEGCCqFAwcBAQECMBUGCSqFAwcBAgECAQYIKoUDBwEBAgMDgYQABIGAh0+2qnmiMMYQJq3srMPiVv0hF7AQURDImqwJ0VsHTb//EMGhJC6zCvm3qvIyjOWw0ORU8MgUB2DXhjkh0HssENm4ZEgXEseJkzy7BYXn9s7UtEIOzc+hw87lbiJDwFgOcenE1qmDJKYBOwcDJqUBmamYLx2v8dAtvXby1gmrpbw=");
        byte[] encPriv = Base64.decode("MGoCAQAwIQYIKoUDBwEBAQIwFQYJKoUDBwECAQIBBggqhQMHAQECAwRCBECh5Zx2fiePeHs0qJquxbijT2m5Ef3OU14CEtPIWTnNLI4qmHe2PEaGqpW2X3BmCERi+CW7FUEndUb6BtzqrNnF");

        KeyFactory keyFact = KeyFactory.getInstance("ECGOST3410-2012", "BC");

        PublicKey pub = keyFact.generatePublic(new X509EncodedKeySpec(encPub));
        PrivateKey priv = keyFact.generatePrivate(new PKCS8EncodedKeySpec(encPriv));

        assertTrue(pub.toString().startsWith("ECGOST3410-2012 Public Key [01:66:a0:e4:29:12:09:bb:61:b4:fc:22:71:fe:ef:fa:dc:6a:82:d2]"));
        assertTrue(pub.toString().contains("    X: 102c7bd0213986d7600714c8f054e4d0b0e58c32f2aab7f90ab32e24a1c110ffbf4d075bd109ac9ac8105110b01721fd56e2c3acecad2610c630a279aab64f87"));
        assertTrue(pub.toString().contains("    Y: bca5ab09d6f276bd2dd0f1af1d2f98a99901a52603073b01a62483a9d6c4e9710e58c043226ee5cec3a1cfcd0e42b4d4cef6e78505bb3c9389c712174864b8d9"));
        assertTrue(priv.toString().startsWith("ECGOST3410-2012 Private Key [01:66:a0:e4:29:12:09:bb:61:b4:fc:22:71:fe:ef:fa:dc:6a:82:d2]"));
        assertTrue(priv.toString().contains("    X: 102c7bd0213986d7600714c8f054e4d0b0e58c32f2aab7f90ab32e24a1c110ffbf4d075bd109ac9ac8105110b01721fd56e2c3acecad2610c630a279aab64f87"));
        assertTrue(priv.toString().contains("    Y: bca5ab09d6f276bd2dd0f1af1d2f98a99901a52603073b01a62483a9d6c4e9710e58c043226ee5cec3a1cfcd0e42b4d4cef6e78505bb3c9389c712174864b8d9"));
    }

    public void testSM2()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

        kpGen.initialize(new ECGenParameterSpec("sm2p256v1"));

        KeyPair kp = kpGen.generateKeyPair();

        doBasicTest("EC", kpGen.generateKeyPair());

        byte[] encPub = Base64.decode("MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAELAtcshndZO6GOXfZxKR6TEu+eyRa4G2gH3iN0YPInldPfyGR18/FI/jHhObqZ1o3mh/c/wAJnNfqC6xnJ8kfYQ==");
        byte[] encPriv = Base64.decode("MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgyv+YdWo5OtAv7E0znvq978yw2KdGKE4TsWw+yHqNtVKgCgYIKoEcz1UBgi2hRANCAAQsC1yyGd1k7oY5d9nEpHpMS757JFrgbaAfeI3Rg8ieV09/IZHXz8Uj+MeE5upnWjeaH9z/AAmc1+oLrGcnyR9h");

        KeyFactory keyFact = KeyFactory.getInstance("EC", "BC");

        PublicKey pub = keyFact.generatePublic(new X509EncodedKeySpec(encPub));
        PrivateKey priv = keyFact.generatePrivate(new PKCS8EncodedKeySpec(encPriv));
           
        assertTrue(pub.toString().startsWith("EC Public Key [38:20:5a:95:6f:1d:6f:10:74:42:a0:a7:ee:d4:b8:83:6d:32:2f:e6]"));
        assertTrue(pub.toString().contains("    X: 2c0b5cb219dd64ee863977d9c4a47a4c4bbe7b245ae06da01f788dd183c89e57"));
        assertTrue(pub.toString().contains("    Y: 4f7f2191d7cfc523f8c784e6ea675a379a1fdcff00099cd7ea0bac6727c91f61"));
        assertTrue(priv.toString().startsWith("EC Private Key [38:20:5a:95:6f:1d:6f:10:74:42:a0:a7:ee:d4:b8:83:6d:32:2f:e6]"));
        assertTrue(priv.toString().contains("    X: 2c0b5cb219dd64ee863977d9c4a47a4c4bbe7b245ae06da01f788dd183c89e57"));
        assertTrue(priv.toString().contains("    Y: 4f7f2191d7cfc523f8c784e6ea675a379a1fdcff00099cd7ea0bac6727c91f61"));
    }

    public void testRSA()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        doBasicTest("RSA", kpGen.generateKeyPair());

        byte[] encPub = Base64.decode("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtU6SHvIgdoeKm9CueKoR+i13I4XZAzqPV+ba" +
            "dnUdrTlCziTNfbGdEVSRPkrdNcQzYegj68K1gHYT755dNtKAqnJH6k6oQfH083MT0eYbTni1sf3zNOY+Ns4zIym3zMBD5VQ6pzfSk9SZys" +
            "bohheEkMLLg6CYq4x1sxnsS1fa7X2mubKXmxoam5t0kztXPI0v7E6iYWYfiIIvEir6421zffk0gyznfLNP1HWSptcOgNNbRFyGvPh8ZFyw" +
            "roNATwfQFTEZ6pf3Fw7eMlMN0eDjvVib9v2iEL2DSDZxOHYm9kPF2ETJuRRoEq6JW2AKSs3yeTf8ubEZnueqIUW6lKFEdwIDAQAB");
        byte[] encPriv = Base64.decode(" MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC1TpIe8iB2h4qb0K54qhH6LXcjhd" +
            "kDOo9X5tp2dR2tOULOJM19sZ0RVJE+St01xDNh6CPrwrWAdhPvnl020oCqckfqTqhB8fTzcxPR5htOeLWx/fM05j42zjMjKbfMwEPlVDqn" +
            "N9KT1JnKxuiGF4SQwsuDoJirjHWzGexLV9rtfaa5spebGhqbm3STO1c8jS/sTqJhZh+Igi8SKvrjbXN9+TSDLOd8s0/UdZKm1w6A01tEXI" +
            "a8+HxkXLCug0BPB9AVMRnql/cXDt4yUw3R4OO9WJv2/aIQvYNINnE4dib2Q8XYRMm5FGgSrolbYApKzfJ5N/y5sRme56ohRbqUoUR3AgMB" +
            "AAECggEAFV6j6WLXgbD7HN9tWQqOoOKv+q9hgzhpQc6TbEfkjhDEN4Dt+YUwQqUpk2KGjTpJZh5S8YxbET+ZnPIZAYexI6XhpRPNUCyBFx" +
            "q2uNQ63rZqkAajHlaO+a23KEtX/xmgRwz09tWlC8iQse5c5MUr2lYjX6nTpNCi5M/G4qCBzOEByjxkKCXbgaTKsgLb7ax2CoC3BUbWjQnb" +
            "Q2V9tRImBX92b1NF0ER0Xovy7VH0rwrQnTEkD8U6OrRs+UAX+zCzkV69BJPou47s4jSdDksy5vhteVdx+HnucEeLgpJoqixiDWofZvX7+N" +
            "AsGs+e74bV/vQinuY6a1ILEH3g1+rhGQKBgQD1J7sUdmbXelGUys5rERdYP9xTNuyqV38DrgPDyE8pgpwrvM5gn1cRb8Wop6xOp/vVME8F" +
            "u9PE65+T5nRb8zEvypi+4mGsjksI7ZsQ4VqV7G1GfTT8QKjr+gEk7t+jN2ymL6lp2x+bbSHQniPP51FDl72RsKY0Pk4Iy9aMKbxXHwKBgQ" +
            "C9U8mqMveT8e+ztiVwUdM2AvQSv+WNyVD5q78db5mrxur20b8UU7cyDFJoH6Y72GT/sKuL4LSAD8ZrUg5rnZWtXP63WnAlRJaMI0d7McV7" +
            "OwsaByJVlI/Yq3OpC8x1+Pf1jy6HJzxFVmMMllYi63CzqPwIAgnGdHP4C/p/CmEfqQKBgG6ip4LsjCziPr7vZ4haBjcFWuETAGs/YUq/1W" +
            "MdmtwY3XG/m0NvpVNxJbqfMNuuY7AqRP9JbKCJ1VJhxlFYxvHSdGxwrbO545L75+cOTFssf4Q4LRlJ9PHJuYp5YuO9t4KoL8Rd5z21WnVT" +
            "aMYClmHysNJ27grVs1G06/YFP8HxAoGAKvFjT5CJ6Wu58+g/q69Tme+njs0p8zQTgt361mFm2LiguOUwUxr99YMn+egb230kw34+GtcX+e" +
            "gaGGOfU7eFqLHsMIh54WoiP50M7JuIcIAe74NovUKaMgoJjPFZKfUTwQX+BrfWit+iTcuXtAn1ITsWF3bm4rWtTDjjU4d2KikCgYEA7Zwj" +
            "/hGL7pmbDjfBK0aG+06JPQ1LHYVXHOUxco9eB1sgJXoxBjqoJPU0j7NCrn6i3tiDtLPYNAO9ehaRLucFk8FjthrewHmZY+x+nmzkEbMbi1" +
            "kDTIvY4pw5jn9k5CEBAe2MSymjzfPTWV2YhuG1Lu5ibSQ+LMMbUppniD9N2pA=");

        KeyFactory keyFact = KeyFactory.getInstance("RSA", "BC");

        PublicKey pub = keyFact.generatePublic(new X509EncodedKeySpec(encPub));
        PrivateKey priv = keyFact.generatePrivate(new PKCS8EncodedKeySpec(encPriv));

        String pubString = pub.toString();

        assertTrue(pubString.startsWith("RSA Public Key [33:25:14:cc:b5:ab:65:6d:70:d3:91:2b:7f:1f:de:c4:ec:04:2f:48],[56:66:d1:a4]"));
        assertTrue(pubString.contains("    modulus: b54e921ef22076878a9bd0ae78aa11fa2d772385d9033a8f57e6da76751dad3942ce24cd7db19d1154913e4add35c43361e823ebc2b5807613ef9e5d36d280aa7247ea4ea841f1f4f37313d1e61b4e78b5b1fdf334e63e36ce332329b7ccc043e5543aa737d293d499cac6e886178490c2cb83a098ab8c75b319ec4b57daed7da6b9b2979b1a1a9b9b74933b573c8d2fec4ea261661f88822f122afae36d737df934832ce77cb34fd47592a6d70e80d35b445c86bcf87c645cb0ae83404f07d0153119ea97f7170ede32530dd1e0e3bd589bf6fda210bd83483671387626f643c5d844c9b9146812ae895b600a4acdf27937fcb9b1199ee7aa2145ba94a14477"));
        assertTrue(pubString.contains("public exponent: 10001"));

        String privString = priv.toString();
        assertTrue(privString.startsWith("RSA Private CRT Key [33:25:14:cc:b5:ab:65:6d:70:d3:91:2b:7f:1f:de:c4:ec:04:2f:48],[56:66:d1:a4]"));
        assertTrue(privString.contains("   modulus: b54e921ef22076878a9bd0ae78aa11fa2d772385d9033a8f57e6da76751dad3942ce24cd7db19d1154913e4add35c43361e823ebc2b5807613ef9e5d36d280aa7247ea4ea841f1f4f37313d1e61b4e78b5b1fdf334e63e36ce332329b7ccc043e5543aa737d293d499cac6e886178490c2cb83a098ab8c75b319ec4b57daed7da6b9b2979b1a1a9b9b74933b573c8d2fec4ea261661f88822f122afae36d737df934832ce77cb34fd47592a6d70e80d35b445c86bcf87c645cb0ae83404f07d0153119ea97f7170ede32530dd1e0e3bd589bf6fda210bd83483671387626f643c5d844c9b9146812ae895b600a4acdf27937fcb9b1199ee7aa2145ba94a14477"));
        assertTrue(pubString.contains("public exponent: 10001"));
        
        priv = keyFact.generatePrivate(new RSAPrivateKeySpec(((RSAPrivateKey)priv).getModulus(), ((RSAPrivateKey)priv).getPrivateExponent()));

        assertEquals(priv, priv);
        assertFalse(priv.equals(pub));

        doSerialisationCheck(priv);

        PrivateKey privKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(priv.getEncoded()));

        assertEquals(priv.getAlgorithm(), "RSA");
        assertEquals(priv, privKey);
        assertEquals(priv.hashCode(), privKey.hashCode());

        String privKeyString = privKey.toString();

        assertTrue(privKeyString.startsWith("RSA Private Key [33:25:14:cc:b5:ab:65:6d:70:d3:91:2b:7f:1f:de:c4:ec:04:2f:48],[]"));
        assertTrue(privKeyString.contains("    modulus: b54e921ef22076878a9bd0ae78aa11fa2d772385d9033a8f57e6da76751dad3942ce24cd7db19d1154913e4add35c43361e823ebc2b5807613ef9e5d36d280aa7247ea4ea841f1f4f37313d1e61b4e78b5b1fdf334e63e36ce332329b7ccc043e5543aa737d293d499cac6e886178490c2cb83a098ab8c75b319ec4b57daed7da6b9b2979b1a1a9b9b74933b573c8d2fec4ea261661f88822f122afae36d737df934832ce77cb34fd47592a6d70e80d35b445c86bcf87c645cb0ae83404f07d0153119ea97f7170ede32530dd1e0e3bd589bf6fda210bd83483671387626f643c5d844c9b9146812ae895b600a4acdf27937fcb9b1199ee7aa2145ba94a14477"));
    }

    private void doBasicTest(String algorithm, KeyPair kp)
        throws Exception
    {
        assertEquals(algorithm, kp.getPublic().getAlgorithm());
        assertEquals(algorithm, kp.getPrivate().getAlgorithm());

        assertEquals("X.509", kp.getPublic().getFormat());
        assertEquals("PKCS#8", kp.getPrivate().getFormat());

        doSerialisationCheck(kp.getPublic());
        doSerialisationCheck(kp.getPrivate());

        KeyFactory keyFact = KeyFactory.getInstance(algorithm, "BC");

        PublicKey pub = keyFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        PrivateKey priv = keyFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(algorithm, pub.getAlgorithm());
        assertEquals(algorithm, priv.getAlgorithm());

        assertEquals(pub, pub);
        assertEquals(priv, priv);

        assertFalse(pub.equals(priv));
        assertFalse(priv.equals(pub));

        assertEquals(kp.getPublic(), pub);
        assertEquals(kp.getPublic().hashCode(), pub.hashCode());
        assertEquals(kp.getPrivate(), priv);
        assertEquals(kp.getPrivate().hashCode(), priv.hashCode());
    }

    private void doSerialisationCheck(Object o)
        throws IOException, ClassNotFoundException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(o);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        Object read = oIn.readObject();

        assertEquals(o, read);
        assertEquals(o.hashCode(), read.hashCode());
    }
}
