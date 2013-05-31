package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Exercise the various key stores, making sure we at least get back what we put in!
 * <p>
 * This tests both the PKCS12 key store.
 */
public class PKCS12StoreTest
    extends SimpleTest
{
    static char[]   passwd = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd' };

    //
    // pkcs-12 pfx-pdu
    //
    byte[]  pkcs12 = Base64.decode(
          "MIACAQMwgAYJKoZIhvcNAQcBoIAkgAQBMAQBgAQBMAQBgAQBBgQBCQQJKoZI"
        + "hvcNAQcBBAGgBAGABAEkBAGABAEEBAEBBAEwBAEEBAEDBAOCAzQEAQQEAQEE"
        + "ATAEAQQEAQMEA4IDMAQBBAQBAQQBBgQBBAQBAQQBCwQBBAQBCwQLKoZIhvcN"
        + "AQwKAQIEAQQEAQEEAaAEAQQEAQMEA4ICpQQBBAQBAQQBMAQBBAQBAwQDggKh"
        + "BAEEBAEBBAEwBAEEBAEBBAEbBAEEBAEBBAEGBAEEBAEBBAEKBAEEBAEKBAoq"
        + "hkiG9w0BDAEDBAEEBAEPBA8wDQQIoagiwNZPJR4CAQEEAQQEAQEEAQQEAQQE"
        + "AQMEA4ICgAQBBAQDggKABIICgEPG0XlhMFyrs4ZWDrvEzl51ICfXd6K2ql2l"
        + "nnxhszUbigtSj6x49VEx4PfOB9fQFeidc5L5An+nKp646NBMIY0UwXGs8BLQ"
        + "au59jtOs987+l7QYIvl6fdGUIuLPhVSnZZDyqD+HQjU/0/ccKFHRif4tlEQq"
        + "aErvZbFeH0pg4ijf1HfgX6gBJGRKdO+msa4qKGnZdHCSLZehyyxvxAmURetg"
        + "yhtEl7RmedTB+4TDs7atekqxkNlD9tfwDUX6sb0IH6qbEA6P/DlVMdaD54Cl"
        + "QDxRzOfIIjklZhv5OMFWtPK0aYPcqyxzLpw1qRAyoTVXpidkj/hpIpgCVBP/"
        + "k5s2+WdGbLgA/4/zSrF6feRCE5llzM2IGxiHVq4oPzzngl3R+Fi5VCPDMcuW"
        + "NRuIOzJA+RNV2NPOE/P3knThDnwiImq+rfxmvZ1u6T06s20RmWK6cxp7fTEw"
        + "lQ9BOsv+mmyV8dr6cYJq4IlRzHdFOyEUBDwfHThyribNKKobO50xh2f93xYj"
        + "Rn5UMOQBJIe3b7OKZt5HOIMrJSZO02IZgvImi9yQWi96PnWa419D1cAsLWvM"
        + "xiN0HqZMbDFfxVM2BZmsxiexLhkHWKwLqfQDzRjJfmVww8fnXpWZhFXKyut9"
        + "gMGEyCNoba4RU3QI/wHKWYaK74qtJpsucuLWBH6UcsHsCry6VZkwRxWwC0lb"
        + "/F3Bm5UKHax5n9JHJ2amQm9zW3WJ0S5stpPObfmg5ArhbPY+pVOsTqBRlop1"
        + "bYJLD/X8Qbs468Bwzej0FhoEU59ZxFrbjLSBsMUYrVrwD83JE9kEazMLVchc"
        + "uCB9WT1g0hxYb7VA0BhOrWhL8F5ZH72RMCYLPI0EAQQEAQEEATEEAQQEAQEE"
        + "AXgEAQQEAQEEATAEAQQEAQEEAVEEAQQEAQEEAQYEAQQEAQEEAQkEAQQEAQkE"
        + "CSqGSIb3DQEJFAQBBAQBAQQBMQQBBAQBAQQBRAQBBAQBAQQBHgQBBAQBAQQB"
        + "QgQBBAQBQgRCAEQAYQB2AGkAZAAgAEcALgAgAEgAbwBvAGsAJwBzACAAVgBl"
        + "AHIAaQBTAGkAZwBuACwAIABJAG4AYwAuACAASQBEBAEEBAEBBAEwBAEEBAEB"
        + "BAEjBAEEBAEBBAEGBAEEBAEBBAEJBAEEBAEJBAkqhkiG9w0BCRUEAQQEAQEE"
        + "ATEEAQQEAQEEARYEAQQEAQEEAQQEAQQEAQEEARQEAQQEARQEFKEcMJ798oZL"
        + "FkH0OnpbUBnrTLgWBAIAAAQCAAAEAgAABAEwBAGABAEGBAEJBAkqhkiG9w0B"
        + "BwYEAaAEAYAEATAEAYAEAQIEAQEEAQAEATAEAYAEAQYEAQkECSqGSIb3DQEH"
        + "AQQBMAQBGwQBBgQBCgQKKoZIhvcNAQwBBgQPMA0ECEE7euvmxxwYAgEBBAGg"
        + "BAGABAEEBAEIBAgQIWDGlBWxnwQBBAQBCAQI2WsMhavhSCcEAQQEAQgECPol"
        + "uHJy9bm/BAEEBAEQBBCiRxtllKXkJS2anKD2q3FHBAEEBAEIBAjKy6BRFysf"
        + "7gQBBAQDggMwBIIDMJWRGu2ZLZild3oz7UBdpBDUVMOA6eSoWiRIfVTo4++l"
        + "RUBm8TpmmGrVkV32PEoLkoV+reqlyWCvqqSjRzi3epQiVwPQ6PV+ccLqxDhV"
        + "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");

    byte[] certUTF = Base64.decode(
        "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"
      + "RgICCAA=");

    byte[] pkcs12noFriendly = Base64.decode(
        "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"
      + "tTy3wnQisALy9aYECKiM2gZrLi+fAAA=");

    static char[]   noFriendlyPassword = "sschette12".toCharArray();

    byte[] pkcs12StorageIssue = Base64.decode(
        "MIIO8QIBAzCCDrEGCSqGSIb3DQEHAaCCDqIEgg6eMIIOmjCCBBMGCSqGSIb3"
      + "DQEHAaCCBAQEggQAMIID/DCCA/gGCyqGSIb3DQEMCgECoIICtjCCArIwHAYK"
      + "KoZIhvcNAQwBAzAOBAgURJ+/5hA2pgICB9AEggKQYZ4POE8clgH9Bjd1XO8m"
      + "sr6NiRBiA08CllHSOn2RzyAgHTa+cKaWrEVVJ9mCd9XveSUCoBF9E1C3jSl0"
      + "XIqLNgYd6mWK9BpeMRImM/5crjy///K4ab9kymzkc5qc0pIpdCQCZ04YmtFP"
      + "B80VCgyaoh2xoxqgjBCIgdSg5XdepdA5nXkG9EsQ1oVUyCykv20lKgKKRseG"
      + "Jo23AX8YUYR7ANqP2gz9lvlX6RBczuoZ62ujopUexiQgt5SZx97sgo3o/b/C"
      + "px17A2L4wLdeAYCMCsZhC2UeaqnZCHSsvnPZfRGiuSEGbV5gHLmXszLDaEdQ"
      + "Bo873GTpKTTzBfRFzNCtYtZRqh2AUsInWZWQUcCeX6Ogwa0wTonkp18/tqsh"
      + "Fj1fVpnsRmjJTTXFxkPtUw5GPJnDAM0t1xqV7kOjN76XnZrMyk2azQ1Mf3Hn"
      + "sGpF+VRGH6JtxbM0Jm5zD9uHcmkSfNR3tP/+vHOB1mkIR9tD2cHvBg7pAlPD"
      + "RfDVWynhS+UBNlQ0SEM/pgR7PytRSUoKc/hhe3N8VerF7VL3BwWfBLlZFYZH"
      + "FvPQg4coxF7+We7nrSQfXvdVBP9Zf0PTdf3pbZelGCPVjOzbzY/o/cB23IwC"
      + "ONxlY8SC1nJDXrPZ5sY51cg/qUqor056YqipRlI6I+FoTMmMDKPAiV1V5ibo"
      + "DNQJkyv/CAbTX4+oFlxgddTwYcPZgd/GoGjiP9yBHHdRISatHwMcM06CzXJS"
      + "s3MhzXWD4aNxvvSpXAngDLdlB7cm4ja2klmMzL7IuxzLXFQFFvYf7IF5I1pC"
      + "YZOmTlJgp0efL9bHjuHFnh0S0lPtlGDOjJ/4YpWvSKDplcPiXhaFVjsUtclE"
      + "oxCC5xppRm8QWS8xggEtMA0GCSsGAQQBgjcRAjEAMBMGCSqGSIb3DQEJFTEG"
      + "BAQBAAAAMGkGCSsGAQQBgjcRATFcHloATQBpAGMAcgBvAHMAbwBmAHQAIABS"
      + "AFMAQQAgAFMAQwBoAGEAbgBuAGUAbAAgAEMAcgB5AHAAdABvAGcAcgBhAHAA"
      + "aABpAGMAIABQAHIAbwB2AGkAZABlAHIwgZsGCSqGSIb3DQEJFDGBjR6BigA3"
      + "AGQAZQBmADUAYgA0ADMANgBjAGEAYgBkADAAMAAyAGQAZAAyADkAMAAzAGIA"
      + "MQA2ADgANgBjADcAOQA0ADgAXwA0ADYAZgAyADYAZgBkADQALQA4ADEAMgBk"
      + "AC0ANABlAGYAYgAtADgAMAA4ADgALQA0ADUAYQBiADkAMQA5ADEAMAA3AGMA"
      + "YzCCCn8GCSqGSIb3DQEHBqCCCnAwggpsAgEAMIIKZQYJKoZIhvcNAQcBMBwG"
      + "CiqGSIb3DQEMAQYwDgQIbr2xdnQ9inMCAgfQgIIKOHg9VKz+jlM+3abi3cp6"
      + "/XMathxDSEJLrxJs6j5DAVX17S4sw1Q/1pptjdMdd8QtTfUB6JpfgJ5Kpn+h"
      + "gZMf6M8wWue0U/RZN0D9w7o+2n+X3ItdEXu80eJVDOm7I2p8qiXtijbMbXRL"
      + "Cup1lgfPM5uv2D63/hmWRXLeG8eySrJnKENngpM559V8TI2JcTUBy1ZP3kcH"
      + "KbcJ/tVPnIIe4qguxfsTmDtAQviGvWUohbt+RGFmtqfgntK7o6b+S8uRSwEs"
      + "fOU/pnVE9M1ugtNJZI/xeGJq6umZWXA/OrAcK7feWUwqRvfivDGQJEoggByd"
      + "4/g92PhK1JGkwlCb1HdfhOOKKChowQ4zVvSOm+uBxARGhk2i5uW9I20I0vSJ"
      + "px42O2VFVJweOchfp+wBtSHBKYP1ZXyXWMvOtULClosSeesbYMAwvyBfpYEz"
      + "3rQt/1iZkqDmEisXk8X1aEKG1KSWaSPyb/+6glWikDm+YdQw3Khu7IZt1l/H"
      + "qWGecccel+R9mT4YjRzHlahUYk4U+RNVasVpH1Kxz2j3CZqL+b3jQOwSAPd/"
      + "hKI+S/pjIpBPfiC4WxORAzGZzY2j+a79B70h1DO1D9jGur3vJDbdmGBNgs6d"
      + "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"
      + "g141BQ==");

    static char[]   storagePassword = "pass".toCharArray();

    byte[] pkcs12nopass = Base64.decode(
        "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"
      + "j2CPp38YIFBEqvjsBAi8G+yhJe3A/wICCAA=");

    /**
     * we generate a self signed certificate for the sake of testing - RSA
     */
    public Certificate createCert(
        PublicKey       pubKey,
        PrivateKey      privKey)
        throws Exception
    {
        //
        // distinguished name table.
        //
        Hashtable                   attrs = new Hashtable();

        attrs.put(X509Principal.C, "AU");
        attrs.put(X509Principal.O, "The Legion of the Bouncy Castle");
        attrs.put(X509Principal.L, "Melbourne");
        attrs.put(X509Principal.ST, "Victoria");
        attrs.put(X509Principal.EmailAddress, "feedback-crypto@bouncycastle.org");

        //
        // extensions
        //

        //
        // create the certificate - version 3
        //
        X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(1));
        certGen.setIssuerDN(new X509Principal(attrs));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)));
        certGen.setSubjectDN(new X509Principal(attrs));
        certGen.setPublicKey(pubKey);
        certGen.setSignatureAlgorithm("MD5WithRSAEncryption");

        X509Certificate cert = certGen.generateX509Certificate(privKey);

        cert.checkValidity(new Date());

        cert.verify(pubKey);

        return cert;
    }

    public void testPKCS12Store()
        throws Exception
    {
        BigInteger  mod = new BigInteger("bb1be8074e4787a8d77967f1575ef72dd7582f9b3347724413c021beafad8f32dba5168e280cbf284df722283dad2fd4abc750e3d6487c2942064e2d8d80641aa5866d1f6f1f83eec26b9b46fecb3b1c9856a303148a5cc899c642fb16f3d9d72f52526c751dc81622c420c82e2cfda70fe8d13f16cc7d6a613a5b2a2b5894d1", 16);
        KeyStore store = KeyStore.getInstance("PKCS12", "BC");
        ByteArrayInputStream stream = new ByteArrayInputStream(pkcs12);

        store.load(stream, passwd);

        Enumeration en = store.aliases();
        String      pName = null;

        while (en.hasMoreElements())
        {
            String  n = (String)en.nextElement();
            if (store.isKeyEntry(n))
            {
                pName = n;
            }
        }

        PrivateKey key = (PrivateKey)store.getKey(pName, null);

        if (!((RSAPrivateKey)key).getModulus().equals(mod))
        {
            fail("Modulus doesn't match.");
        }

        Certificate[]    ch = store.getCertificateChain(pName);

        if (ch.length != 3)
        {
            fail("chain was wrong length");
        }

        if (!((X509Certificate)ch[0]).getSerialNumber().equals(new BigInteger("96153094170511488342715101755496684211")))
        {
            fail("chain[0] wrong certificate.");
        }

        if (!((X509Certificate)ch[1]).getSerialNumber().equals(new BigInteger("279751514312356623147411505294772931957")))
        {
            fail("chain[1] wrong certificate.");
        }

        if (!((X509Certificate)ch[2]).getSerialNumber().equals(new BigInteger("11341398017")))
        {
            fail("chain[2] wrong certificate.");
        }

        //
        // save test
        //
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        store.store(bOut, passwd);

        stream = new ByteArrayInputStream(bOut.toByteArray());

        store.load(stream, passwd);

        key = (PrivateKey)store.getKey(pName, null);

        if (!((RSAPrivateKey)key).getModulus().equals(mod))
        {
            fail("Modulus doesn't match.");
        }

        store.deleteEntry(pName);

        if (store.getKey(pName, null) != null)
        {
            fail("Failed deletion test.");
        }

        //
        // cert chain test
        //
        store.setCertificateEntry("testCert", ch[2]);
        
        if (store.getCertificateChain("testCert") != null)
        {
            fail("Failed null chain test.");
        }
        
        //
        // UTF 8 single cert test
        //
        store = KeyStore.getInstance("PKCS12", "BC");
        stream = new ByteArrayInputStream(certUTF);

        store.load(stream, "user".toCharArray());

        if (store.getCertificate("37") == null)
        {
            fail("Failed to find UTF cert.");
        }

        //
        // try for a self generated certificate
        //
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16));

        RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16),
            new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
            new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
            new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
            new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
            new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
            new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

        //
        // set up the keys
        //
        PrivateKey          privKey = null;
        PublicKey           pubKey = null;

        try
        {
            KeyFactory  fact = KeyFactory.getInstance("RSA", "BC");

            privKey = fact.generatePrivate(privKeySpec);
            pubKey = fact.generatePublic(pubKeySpec);
        }
        catch (Exception e)
        {
            fail("error setting up keys - " + e.toString());
        }

        Certificate[] chain = new Certificate[1];

        chain[0] = createCert(pubKey, privKey);

        store = KeyStore.getInstance("PKCS12", "BC");

        store.load(null, null);

        store.setKeyEntry("privateKey", privKey, null, chain);
        
        if (!store.containsAlias("privateKey"))
        {
            fail("couldn't find alias privateKey");
        }
        
        if (store.isCertificateEntry("privateKey"))
        {
            fail("cert identified as certificate entry");
        }
        
        if (!store.isKeyEntry("privateKey"))
        {
            fail("cert not dentified as key entry");
        }
        
        if (!"privateKey".equals(store.getCertificateAlias(chain[0])))
        {
            fail("Did not return alias for key certificate privateKey");
        }

        store.store(new ByteArrayOutputStream(), passwd);

        //
        // no friendly name test
        //
        store = KeyStore.getInstance("PKCS12", "BC");
        stream = new ByteArrayInputStream(pkcs12noFriendly);

        store.load(stream, noFriendlyPassword);

        en = store.aliases();
        pName = null;

        while (en.hasMoreElements())
        {
             String  n = (String)en.nextElement();

             if (store.isKeyEntry(n))
             {
                 pName = n;
             }
        }
        
        ch = store.getCertificateChain(pName);

        for (int i = 0; i != ch.length; i++)
        {
            //System.out.println(ch[i]);
        }
        
        if (ch.length != 1)
        {
            fail("no cert found in pkcs12noFriendly");
        }
        
        //
        // failure tests
        //
        ch = store.getCertificateChain("dummy");
        
        store.getCertificate("dummy");

        //
        // storage test
        //
        store = KeyStore.getInstance("PKCS12", "BC");
        stream = new ByteArrayInputStream(pkcs12StorageIssue);

        store.load(stream, storagePassword);

        en = store.aliases();
        pName = null;

        while (en.hasMoreElements())
        {
             String  n = (String)en.nextElement();

             if (store.isKeyEntry(n))
             {
                 pName = n;
             }
        }
        
        ch = store.getCertificateChain(pName);
        if (ch.length != 2)
        {
            fail("Certificate chain wrong length");
        }

        store.store(new ByteArrayOutputStream(), storagePassword);
        
        //
        // basic certificate check
        //
        store.setCertificateEntry("cert", ch[1]);
        
        if (!store.containsAlias("cert"))
        {
            fail("couldn't find alias cert");
        }
        
        if (!store.isCertificateEntry("cert"))
        {
            fail("cert not identified as certificate entry");
        }
        
        if (store.isKeyEntry("cert"))
        {
            fail("cert identified as key entry");
        }
        
        if (!"cert".equals(store.getCertificateAlias(ch[1])))
        {
            fail("Did not return alias for certificate entry");
        }

        //
        // test of reading incorrect zero-length encoding
        //
        store = KeyStore.getInstance("PKCS12", "BC");
        stream = new ByteArrayInputStream(pkcs12nopass);
        
        store.load(stream, "".toCharArray());
    }

    public String getName()
    {
        return "PKCS12Store";
    }

    public void performTest()
        throws Exception
    {
        testPKCS12Store();
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PKCS12StoreTest());
    }
}
