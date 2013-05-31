package org.bouncycastle.cms.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.PKCS5Scheme2PBEKey;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.PKCS5Scheme2UTF8PBEKey;
import org.bouncycastle.cms.PasswordRecipientInformation;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

public class EnvelopedDataTest
    extends TestCase 
{
    private static String          _signDN;
    private static KeyPair         _signKP;  
    private static X509Certificate _signCert;

    private static String          _origDN;
    private static KeyPair         _origKP;
    private static X509Certificate _origCert;

    private static String          _reciDN;
    private static KeyPair         _reciKP;
    private static X509Certificate _reciCert;

    private static KeyPair         _origEcKP;
    private static KeyPair         _reciEcKP;
    private static X509Certificate _reciEcCert;

    private static boolean         _initialised = false;

    private byte[] oldKEK = Base64.decode(
                          "MIAGCSqGSIb3DQEHA6CAMIACAQIxQaI/MD0CAQQwBwQFAQIDBAUwDQYJYIZIAWUDBAEFBQAEI"
                        + "Fi2eHTPM4bQSjP4DUeDzJZLpfemW2gF1SPq7ZPHJi1mMIAGCSqGSIb3DQEHATAUBggqhkiG9w"
                        + "0DBwQImtdGyUdGGt6ggAQYk9X9z01YFBkU7IlS3wmsKpm/zpZClTceAAAAAAAAAAAAAA==");

    private byte[] ecKeyAgreeMsgAES256 = Base64.decode(
           "MIAGCSqGSIb3DQEHA6CAMIACAQIxgcShgcECAQOgQ6FBMAsGByqGSM49AgEF"
         + "AAMyAAPdXlSTpub+qqno9hUGkUDl+S3/ABhPziIB5yGU4678tgOgU5CiKG9Z"
         + "kfnabIJ3nZYwGgYJK4EFEIZIPwACMA0GCWCGSAFlAwQBLQUAMFswWTAtMCgx"
         + "EzARBgNVBAMTCkFkbWluLU1EU0UxETAPBgNVBAoTCDRCQ1QtMklEAgEBBCi/"
         + "rJRLbFwEVW6PcLLmojjW9lI/xGD7CfZzXrqXFw8iHaf3hTRau1gYMIAGCSqG"
         + "SIb3DQEHATAdBglghkgBZQMEASoEEMtCnKKPwccmyrbgeSIlA3qggAQQDLw8"
         + "pNJR97bPpj6baG99bQQQwhEDsoj5Xg1oOxojHVcYzAAAAAAAAAAAAAA=");

    private byte[] ecKeyAgreeMsgAES128 = Base64.decode(
           "MIAGCSqGSIb3DQEHA6CAMIACAQIxgbShgbECAQOgQ6FBMAsGByqGSM49AgEF"
         + "AAMyAAL01JLEgKvKh5rbxI/hOxs/9WEezMIsAbUaZM4l5tn3CzXAN505nr5d"
         + "LhrcurMK+tAwGgYJK4EFEIZIPwACMA0GCWCGSAFlAwQBBQUAMEswSTAtMCgx"
         + "EzARBgNVBAMTCkFkbWluLU1EU0UxETAPBgNVBAoTCDRCQ1QtMklEAgEBBBhi"
         + "FLjc5g6aqDT3f8LomljOwl1WTrplUT8wgAYJKoZIhvcNAQcBMB0GCWCGSAFl"
         + "AwQBAgQQzXjms16Y69S/rB0EbHqRMaCABBAFmc/QdVW6LTKdEy97kaZzBBBa"
         + "fQuviUS03NycpojELx0bAAAAAAAAAAAAAA==");

    private byte[] ecKeyAgreeMsgDESEDE = Base64.decode(
           "MIAGCSqGSIb3DQEHA6CAMIACAQIxgcahgcMCAQOgQ6FBMAsGByqGSM49AgEF"
         + "AAMyAALIici6Nx1WN5f0ThH2A8ht9ovm0thpC5JK54t73E1RDzCifePaoQo0"
         + "xd6sUqoyGaYwHAYJK4EFEIZIPwACMA8GCyqGSIb3DQEJEAMGBQAwWzBZMC0w"
         + "KDETMBEGA1UEAxMKQWRtaW4tTURTRTERMA8GA1UEChMINEJDVC0ySUQCAQEE"
         + "KJuqZQ1NB1vXrKPOnb4TCpYOsdm6GscWdwAAZlm2EHMp444j0s55J9wwgAYJ"
         + "KoZIhvcNAQcBMBQGCCqGSIb3DQMHBAjwnsDMsafCrKCABBjyPvqFOVMKxxut"
         + "VfTx4fQlNGJN8S2ATRgECMcTQ/dsmeViAAAAAAAAAAAAAA==");

   private byte[] ecMQVKeyAgreeMsgAES128 = Base64.decode(
          "MIAGCSqGSIb3DQEHA6CAMIACAQIxgf2hgfoCAQOgQ6FBMAsGByqGSM49AgEF"
        + "AAMyAAPDKU+0H58tsjpoYmYCInMr/FayvCCkupebgsnpaGEB7qS9vzcNVUj6"
        + "mrnmiC2grpmhRwRFMEMwQTALBgcqhkjOPQIBBQADMgACZpD13z9c7DzRWx6S"
        + "0xdbq3S+EJ7vWO+YcHVjTD8NcQDcZcWASW899l1PkL936zsuMBoGCSuBBRCG"
        + "SD8AEDANBglghkgBZQMEAQUFADBLMEkwLTAoMRMwEQYDVQQDEwpBZG1pbi1N"
        + "RFNFMREwDwYDVQQKEwg0QkNULTJJRAIBAQQYFq58L71nyMK/70w3nc6zkkRy"
        + "RL7DHmpZMIAGCSqGSIb3DQEHATAdBglghkgBZQMEAQIEEDzRUpreBsZXWHBe"
        + "onxOtSmggAQQ7csAZXwT1lHUqoazoy8bhAQQq+9Zjj8iGdOWgyebbfj67QAA"
        + "AAAAAAAAAAA=");


    private byte[] ecKeyAgreeKey = Base64.decode(
        "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDC8vp7xVTbKSgYVU5Wc"
      + "hGkWbzaj+yUFETIWP1Dt7+WSpq3ikSPdl7PpHPqnPVZfoIWhZANiAgSYHTgxf+Dd"
      + "Tt84dUvuSKkFy3RhjxJmjwIscK6zbEUzKhcPQG2GHzXhWK5x1kov0I74XpGhVkya"
      + "ElH5K6SaOXiXAzcyNGggTOk4+ZFnz5Xl0pBje3zKxPhYu0SnCw7Pcqw=");

    private byte[] bobPrivRsaEncrypt = Base64.decode(
       "MIIChQIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKnhZ5g/OdVf"
     + "8qCTQV6meYmFyDVdmpFb+x0B2hlwJhcPvaUi0DWFbXqYZhRBXM+3twg7CcmR"
     + "uBlpN235ZR572akzJKN/O7uvRgGGNjQyywcDWVL8hYsxBLjMGAgUSOZPHPtd"
     + "YMTgXB9T039T2GkB8QX4enDRvoPGXzjPHCyqaqfrAgMBAAECgYBnzUhMmg2P"
     + "mMIbZf8ig5xt8KYGHbztpwOIlPIcaw+LNd4Ogngwy+e6alatd8brUXlweQqg"
     + "9P5F4Kmy9Bnah5jWMIR05PxZbMHGd9ypkdB8MKCixQheIXFD/A0HPfD6bRSe"
     + "TmPwF1h5HEuYHD09sBvf+iU7o8AsmAX2EAnYh9sDGQJBANDDIsbeopkYdo+N"
     + "vKZ11mY/1I1FUox29XLE6/BGmvE+XKpVC5va3Wtt+Pw7PAhDk7Vb/s7q/WiE"
     + "I2Kv8zHCueUCQQDQUfweIrdb7bWOAcjXq/JY1PeClPNTqBlFy2bKKBlf4hAr"
     + "84/sajB0+E0R9KfEILVHIdxJAfkKICnwJAiEYH2PAkA0umTJSChXdNdVUN5q"
     + "SO8bKlocSHseIVnDYDubl6nA7xhmqU5iUjiEzuUJiEiUacUgFJlaV/4jbOSn"
     + "I3vQgLeFAkEAni+zN5r7CwZdV+EJBqRd2ZCWBgVfJAZAcpw6iIWchw+dYhKI"
     + "FmioNRobQ+g4wJhprwMKSDIETukPj3d9NDAlBwJAVxhn1grStavCunrnVNqc"
     + "BU+B1O8BiR4yPWnLMcRSyFRVJQA7HCp8JlDV6abXd8vPFfXuC9WN7rOvTKF8"
     + "Y0ZB9qANMAsGA1UdDzEEAwIAEA==");

    private byte[] rfc4134ex5_1 = Base64.decode(
          "MIIBHgYJKoZIhvcNAQcDoIIBDzCCAQsCAQAxgcAwgb0CAQAwJjASMRAwDgYD"
        + "VQQDEwdDYXJsUlNBAhBGNGvHgABWvBHTbi7NXXHQMA0GCSqGSIb3DQEBAQUA"
        + "BIGAC3EN5nGIiJi2lsGPcP2iJ97a4e8kbKQz36zg6Z2i0yx6zYC4mZ7mX7FB"
        + "s3IWg+f6KgCLx3M1eCbWx8+MDFbbpXadCDgO8/nUkUNYeNxJtuzubGgzoyEd"
        + "8Ch4H/dd9gdzTd+taTEgS0ipdSJuNnkVY4/M652jKKHRLFf02hosdR8wQwYJ"
        + "KoZIhvcNAQcBMBQGCCqGSIb3DQMHBAgtaMXpRwZRNYAgDsiSf8Z9P43LrY4O"
        + "xUk660cu1lXeCSFOSOpOJ7FuVyU=");

    private byte[] rfc4134ex5_2 = Base64.decode(
            "MIIBZQYJKoZIhvcNAQcDoIIBVjCCAVICAQIxggEAMIG9AgEAMCYwEjEQMA4G"
         + "A1UEAxMHQ2FybFJTQQIQRjRrx4AAVrwR024uzV1x0DANBgkqhkiG9w0BAQEF"
         + "AASBgJQmQojGi7Z4IP+CVypBmNFoCDoEp87khtgyff2N4SmqD3RxPx+8hbLQ"
         + "t9i3YcMwcap+aiOkyqjMalT03VUC0XBOGv+HYI3HBZm/aFzxoq+YOXAWs5xl"
         + "GerZwTOc9j6AYlK4qXvnztR5SQ8TBjlzytm4V7zg+TGrnGVNQBNw47Ewoj4C"
         + "AQQwDQQLTWFpbExpc3RSQzIwEAYLKoZIhvcNAQkQAwcCAToEGHcUr5MSJ/g9"
         + "HnJVHsQ6X56VcwYb+OfojTBJBgkqhkiG9w0BBwEwGgYIKoZIhvcNAwIwDgIC"
         + "AKAECJwE0hkuKlWhgCBeKNXhojuej3org9Lt7n+wWxOhnky5V50vSpoYRfRR"
         + "yw==");

    public EnvelopedDataTest()
    {
    }

    private static void init()
        throws Exception
    {
        if (!_initialised)
        {
            _initialised = true;
            
            _signDN   = "O=Bouncy Castle, C=AU";
            _signKP   = CMSTestUtil.makeKeyPair();  
            _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

            _origDN   = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            _origKP   = CMSTestUtil.makeKeyPair();
            _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);

            _reciDN   = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP   = CMSTestUtil.makeKeyPair();
            _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);

            _origEcKP = CMSTestUtil.makeEcDsaKeyPair();
            _reciEcKP = CMSTestUtil.makeEcDsaKeyPair();
            _reciEcCert = CMSTestUtil.makeCertificate(_reciEcKP, _reciDN, _signKP, _signDN);
        }
    }
    
    public static void main(
        String args[])
        throws Exception
    {
        junit.textui.TestRunner.run(EnvelopedDataTest.suite());
    }

    public static Test suite() 
        throws Exception
    {
        init();
        
        return new CMSTestSetup(new TestSuite(EnvelopedDataTest.class));
    }

    public void testKeyTrans()
        throws Exception
    {
        byte[]          data     = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                CMSEnvelopedDataGenerator.DES_EDE3_CBC, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();


        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);
        
        Collection  c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());
            
            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testKeyTransCAST5SunJCE()
        throws Exception
    {
        if (Security.getProvider("SunJCE") == null)
        {
            return;
        }
        
        String version = System.getProperty("java.version");
        if (version.startsWith("1.4") || version.startsWith("1.3"))
        {
            return;
        }
        
        byte[]          data     = "WallaWallaWashington".getBytes();
    
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
    
        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                CMSEnvelopedDataGenerator.CAST5_CBC, "SunJCE");
        RecipientInformationStore  recipients = ed.getRecipientInfos();
        
        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.CAST5_CBC);

        Collection  c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator    it = c.iterator();
        
        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();
    
            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());
            
            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "SunJCE");
    
            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testKeyTransRC4()
        throws Exception
    {
        byte[]          data     = "WallaWallaBouncyCastle".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                "1.2.840.113549.3.4", "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), "1.2.840.113549.3.4");
        
        Collection  c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }
    
    public void testKeyTrans128RC4()
        throws Exception
    {
        byte[]          data     = "WallaWallaBouncyCastle".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                "1.2.840.113549.3.4", 128, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), "1.2.840.113549.3.4");
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
        else
        {
            fail("no recipient found");
        }
    }
    
    public void testKeyTransODES()
        throws Exception
    {
        byte[]          data     = "WallaWallaBouncyCastle".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                "1.3.14.3.2.7", "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), "1.3.14.3.2.7");
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
        else
        {
            fail("no recipient found");
        }
    }

    public void testKeyTransSmallAES()
        throws Exception
    {
        byte[]          data     = new byte[] { 0, 1, 2, 3 };

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                              new CMSProcessableByteArray(data),
                              CMSEnvelopedDataGenerator.AES128_CBC, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(),
                                   CMSEnvelopedDataGenerator.AES128_CBC);
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "BC");
            assertEquals(true, Arrays.equals(data, recData));
        }
        else
        {
            fail("no recipient found");
        }
    }

    public void testKeyTransCAST5()
        throws Exception
    {
        tryKeyTrans(CMSEnvelopedDataGenerator.CAST5_CBC, new DERObjectIdentifier(CMSEnvelopedDataGenerator.CAST5_CBC), ASN1Sequence.class);
    }

    public void testKeyTransAES128()
        throws Exception
    {
        tryKeyTrans(CMSEnvelopedDataGenerator.AES128_CBC, NISTObjectIdentifiers.id_aes128_CBC, DEROctetString.class);
    }

    public void testKeyTransAES192()
        throws Exception
    {
        tryKeyTrans(CMSEnvelopedDataGenerator.AES192_CBC, NISTObjectIdentifiers.id_aes192_CBC, DEROctetString.class);
    }

    public void testKeyTransAES256()
        throws Exception
    {
        tryKeyTrans(CMSEnvelopedDataGenerator.AES256_CBC, NISTObjectIdentifiers.id_aes256_CBC, DEROctetString.class);
    }

    public void testKeyTransSEED()
        throws Exception
    {
        tryKeyTrans(CMSEnvelopedDataGenerator.SEED_CBC, KISAObjectIdentifiers.id_seedCBC, DEROctetString.class);
    }

    public void testKeyTransCamellia128()
        throws Exception
    {
        tryKeyTrans(CMSEnvelopedDataGenerator.CAMELLIA128_CBC, NTTObjectIdentifiers.id_camellia128_cbc, DEROctetString.class);
    }

    public void testKeyTransCamellia192()
        throws Exception
    {
        tryKeyTrans(CMSEnvelopedDataGenerator.CAMELLIA192_CBC, NTTObjectIdentifiers.id_camellia192_cbc, DEROctetString.class);
    }

    public void testKeyTransCamellia256()
        throws Exception
    {
        tryKeyTrans(CMSEnvelopedDataGenerator.CAMELLIA256_CBC, NTTObjectIdentifiers.id_camellia256_cbc, DEROctetString.class);
    }

    private void tryKeyTrans(String generatorOID, DERObjectIdentifier checkOID, Class asn1Params)
        throws Exception
    {
        byte[]          data     = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                generatorOID, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(checkOID.getId(), ed.getEncryptionAlgOID());

        if (asn1Params != null)
        {
            ASN1InputStream aIn = new ASN1InputStream(ed.getEncryptionAlgParams());

            assertTrue(asn1Params.isAssignableFrom(aIn.readObject().getClass()));
        }

        Collection  c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator    it = c.iterator();

        if (!it.hasNext())
        {
            fail("no recipients found");
        }

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testErrorneousKEK()
        throws Exception
    {
        byte[]    data = "WallaWallaWashington".getBytes();
        SecretKey kek  = new SecretKeySpec(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }, "AES");

        CMSEnvelopedData ed = new CMSEnvelopedData(oldKEK);

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), NISTObjectIdentifiers.id_aes128_wrap.getId());

            byte[] recData = recipient.getContent(kek, "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
        else
        {
            fail("no recipient found");
        }
    }

    public void testDESKEK()
        throws Exception
    {
        tryKekAlgorithm(CMSTestUtil.makeDesede192Key(), new DERObjectIdentifier("1.2.840.113549.1.9.16.3.6"));
    }
    public void testRC2128KEK()
        throws Exception
    {
        tryKekAlgorithm(CMSTestUtil.makeRC2128Key(), new DERObjectIdentifier("1.2.840.113549.1.9.16.3.7"));
    }

    public void testAES128KEK()
        throws Exception
    {
        tryKekAlgorithm(CMSTestUtil.makeAESKey(128), NISTObjectIdentifiers.id_aes128_wrap);
    }

    public void testAES192KEK()
        throws Exception
    {
        tryKekAlgorithm(CMSTestUtil.makeAESKey(192), NISTObjectIdentifiers.id_aes192_wrap);
    }

    public void testAES256KEK()
        throws Exception
    {
        tryKekAlgorithm(CMSTestUtil.makeAESKey(256), NISTObjectIdentifiers.id_aes256_wrap);
    }

    public void testSEED128KEK()
        throws Exception
    {
        tryKekAlgorithm(CMSTestUtil.makeSEEDKey(), KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap);
    }

    public void testCamellia128KEK()
        throws Exception
    {
        tryKekAlgorithm(CMSTestUtil.makeCamelliaKey(128), NTTObjectIdentifiers.id_camellia128_wrap);
    }

    public void testCamellia192KEK()
        throws Exception
    {
        tryKekAlgorithm(CMSTestUtil.makeCamelliaKey(192), NTTObjectIdentifiers.id_camellia192_wrap);
    }

    public void testCamellia256KEK()
        throws Exception
    {
        tryKekAlgorithm(CMSTestUtil.makeCamelliaKey(256), NTTObjectIdentifiers.id_camellia256_wrap);
    }

    private void tryKekAlgorithm(SecretKey kek, DERObjectIdentifier algOid)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        byte[]    data = "WallaWallaWashington".getBytes();
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        byte[]  kekId = new byte[] { 1, 2, 3, 4, 5 };

        edGen.addKEKRecipient(kek, kekId);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                CMSEnvelopedDataGenerator.DES_EDE3_CBC, "BC");

        RecipientInformationStore recipients = ed.getRecipientInfos();

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(algOid.getId(), recipient.getKeyEncryptionAlgOID());

            byte[] recData = recipient.getContent(kek, "BC");

            assertTrue(Arrays.equals(data, recData));
        }
        else
        {
            fail("no recipient found");
        }
    }

    public void testECKeyAgree()
        throws Exception
    {
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyAgreementRecipient(CMSEnvelopedDataGenerator.ECDH_SHA1KDF, _origEcKP.getPrivate(), _origEcKP.getPublic(), _reciEcCert, CMSEnvelopedDataGenerator.AES128_WRAP, "BC");

        CMSEnvelopedData ed = edGen.generate(
                              new CMSProcessableByteArray(data),
                              CMSEnvelopedDataGenerator.AES128_CBC, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(),
                                   CMSEnvelopedDataGenerator.AES128_CBC);

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(_reciEcKP.getPrivate(), "BC");
            assertEquals(true, Arrays.equals(data, recData));
        }
        else
        {
            fail("no recipient found");
        }
    }

    public void testECKeyAgreeVectors()
        throws Exception
    {
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(ecKeyAgreeKey);
        KeyFactory          fact = KeyFactory.getInstance("ECDH", "BC");
        PrivateKey          privKey = fact.generatePrivate(privSpec);

        verifyECKeyAgreeVectors(privKey, "2.16.840.1.101.3.4.1.42", ecKeyAgreeMsgAES256);
        verifyECKeyAgreeVectors(privKey, "2.16.840.1.101.3.4.1.2", ecKeyAgreeMsgAES128);
        verifyECKeyAgreeVectors(privKey, "1.2.840.113549.3.7", ecKeyAgreeMsgDESEDE);
    }
    /*
    public void testECMQVKeyAgreeVectors()
        throws Exception
    {
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(ecKeyAgreeKey);
        KeyFactory          fact = KeyFactory.getInstance("ECDH", "BC");
        PrivateKey          privKey = fact.generatePrivate(privSpec);

        verifyECMQVKeyAgreeVectors(privKey, "2.16.840.1.101.3.4.1.2", ecMQVKeyAgreeMsgAES128);
    }
    */
    public void testPasswordAES256()
        throws Exception
    {
        passwordTest(CMSEnvelopedDataGenerator.AES256_CBC);
        passwordUTF8Test(CMSEnvelopedDataGenerator.AES256_CBC);
    }

    public void testPasswordDESEDE()
        throws Exception
    {
        passwordTest(CMSEnvelopedDataGenerator.DES_EDE3_CBC);
        passwordUTF8Test(CMSEnvelopedDataGenerator.DES_EDE3_CBC);
    }

    public void testRFC4134ex5_1()
        throws Exception
    {
        byte[] data = Hex.decode("5468697320697320736f6d652073616d706c6520636f6e74656e742e");

        KeyFactory kFact = KeyFactory.getInstance("RSA", "BC");
        Key key = kFact.generatePrivate(new PKCS8EncodedKeySpec(bobPrivRsaEncrypt));

        CMSEnvelopedData ed = new CMSEnvelopedData(rfc4134ex5_1);

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals("1.2.840.113549.3.7", ed.getEncryptionAlgOID());

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(key, "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
        else
        {
            fail("no recipient found");
        }
    }

    public void testRFC4134ex5_2()
        throws Exception
    {
        byte[] data = Hex.decode("5468697320697320736f6d652073616d706c6520636f6e74656e742e");

        KeyFactory kFact = KeyFactory.getInstance("RSA", "BC");
        Key key = kFact.generatePrivate(new PKCS8EncodedKeySpec(bobPrivRsaEncrypt));

        CMSEnvelopedData ed = new CMSEnvelopedData(rfc4134ex5_2);

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals("1.2.840.113549.3.2", ed.getEncryptionAlgOID());

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        if (it.hasNext())
        {
            while (it.hasNext())
            {
                RecipientInformation   recipient = (RecipientInformation)it.next();
                byte[] recData;

                if (recipient instanceof KeyTransRecipientInformation)
                {
                    recData = recipient.getContent(key, "BC");

                    assertEquals(true, Arrays.equals(data, recData));
                }
            }
        }
        else
        {
            fail("no recipient found");
        }
    }

    public void testOriginatorInfo()
        throws Exception
    {
        CMSEnvelopedData env = new CMSEnvelopedData(CMSSampleMessages.originatorMessage);

        RecipientInformationStore  recipients = env.getRecipientInfos();

        assertEquals(CMSEnvelopedDataGenerator.DES_EDE3_CBC, env.getEncryptionAlgOID());

    }

    private void passwordTest(String algorithm)
        throws Exception
    {
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addPasswordRecipient(new PKCS5Scheme2PBEKey("password".toCharArray(), new byte[20], 5), algorithm);

        CMSEnvelopedData ed = edGen.generate(
                              new CMSProcessableByteArray(data),
                              CMSEnvelopedDataGenerator.AES128_CBC, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(),
                                   CMSEnvelopedDataGenerator.AES128_CBC);

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(new PKCS5Scheme2PBEKey("password".toCharArray(), new byte[20], 5), "BC");
            assertEquals(true, Arrays.equals(data, recData));
        }
        else
        {
            fail("no recipient found");
        }
    }

    private void passwordUTF8Test(String algorithm)
        throws Exception
    {
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addPasswordRecipient(new PKCS5Scheme2UTF8PBEKey("abc\u5639\u563b".toCharArray(), new byte[20], 5), algorithm);

        CMSEnvelopedData ed = edGen.generate(
                              new CMSProcessableByteArray(data),
                              CMSEnvelopedDataGenerator.AES128_CBC, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(),
                                   CMSEnvelopedDataGenerator.AES128_CBC);

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(new PKCS5Scheme2UTF8PBEKey("abc\u5639\u563b".toCharArray(), new byte[20], 5), "BC");
            assertEquals(true, Arrays.equals(data, recData));
        }
        else
        {
            fail("no recipient found");
        }
    }

    private void verifyECKeyAgreeVectors(PrivateKey privKey, String wrapAlg, byte[] message)
        throws CMSException, GeneralSecurityException
    {
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CMSEnvelopedData ed = new CMSEnvelopedData(message);

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        assertEquals(wrapAlg, ed.getEncryptionAlgOID());

        if (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals("1.3.133.16.840.63.0.2", recipient.getKeyEncryptionAlgOID());

            byte[] recData = recipient.getContent(privKey, "BC");

            assertTrue(Arrays.equals(data, recData));
        }
        else
        {
            fail("no recipient found");
        }
    }

    private void verifyECMQVKeyAgreeVectors(PrivateKey privKey, String wrapAlg, byte[] message)
        throws CMSException, GeneralSecurityException
    {
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CMSEnvelopedData ed = new CMSEnvelopedData(message);

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        assertEquals(wrapAlg, ed.getEncryptionAlgOID());

        if (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals("1.3.133.16.840.63.0.16", recipient.getKeyEncryptionAlgOID());

            byte[] recData = recipient.getContent(privKey, "BC");

            assertTrue(Arrays.equals(data, recData));
        }
        else
        {
            fail("no recipient found");
        }
    }
}
