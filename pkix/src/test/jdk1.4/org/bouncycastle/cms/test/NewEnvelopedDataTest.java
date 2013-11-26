package org.bouncycastle.cms.test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Iterator;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RC2CBCParameter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.OriginatorInfoGenerator;
import org.bouncycastle.cms.OriginatorInformation;
import org.bouncycastle.cms.PasswordRecipient;
import org.bouncycastle.cms.PasswordRecipientInformation;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.cms.bc.BcCMSContentEncryptorBuilder;
import org.bouncycastle.cms.bc.BcRSAKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKEKEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JcePasswordEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

public class NewEnvelopedDataTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    
    private static String          _signDN;
    private static KeyPair         _signKP;
    private static X509Certificate _signCert;

    private static String          _origDN;
    private static KeyPair         _origKP;
    private static X509Certificate _origCert;

    private static String          _reciDN;
    private static String          _reciDN2;
    private static KeyPair         _reciKP;
    private static KeyPair         _reciOaepKP;
    private static X509Certificate _reciCert;
    private static X509Certificate _reciCertOaep;

    private static KeyPair         _origEcKP;
    private static KeyPair         _reciEcKP;
    private static X509Certificate _reciEcCert;
    private static KeyPair         _reciEcKP2;
    private static X509Certificate _reciEcCert2;

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

    private byte[] tooShort3DES = Base64.decode(
            "MIAGCSqGSIb3DQEHA6CAMIACAQAxgcQwgcECAQAwKjAlMRYwFAYDVQQKDA1C" +
            "b3VuY3kgQ2FzdGxlMQswCQYDVQQGEwJBVQIBCjANBgkqhkiG9w0BAQEFAASB" +
            "gJIM2QN0o6iv8Ux018pVCJ8js+ROV4t6+KoMwLJ4DzRKLU8XCAb9BS+crP+F" +
            "ghNTxTpTX8TaxPrO4wV0USgVHu2SvFnxNaWZjBDVIyZI2HR4QkSTqFMhsUB2" +
            "6CuZIWBZkhqQ6ruDfvn9UuBWVnfsBD4iryZ1idr713sDeVo5TyvTMIAGCSqG" +
            "SIb3DQEHATAUBggqhkiG9w0DBwQIQq9e4+WB3CqggAQIwU4cOlmkWUcAAAAA" +
            "AAAAAAAA");

    private byte[] tooShort3DESKey = Base64.decode(
            "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAODZDCj0nQdV" +
            "f0GGeFsPjjvPx1Vem0V6IkJ4SzazGKfddk0pX58ZDCnG+S+OPiXmPDqValiu" +
            "9FtNy2/r9rrf/6qtcVQJkfSJv9E5Y7HgI98L/Y9lKxZWsfRqu/SlYO5zx0Dc" +
            "2rzDvvZRtrtaq0uuHXWJlbWda2L9S65sv/Le/zvjAgMBAAECgYEAnn+iGMTG" +
            "ZMMaH6Cg+t/uTa9cPougPMuplt2hd3+sY7izihUeONK5RkHiqmlE2gaAcnOd" +
            "McKysiIWxGC73mPEnsOObPkaFlneVb5CtjTaTMdptuLNEQkwvtKhuW2HnMra" +
            "4afEgFZdll3FyRpvW/CDooe4Bppjd4aGn/Sr/o9nOzECQQD4QKLwZssuclji" +
            "nD/8gU1CqGMMnGNogTMpHm1269HUOE7r1y3MuapUqSWsVhpuEQ8P/Tko0haJ" +
            "jeZn2eWTbZu/AkEA591snui8FMeGvkRgvyMFNvXZWDEjsh+N74XEL1lykTgZ" +
            "FQJ+cmThnrdM/8yj1dKkdASYrk5kFJ4PVE6CzDI43QJAFS22eNncJZc9u/9m" +
            "eg0x4SjqYk4JMQYsripZXlbZ7Mfs+7O8xYVlYZmYjC5ATPmJlmyc7r2VjKCd" +
            "cmilbEFikwJBAMh7yf8BaBdjitubzjeW9VxXaa37F01eQWD5PfBfHFP6uJ1V" +
            "AbayCfAtuHN6I7OwJih3DPmyqJC3NrQECs67IjUCQAb4TfVE/2G1s66SGnb4" +
            "no34BspoV/i4f0uLhJap84bTHcF/ZRSXCmQOCRGdSvQkXHeNPI5Lus6lOHuU" +
            "vUDbQC8=");

    public NewEnvelopedDataTest()
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
            _reciDN2  = "CN=Fred, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP   = CMSTestUtil.makeKeyPair();
            _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);
            _reciCertOaep = CMSTestUtil.makeOaepCertificate(_reciKP, _reciDN, _signKP, _signDN);

            _origEcKP = CMSTestUtil.makeEcDsaKeyPair();
            _reciEcKP = CMSTestUtil.makeEcDsaKeyPair();
            _reciEcCert = CMSTestUtil.makeCertificate(_reciEcKP, _reciDN, _signKP, _signDN);
            _reciEcKP2 = CMSTestUtil.makeEcDsaKeyPair();
            _reciEcCert2 = CMSTestUtil.makeCertificate(_reciEcKP2, _reciDN2, _signKP, _signDN);
        }
    }

    public static void main(
        String args[])
        throws Exception
    {
        junit.textui.TestRunner.run(NewEnvelopedDataTest.suite());
    }

    public static Test suite()
        throws Exception
    {
        init();

        return new CMSTestSetup(new TestSuite(NewEnvelopedDataTest.class));
    }

    public void testUnprotectedAttributes()
        throws Exception
    {
        byte[]          data     = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        Hashtable attrs = new Hashtable();

        attrs.put(PKCSObjectIdentifiers.id_aa_contentHint, new Attribute(PKCSObjectIdentifiers.id_aa_contentHint, new DERSet(new DERUTF8String("Hint"))));
        attrs.put(PKCSObjectIdentifiers.id_aa_receiptRequest, new Attribute(PKCSObjectIdentifiers.id_aa_receiptRequest, new DERSet(new DERUTF8String("Request"))));

        AttributeTable attrTable = new AttributeTable(attrs);

        edGen.setUnprotectedAttributeGenerator(new SimpleAttributeTableGenerator(attrTable));

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        attrTable = ed.getUnprotectedAttributes();

        assertEquals(attrs.size(), 2);

        assertEquals(new DERUTF8String("Hint"), attrTable.get(PKCSObjectIdentifiers.id_aa_contentHint).getAttrValues().getObjectAt(0));
        assertEquals(new DERUTF8String("Request"), attrTable.get(PKCSObjectIdentifiers.id_aa_receiptRequest).getAttrValues().getObjectAt(0));
                
        Collection  c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testKeyTrans()
        throws Exception
    {
        byte[]          data     = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));
        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(ASN1OctetString.getInstance(ASN1OctetString.getInstance(_reciCert.getExtensionValue(Extension.subjectKeyIdentifier.getId())).getOctets()).getOctets(), _reciCert.getPublicKey()).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());

        RecipientInformationStore  recipients = ed.getRecipientInfos();


        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        Collection  c = recipients.getRecipients();

        assertEquals(2, c.size());

        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertEquals(true, Arrays.equals(data, recData));
        }

        RecipientId id = new JceKeyTransRecipientId(_reciCert);

        Collection collection = recipients.getRecipients(id);
        if (collection.size() != 2)
        {
            fail("recipients not matched using general recipient ID.");
        }
        assertTrue(collection.iterator().next() instanceof RecipientInformation);
    }

    public void testKeyTransWithAlgMapping()
        throws Exception
    {
        byte[]          data     = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setAlgorithmMapping(PKCSObjectIdentifiers.rsaEncryption, "RSA/2/PKCS1Padding").setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        Collection  c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setAlgorithmMapping(PKCSObjectIdentifiers.rsaEncryption, "RSA/2/PKCS1Padding").setProvider(BC));

            assertEquals(true, Arrays.equals(data, recData));
        }

        RecipientId id = new JceKeyTransRecipientId(_reciCert);

        Collection collection = recipients.getRecipients(id);
        if (collection.size() != 1)
        {
            fail("recipients not matched using general recipient ID.");
        }
        assertTrue(collection.iterator().next() instanceof RecipientInformation);
    }

    public void testOriginatorInfoGeneration()
        throws Exception
    {
        byte[]          data     = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        X509CertificateHolder origCert = new X509CertificateHolder(_origCert.getEncoded());

        edGen.setOriginatorInfo(new OriginatorInfoGenerator(origCert).generate());

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));
        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(ASN1OctetString.getInstance(ASN1OctetString.getInstance(_reciCert.getExtensionValue(Extension.subjectKeyIdentifier.getId())).getOctets()).getOctets(), _reciCert.getPublicKey()).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());

        RecipientInformationStore  recipients = ed.getRecipientInfos();


        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        assertTrue(ed.getOriginatorInfo().getCertificates().getMatches(null).contains(origCert));

        Collection  c = recipients.getRecipients();

        assertEquals(2, c.size());

        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertEquals(true, Arrays.equals(data, recData));
        }

        RecipientId id = new JceKeyTransRecipientId(_reciCert);

        Collection collection = recipients.getRecipients(id);
        if (collection.size() != 2)
        {
            fail("recipients not matched using general recipient ID.");
        }
        assertTrue(collection.iterator().next() instanceof RecipientInformation);
    }

    public void testKeyTransRC2bit40()
        throws Exception
    {
        byte[]          data     = "WallaWallaBouncyCastle".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.RC2_CBC, 40).setProvider(BC).build());

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getContentEncryptionAlgorithm().getAlgorithm(), CMSAlgorithm.RC2_CBC);

        RC2CBCParameter rc2P = RC2CBCParameter.getInstance(ed.getContentEncryptionAlgorithm().getParameters());
        assertEquals(160, rc2P.getRC2ParameterVersion().intValue());

        Collection  c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testKeyTransRC4()
        throws Exception
    {
        byte[]          data     = "WallaWallaBouncyCastle".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier("1.2.840.113549.3.4")).setProvider(BC).build());

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), "1.2.840.113549.3.4");

        Collection  c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testKeyTrans128RC4()
        throws Exception
    {
        byte[]          data     = "WallaWallaBouncyCastle".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier("1.2.840.113549.3.4"), 128).setProvider(BC).build());

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), "1.2.840.113549.3.4");

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertEquals(true, Arrays.equals(data, recData));
        }
        else
        {
            fail("no recipient found");
        }
    }

    public void testKeyTransLight128RC4()
        throws Exception
    {
        byte[]          data     = "WallaWallaBouncyCastle".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new BcRSAKeyTransRecipientInfoGenerator(new JcaX509CertificateHolder(_reciCert)));

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier("1.2.840.113549.3.4"), 128).setProvider(BC).build());

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), "1.2.840.113549.3.4");

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

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

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier("1.3.14.3.2.7")).setProvider(BC).build());

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), "1.3.14.3.2.7");

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

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

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
                              new CMSProcessableByteArray(data),
                              new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(),
                                   CMSEnvelopedDataGenerator.AES128_CBC);

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));
            assertEquals(true, Arrays.equals(data, recData));
        }
        else
        {
            fail("no recipient found");
        }
    }

    public void testKeyTransDESEDE3Short()
        throws Exception
    {
        byte[]          data     = new byte[] { 0, 1, 2, 3 };
        KeyFactory      kf = KeyFactory.getInstance("RSA", BC);
        PrivateKey      kPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(tooShort3DESKey));

        CMSEnvelopedData ed = new CMSEnvelopedData(tooShort3DES);

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();
            try
            {
                byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(kPriv).setKeySizeValidation(true).setProvider(BC));
                fail("invalid 3DES-EDE key not picked up");
            }
            catch (CMSException e)
            {
                assertEquals("Expected key size for algorithm OID not found in recipient.", e.getMessage());
            }

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(kPriv).setKeySizeValidation(false).setProvider(BC));
            assertEquals(true, Arrays.equals(data, recData));
        }
        else
        {
            fail("no recipient found");
        }
    }

    public void testKeyTransDESEDE3Light()
        throws Exception
    {
        byte[]          data     = new byte[] { 0, 1, 2, 3 };

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new BcRSAKeyTransRecipientInfoGenerator(new JcaX509CertificateHolder(_reciCert)));

        CMSEnvelopedData ed = edGen.generate(
                              new CMSProcessableByteArray(data),
                              new BcCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC, 192).build());

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setKeySizeValidation(true).setProvider(BC));
            assertEquals(true, Arrays.equals(data, recData));
        }
        else
        {
            fail("no recipient found");
        }
    }

    public void testKeyTransDES()
         throws Exception
     {
         tryKeyTrans(CMSAlgorithm.DES_CBC, CMSAlgorithm.DES_CBC, 8, DEROctetString.class);
     }

   public void testKeyTransCAST5()
        throws Exception
    {
        tryKeyTrans(CMSAlgorithm.CAST5_CBC, CMSAlgorithm.CAST5_CBC, 16, ASN1Sequence.class);
    }

    public void testKeyTransAES128()
        throws Exception
    {
        tryKeyTrans(CMSAlgorithm.AES128_CBC, NISTObjectIdentifiers.id_aes128_CBC, 16, DEROctetString.class);
    }

    public void testKeyTransAES192()
        throws Exception
    {
        tryKeyTrans(CMSAlgorithm.AES192_CBC, NISTObjectIdentifiers.id_aes192_CBC, 24, DEROctetString.class);
    }

    public void testKeyTransAES256()
        throws Exception
    {
        tryKeyTrans(CMSAlgorithm.AES256_CBC, NISTObjectIdentifiers.id_aes256_CBC, 32, DEROctetString.class);
    }

    public void testKeyTransSEED()
        throws Exception
    {
        tryKeyTrans(CMSAlgorithm.SEED_CBC, KISAObjectIdentifiers.id_seedCBC, 16, DEROctetString.class);
    }

    public void testKeyTransCamellia128()
        throws Exception
    {
        tryKeyTrans(CMSAlgorithm.CAMELLIA128_CBC, NTTObjectIdentifiers.id_camellia128_cbc, 16, DEROctetString.class);
    }

    public void testKeyTransCamellia192()
        throws Exception
    {
        tryKeyTrans(CMSAlgorithm.CAMELLIA192_CBC, NTTObjectIdentifiers.id_camellia192_cbc, 24, DEROctetString.class);
    }

    public void testKeyTransCamellia256()
        throws Exception
    {
        tryKeyTrans(CMSAlgorithm.CAMELLIA256_CBC, NTTObjectIdentifiers.id_camellia256_cbc, 32, DEROctetString.class);
    }

    private void tryKeyTrans(ASN1ObjectIdentifier generatorOID, ASN1ObjectIdentifier checkOID, int keySize, Class asn1Params)
        throws Exception
    {
        byte[]          data     = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(generatorOID).setProvider(BC).build();
        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            encryptor);

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(checkOID.getId(), ed.getEncryptionAlgOID());
        assertEquals(keySize, ((byte[])encryptor.getKey().getRepresentation()).length);

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

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setKeySizeValidation(true).setProvider(BC));

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testErroneousKEK()
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

            byte[] recData = recipient.getContent(new JceKEKEnvelopedRecipient(kek).setProvider(BC));

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
        tryKekAlgorithm(CMSTestUtil.makeDesede192Key(), new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.3.6"));
    }
    public void testRC2128KEK()
        throws Exception
    {
        tryKekAlgorithm(CMSTestUtil.makeRC2128Key(), new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.3.7"));
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

    private void tryKekAlgorithm(SecretKey kek, ASN1ObjectIdentifier algOid)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        byte[]    data = "WallaWallaWashington".getBytes();
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        byte[]  kekId = new byte[] { 1, 2, 3, 4, 5 };

        edGen.addRecipientInfoGenerator(new JceKEKRecipientInfoGenerator(kekId, kek).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(algOid.getId(), recipient.getKeyEncryptionAlgOID());

            byte[] recData = recipient.getContent(new JceKEKEnvelopedRecipient(kek).setKeySizeValidation(true).setProvider(BC));

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

        edGen.addRecipientInfoGenerator(new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECDH_SHA1KDF,
            _origEcKP.getPrivate(), _origEcKP.getPublic(),
             CMSAlgorithm.AES128_WRAP).addRecipient(_reciEcCert).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.AES128_CBC);

        RecipientInformationStore recipients = ed.getRecipientInfos();

        confirmDataReceived(recipients, data, _reciEcCert, _reciEcKP.getPrivate(), BC);
        confirmNumberRecipients(recipients, 1);
    }

    public void testECMQVKeyAgree()
        throws Exception
    {
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECMQV_SHA1KDF,
            _origEcKP.getPrivate(), _origEcKP.getPublic(),
            CMSAlgorithm.AES128_WRAP).addRecipient(_reciEcCert).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.AES128_CBC);

        RecipientInformationStore recipients = ed.getRecipientInfos();

        confirmDataReceived(recipients, data, _reciEcCert, _reciEcKP.getPrivate(), BC);
        confirmNumberRecipients(recipients, 1);
    }

    public void testECMQVKeyAgreeMultiple()
        throws Exception
    {
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        JceKeyAgreeRecipientInfoGenerator recipientGenerator = new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECMQV_SHA1KDF,
            _origEcKP.getPrivate(), _origEcKP.getPublic(), CMSAlgorithm.AES128_WRAP).setProvider(BC);

        recipientGenerator.addRecipient(_reciEcCert);
        recipientGenerator.addRecipient(_reciEcCert2);

        edGen.addRecipientInfoGenerator(recipientGenerator);

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.AES128_CBC);

        RecipientInformationStore recipients = ed.getRecipientInfos();

        confirmDataReceived(recipients, data, _reciEcCert, _reciEcKP.getPrivate(), BC);
        confirmDataReceived(recipients, data, _reciEcCert2, _reciEcKP2.getPrivate(), BC);
        confirmNumberRecipients(recipients, 2);
    }

    private static void confirmDataReceived(RecipientInformationStore recipients,
        byte[] expectedData, X509Certificate reciCert, PrivateKey reciPrivKey, String provider)
        throws CMSException, NoSuchProviderException, CertificateEncodingException, IOException
    {
        RecipientId rid = new JceKeyAgreeRecipientId(reciCert);

        RecipientInformation recipient = recipients.get(rid);
        assertNotNull(recipient);

        byte[] actualData = recipient.getContent(new JceKeyAgreeEnvelopedRecipient(reciPrivKey).setProvider(provider));
        assertEquals(true, Arrays.equals(expectedData, actualData));
    }

    private static void confirmNumberRecipients(RecipientInformationStore recipients, int count)
    {
        assertEquals(count, recipients.getRecipients().size());
    }

    public void testECKeyAgreeVectors()
        throws Exception
    {
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(ecKeyAgreeKey);
        KeyFactory          fact = KeyFactory.getInstance("ECDH", BC);
        PrivateKey          privKey = fact.generatePrivate(privSpec);

        verifyECKeyAgreeVectors(privKey, "2.16.840.1.101.3.4.1.42", ecKeyAgreeMsgAES256);
        verifyECKeyAgreeVectors(privKey, "2.16.840.1.101.3.4.1.2", ecKeyAgreeMsgAES128);
        verifyECKeyAgreeVectors(privKey, "1.2.840.113549.3.7", ecKeyAgreeMsgDESEDE);
    }

    public void testECMQVKeyAgreeVectors()
        throws Exception
    {
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(ecKeyAgreeKey);
        KeyFactory          fact = KeyFactory.getInstance("ECDH", BC);
        PrivateKey          privKey = fact.generatePrivate(privSpec);

        verifyECMQVKeyAgreeVectors(privKey, "2.16.840.1.101.3.4.1.2", ecMQVKeyAgreeMsgAES128);
    }

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

        KeyFactory kFact = KeyFactory.getInstance("RSA", BC);
        Key key = kFact.generatePrivate(new PKCS8EncodedKeySpec(bobPrivRsaEncrypt));

        CMSEnvelopedData ed = new CMSEnvelopedData(rfc4134ex5_1);

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals("1.2.840.113549.3.7", ed.getEncryptionAlgOID());

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient((PrivateKey)key).setProvider(BC));

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

        KeyFactory kFact = KeyFactory.getInstance("RSA", BC);
        PrivateKey key = kFact.generatePrivate(new PKCS8EncodedKeySpec(bobPrivRsaEncrypt));

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
                    recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(key).setProvider(BC));

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

        OriginatorInformation origInfo = env.getOriginatorInfo();

        assertEquals(new X500Name("C=US,O=U.S. Government,OU=HSPD12Lab,OU=Agents,CN=user1"), ((X509CertificateHolder)origInfo.getCertificates().getMatches(null).iterator().next()).getSubject());
        assertEquals(CMSEnvelopedDataGenerator.DES_EDE3_CBC, env.getEncryptionAlgOID());
    }

    private void passwordTest(String algorithm)
        throws Exception
    {
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JcePasswordRecipientInfoGenerator(new ASN1ObjectIdentifier(algorithm), "password".toCharArray()).setProvider(BC).setPasswordConversionScheme(PasswordRecipient.PKCS5_SCHEME2).setSaltAndIterationCount(new byte[20], 5));

        CMSEnvelopedData ed = edGen.generate(
                              new CMSProcessableByteArray(data),
                              new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(),
                                   CMSEnvelopedDataGenerator.AES128_CBC);

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        if (it.hasNext())
        {
            PasswordRecipientInformation recipient = (PasswordRecipientInformation)it.next();

            byte[] recData = recipient.getContent(new JcePasswordEnvelopedRecipient("password".toCharArray()).setPasswordConversionScheme(PasswordRecipient.PKCS5_SCHEME2).setProvider(BC));

            assertEquals(true, Arrays.equals(data, recData));
        }
        else
        {
            fail("no recipient found");
        }

        //
        // try algorithm parameters constructor
        //
        it = c.iterator();

        RecipientInformation   recipient = (RecipientInformation)it.next();

        byte[] recData = recipient.getContent(new JcePasswordEnvelopedRecipient("password".toCharArray()).setPasswordConversionScheme(PasswordRecipient.PKCS5_SCHEME2).setProvider(BC));
        assertEquals(true, Arrays.equals(data, recData));
    }

    private void passwordUTF8Test(String algorithm)
        throws Exception
    {
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JcePasswordRecipientInfoGenerator(new ASN1ObjectIdentifier(algorithm), "abc\u5639\u563b".toCharArray()).setProvider(BC).setSaltAndIterationCount(new byte[20], 5));

        CMSEnvelopedData ed = edGen.generate(
                              new CMSProcessableByteArray(data),
                              new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(),
                                   CMSEnvelopedDataGenerator.AES128_CBC);

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(new JcePasswordEnvelopedRecipient("abc\u5639\u563b".toCharArray()).setProvider(BC));
            assertEquals(true, Arrays.equals(data, recData));
        }
        else
        {
            fail("no recipient found");
        }

        //
        // try algorithm parameters constructor
        //
        it = c.iterator();

        RecipientInformation   recipient = (RecipientInformation)it.next();

        byte[] recData = recipient.getContent(new JcePasswordEnvelopedRecipient("abc\u5639\u563b".toCharArray()).setProvider(BC));
        assertEquals(true, Arrays.equals(data, recData));
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

            byte[] recData = recipient.getContent(new JceKeyAgreeEnvelopedRecipient(privKey).setProvider(BC));

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

            byte[] recData = recipient.getContent(new JceKeyAgreeEnvelopedRecipient(privKey).setProvider(BC));

            assertTrue(Arrays.equals(data, recData));
        }
        else
        {
            fail("no recipient found");
        }
    }
}
