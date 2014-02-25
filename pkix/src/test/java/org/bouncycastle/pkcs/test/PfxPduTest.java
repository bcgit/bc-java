package org.bouncycastle.pkcs.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.bc.BcDefaultDigestProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBagFactory;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilderProvider;
import org.bouncycastle.pkcs.bc.BcPKCS12PBEInputDecryptorProviderBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12PBEOutputEncryptorBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilderProvider;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;

public class PfxPduTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final char[] passwd = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};

    //
    // personal keys
    //
    private static final RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
        new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
        new BigInteger("11", 16));

    private static final RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(
        new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
        new BigInteger("11", 16),
        new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
        new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
        new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
        new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
        new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
        new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

    //
    // intermediate keys.
    //
    private static final RSAPublicKeySpec intPubKeySpec = new RSAPublicKeySpec(
        new BigInteger("8de0d113c5e736969c8d2b047a243f8fe18edad64cde9e842d3669230ca486f7cfdde1f8eec54d1905fff04acc85e61093e180cadc6cea407f193d44bb0e9449b8dbb49784cd9e36260c39e06a947299978c6ed8300724e887198cfede20f3fbde658fa2bd078be946a392bd349f2b49c486e20c405588e306706c9017308e69", 16),
        new BigInteger("ffff", 16));


    private static final RSAPrivateCrtKeySpec intPrivKeySpec = new RSAPrivateCrtKeySpec(
        new BigInteger("8de0d113c5e736969c8d2b047a243f8fe18edad64cde9e842d3669230ca486f7cfdde1f8eec54d1905fff04acc85e61093e180cadc6cea407f193d44bb0e9449b8dbb49784cd9e36260c39e06a947299978c6ed8300724e887198cfede20f3fbde658fa2bd078be946a392bd349f2b49c486e20c405588e306706c9017308e69", 16),
        new BigInteger("ffff", 16),
        new BigInteger("7deb1b194a85bcfd29cf871411468adbc987650903e3bacc8338c449ca7b32efd39ffc33bc84412fcd7df18d23ce9d7c25ea910b1ae9985373e0273b4dca7f2e0db3b7314056ac67fd277f8f89cf2fd73c34c6ca69f9ba477143d2b0e2445548aa0b4a8473095182631da46844c356f5e5c7522eb54b5a33f11d730ead9c0cff", 16),
        new BigInteger("ef4cede573cea47f83699b814de4302edb60eefe426c52e17bd7870ec7c6b7a24fe55282ebb73775f369157726fcfb988def2b40350bdca9e5b418340288f649", 16),
        new BigInteger("97c7737d1b9a0088c3c7b528539247fd2a1593e7e01cef18848755be82f4a45aa093276cb0cbf118cb41117540a78f3fc471ba5d69f0042274defc9161265721", 16),
        new BigInteger("6c641094e24d172728b8da3c2777e69adfd0839085be7e38c7c4a2dd00b1ae969f2ec9d23e7e37090fcd449a40af0ed463fe1c612d6810d6b4f58b7bfa31eb5f", 16),
        new BigInteger("70b7123e8e69dfa76feb1236d0a686144b00e9232ed52b73847e74ef3af71fb45ccb24261f40d27f98101e230cf27b977a5d5f1f15f6cf48d5cb1da2a3a3b87f", 16),
        new BigInteger("e38f5750d97e270996a286df2e653fd26c242106436f5bab0f4c7a9e654ce02665d5a281f2c412456f2d1fa26586ef04a9adac9004ca7f913162cb28e13bf40d", 16));

    //
    // ca keys
    //
    private static final RSAPublicKeySpec caPubKeySpec = new RSAPublicKeySpec(
        new BigInteger("b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5", 16),
        new BigInteger("11", 16));

    private static final RSAPrivateCrtKeySpec caPrivKeySpec = new RSAPrivateCrtKeySpec(
        new BigInteger("b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5", 16),
        new BigInteger("11", 16),
        new BigInteger("92e08f83cc9920746989ca5034dcb384a094fb9c5a6288fcc4304424ab8f56388f72652d8fafc65a4b9020896f2cde297080f2a540e7b7ce5af0b3446e1258d1dd7f245cf54124b4c6e17da21b90a0ebd22605e6f45c9f136d7a13eaac1c0f7487de8bd6d924972408ebb58af71e76fd7b012a8d0e165f3ae2e5077a8648e619", 16),
        new BigInteger("f75e80839b9b9379f1cf1128f321639757dba514642c206bbbd99f9a4846208b3e93fbbe5e0527cc59b1d4b929d9555853004c7c8b30ee6a213c3d1bb7415d03", 16),
        new BigInteger("b892d9ebdbfc37e397256dd8a5d3123534d1f03726284743ddc6be3a709edb696fc40c7d902ed804c6eee730eee3d5b20bf6bd8d87a296813c87d3b3cc9d7947", 16),
        new BigInteger("1d1a2d3ca8e52068b3094d501c9a842fec37f54db16e9a67070a8b3f53cc03d4257ad252a1a640eadd603724d7bf3737914b544ae332eedf4f34436cac25ceb5", 16),
        new BigInteger("6c929e4e81672fef49d9c825163fec97c4b7ba7acb26c0824638ac22605d7201c94625770984f78a56e6e25904fe7db407099cad9b14588841b94f5ab498dded", 16),
        new BigInteger("dae7651ee69ad1d081ec5e7188ae126f6004ff39556bde90e0b870962fa7b926d070686d8244fe5a9aa709a95686a104614834b0ada4b10f53197a5cb4c97339", 16));

    //
    // pkcs-12 pfx-pdu
    //
    private String pkcs12Pass = "hello world";

    private byte[]  pkcs12 = Base64.decode(
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

    private String sha256Pass = "D317F8D5191F2602C527F8E6E0E8855C4517EC9512F7A06A7A588ACF0B3A6325";

    private byte[] sha256Pfx = Base64.decode(
              "MIIFvwIBAzCCBXEGCSqGSIb3DQEHAaCCBWIEggVeMIIFWjCCBVYGCSqGSIb3"
            + "DQEHAaCCBUcEggVDMIIFPzCCBTsGCyqGSIb3DQEMCgECoIIFKjCCBSYwUAYJ"
            + "KoZIhvcNAQUNMEMwIgYJKoZIhvcNAQUMMBUEEFEZik5RaSrwXtrWCnaLzAQC"
            + "AQEwHQYJYIZIAWUDBAEqBBBTqY5oFOjZxnBBtWchzf0TBIIE0Pcvwtwthm8d"
            + "yR16f5yqtofxGzJ0aAbCF7JJ+XsL9QhNuqndTtnXits+E2WgNwwm24XyRhPA"
            + "obAwqz+DvH+gdUbKoN/gCEp+/6xhlwMQZyjyqi5ePznwLQ/bJueqmXZDT+pO"
            + "zTIeMXMF0YaSjcZZ4FJnZtBX7XQDEAPmialrknhcSZI5RoLjOzFv51FgYd9+"
            + "nWdtWlRINS9LrGCVL+y8wwHp55tWEoCR2/o9YWFMYNrUkVUUzImHCN1fkbIH"
            + "XQxPp5fUqP00kwYY4288JZrzHGWGmSVYm54ok5YRLpCs0yhB0ve//iH/fNNO"
            + "esShfBTUcRCc086skxgoCVWBZERyVJHWkKl/Q4RVzYt70k2/Qfq/xBNwVCrw"
            + "YiOB0TwSQJKpvRbtufPx2vODfAmhIKes08ZLJHsMJ+O3p99O2rWZslNY7nfx"
            + "1vWXYLVkHg0q79ThgbP4p0qQQziIVZoF9ViisJTJWzZbfJLdaKPeHcduvXsR"
            + "lRvfEpR6/lifcxvkloxjpYtM6JEjtvT1x442VRKJWZofkjCohpLSmEDt77FM"
            + "ENvra7B9ojlY+0DkwNV34FlSRrwi/nVl2XhebI11DfQFEUN+krNoZ3U4n5Sb"
            + "g0Heibg5mILPwVS5Zh2vEybXzFY6b1XPA7TlGQATm6xBaU+BNFiACp+7+6CZ"
            + "PxofFKKlWq0+Apx43JDATerwlPBKxLqxxgo0xTJUtL8OKnt6oSFX4P6O6AgX"
            + "D9Pz3dzdWW9ga65N2qEmqpeIsd6SB4eGRJ1Vf1ePDgdVBUD9DG/eWfpn8l1T"
            + "neg7wsQOGDrX00uDfio/WrjRBOw37IfToqJ/j6y/Ybggg5tldvCNoxq/42rC"
            + "RvP0GJH+LJAHgB9sOWbksR7tKizWeFEyHwrAQfYc8aIZocApObtsZp8O5nuI"
            + "MNcSCc77WZfVacrJzssKki1YHPoZeTYb9q4DRm0F6Rk+bqyvd7vs2DyLN7jT"
            + "bkWoSoyCw8PAOuc8Q/+X3jhs18RQGzsEpeTOHoYJWeTUxgPrPqDFNKNLhD+L"
            + "7mvDM7EvB08tVfLTSMeVBY+RUW6eFCbdlHfqszvp9pFZPNxQHtgbAYplwK6J"
            + "i24gCH2UMF+BNzdcN2Fw9vP3nao+mzjtY1HuYebDDNNxgBAEoUFS4jr1YLoa"
            + "+li3A9T/NqSf+J5OwASsSsp0YttAJQ+VU19amwJ141U+04kVc2bUIvSxEyxu"
            + "UzWfFs26J1FhKzacirtpNv21iH78NHWOgS3jlEZMirpCHtHDbwF0z3V0upJ7"
            + "cZzMwHJPQIGP4Nk8ei20dEogc/D2ijXHGRKdRjstzi89YXs4iLWjy2lEqhlK"
            + "IvmlbF/snra1He2En/TFYv7m1zMuEPtS/+DTcwzqoe10Lko+2bNlOikW58u/"
            + "OdAlteo1IissecMjL6743ttt8SAwx9gpAn6XHaIfFL1jiGKUQPJ5Mx9RUzfB"
            + "lsKzHLNWmrDCZtR4BC4A21aRUueDGgRbtiOCYLbVtoiTc2XWM5juahaWCNKm"
            + "4+ENQNOPrB4rJUeWJquNOj9+Brhe6pWWfi4EYVBuWlbTQB7u3uP9lnYvQHSo"
            + "nOjkhjwEhPZneaKctEqXx2LoYc8arY1LSSpaXORcOJc/LkgVCq3bBEDNCJrZ"
            + "DBOUpcPXDj43MEUwMTANBglghkgBZQMEAgEFAAQgdWQUVEirOjgax8qJhjqC"
            + "bArDHuZQQvCmtrjqyhWbI4MEENBoJ4T1+xY5fmdiwmoXPPM=");

    private String pkcs5Pass = "hello";

    private byte[] pkcs5Aes128Pfx = Base64.decode(
        "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"
      + "gw8dRrSS4gQISYYYgNAwxl0CAggA");

    private byte[] pkcs5Aes192Pfx = Base64.decode(
        "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"
      + "4EPgRMGPtQQItR+KgKM/oRMCAggA");

    private byte[] pkcs5Camellia128Pfx = Base64.decode(
        "MIIFswIBAzCCBXkGCSqGSIb3DQEHAaCCBWoEggVmMIIFYjCCAxcGCSqGSIb3"
      + "DQEHBqCCAwgwggMEAgEAMIIC/QYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYw"
      + "DgQIq+wFOOOtSokCAggAgIIC0IWDRpk4L/tSSMfwWx0mN3ecbaL+m2XZWvN9"
      + "hK1K5PghAYquCs36l603cYSV9pypOkGC5rn1d2fyZCFhUMOObSC7V/mpkitr"
      + "OfOYpaW7tU1JJecpONgIHlbd8N4fbBtH73E7vdmi6X/tg4Tl7yJf40fruYVq"
      + "yzqfJCO2aGJIFv6JWsFivjCwehBa+6ppCHBnNcj4SsVlozj1y2B0Wl2TVi3r"
      + "joBIsK2RQ+RMjM55k3pS57mV+jXtd29wb2q9utDKogvpBCboTk8dPMFcFGWz"
      + "2D41onJoEJKizAEIgXiS7UvqHddhIL9O/rSZ68j2d2GcFi1Oxer1PyZoCI61"
      + "CpZdk2QeNeVaVFTPJ26We6J34w2ivZwHOhn+iUZ7q0Sm9gcYa1QRG79LA/AC"
      + "nE3Xxzl4nEjRRi5AKb6IOnMKBbr0povesS8tL323x91uPZc0jMctC6Q+vegX"
      + "tIZ7dZPuNxhqRHqb62LSm11cpYQWibj16rRQ0ulOFSQGIr514PvfbIig6oo8"
      + "niwHuefp/ey/Zvl/dAl+um2UkVdR9Mwn8vTM8oMF+ptJfpWyZEIrP785Rpu3"
      + "oyBMyEYA2djX7JsFvoCxKxGCC5VK3C/9EFv9xUGmiV0zrTPcHb1P4sK1AJyI"
      + "vhSY+Tgv+Fjq5KoPCa4ZXP+Y+vSzkttcP8u7x0wt9cblvgzdBy9Ee1xqCdJd"
      + "F67U6vbQ6ErDrdVAwtRqc0TsPKG1XH5NFtxTwILyCeh8XzdYMIaHkEnTuITQ"
      + "eeICaUJ2YPZrADLxXTNHI9e6dVcDvhjf/JfBXZfiiqFH8XmbCIMqyGSGTmQr"
      + "8uwb8cquLMS78RbXSHLNcv+f/DmPOClNjmWgVAYxaDuw5lZBaU+YDyZaKEy2"
      + "Mdjd+lR/g2LZhvAEfcM3V4bzr17s0GOSwJ5/5yzczPKZZ8auMwML+Bcmoggt"
      + "EJgubVFHg/3l11xVe2djfg78CTCCAkMGCSqGSIb3DQEHAaCCAjQEggIwMIIC"
      + "LDCCAigGCyqGSIb3DQEMCgECoIIBtTCCAbEwSwYJKoZIhvcNAQUNMD4wGwYJ"
      + "KoZIhvcNAQUMMA4ECInc03N3q5vSAgIIADAfBgsqgwiMmks9AQEBAgQQR+Uo"
      + "WVvmSL5AcwwRq6vtOQSCAWD0Ms1i2wHGaFi6qUWLqA5EnmYFwqwQQlfz5To+"
      + "FwVEpHQHrqd0pehOt1J9vyDVYwfjU8DUOJDovCiBIzRsopyf0Qp5hcZnaTDw"
      + "YJSNd3pIAYiEUAzfdtC7tQw2v0aLt5X/7zthEcoRtTe061dK8DhbV4fALWa9"
      + "VF2E91L35+wq52DblvpJHBw28PHTbuhfJZsNshXKO7qU7uk+UR6V/Pwc7rsp"
      + "x/TQ35fVfm7v53rapdHlMVyY4Bx/4fdEWV9aK1cV3qOfiBMByxt8WD0xBLoc"
      + "Yy3qo3+k/N7q6t4hqjus3LPVrmCbpgAe5S5EkDgnjy7Mpz19tf7hhzL957p2"
      + "ecWregvR9rQHoWZNOaxS2e2hdOiZUPSxIJ46nOJyCnoZQHG0CFVEwwJkGcWf"
      + "Thjz38U203IRzuCPgsO1f8wjSXXMp4xJQtJW2TqMm+5/aaDtuXAsUGqQzGiH"
      + "DQfUs4z/PCKyMWAwIwYJKoZIhvcNAQkVMRYEFKm5GgFnzYtYLITaZeZPkaaT"
      + "XG/4MDkGCSqGSIb3DQEJFDEsHioAdABlAHMAdABAAGIAbwB1AG4AYwB5AGMA"
      + "YQBzAHQAbABlAC4AbwByAGcwMTAhMAkGBSsOAwIaBQAEFHIzAiyzoVOmPvLE"
      + "XCD2HHG5MC23BAhhHlFnklHZYgICCAA=");

    private byte[] pkcs5Camellia256Pfx = Base64.decode(
        "MIIFswIBAzCCBXkGCSqGSIb3DQEHAaCCBWoEggVmMIIFYjCCAxcGCSqGSIb3"
      + "DQEHBqCCAwgwggMEAgEAMIIC/QYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYw"
      + "DgQIq+wFOOOtSokCAggAgIIC0IWDRpk4L/tSSMfwWx0mN3ecbaL+m2XZWvN9"
      + "hK1K5PghAYquCs36l603cYSV9pypOkGC5rn1d2fyZCFhUMOObSC7V/mpkitr"
      + "OfOYpaW7tU1JJecpONgIHlbd8N4fbBtH73E7vdmi6X/tg4Tl7yJf40fruYVq"
      + "yzqfJCO2aGJIFv6JWsFivjCwehBa+6ppCHBnNcj4SsVlozj1y2B0Wl2TVi3r"
      + "joBIsK2RQ+RMjM55k3pS57mV+jXtd29wb2q9utDKogvpBCboTk8dPMFcFGWz"
      + "2D41onJoEJKizAEIgXiS7UvqHddhIL9O/rSZ68j2d2GcFi1Oxer1PyZoCI61"
      + "CpZdk2QeNeVaVFTPJ26We6J34w2ivZwHOhn+iUZ7q0Sm9gcYa1QRG79LA/AC"
      + "nE3Xxzl4nEjRRi5AKb6IOnMKBbr0povesS8tL323x91uPZc0jMctC6Q+vegX"
      + "tIZ7dZPuNxhqRHqb62LSm11cpYQWibj16rRQ0ulOFSQGIr514PvfbIig6oo8"
      + "niwHuefp/ey/Zvl/dAl+um2UkVdR9Mwn8vTM8oMF+ptJfpWyZEIrP785Rpu3"
      + "oyBMyEYA2djX7JsFvoCxKxGCC5VK3C/9EFv9xUGmiV0zrTPcHb1P4sK1AJyI"
      + "vhSY+Tgv+Fjq5KoPCa4ZXP+Y+vSzkttcP8u7x0wt9cblvgzdBy9Ee1xqCdJd"
      + "F67U6vbQ6ErDrdVAwtRqc0TsPKG1XH5NFtxTwILyCeh8XzdYMIaHkEnTuITQ"
      + "eeICaUJ2YPZrADLxXTNHI9e6dVcDvhjf/JfBXZfiiqFH8XmbCIMqyGSGTmQr"
      + "8uwb8cquLMS78RbXSHLNcv+f/DmPOClNjmWgVAYxaDuw5lZBaU+YDyZaKEy2"
      + "Mdjd+lR/g2LZhvAEfcM3V4bzr17s0GOSwJ5/5yzczPKZZ8auMwML+Bcmoggt"
      + "EJgubVFHg/3l11xVe2djfg78CTCCAkMGCSqGSIb3DQEHAaCCAjQEggIwMIIC"
      + "LDCCAigGCyqGSIb3DQEMCgECoIIBtTCCAbEwSwYJKoZIhvcNAQUNMD4wGwYJ"
      + "KoZIhvcNAQUMMA4ECInc03N3q5vSAgIIADAfBgsqgwiMmks9AQEBAgQQR+Uo"
      + "WVvmSL5AcwwRq6vtOQSCAWD0Ms1i2wHGaFi6qUWLqA5EnmYFwqwQQlfz5To+"
      + "FwVEpHQHrqd0pehOt1J9vyDVYwfjU8DUOJDovCiBIzRsopyf0Qp5hcZnaTDw"
      + "YJSNd3pIAYiEUAzfdtC7tQw2v0aLt5X/7zthEcoRtTe061dK8DhbV4fALWa9"
      + "VF2E91L35+wq52DblvpJHBw28PHTbuhfJZsNshXKO7qU7uk+UR6V/Pwc7rsp"
      + "x/TQ35fVfm7v53rapdHlMVyY4Bx/4fdEWV9aK1cV3qOfiBMByxt8WD0xBLoc"
      + "Yy3qo3+k/N7q6t4hqjus3LPVrmCbpgAe5S5EkDgnjy7Mpz19tf7hhzL957p2"
      + "ecWregvR9rQHoWZNOaxS2e2hdOiZUPSxIJ46nOJyCnoZQHG0CFVEwwJkGcWf"
      + "Thjz38U203IRzuCPgsO1f8wjSXXMp4xJQtJW2TqMm+5/aaDtuXAsUGqQzGiH"
      + "DQfUs4z/PCKyMWAwIwYJKoZIhvcNAQkVMRYEFKm5GgFnzYtYLITaZeZPkaaT"
      + "XG/4MDkGCSqGSIb3DQEJFDEsHioAdABlAHMAdABAAGIAbwB1AG4AYwB5AGMA"
      + "YQBzAHQAbABlAC4AbwByAGcwMTAhMAkGBSsOAwIaBQAEFHIzAiyzoVOmPvLE"
      + "XCD2HHG5MC23BAhhHlFnklHZYgICCAA=");

    private byte[] pkcs5Cast5Pfx = Base64.decode(
        "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"
      + "CKHZUIQsQX9hAgIIAA==");

    private byte[] gostPfx = Base64.decode(
        "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"
      + "BAgY5sDtkrVeBQICCAA=");

    private byte[] gostPfxFoo123 = Base64.decode(
        "MIID6gIBAzCCA6MGCSqGSIb3DQEHAaCCA5QEggOQMIIDjDCCApQGCSqGSIb3"
      + "DQEHBqCCAoUwggKBAgEAMIICegYJKoZIhvcNAQcBMFUGCSqGSIb3DQEFDTBI"
      + "MCcGCSqGSIb3DQEFDDAaBAhIVrbUVNoQ2wICCAAwCgYGKoUDAgIKBQAwHQYG"
      + "KoUDAgIVMBMECBLmAh+XCCYhBgcqhQMCAh8BgIICFP9hQLgDq5SORy2npOdo"
      + "1bvoGl9Qdga1kV9s2c1/Y1kTGpuiYKfm5Il+PurzYdE5t/Wi2+SxoePm/AKA"
      + "x1Ep5btK/002wnyRbUKdjgF1r7fMXRrd5Ioy8lYxB1v6qhHmzE5fz7FxY+iV"
      + "Z70dSRS0JkTasI8MRsFLkJJfDb9twgoch8lYGFfYirHLcVy4xxA3JO9VSHm2"
      + "8nuSWSnsmGN0ufPX14UpV2RFe3Rt0gZ0Jc8u2h2Mo0sIoVU6HVwdXzoe6LN7"
      + "1NPZdRuhVtjxEvjDAvNJ8WHXQnBQMai2nVAj87uNr6OHLRs+foEccEY9WpPQ"
      + "GPt4XbPt4MtmVctT2+Gsvf6Ws2UCx6hD4k8i28a6xS8lhTVam2g/2Z5cxtUV"
      + "HxYt7j13HjuQVsuSNdgtrUnw3l43LnBxRZhlFz0r2zrvTB04ynenS+lGdVuG"
      + "0TauIH+rdP1ubujw6lFdG9RNgUxWvS5IdwbFGX73a+ZrWiYJeERX11N/6r3g"
      + "0EqVFNH9t/ROsdAtCCe2FycQoOSb+VxPU6I+SHjwe7Oa7R8Xxazh/eWTsV59"
      + "QzPuLriUMbyYdQIf4xdclgcJoxFElopgl4orRfzH3XQsVbtTxN33lwjkE0j/"
      + "686VtcO+b+dU7+BEB7O5yDcx1tupgre0ha/0KOlYfPvmbogGdDf0r6MOwrS7"
      + "QFXxKlHfp8vn4mNwoy7pjrzjmjclkbkwgfEGCSqGSIb3DQEHAaCB4wSB4DCB"
      + "3TCB2gYLKoZIhvcNAQwKAQKggaMwgaAwVQYJKoZIhvcNAQUNMEgwJwYJKoZI"
      + "hvcNAQUMMBoECLD6Ld7TqurqAgIIADAKBgYqhQMCAgoFADAdBgYqhQMCAhUw"
      + "EwQIoYXV7LETOEAGByqFAwICHwEERyBQK9LuYnOO0ELrge+a6JFeAVwPL85V"
      + "ip2Kj/GfD3nzZR4tPzCwAt79RriKQklNqa3uCc9o0C9Zk5Qcj36SqiXxD1tz"
      + "Ea63MSUwIwYJKoZIhvcNAQkVMRYEFKjg5gKM+i+vFhSwaga8YGaZ5thVMD4w"
      + "LjAKBgYqhQMCAgkFAAQgIwD0CRCwva2Bjdlv5g970H2bCB1aafBNr/hxJLZE"
      + "Ey4ECAW3VYXJzJpYAgIIAA==");

    /**
     * we generate the CA's certificate
     */
    public static X509Certificate createMasterCert(
        PublicKey pubKey,
        PrivateKey privKey)
        throws Exception
    {
        //
        // signers name
        //
        String issuer = "C=AU, O=The Legion of the Bouncy Castle, OU=Bouncy Primary Certificate";

        //
        // subjects name - the same as we are self signed.
        //
        String subject = "C=AU, O=The Legion of the Bouncy Castle, OU=Bouncy Primary Certificate";

        //
        // create the certificate - version 1
        //
        X509v1CertificateBuilder v1CertBuilder = new JcaX509v1CertificateBuilder(
            new X500Name(issuer),
            BigInteger.valueOf(1),
            new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)),
            new X500Name(subject),
            pubKey);

        X509CertificateHolder cert = v1CertBuilder.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(privKey));

        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(cert);
    }

    /**
     * we generate an intermediate certificate signed by our CA
     */
    public static X509Certificate createIntermediateCert(
        PublicKey pubKey,
        PrivateKey caPrivKey,
        X509Certificate caCert)
        throws Exception
    {
        //
        // subject name builder.
        //
        X500NameBuilder subjectBuilder = new X500NameBuilder(BCStyle.INSTANCE);

        subjectBuilder.addRDN(BCStyle.C, "AU");
        subjectBuilder.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
        subjectBuilder.addRDN(BCStyle.OU, "Bouncy Intermediate Certificate");
        subjectBuilder.addRDN(BCStyle.EmailAddress, "feedback-crypto@bouncycastle.org");

        //
        // create the certificate - version 3
        //
        X509v3CertificateBuilder v3CertBuilder = new JcaX509v3CertificateBuilder(
            JcaX500NameUtil.getIssuer(caCert),
            BigInteger.valueOf(2),
            new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)),
            subjectBuilder.build(),
            pubKey);


        //
        // extensions
        //
        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();

        v3CertBuilder.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            utils.createSubjectKeyIdentifier(pubKey));

        v3CertBuilder.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            utils.createAuthorityKeyIdentifier(caCert));

        v3CertBuilder.addExtension(
            Extension.basicConstraints,
            true,
            new BasicConstraints(0));

        X509CertificateHolder cert = v3CertBuilder.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(caPrivKey));

        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(cert);
    }

    /**
     * we generate a certificate signed by our CA's intermediate certficate
     */
    public static X509Certificate createCert(
        PublicKey pubKey,
        PrivateKey caPrivKey,
        PublicKey caPubKey)
        throws Exception
    {
        //
        // signer name builder.
        //
        X500NameBuilder issuerBuilder = new X500NameBuilder(BCStyle.INSTANCE);

        issuerBuilder.addRDN(BCStyle.C, "AU");
        issuerBuilder.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
        issuerBuilder.addRDN(BCStyle.OU, "Bouncy Intermediate Certificate");
        issuerBuilder.addRDN(BCStyle.EmailAddress, "feedback-crypto@bouncycastle.org");

        //
        // subject name builder
        //
        X500NameBuilder subjectBuilder = new X500NameBuilder(BCStyle.INSTANCE);

        subjectBuilder.addRDN(BCStyle.C, "AU");
        subjectBuilder.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
        subjectBuilder.addRDN(BCStyle.L, "Melbourne");
        subjectBuilder.addRDN(BCStyle.CN, "Eric H. Echidna");
        subjectBuilder.addRDN(BCStyle.EmailAddress, "feedback-crypto@bouncycastle.org");

        //
        // create the certificate - version 3
        //
        //
        // create the certificate - version 3
        //
        X509v3CertificateBuilder v3CertBuilder = new JcaX509v3CertificateBuilder(
            issuerBuilder.build(),
            BigInteger.valueOf(3),
            new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)),
            subjectBuilder.build(),
            pubKey);


        //
        // add the extensions
        //
        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();

        v3CertBuilder.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            utils.createSubjectKeyIdentifier(pubKey));

        v3CertBuilder.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            utils.createAuthorityKeyIdentifier(caPubKey));

        X509CertificateHolder cert = v3CertBuilder.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(caPrivKey));

        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(cert);
    }

    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testPfxPdu()
        throws Exception
    {
        //
        // set up the keys
        //
        KeyFactory fact = KeyFactory.getInstance("RSA", BC);
        PrivateKey privKey = fact.generatePrivate(privKeySpec);
        PublicKey pubKey = fact.generatePublic(pubKeySpec);

        X509Certificate[] chain = createCertChain(fact, pubKey);

        PKCS12PfxPdu pfx = createPfx(privKey, pubKey, chain);

        //
        // now try reading our object
        //
        KeyStore store = KeyStore.getInstance("PKCS12", "BC");

        store.load(new ByteArrayInputStream(pfx.toASN1Structure().getEncoded()), passwd);

        PrivateKey recPrivKey = (PrivateKey)store.getKey("Eric's Key", passwd);

        if (!privKey.equals(recPrivKey))
        {
            fail("private key extraction failed");
        }

        Certificate[] certChain = store.getCertificateChain("Eric's Key");

        for (int i = 0; i != certChain.length; i++)
        {
            if (!certChain[i].equals(chain[i]))
            {
                fail("certificate recovery failed");
            }
        }
    }

    public void testPfxPduMac()
        throws Exception
    {
        //
        // set up the keys
        //
        KeyFactory fact = KeyFactory.getInstance("RSA", BC);
        PrivateKey privKey = fact.generatePrivate(privKeySpec);
        PublicKey pubKey = fact.generatePublic(pubKeySpec);

        X509Certificate[] chain = createCertChain(fact, pubKey);

        PKCS12PfxPdu pfx = createPfx(privKey, pubKey, chain);

        assertTrue(pfx.hasMac());
        assertTrue(pfx.isMacValid(new BcPKCS12MacCalculatorBuilderProvider(BcDefaultDigestProvider.INSTANCE), passwd));
        assertFalse(pfx.isMacValid(new BcPKCS12MacCalculatorBuilderProvider(BcDefaultDigestProvider.INSTANCE), "not right".toCharArray()));
    }

    public void testBcEncryptedPrivateKeyInfo()
        throws Exception
    {
        KeyFactory fact = KeyFactory.getInstance("RSA", BC);
        PrivateKey privKey = fact.generatePrivate(privKeySpec);

        PKCS8EncryptedPrivateKeyInfoBuilder builder = new JcaPKCS8EncryptedPrivateKeyInfoBuilder(privKey);

        PKCS8EncryptedPrivateKeyInfo priv = builder.build(new BcPKCS12PBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, new CBCBlockCipher(new DESedeEngine())).build(passwd));

        PrivateKeyInfo info = priv.decryptPrivateKeyInfo(new BcPKCS12PBEInputDecryptorProviderBuilder().build(passwd));

        assertTrue(Arrays.areEqual(info.getEncoded(), privKey.getEncoded()));
    }

    public void testEncryptedPrivateKeyInfo()
        throws Exception
    {
        KeyFactory fact = KeyFactory.getInstance("RSA", BC);
        PrivateKey privKey = fact.generatePrivate(privKeySpec);

        PKCS8EncryptedPrivateKeyInfoBuilder builder = new JcaPKCS8EncryptedPrivateKeyInfoBuilder(privKey);

        PKCS8EncryptedPrivateKeyInfo priv = builder.build(new JcePKCSPBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC).build(passwd));

        PrivateKeyInfo info = priv.decryptPrivateKeyInfo(new JcePKCSPBEInputDecryptorProviderBuilder().build(passwd));

        assertTrue(Arrays.areEqual(info.getEncoded(), privKey.getEncoded()));
    }

    public void testEncryptedPrivateKeyInfoPKCS5()
        throws Exception
    {
        KeyFactory fact = KeyFactory.getInstance("RSA", BC);
        PrivateKey privKey = fact.generatePrivate(privKeySpec);

        PKCS8EncryptedPrivateKeyInfoBuilder builder = new JcaPKCS8EncryptedPrivateKeyInfoBuilder(privKey);

        PKCS8EncryptedPrivateKeyInfo priv = builder.build(new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC).build(passwd));

        PrivateKeyInfo info = priv.decryptPrivateKeyInfo(new JcePKCSPBEInputDecryptorProviderBuilder().build(passwd));

        assertTrue(Arrays.areEqual(info.getEncoded(), privKey.getEncoded()));
    }

    public void testKeyBag()
        throws Exception
    {
        OutputEncryptor encOut = new BcPKCS12PBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, new CBCBlockCipher(new DESedeEngine())).build(passwd);
        InputDecryptorProvider inputDecryptorProvider = new BcPKCS12PBEInputDecryptorProviderBuilder().build(passwd);
        KeyFactory fact = KeyFactory.getInstance("RSA", BC);
        PrivateKey privKey = fact.generatePrivate(privKeySpec);
        PKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(privKey);

        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("Eric's Key"));

        PKCS12PfxPduBuilder builder = new PKCS12PfxPduBuilder();

        builder.addEncryptedData(encOut, keyBagBuilder.build());

        PKCS12PfxPdu pfx = builder.build(new BcPKCS12MacCalculatorBuilder(), passwd);
        assertTrue(pfx.hasMac());
        assertTrue(pfx.isMacValid(new BcPKCS12MacCalculatorBuilderProvider(BcDefaultDigestProvider.INSTANCE), passwd));

        ContentInfo[] infos = pfx.getContentInfos();

        for (int i = 0; i != infos.length; i++)
        {
            if (infos[i].getContentType().equals(PKCSObjectIdentifiers.encryptedData))
            {
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i], inputDecryptorProvider);

                PKCS12SafeBag[] bags = dataFact.getSafeBags();

                assertEquals(1, bags.length);
                assertEquals(PKCSObjectIdentifiers.keyBag, bags[0].getType());

                assertTrue(Arrays.areEqual(privKey.getEncoded(), ((PrivateKeyInfo)bags[0].getBagValue()).getEncoded()));

                Attribute[] attributes = bags[0].getAttributes();

                assertEquals(1, attributes.length);

                assertEquals(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, attributes[0].getAttrType());

                ASN1Encodable[] attrValues = attributes[0].getAttributeValues();

                assertEquals(1, attrValues.length);
                assertEquals(new DERBMPString("Eric's Key"), attrValues[0]);
            }
            else
            {
                fail("unknown bag encountered");
            }
        }
    }

    public void testSafeBagRecovery()
        throws Exception
    {
        InputDecryptorProvider inputDecryptorProvider = new BcPKCS12PBEInputDecryptorProviderBuilder().build(passwd);
        KeyFactory fact = KeyFactory.getInstance("RSA", BC);
        PrivateKey privKey = fact.generatePrivate(privKeySpec);
        PublicKey pubKey = fact.generatePublic(pubKeySpec);

        X509Certificate[] chain = createCertChain(fact, pubKey);

        PKCS12PfxPdu pfx = createPfx(privKey, pubKey, chain);

        ContentInfo[] infos = pfx.getContentInfos();

        for (int i = 0; i != infos.length; i++)
        {
            if (infos[i].getContentType().equals(PKCSObjectIdentifiers.encryptedData))
            {
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i], inputDecryptorProvider);

                PKCS12SafeBag[] bags = dataFact.getSafeBags();

                assertEquals(3, bags.length);
                assertEquals(PKCSObjectIdentifiers.certBag, bags[0].getType());

                for (int j = 0; j != bags.length; j++)
                {
                    assertTrue(Arrays.areEqual(chain[j].getEncoded(), ((X509CertificateHolder)bags[j].getBagValue()).getEncoded()));
                }
            }
            else
            {
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i]);

                PKCS12SafeBag[] bags = dataFact.getSafeBags();

                assertEquals(1, bags.length);
                assertEquals(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag, bags[0].getType());

                PKCS8EncryptedPrivateKeyInfo encInfo = (PKCS8EncryptedPrivateKeyInfo)bags[0].getBagValue();
                PrivateKeyInfo info = encInfo.decryptPrivateKeyInfo(inputDecryptorProvider);

                assertTrue(Arrays.areEqual(info.getEncoded(), privKey.getEncoded()));
            }
        }
    }

    public void testExceptions()
        throws Exception
    {
        PKCS12SafeBagFactory dataFact;

        try
        {
            dataFact = new PKCS12SafeBagFactory(new ContentInfo(PKCSObjectIdentifiers.data, new DERSequence()), null);
        }
        catch (IllegalArgumentException e)
        {

        }

        try
        {
            dataFact = new PKCS12SafeBagFactory(new ContentInfo(PKCSObjectIdentifiers.encryptedData, new DERSequence()));
        }
        catch (IllegalArgumentException e)
        {

        }
    }

    public void testBasicPKCS12()
        throws Exception
    {
        InputDecryptorProvider inputDecryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder()
                                                              .setProvider("BC").build(pkcs12Pass.toCharArray());
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(pkcs12);

        ContentInfo[] infos = pfx.getContentInfos();

        for (int i = 0; i != infos.length; i++)
        {
            if (infos[i].getContentType().equals(PKCSObjectIdentifiers.encryptedData))
            {
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i], inputDecryptorProvider);

                PKCS12SafeBag[] bags = dataFact.getSafeBags();

                // TODO: finish!
//                assertEquals(3, bags.length);
//                assertEquals(PKCSObjectIdentifiers.certBag, bags[0].getType());
            }
            else
            {
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i]);

                PKCS12SafeBag[] bags = dataFact.getSafeBags();

                assertEquals(1, bags.length);
                assertEquals(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag, bags[0].getType());

                PKCS8EncryptedPrivateKeyInfo encInfo = (PKCS8EncryptedPrivateKeyInfo)bags[0].getBagValue();
                PrivateKeyInfo info = encInfo.decryptPrivateKeyInfo(inputDecryptorProvider);
            }
        }
    }

    public void testSHA256withPKCS5()
        throws Exception
    {
        InputDecryptorProvider inputDecryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder()
                                                              .setProvider("BC").build(sha256Pass.toCharArray());
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(sha256Pfx);

        ContentInfo[] infos = pfx.getContentInfos();

        for (int i = 0; i != infos.length; i++)
        {
            if (infos[i].getContentType().equals(PKCSObjectIdentifiers.encryptedData))
            {
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i], inputDecryptorProvider);

                PKCS12SafeBag[] bags = dataFact.getSafeBags();

                // TODO: finish!
//                assertEquals(3, bags.length);
//                assertEquals(PKCSObjectIdentifiers.certBag, bags[0].getType());
            }
            else
            {
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i]);

                PKCS12SafeBag[] bags = dataFact.getSafeBags();

                assertEquals(1, bags.length);
                assertEquals(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag, bags[0].getType());

                PKCS8EncryptedPrivateKeyInfo encInfo = (PKCS8EncryptedPrivateKeyInfo)bags[0].getBagValue();
                PrivateKeyInfo info = encInfo.decryptPrivateKeyInfo(inputDecryptorProvider);
            }
        }
    }

    public void testCreateAES256andSHA256()
        throws Exception
    {
        OutputEncryptor encOut = new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC).setProvider("BC").build(passwd);

        KeyFactory fact = KeyFactory.getInstance("RSA", BC);
        PrivateKey privKey = fact.generatePrivate(privKeySpec);
        PublicKey pubKey = fact.generatePublic(pubKeySpec);

        X509Certificate[] chain = createCertChain(fact, pubKey);

        PKCS12SafeBagBuilder taCertBagBuilder = new JcaPKCS12SafeBagBuilder(chain[2]);

        taCertBagBuilder.addBagAttribute(PKCS12SafeBag.friendlyNameAttribute, new DERBMPString("Bouncy Primary Certificate"));

        PKCS12SafeBagBuilder caCertBagBuilder = new JcaPKCS12SafeBagBuilder(chain[1]);

        caCertBagBuilder.addBagAttribute(PKCS12SafeBag.friendlyNameAttribute, new DERBMPString("Bouncy Intermediate Certificate"));

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        PKCS12SafeBagBuilder eeCertBagBuilder = new JcaPKCS12SafeBagBuilder(chain[0]);

        eeCertBagBuilder.addBagAttribute(PKCS12SafeBag.friendlyNameAttribute, new DERBMPString("Eric's Key"));
        SubjectKeyIdentifier pubKeyId = extUtils.createSubjectKeyIdentifier(chain[0].getPublicKey());
        eeCertBagBuilder.addBagAttribute(PKCS12SafeBag.localKeyIdAttribute, pubKeyId);

        PKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(privKey, encOut);

        keyBagBuilder.addBagAttribute(PKCS12SafeBag.friendlyNameAttribute, new DERBMPString("Eric's Key"));
        keyBagBuilder.addBagAttribute(PKCS12SafeBag.localKeyIdAttribute, pubKeyId);

        PKCS12PfxPduBuilder builder = new PKCS12PfxPduBuilder();

        builder.addData(keyBagBuilder.build());

        builder.addEncryptedData(new JcePKCSPBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC).setProvider("BC").build(passwd), new PKCS12SafeBag[] { eeCertBagBuilder.build(), caCertBagBuilder.build(), taCertBagBuilder.build() });

        PKCS12PfxPdu pfx = builder.build(new JcePKCS12MacCalculatorBuilder(NISTObjectIdentifiers.id_sha256), passwd);

        assertTrue(pfx.hasMac());
        assertTrue(pfx.isMacValid(new JcePKCS12MacCalculatorBuilderProvider().setProvider("BC"), passwd));

        InputDecryptorProvider inputDecryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder()
                                                              .setProvider("BC").build(passwd);

        pfx = new PKCS12PfxPdu(pfx.toASN1Structure().getEncoded());

        ContentInfo[] infos = pfx.getContentInfos();
        boolean encDataFound = false;
        boolean pkcs8Found = false;

        for (int i = 0; i != infos.length; i++)
        {
            if (infos[i].getContentType().equals(PKCSObjectIdentifiers.encryptedData))
            {
                encDataFound = true;
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i], inputDecryptorProvider);

                PKCS12SafeBag[] bags = dataFact.getSafeBags();

                assertEquals(3, bags.length);
                assertEquals(PKCSObjectIdentifiers.certBag, bags[0].getType());
            }
            else
            {
                pkcs8Found = true;
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i]);

                PKCS12SafeBag[] bags = dataFact.getSafeBags();

                assertEquals(1, bags.length);
                assertEquals(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag, bags[0].getType());

                PKCS8EncryptedPrivateKeyInfo encInfo = (PKCS8EncryptedPrivateKeyInfo)bags[0].getBagValue();
                PrivateKeyInfo info = encInfo.decryptPrivateKeyInfo(inputDecryptorProvider);
            }
        }

        assertTrue(encDataFound);
        assertTrue(pkcs8Found);

        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");

        ks.load(new ByteArrayInputStream(pfx.getEncoded(ASN1Encoding.DL)), passwd);

        assertTrue(ks.containsAlias("Eric's Key"));
    }

    public void testPKCS5()
        throws Exception
    {
        doPKCS5Test(pkcs5Aes128Pfx);
        doPKCS5Test(pkcs5Aes192Pfx);
        doPKCS5Test(pkcs5Camellia128Pfx);
        doPKCS5Test(pkcs5Camellia256Pfx);
        doPKCS5Test(pkcs5Cast5Pfx);
    }

    private void doPKCS5Test(byte[] keyStore)
        throws Exception
    {
        InputDecryptorProvider inputDecryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder()
                                                                      .setProvider("BC").build(pkcs5Pass.toCharArray());
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(keyStore);

        ContentInfo[] infos = pfx.getContentInfos();

        for (int i = 0; i != infos.length; i++)
        {
            if (infos[i].getContentType().equals(PKCSObjectIdentifiers.encryptedData))
            {
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i], inputDecryptorProvider);

                PKCS12SafeBag[] bags = dataFact.getSafeBags();

                // TODO: finish!
//                assertEquals(3, bags.length);
//                assertEquals(PKCSObjectIdentifiers.certBag, bags[0].getType());
            }
            else
            {
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i]);

                PKCS12SafeBag[] bags = dataFact.getSafeBags();

                assertEquals(1, bags.length);
                assertEquals(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag, bags[0].getType());

                PKCS8EncryptedPrivateKeyInfo encInfo = (PKCS8EncryptedPrivateKeyInfo)bags[0].getBagValue();
                PrivateKeyInfo info = encInfo.decryptPrivateKeyInfo(inputDecryptorProvider);
            }
        }
    }

    public void testGOST1()
        throws Exception
    {
        char[] password = "1".toCharArray();

        InputDecryptorProvider inputDecryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder()
                                                                      .setProvider("BC").build(password);
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(gostPfx);

        assertTrue(pfx.hasMac());
        assertTrue(pfx.isMacValid(new JcePKCS12MacCalculatorBuilderProvider().setProvider("BC"), password));

        ContentInfo[] infos = pfx.getContentInfos();

        for (int i = 0; i != infos.length; i++)
        {
            if (infos[i].getContentType().equals(PKCSObjectIdentifiers.encryptedData))
            {
               PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i], inputDecryptorProvider);

              PKCS12SafeBag[] bags = dataFact.getSafeBags();

                // TODO: finish!
//                assertEquals(3, bags.length);
//                assertEquals(PKCSObjectIdentifiers.certBag, bags[0].getType());
            }
            else
            {
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i]);

                PKCS12SafeBag[] bags = dataFact.getSafeBags();

                assertEquals(1, bags.length);
                assertEquals(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag, bags[0].getType());

                PKCS8EncryptedPrivateKeyInfo encInfo = (PKCS8EncryptedPrivateKeyInfo)bags[0].getBagValue();
                PrivateKeyInfo info = encInfo.decryptPrivateKeyInfo(inputDecryptorProvider);
                assertEquals(CryptoProObjectIdentifiers.gostR3410_2001, info.getPrivateKeyAlgorithm().getAlgorithm());
            }
        }
    }

    public void testGOST2()
        throws Exception
    {
        char[] password = "foo123".toCharArray();

        InputDecryptorProvider inputDecryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder()
                                                                      .setProvider("BC").build(password);
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(gostPfxFoo123);

        assertTrue(pfx.hasMac());
        assertTrue(pfx.isMacValid(new JcePKCS12MacCalculatorBuilderProvider().setProvider("BC"), password));

        ContentInfo[] infos = pfx.getContentInfos();

        for (int i = 0; i != infos.length; i++)
        {
            if (infos[i].getContentType().equals(PKCSObjectIdentifiers.encryptedData))
            {
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i], inputDecryptorProvider);

                PKCS12SafeBag[] bags = dataFact.getSafeBags();

                // TODO: finish!
//                assertEquals(3, bags.length);
//                assertEquals(PKCSObjectIdentifiers.certBag, bags[0].getType());
            }
            else
            {
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i]);

                PKCS12SafeBag[] bags = dataFact.getSafeBags();

                assertEquals(1, bags.length);
                assertEquals(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag, bags[0].getType());

                PKCS8EncryptedPrivateKeyInfo encInfo = (PKCS8EncryptedPrivateKeyInfo)bags[0].getBagValue();
                PrivateKeyInfo info = encInfo.decryptPrivateKeyInfo(inputDecryptorProvider);
                assertEquals(CryptoProObjectIdentifiers.gostR3410_2001, info.getPrivateKeyAlgorithm().getAlgorithm());
            }
        }
    }

    private X509Certificate[] createCertChain(KeyFactory fact, PublicKey pubKey)
        throws Exception
    {
        PrivateKey caPrivKey = fact.generatePrivate(caPrivKeySpec);
        PublicKey caPubKey = fact.generatePublic(caPubKeySpec);
        PrivateKey intPrivKey = fact.generatePrivate(intPrivKeySpec);
        PublicKey intPubKey = fact.generatePublic(intPubKeySpec);

        X509Certificate[] chain = new X509Certificate[3];

        chain[2] = createMasterCert(caPubKey, caPrivKey);
        chain[1] = createIntermediateCert(intPubKey, caPrivKey, chain[2]);
        chain[0] = createCert(pubKey, intPrivKey, intPubKey);
        return chain;
    }

    private PKCS12PfxPdu createPfx(PrivateKey privKey, PublicKey pubKey, X509Certificate[] chain)
        throws NoSuchAlgorithmException, IOException, PKCSException
    {
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        PKCS12SafeBagBuilder taCertBagBuilder = new JcaPKCS12SafeBagBuilder(chain[2]);

        taCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("Bouncy Primary Certificate"));

        PKCS12SafeBagBuilder caCertBagBuilder = new JcaPKCS12SafeBagBuilder(chain[1]);

        caCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("Bouncy Intermediate Certificate"));

        PKCS12SafeBagBuilder eeCertBagBuilder = new JcaPKCS12SafeBagBuilder(chain[0]);

        eeCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("Eric's Key"));
        eeCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, extUtils.createSubjectKeyIdentifier(pubKey));

        PKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(privKey, new BcPKCS12PBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, new CBCBlockCipher(new DESedeEngine())).build(passwd));

        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("Eric's Key"));
        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, extUtils.createSubjectKeyIdentifier(pubKey));

        //
        // construct the actual key store
        //
        PKCS12PfxPduBuilder pfxPduBuilder = new PKCS12PfxPduBuilder();

        PKCS12SafeBag[] certs = new PKCS12SafeBag[3];

        certs[0] = eeCertBagBuilder.build();
        certs[1] = caCertBagBuilder.build();
        certs[2] = taCertBagBuilder.build();

        pfxPduBuilder.addEncryptedData(new BcPKCS12PBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC, new CBCBlockCipher(new RC2Engine())).build(passwd), certs);

        pfxPduBuilder.addData(keyBagBuilder.build());

        return pfxPduBuilder.build(new BcPKCS12MacCalculatorBuilder(), passwd);
    }
}
