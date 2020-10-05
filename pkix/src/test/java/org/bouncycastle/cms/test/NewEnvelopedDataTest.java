package org.bouncycastle.cms.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Iterator;

import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.Assert;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CCMParameters;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RC2CBCParameter;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KeyAgreeRecipientInformation;
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
import org.bouncycastle.cms.bc.BcPasswordEnvelopedRecipient;
import org.bouncycastle.cms.bc.BcPasswordRecipientInfoGenerator;
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
import org.bouncycastle.jce.ECGOST3410NamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

public class NewEnvelopedDataTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static String _signDN;
    private static KeyPair _signKP;
    private static X509Certificate _signCert;

    private static String _origDN;
    private static KeyPair _origKP;
    private static X509Certificate _origCert;

    private static String _reciDN;
    private static String _reciDN2;
    private static KeyPair _reciKP;
    private static KeyPair _reciOaepKP;
    private static X509Certificate _reciCert;
    private static X509Certificate _reciCertOaep;

    private static KeyPair _origEcKP;
    private static KeyPair _reciEcKP;
    private static X509Certificate _reciEcCert;
    private static KeyPair _reciEcKP2;
    private static X509Certificate _reciEcCert2;
    private static KeyPair _reciKemsKP;
    private static X509Certificate _reciKemsCert;

    private static KeyPair _origDhKP;
    private static KeyPair _reciDhKP;
    private static X509Certificate _reciDhCert;

    private static boolean _initialised = false;

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

    // from RFC 4490

    private byte[] gost3410_RecipCert = Base64.decode(
        "MIIB0DCCAX8CECv1xh7CEb0Xx9zUYma0LiEwCAYGKoUDAgIDMG0xHzAdBgNVBAMM" +
            "Fkdvc3RSMzQxMC0yMDAxIGV4YW1wbGUxEjAQBgNVBAoMCUNyeXB0b1BybzELMAkG" +
            "A1UEBhMCUlUxKTAnBgkqhkiG9w0BCQEWGkdvc3RSMzQxMC0yMDAxQGV4YW1wbGUu" +
            "Y29tMB4XDTA1MDgxNjE0MTgyMFoXDTE1MDgxNjE0MTgyMFowbTEfMB0GA1UEAwwW" +
            "R29zdFIzNDEwLTIwMDEgZXhhbXBsZTESMBAGA1UECgwJQ3J5cHRvUHJvMQswCQYD" +
            "VQQGEwJSVTEpMCcGCSqGSIb3DQEJARYaR29zdFIzNDEwLTIwMDFAZXhhbXBsZS5j" +
            "b20wYzAcBgYqhQMCAhMwEgYHKoUDAgIkAAYHKoUDAgIeAQNDAARAhJVodWACGkB1" +
            "CM0TjDGJLP3lBQN6Q1z0bSsP508yfleP68wWuZWIA9CafIWuD+SN6qa7flbHy7Df" +
            "D2a8yuoaYDAIBgYqhQMCAgMDQQA8L8kJRLcnqeyn1en7U23Sw6pkfEQu3u0xFkVP" +
            "vFQ/3cHeF26NG+xxtZPz3TaTVXdoiYkXYiD02rEx1bUcM97i");

    private byte[] gost3410_2001_KeyTrans = Base64.decode(
        "MIIBpwYJKoZIhvcNAQcDoIIBmDCCAZQCAQAxggFTMIIBTwIBADCBgTBtMR8wHQYD" +
            "VQQDDBZHb3N0UjM0MTAtMjAwMSBleGFtcGxlMRIwEAYDVQQKDAlDcnlwdG9Qcm8x" +
            "CzAJBgNVBAYTAlJVMSkwJwYJKoZIhvcNAQkBFhpHb3N0UjM0MTAtMjAwMUBleGFt" +
            "cGxlLmNvbQIQK/XGHsIRvRfH3NRiZrQuITAcBgYqhQMCAhMwEgYHKoUDAgIkAAYH" +
            "KoUDAgIeAQSBpzCBpDAoBCBqL6ghBpVon5/kR6qey2EVK35BYLxdjfv1PSgbGJr5" +
            "dQQENm2Yt6B4BgcqhQMCAh8BoGMwHAYGKoUDAgITMBIGByqFAwICJAAGByqFAwIC" +
            "HgEDQwAEQE0rLzOQ5tyj3VUqzd/g7/sx93N+Tv+/eImKK8PNMZQESw5gSJYf28dd" +
            "Em/askCKd7W96vLsNMsjn5uL3Z4SwPYECJeV4ywrrSsMMDgGCSqGSIb3DQEHATAd" +
            "BgYqhQMCAhUwEwQIvBCLHwv/NCkGByqFAwICHwGADKqOch3uT7Mu4w+hNw==");

    private byte[] gost3410_2001_KeyAgree = Base64.decode(
        "MIIBpAYJKoZIhvcNAQcDoIIBlTCCAZECAQIxggFQoYIBTAIBA6BloWMwHAYGKoUD" +
            "AgITMBIGByqFAwICJAAGByqFAwICHgEDQwAEQLNVOfRngZcrpcTZhB8n+4HtCDLm" +
            "mtTyAHi4/4Nk6tIdsHg8ff4DwfQG5DvMFrnF9vYZNxwXuKCqx9GhlLOlNiChCgQI" +
            "L/D20YZLMoowHgYGKoUDAgJgMBQGByqFAwICDQAwCQYHKoUDAgIfATCBszCBsDCB" +
            "gTBtMR8wHQYDVQQDDBZHb3N0UjM0MTAtMjAwMSBleGFtcGxlMRIwEAYDVQQKDAlD" +
            "cnlwdG9Qcm8xCzAJBgNVBAYTAlJVMSkwJwYJKoZIhvcNAQkBFhpHb3N0UjM0MTAt" +
            "MjAwMUBleGFtcGxlLmNvbQIQK/XGHsIRvRfH3NRiZrQuIQQqMCgEIBajHOfOTukN" +
            "8ex0aQRoHsefOu24Ox8dSn75pdnLGdXoBAST/YZ+MDgGCSqGSIb3DQEHATAdBgYq" +
            "hQMCAhUwEwQItzXhegc1oh0GByqFAwICHwGADDmxivS/qeJlJbZVyQ==");

    public byte[] gost2001_Rand_Cert = Base64.decode(
        "MIIELDCCA9ugAwIBAgIENqPHFzAIBgYqhQMCAgMwgckxCzAJBgNVBAYTAlJVMSAwHgYDVQQIDBfQoS7Qn9C40YLQtdGA0LHR" +
            "g9GA0LPRijEfMB0GA1UECgwW0KHQvtCy0YDQtdC80LXQvdC90LjQujEfMB0GA1UECwwW0KDRg9C60L7QstC+0LTRgdGC0LLQ" +
            "vjEZMBcGA1UEDAwQ0KDQtdC00LDQutGC0L7RgDE7MDkGA1UEAwwy0J/Rg9GI0LrQuNC9INCQ0LvQtdC60YHQsNC90LTRgCDQ" +
            "odC10YDQs9C10LXQstC40YcwHhcNMTcwNzE1MTQwMDAwWhcNMzcwNzE1MTQwMDAwWjCByTELMAkGA1UEBhMCUlUxIDAeBgNV" +
            "BAgMF9ChLtCf0LjRgtC10YDQsdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQtdC90L3QuNC6MR8wHQYDVQQLDBbQ" +
            "oNGD0LrQvtCy0L7QtNGB0YLQstC+MRkwFwYDVQQMDBDQoNC10LTQsNC60YLQvtGAMTswOQYDVQQDDDLQn9GD0YjQutC40L0g" +
            "0JDQu9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhzBjMBwGBiqFAwICEzASBgcqhQMCAiQABgcqhQMCAh4BA0MA" +
            "BEC0WD4VzaInvp+WfjF+XIdZeWMrNSJVxUM6d/acwVMPwetEBtr1U82Cgf2U5eoz6eHxaLsAVG+qbiiMwV/4GKsao4IBpTCC" +
            "AaEwDgYDVR0PAQH/BAQDAgH+MGMGA1UdJQRcMFoGCCsGAQUFBwMBBggrBgEFBQcDAgYIKwYBBQUHAwMGCCsGAQUFBwMEBggr" +
            "BgEFBQcDBQYIKwYBBQUHAwYGCCsGAQUFBwMHBggrBgEFBQcDCAYIKwYBBQUHAwkwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E" +
            "FgQUqcUQmyYjxhQ9t5JX327oLxMjtkcwgfkGA1UdIwSB8TCB7oAUqcUQmyYjxhQ9t5JX327oLxMjtkehgc+kgcwwgckxCzAJ" +
            "BgNVBAYTAlJVMSAwHgYDVQQIDBfQoS7Qn9C40YLQtdGA0LHRg9GA0LPRijEfMB0GA1UECgwW0KHQvtCy0YDQtdC80LXQvdC9" +
            "0LjQujEfMB0GA1UECwwW0KDRg9C60L7QstC+0LTRgdGC0LLQvjEZMBcGA1UEDAwQ0KDQtdC00LDQutGC0L7RgDE7MDkGA1UE" +
            "Awwy0J/Rg9GI0LrQuNC9INCQ0LvQtdC60YHQsNC90LTRgCDQodC10YDQs9C10LXQstC40YeCBDajxxcwCAYGKoUDAgIDA0EA" +
            "2rrXsssEqxuRPtVRa+vlrgoXUa9WV+24uZ1LzsiMehSOv/pUo7kJZwoA5VCedJw0C8dce6Uc6lDJkNzpHN40hA=="
    );

    public byte[] gost2001_Rand_Key = Base64.decode(
        "MEUCAQAwHAYGKoUDAgJiMBIGByqFAwICJAAGByqFAwICHgEEIgQgDWFcH/5KjwIwXrMdyO5CBnJdoOVtKp7WMb4EIljc+K4="
    );

    public byte[] gost2001_Rand_Msg = Base64.decode(
        "MIIB+AYJKoZIhvcNAQcDoIIB6TCCAeUCAQAxggGkMIIBoAIBADCB0jCByTELMAkGA1UEBhMCUlUxIDAeBgNVBAgMF9ChLtCf" +
            "0LjRgtC10YDQsdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQtdC90L3QuNC6MR8wHQYDVQQLDBbQoNGD0LrQvtCy" +
            "0L7QtNGB0YLQstC+MRkwFwYDVQQMDBDQoNC10LTQsNC60YLQvtGAMTswOQYDVQQDDDLQn9GD0YjQutC40L0g0JDQu9C10LrR" +
            "gdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhwIENqPHFzAcBgYqhQMCAhMwEgYHKoUDAgIkAAYHKoUDAgIeAQSBpzCBpDAo" +
            "BCCbkNQAmR9ny2u5W8MvFHs8iO91uA2iCy+2nccpwOQ0agQE9BJtXaB4BgcqhQMCAh8BoGMwHAYGKoUDAgITMBIGByqFAwIC" +
            "JAAGByqFAwICHgEDQwAEQOeSFV7jo7EvygKSgHH79eel7sgWu0yW4swAK81Pw8jHMazuL6SpTUqUWNPW1jf4aFFHQAQmrxWV" +
            "maCQn7gSJl8ECFgM3TO2P26NMDgGCSqGSIb3DQEHATAdBgYqhQMCAhUwEwQIC4ytWGecO5AGByqFAwICHwGADIzrpurLkuk0" +
            "xGGidg=="
    );

    public byte[] gost2001_Rand_Sender_Cert = Base64.decode(
        "MIIERTCCA/SgAwIBAgIEUu7tIDAIBgYqhQMCAgMwgdExCzAJBgNVBAYTAlJVMSAwHgYDVQQIDBfQoS7Qn9C40YLQtdGA0LHR" +
            "g9GA0LPRijEfMB0GA1UECgwW0KHQvtCy0YDQtdC80LXQvdC90LjQujEoMCYGA1UECwwf0JTQtdC50YHRgtCy0YPRjtGJ0LjQ" +
            "tSDQu9C40YbQsDEtMCsGA1UEDAwk0KTQuNC70L7RgdC+0LIg0Lgg0L/Rg9Cx0LvQuNGG0LjRgdGCMSYwJAYDVQQDDB3QldCy" +
            "0LPQtdC90ZbQuSDQntC90aPQs9C40L3RijAeFw0xNzA3MTYxNDAwMDBaFw0zNzA3MTYxNDAwMDBaMIHRMQswCQYDVQQGEwJS" +
            "VTEgMB4GA1UECAwX0KEu0J/QuNGC0LXRgNCx0YPRgNCz0YoxHzAdBgNVBAoMFtCh0L7QstGA0LXQvNC10L3QvdC40LoxKDAm" +
            "BgNVBAsMH9CU0LXQudGB0YLQstGD0Y7RidC40LUg0LvQuNGG0LAxLTArBgNVBAwMJNCk0LjQu9C+0YHQvtCyINC4INC/0YPQ" +
            "sdC70LjRhtC40YHRgjEmMCQGA1UEAwwd0JXQstCz0LXQvdGW0Lkg0J7QvdGj0LPQuNC90YowYzAcBgYqhQMCAhMwEgYHKoUD" +
            "AgIkAAYHKoUDAgIeAQNDAARAM++vMY04j9Bvcn71wM9atNkRo4lCixrOR82HncQbwnyBS6R0BqRmL+Q32TzEYpslzRkQnj/z" +
            "yORa31QVSRghQaOCAa4wggGqMA4GA1UdDwEB/wQEAwIB/jBjBgNVHSUEXDBaBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUF" +
            "BwMDBggrBgEFBQcDBAYIKwYBBQUHAwUGCCsGAQUFBwMGBggrBgEFBQcDBwYIKwYBBQUHAwgGCCsGAQUFBwMJMA8GA1UdEwEB" +
            "/wQFMAMBAf8wHQYDVR0OBBYEFCLkv9o8dmaV1StuS8QFO64FJXXXMIIBAQYDVR0jBIH5MIH2gBQi5L/aPHZmldUrbkvEBTuu" +
            "BSV116GB16SB1DCB0TELMAkGA1UEBhMCUlUxIDAeBgNVBAgMF9ChLtCf0LjRgtC10YDQsdGD0YDQs9GKMR8wHQYDVQQKDBbQ" +
            "odC+0LLRgNC10LzQtdC90L3QuNC6MSgwJgYDVQQLDB/QlNC10LnRgdGC0LLRg9GO0YnQuNC1INC70LjRhtCwMS0wKwYDVQQM" +
            "DCTQpNC40LvQvtGB0L7QsiDQuCDQv9GD0LHQu9C40YbQuNGB0YIxJjAkBgNVBAMMHdCV0LLQs9C10L3RltC5INCe0L3Ro9Cz" +
            "0LjQvdGKggRS7u0gMAgGBiqFAwICAwNBAIMLOOeDFPnrGkC/QG/pvLRZhEeiVkGVgy/h5WJancJDouHzedhI+mJqBFEYRoIy" +
            "4KP5Q93Bf1NClXwIfnTOxWo="
    );

    public byte[] gost2001_Rand_Sender_Key = Base64.decode(
        "MEUCAQAwHAYGKoUDAgJiMBIGByqFAwICJAAGByqFAwICHgEEIgQgGmpna37puqaRGBZjUAX5UfWaL67C9rvxCpOIexI0KUM="
    );

    public byte[] gost2001_Rand_Reci_Cert = Base64.decode(
        "MIIELDCCA9ugAwIBAgIERMAcpzAIBgYqhQMCAgMwgckxCzAJBgNVBAYTAlJVMSAwHgYDVQQIDBfQoS7Qn9C40YLQtdGA0LHR" +
            "g9GA0LPRijEfMB0GA1UECgwW0KHQvtCy0YDQtdC80LXQvdC90LjQujEfMB0GA1UECwwW0KDRg9C60L7QstC+0LTRgdGC0LLQ" +
            "vjEZMBcGA1UEDAwQ0KDQtdC00LDQutGC0L7RgDE7MDkGA1UEAwwy0J/Rg9GI0LrQuNC9INCQ0LvQtdC60YHQsNC90LTRgCDQ" +
            "odC10YDQs9C10LXQstC40YcwHhcNMTcwNzE2MTQwMDAwWhcNMzcwNzE2MTQwMDAwWjCByTELMAkGA1UEBhMCUlUxIDAeBgNV" +
            "BAgMF9ChLtCf0LjRgtC10YDQsdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQtdC90L3QuNC6MR8wHQYDVQQLDBbQ" +
            "oNGD0LrQvtCy0L7QtNGB0YLQstC+MRkwFwYDVQQMDBDQoNC10LTQsNC60YLQvtGAMTswOQYDVQQDDDLQn9GD0YjQutC40L0g" +
            "0JDQu9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhzBjMBwGBiqFAwICEzASBgcqhQMCAiQABgcqhQMCAh4BA0MA" +
            "BEA6Dzd7VQJA7712CfHiH4L0TVcaH+iLJ6vHkfdgAvS+8mGt/L2H9qQP7O41SgDKQqtfrr+tHDig7/ft5Bl1TFNoo4IBpTCC" +
            "AaEwDgYDVR0PAQH/BAQDAgH+MGMGA1UdJQRcMFoGCCsGAQUFBwMBBggrBgEFBQcDAgYIKwYBBQUHAwMGCCsGAQUFBwMEBggr" +
            "BgEFBQcDBQYIKwYBBQUHAwYGCCsGAQUFBwMHBggrBgEFBQcDCAYIKwYBBQUHAwkwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E" +
            "FgQU8ZLn4r4PajaqWCwLYW6XauO3XsgwgfkGA1UdIwSB8TCB7oAU8ZLn4r4PajaqWCwLYW6XauO3Xsihgc+kgcwwgckxCzAJ" +
            "BgNVBAYTAlJVMSAwHgYDVQQIDBfQoS7Qn9C40YLQtdGA0LHRg9GA0LPRijEfMB0GA1UECgwW0KHQvtCy0YDQtdC80LXQvdC9" +
            "0LjQujEfMB0GA1UECwwW0KDRg9C60L7QstC+0LTRgdGC0LLQvjEZMBcGA1UEDAwQ0KDQtdC00LDQutGC0L7RgDE7MDkGA1UE" +
            "Awwy0J/Rg9GI0LrQuNC9INCQ0LvQtdC60YHQsNC90LTRgCDQodC10YDQs9C10LXQstC40YeCBETAHKcwCAYGKoUDAgIDA0EA" +
            "Ul4Y7XAhFUEoTUwdue+wbyxk86SpIFwC6NuVjTSIF3F9ACxfz2N6iwHaRv6GTVRIAEjj5G/rhdxRivvC8hU4QQ=="
    );

    public byte[] gost2001_Rand_Reci_Key = Base64.decode(
        "MEUCAQAwHAYGKoUDAgJiMBIGByqFAwICJAAGByqFAwICHgEEIgQg5oDAn/BdWX4RSfHeqZyHAo/CNAy+2a0Jq3Z922cYeSQ="
    );

    public byte[] gost2001_Rand_Gen_Msg = Base64.decode(
        "MIICAQYJKoZIhvcNAQcDoIIB8jCCAe4CAQAxggGtoYIBqQIBA6BloWMwHAYGKoUDAgITMBIGByqFAwICJAAGByqFAwICHgED" +
            "QwAEQDPvrzGNOI/Qb3J+9cDPWrTZEaOJQosazkfNh53EG8J8gUukdAakZi/kN9k8xGKbJc0ZEJ4/88jkWt9UFUkYIUGhCgQI" +
            "SQHkq1IzGZ8wKAYGKoUDAgJgMB4GByqFAwICDQEwEwYHKoUDAgIfAQQISQHkq1IzGZ8wggEFMIIBATCB0jCByTELMAkGA1UE" +
            "BhMCUlUxIDAeBgNVBAgMF9ChLtCf0LjRgtC10YDQsdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQtdC90L3QuNC6" +
            "MR8wHQYDVQQLDBbQoNGD0LrQvtCy0L7QtNGB0YLQstC+MRkwFwYDVQQMDBDQoNC10LTQsNC60YLQvtGAMTswOQYDVQQDDDLQ" +
            "n9GD0YjQutC40L0g0JDQu9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhwIERMAcpwQqMCgEIA4jC8qro8xNnn+R" +
            "JTNYpV8dSdw82e/pnqnyo21o+qZkBAT9DaUDMDgGCSqGSIb3DQEHATAdBgYqhQMCAhUwEwQIziBZysW+ewMGByqFAwICHwGA" +
            "DFKaSCs2xd4ef/khFQ=="
    );

    public byte[] gost2012_Sender_Cert = Base64.decode(
        "MIIETDCCA/mgAwIBAgIEB/tRdzAKBggqhQMHAQEDAjCB0TELMAkGA1UEBhMCUlUxIDAeBgNVBAgMF9ChLtCf0LjRgtC10YDQ" +
            "sdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQtdC90L3QuNC6MSgwJgYDVQQLDB/QlNC10LnRgdGC0LLRg9GO0YnQ" +
            "uNC1INC70LjRhtCwMS0wKwYDVQQMDCTQpNC40LvQvtGB0L7QsiDQuCDQv9GD0LHQu9C40YbQuNGB0YIxJjAkBgNVBAMMHdCV" +
            "0LLQs9C10L3RltC5INCe0L3Ro9Cz0LjQvdGKMB4XDTE3MDcxNTE0MDAwMFoXDTM3MDcxNTE0MDAwMFowgdExCzAJBgNVBAYT" +
            "AlJVMSAwHgYDVQQIDBfQoS7Qn9C40YLQtdGA0LHRg9GA0LPRijEfMB0GA1UECgwW0KHQvtCy0YDQtdC80LXQvdC90LjQujEo" +
            "MCYGA1UECwwf0JTQtdC50YHRgtCy0YPRjtGJ0LjQtSDQu9C40YbQsDEtMCsGA1UEDAwk0KTQuNC70L7RgdC+0LIg0Lgg0L/R" +
            "g9Cx0LvQuNGG0LjRgdGCMSYwJAYDVQQDDB3QldCy0LPQtdC90ZbQuSDQntC90aPQs9C40L3RijBmMB8GCCqFAwcBAQEBMBMG" +
            "ByqFAwICJAAGCCqFAwcBAQICA0MABEAl9XE868NRYm3CQXCPO+BJlVi7kxORfoyRaHyWyKBFf4TYV4eEUF/WjAf3fAqsndp6" +
            "v1DNqa3KS1R1yqn1Ug4do4IBrjCCAaowDgYDVR0PAQH/BAQDAgH+MGMGA1UdJQRcMFoGCCsGAQUFBwMBBggrBgEFBQcDAgYI" +
            "KwYBBQUHAwMGCCsGAQUFBwMEBggrBgEFBQcDBQYIKwYBBQUHAwYGCCsGAQUFBwMHBggrBgEFBQcDCAYIKwYBBQUHAwkwDwYD" +
            "VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUzhoR/a0hWGOpy6GPEm7LBCJ3dLYwggEBBgNVHSMEgfkwgfaAFM4aEf2tIVhjqcuh" +
            "jxJuywQid3S2oYHXpIHUMIHRMQswCQYDVQQGEwJSVTEgMB4GA1UECAwX0KEu0J/QuNGC0LXRgNCx0YPRgNCz0YoxHzAdBgNV" +
            "BAoMFtCh0L7QstGA0LXQvNC10L3QvdC40LoxKDAmBgNVBAsMH9CU0LXQudGB0YLQstGD0Y7RidC40LUg0LvQuNGG0LAxLTAr" +
            "BgNVBAwMJNCk0LjQu9C+0YHQvtCyINC4INC/0YPQsdC70LjRhtC40YHRgjEmMCQGA1UEAwwd0JXQstCz0LXQvdGW0Lkg0J7Q" +
            "vdGj0LPQuNC90YqCBAf7UXcwCgYIKoUDBwEBAwIDQQDcFDvbdfUu1087tslF70OeZgLW5QHRtPLUaldE9x1Geu2veJos9fZ7" +
            "nqISVcd1wrf6FfADt3Tw2pQuG8mVCNUi"
    );

    public byte[] gost2012_Sender_Key = Base64.decode(
        "MEgCAQAwHwYIKoUDBwEBBgEwEwYHKoUDAgIkAAYIKoUDBwEBAgIEIgQgYARzlWBWAJLs64jQbYW4UEXqFN/ChtWCSHqRgivT" +
            "8Ds="
    );

    public byte[] gost2012_Reci_Cert = Base64.decode(
        "MIIEMzCCA+CgAwIBAgIEe7X7RjAKBggqhQMHAQEDAjCByTELMAkGA1UEBhMCUlUxIDAeBgNVBAgMF9ChLtCf0LjRgtC10YDQ" +
            "sdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQtdC90L3QuNC6MR8wHQYDVQQLDBbQoNGD0LrQvtCy0L7QtNGB0YLQ" +
            "stC+MRkwFwYDVQQMDBDQoNC10LTQsNC60YLQvtGAMTswOQYDVQQDDDLQn9GD0YjQutC40L0g0JDQu9C10LrRgdCw0L3QtNGA" +
            "INCh0LXRgNCz0LXQtdCy0LjRhzAeFw0xNzA3MTUxNDAwMDBaFw0zNzA3MTUxNDAwMDBaMIHJMQswCQYDVQQGEwJSVTEgMB4G" +
            "A1UECAwX0KEu0J/QuNGC0LXRgNCx0YPRgNCz0YoxHzAdBgNVBAoMFtCh0L7QstGA0LXQvNC10L3QvdC40LoxHzAdBgNVBAsM" +
            "FtCg0YPQutC+0LLQvtC00YHRgtCy0L4xGTAXBgNVBAwMENCg0LXQtNCw0LrRgtC+0YAxOzA5BgNVBAMMMtCf0YPRiNC60LjQ" +
            "vSDQkNC70LXQutGB0LDQvdC00YAg0KHQtdGA0LPQtdC10LLQuNGHMGYwHwYIKoUDBwEBAQEwEwYHKoUDAgIkAAYIKoUDBwEB" +
            "AgIDQwAEQGQ4aJ3On0XqEt62PUfquYCAx0690AzlyE9IO8r5zkNKldvK4THC1IgBHkRzKiewquMm0YuYh76NI01uNjThOjyj" +
            "ggGlMIIBoTAOBgNVHQ8BAf8EBAMCAf4wYwYDVR0lBFwwWgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDAwYIKwYBBQUH" +
            "AwQGCCsGAQUFBwMFBggrBgEFBQcDBgYIKwYBBQUHAwcGCCsGAQUFBwMIBggrBgEFBQcDCTAPBgNVHRMBAf8EBTADAQH/MB0G" +
            "A1UdDgQWBBROPw+FggywJjV9aLLSKz2Cr0BD9zCB+QYDVR0jBIHxMIHugBROPw+FggywJjV9aLLSKz2Cr0BD96GBz6SBzDCB" +
            "yTELMAkGA1UEBhMCUlUxIDAeBgNVBAgMF9ChLtCf0LjRgtC10YDQsdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQ" +
            "tdC90L3QuNC6MR8wHQYDVQQLDBbQoNGD0LrQvtCy0L7QtNGB0YLQstC+MRkwFwYDVQQMDBDQoNC10LTQsNC60YLQvtGAMTsw" +
            "OQYDVQQDDDLQn9GD0YjQutC40L0g0JDQu9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRh4IEe7X7RjAKBggqhQMH" +
            "AQEDAgNBAJR6UhzmUlRzlbiCU8IjhrR15c2uFtcHqHaUfiO8XJ2bnOiwxADZbnqlN3Foul6QrTXa5Vu1UbA2hFobJeuDniQ="
    );

    public byte[] gost2012_Reci_Key = Base64.decode(
        "MEgCAQAwHwYIKoUDBwEBBgEwEwYHKoUDAgIkAAYIKoUDBwEBAgIEIgQgbtgmrFxhZLQm9H1Gx0+BAVTP6ZVLu20KcmKNzdIh" +
            "rKc="
    );

    public byte[] gost2012_Reci_Msg = Base64.decode(
        "MIICBgYJKoZIhvcNAQcDoIIB9zCCAfMCAQAxggGyoYIBrgIBA6BooWYwHwYIKoUDBwEBAQEwEwYHKoUDAgIkAAYIKoUDBwEB" +
            "AgIDQwAEQCX1cTzrw1FibcJBcI874EmVWLuTE5F+jJFofJbIoEV/hNhXh4RQX9aMB/d8Cqyd2nq/UM2prcpLVHXKqfVSDh2h" +
            "CgQIDIhh5975RYMwKgYIKoUDBwEBBgEwHgYHKoUDAgINATATBgcqhQMCAh8BBAgMiGHn3vlFgzCCAQUwggEBMIHSMIHJMQsw" +
            "CQYDVQQGEwJSVTEgMB4GA1UECAwX0KEu0J/QuNGC0LXRgNCx0YPRgNCz0YoxHzAdBgNVBAoMFtCh0L7QstGA0LXQvNC10L3Q" +
            "vdC40LoxHzAdBgNVBAsMFtCg0YPQutC+0LLQvtC00YHRgtCy0L4xGTAXBgNVBAwMENCg0LXQtNCw0LrRgtC+0YAxOzA5BgNV" +
            "BAMMMtCf0YPRiNC60LjQvSDQkNC70LXQutGB0LDQvdC00YAg0KHQtdGA0LPQtdC10LLQuNGHAgR7tftGBCowKAQgLMyx3zUe" +
            "56F7eAKUAezilo3fxp6M/E+YkVVUDgFadfcEBHMmXJMwOAYJKoZIhvcNAQcBMB0GBiqFAwICFTATBAhJHfyezbxrUQYHKoUD" +
            "AgIfAYAMLLM89stnSyrWGWSW"
    );

    public byte[] gost2012_512_Sender_Cert = Base64.decode(
        "MIIE0jCCBD6gAwIBAgIEMBwU/jAKBggqhQMHAQEDAzCB0TELMAkGA1UEBhMCUlUxIDAeBgNVBAgMF9ChLtCf0LjRgtC10YDQ" +
            "sdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQtdC90L3QuNC6MSgwJgYDVQQLDB/QlNC10LnRgdGC0LLRg9GO0YnQ" +
            "uNC1INC70LjRhtCwMS0wKwYDVQQMDCTQpNC40LvQvtGB0L7QsiDQuCDQv9GD0LHQu9C40YbQuNGB0YIxJjAkBgNVBAMMHdCV" +
            "0LLQs9C10L3RltC5INCe0L3Ro9Cz0LjQvdGKMB4XDTE3MDcxNTE0MDAwMFoXDTM3MDcxNTE0MDAwMFowgdExCzAJBgNVBAYT" +
            "AlJVMSAwHgYDVQQIDBfQoS7Qn9C40YLQtdGA0LHRg9GA0LPRijEfMB0GA1UECgwW0KHQvtCy0YDQtdC80LXQvdC90LjQujEo" +
            "MCYGA1UECwwf0JTQtdC50YHRgtCy0YPRjtGJ0LjQtSDQu9C40YbQsDEtMCsGA1UEDAwk0KTQuNC70L7RgdC+0LIg0Lgg0L/R" +
            "g9Cx0LvQuNGG0LjRgdGCMSYwJAYDVQQDDB3QldCy0LPQtdC90ZbQuSDQntC90aPQs9C40L3RijCBqjAhBggqhQMHAQEBAjAV" +
            "BgkqhQMHAQIBAgEGCCqFAwcBAQIDA4GEAASBgLnNMC1uA9NjhZMyIotCn+4H+iqcTv5paCYmRIuIvWZO7OvUv3u9aWK5Lb0w" +
            "CH2Imbg/ffZV84xSwbNST83w4IFh8u1mAnf302+uuqt62pBU3VtPOPt3RYRwEABSDuTlBP2VocXa2iP53HM09fxhS/AJ14eR" +
            "K2oJ4cNpASXDH1mSo4IBrjCCAaowDgYDVR0PAQH/BAQDAgH+MGMGA1UdJQRcMFoGCCsGAQUFBwMBBggrBgEFBQcDAgYIKwYB" +
            "BQUHAwMGCCsGAQUFBwMEBggrBgEFBQcDBQYIKwYBBQUHAwYGCCsGAQUFBwMHBggrBgEFBQcDCAYIKwYBBQUHAwkwDwYDVR0T" +
            "AQH/BAUwAwEB/zAdBgNVHQ4EFgQUEImfPZM/dIJULOrK4d/vMchap9kwggEBBgNVHSMEgfkwgfaAFBCJnz2TP3SCVCzqyuHf" +
            "7zHIWqfZoYHXpIHUMIHRMQswCQYDVQQGEwJSVTEgMB4GA1UECAwX0KEu0J/QuNGC0LXRgNCx0YPRgNCz0YoxHzAdBgNVBAoM" +
            "FtCh0L7QstGA0LXQvNC10L3QvdC40LoxKDAmBgNVBAsMH9CU0LXQudGB0YLQstGD0Y7RidC40LUg0LvQuNGG0LAxLTArBgNV" +
            "BAwMJNCk0LjQu9C+0YHQvtCyINC4INC/0YPQsdC70LjRhtC40YHRgjEmMCQGA1UEAwwd0JXQstCz0LXQvdGW0Lkg0J7QvdGj" +
            "0LPQuNC90YqCBDAcFP4wCgYIKoUDBwEBAwMDgYEAKZRx05mBwO7VIzj1FFJcHlfbHuLF+XZbFZaVfWc32R+KLxBJ0t1RuQ34" +
            "KtjQhu8/oU2rR/pKcmyHRw3nxJy+DExdj7sWJ01uWH6vBa+nsXS8OzSIg+wb9hlrFy0wZSkQjyNMtSiNg+On1yzFeI2fxuAY" +
            "OtIKHdqht+V+6M0g8BA="
    );

    public byte[] gost2012_512_Sender_Key = Base64.decode(
        "MGoCAQAwIQYIKoUDBwEBBgIwFQYJKoUDBwECAQIBBggqhQMHAQECAwRCBEDYpenYz4GDc/sIGl34Cv1T4xtWDlt7FB28ghXT" +
            "n4MXm43IvLwW3YclZbRz7V9W5lR0XoftGJ9q3ICv/IN2F+Dr"
    );

    public byte[] gost2012_512_Reci_Cert = Base64.decode(
        "MIIEuTCCBCWgAwIBAgIECpLweDAKBggqhQMHAQEDAzCByTELMAkGA1UEBhMCUlUxIDAeBgNVBAgMF9ChLtCf0LjRgtC10YDQ" +
            "sdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQtdC90L3QuNC6MR8wHQYDVQQLDBbQoNGD0LrQvtCy0L7QtNGB0YLQ" +
            "stC+MRkwFwYDVQQMDBDQoNC10LTQsNC60YLQvtGAMTswOQYDVQQDDDLQn9GD0YjQutC40L0g0JDQu9C10LrRgdCw0L3QtNGA" +
            "INCh0LXRgNCz0LXQtdCy0LjRhzAeFw0xNzA3MTUxNDAwMDBaFw0zNzA3MTUxNDAwMDBaMIHJMQswCQYDVQQGEwJSVTEgMB4G" +
            "A1UECAwX0KEu0J/QuNGC0LXRgNCx0YPRgNCz0YoxHzAdBgNVBAoMFtCh0L7QstGA0LXQvNC10L3QvdC40LoxHzAdBgNVBAsM" +
            "FtCg0YPQutC+0LLQvtC00YHRgtCy0L4xGTAXBgNVBAwMENCg0LXQtNCw0LrRgtC+0YAxOzA5BgNVBAMMMtCf0YPRiNC60LjQ" +
            "vSDQkNC70LXQutGB0LDQvdC00YAg0KHQtdGA0LPQtdC10LLQuNGHMIGqMCEGCCqFAwcBAQECMBUGCSqFAwcBAgECAQYIKoUD" +
            "BwEBAgMDgYQABIGAnZAIQhH/2nmSIZWfn+K3ftHGWbx1vrh/IeA43Q/z7h9jVPcVV3Csju92lgL5cnXyBAV90CVGw0/bCu1N" +
            "CYUpC0EVx5OmTd54fqicmFgZLqEnX6sbCXvpgCdvXhyYl+h7PTGHcuwGsMXZlIKVQLq6quVKh/UI/IfGK5CcPkX0PVCjggGl" +
            "MIIBoTAOBgNVHQ8BAf8EBAMCAf4wYwYDVR0lBFwwWgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDAwYIKwYBBQUHAwQG" +
            "CCsGAQUFBwMFBggrBgEFBQcDBgYIKwYBBQUHAwcGCCsGAQUFBwMIBggrBgEFBQcDCTAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud" +
            "DgQWBBRvBhSgd/YSnT1ldXAE2V92ksV6WzCB+QYDVR0jBIHxMIHugBRvBhSgd/YSnT1ldXAE2V92ksV6W6GBz6SBzDCByTEL" +
            "MAkGA1UEBhMCUlUxIDAeBgNVBAgMF9ChLtCf0LjRgtC10YDQsdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQtdC9" +
            "0L3QuNC6MR8wHQYDVQQLDBbQoNGD0LrQvtCy0L7QtNGB0YLQstC+MRkwFwYDVQQMDBDQoNC10LTQsNC60YLQvtGAMTswOQYD" +
            "VQQDDDLQn9GD0YjQutC40L0g0JDQu9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRh4IECpLweDAKBggqhQMHAQED" +
            "AwOBgQDilJAjXm+OK+mkfOk2ij3qKj00+gyFzJbxtk8wKEG7QmvlOPQvywke1pmCh8b1Z48OFOdmfKnTLE/D4AI/MQECUb1h" +
            "ChUfgfrSw0LY205tqxp6aqDtc2iPI7XHQAKE+jD819zubjCBzVDOiyRXatiRsEtfXPTBvqQdisM4rSw+OQ=="

    );

    public byte[] gost2012_512_Reci_Key = Base64.decode(
        "MGoCAQAwIQYIKoUDBwEBBgIwFQYJKoUDBwECAQIBBggqhQMHAQECAwRCBEDbd6/MUJS1QjpkwGUCg8OtxzuxiU2qm2VDBDDN" +
            "ZQ8/GtO12OiysmJHAXS9fpO1TRuyySw0r5r4x2g0NCWtVdQf"
    );

    public byte[] gost2012_512_Reci_Msg = Base64.decode(
        "MIICTAYJKoZIhvcNAQcDoIICPTCCAjkCAQAxggH4oYIB9AIBA6CBraGBqjAhBggqhQMHAQEBAjAVBgkqhQMHAQIBAgEGCCqF" +
            "AwcBAQIDA4GEAASBgLnNMC1uA9NjhZMyIotCn+4H+iqcTv5paCYmRIuIvWZO7OvUv3u9aWK5Lb0wCH2Imbg/ffZV84xSwbNS" +
            "T83w4IFh8u1mAnf302+uuqt62pBU3VtPOPt3RYRwEABSDuTlBP2VocXa2iP53HM09fxhS/AJ14eRK2oJ4cNpASXDH1mSoQoE" +
            "CGGh2agBkurNMCoGCCqFAwcBAQYCMB4GByqFAwICDQEwEwYHKoUDAgIfAQQIYaHZqAGS6s0wggEFMIIBATCB0jCByTELMAkG" +
            "A1UEBhMCUlUxIDAeBgNVBAgMF9ChLtCf0LjRgtC10YDQsdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQtdC90L3Q" +
            "uNC6MR8wHQYDVQQLDBbQoNGD0LrQvtCy0L7QtNGB0YLQstC+MRkwFwYDVQQMDBDQoNC10LTQsNC60YLQvtGAMTswOQYDVQQD" +
            "DDLQn9GD0YjQutC40L0g0JDQu9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhwIECpLweAQqMCgEIBEN53tKgcd9" +
            "VW9uczUiwSM0pS/a7/vKIvTIqnIR0E5pBAQ+WRdXMDgGCSqGSIb3DQEHATAdBgYqhQMCAhUwEwQIbDvPAW4Wm0UGByqFAwIC" +
            "HwGADFMeOJyH3t7YSNgxsA=="
    );

    public byte[] gost2012_KeyTrans_Reci_Cert = Base64.decode(
        "MIIEMzCCA+CgAwIBAgIEBSqgszAKBggqhQMHAQEDAjCByTELMAkGA1UEBhMCUlUxIDAeBgNVBAgMF9ChLtCf0LjRgtC10YDQ" +
            "sdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQtdC90L3QuNC6MR8wHQYDVQQLDBbQoNGD0LrQvtCy0L7QtNGB0YLQ" +
            "stC+MRkwFwYDVQQMDBDQoNC10LTQsNC60YLQvtGAMTswOQYDVQQDDDLQn9GD0YjQutC40L0g0JDQu9C10LrRgdCw0L3QtNGA" +
            "INCh0LXRgNCz0LXQtdCy0LjRhzAeFw0xNzA3MTYxNDAwMDBaFw0zNzA3MTYxNDAwMDBaMIHJMQswCQYDVQQGEwJSVTEgMB4G" +
            "A1UECAwX0KEu0J/QuNGC0LXRgNCx0YPRgNCz0YoxHzAdBgNVBAoMFtCh0L7QstGA0LXQvNC10L3QvdC40LoxHzAdBgNVBAsM" +
            "FtCg0YPQutC+0LLQvtC00YHRgtCy0L4xGTAXBgNVBAwMENCg0LXQtNCw0LrRgtC+0YAxOzA5BgNVBAMMMtCf0YPRiNC60LjQ" +
            "vSDQkNC70LXQutGB0LDQvdC00YAg0KHQtdGA0LPQtdC10LLQuNGHMGYwHwYIKoUDBwEBAQEwEwYHKoUDAgIkAAYIKoUDBwEB" +
            "AgIDQwAEQEG5/wUY0LkiqETYAZY6o5mrjwWQNBYbSIKghYgKzLgSv1RCuTEFXRIJQcMG0V80auKVZNty9kcvn9P0IcJpGfGj" +
            "ggGlMIIBoTAOBgNVHQ8BAf8EBAMCAf4wYwYDVR0lBFwwWgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDAwYIKwYBBQUH" +
            "AwQGCCsGAQUFBwMFBggrBgEFBQcDBgYIKwYBBQUHAwcGCCsGAQUFBwMIBggrBgEFBQcDCTAPBgNVHRMBAf8EBTADAQH/MB0G" +
            "A1UdDgQWBBQJwiUIQOJNbB0Fzh6ucd3uRE9QzDCB+QYDVR0jBIHxMIHugBQJwiUIQOJNbB0Fzh6ucd3uRE9QzKGBz6SBzDCB" +
            "yTELMAkGA1UEBhMCUlUxIDAeBgNVBAgMF9ChLtCf0LjRgtC10YDQsdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQ" +
            "tdC90L3QuNC6MR8wHQYDVQQLDBbQoNGD0LrQvtCy0L7QtNGB0YLQstC+MRkwFwYDVQQMDBDQoNC10LTQsNC60YLQvtGAMTsw" +
            "OQYDVQQDDDLQn9GD0YjQutC40L0g0JDQu9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRh4IEBSqgszAKBggqhQMH" +
            "AQEDAgNBAKLmdCiVR9MWeoC+MNudXGny3l2uDBBttvhTli0gDEaQLnBFyvD+cfSLgsheoz8vwhyqD/6W3ATBMRiGjqNJjQE=");

    public byte[] gost2012_KeyTrans_Reci_Key = Base64.decode(
        "MEgCAQAwHwYIKoUDBwEBBgEwEwYHKoUDAgIkAAYIKoUDBwEBAgIEIgQgy+dPu0sLqJ/Fokomiu69lRA48HaPNkP7kmzDHOxP" +
            "QFc="
    );

    public byte[] gost2012_KeyTrans_Msg = Base64.decode(
        "MIIB/gYJKoZIhvcNAQcDoIIB7zCCAesCAQAxggGqMIIBpgIBADCB0jCByTELMAkGA1UEBhMCUlUxIDAeBgNVBAgMF9ChLtCf" +
            "0LjRgtC10YDQsdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQtdC90L3QuNC6MR8wHQYDVQQLDBbQoNGD0LrQvtCy" +
            "0L7QtNGB0YLQstC+MRkwFwYDVQQMDBDQoNC10LTQsNC60YLQvtGAMTswOQYDVQQDDDLQn9GD0YjQutC40L0g0JDQu9C10LrR" +
            "gdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhwIEBSqgszAfBggqhQMHAQEBATATBgcqhQMCAiQABggqhQMHAQECAgSBqjCB" +
            "pzAoBCBnHA+9wEUh7KIkYlboGbtxRfrTL1oPGU3Tzaw8/khaWgQE+N56jaB7BgcqhQMCAh8BoGYwHwYIKoUDBwEBAQEwEwYH" +
            "KoUDAgIkAAYIKoUDBwEBAgIDQwAEQMbb4wVWm1EWIIXKDseCNE6JHmS+4fNh2uB+10Isg7g8/1Wvdh66IFir6fyp8NRwwMkU" +
            "QM0dmAfcpN6M2RSj83wECMCTi+FRlTafMDgGCSqGSIb3DQEHATAdBgYqhQMCAhUwEwQIzZlyAleTrCEGByqFAwICHwGADIO7" +
            "l43OVnBpGM+FjQ=="
    );

    public byte[] github539_GostEnvData = Base64.decode(
        "MIIBxQYJKoZIhvcNAQcDoIIBtjCCAbICAQAxggF8MIIBeAIBADCBojCBlDELMAkG\n" +
            "A1UEBhMCUlUxFjAUBgNVBAgMDVN2ZXJkbG92c2theWExFTATBgNVBAcMDEVrYXRl\n" +
            "cmluYnVyZzETMBEGA1UECgwKUm9zdGVsZWNvbTEMMAoGA1UECwwDUklUMQwwCgYD\n" +
            "VQQDDANNTlAxJTAjBgkqhkiG9w0BCQEWFmdsdWtpaGtoLWFhQHVyYWwucnQucnUC\n" +
            "CQDihx/vS7OqVzAfBggqhQMHAQEBATATBgcqhQMCAiMBBggqhQMHAQECAgSBrDCB\n" +
            "qTAoBCCOzeVj2u7vVt05/1UjBxt51k06wrIhalqaFWacp5+8ywQEZwbtgaB9Bgkq\n" +
            "hQMHAQIFAQGgZjAfBggqhQMHAQEBATATBgcqhQMCAiMBBggqhQMHAQECAgNDAARA\n" +
            "qOyKoz/eS3Pyd1JadxSNEpereq4be7gRJVy8Qfg80CfchQf+gj5+loND0fm3vtiQ\n" +
            "dHdylZWk3UInvTB3/QdHkQQIHQro/keNHKMwLQYJKoZIhvcNAQcBMB0GBiqFAwIC\n" +
            "FTATBAgr82ldAd52+QYHKoUDAgIfAYABQA==");

    public byte[] github539_PrivKey = Base64.decode(
        "MEgCAQAwHwYIKoUDBwEBAQEwEwYHKoUDAgIjAQYIKoUDBwEBAgIEIgQg2Zw10hDxo6SHNVvUpfyXJesDZaEdoAidtV760MFrZBg="
    );

    public NewEnvelopedDataTest()
    {
    }

    public void setUp()
        throws Exception
    {
        init();
    }

    private static void init()
        throws Exception
    {
        if (!_initialised)
        {
            _initialised = true;
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            _signDN = "O=Bouncy Castle, C=AU";
            _signKP = CMSTestUtil.makeKeyPair();
            _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

            _origDN = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            _origKP = CMSTestUtil.makeKeyPair();
            _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);

            _reciDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _reciDN2 = "CN=Fred, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP = CMSTestUtil.makeKeyPair();
            _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);
            _reciCertOaep = CMSTestUtil.makeOaepCertificate(_reciKP, _reciDN, _signKP, _signDN);

            _origEcKP = CMSTestUtil.makeEcDsaKeyPair();
            _reciEcKP = CMSTestUtil.makeEcDsaKeyPair();
            _reciEcCert = CMSTestUtil.makeCertificate(_reciEcKP, _reciDN, _signKP, _signDN);
            _reciEcKP2 = CMSTestUtil.makeEcDsaKeyPair();
            _reciEcCert2 = CMSTestUtil.makeCertificate(_reciEcKP2, _reciDN2, _signKP, _signDN);

            _origDhKP = CMSTestUtil.makeDhKeyPair();
            _reciDhKP = CMSTestUtil.makeDhKeyPair();
            _reciDhCert = CMSTestUtil.makeCertificate(_reciDhKP, _reciDN, _signKP, _signDN);

            _reciKemsKP = CMSTestUtil.makeKeyPair();
            _reciKemsCert = CMSTestUtil.makeCertificate(_reciKemsKP, _reciDN, _signKP, _signDN, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_rsa_KEM));
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
        byte[] data = "WallaWallaWashington".getBytes();

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

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        attrTable = ed.getUnprotectedAttributes();

        assertEquals(attrs.size(), 2);

        assertEquals(new DERUTF8String("Hint"), attrTable.get(PKCSObjectIdentifiers.id_aa_contentHint).getAttrValues().getObjectAt(0));
        assertEquals(new DERUTF8String("Request"), attrTable.get(PKCSObjectIdentifiers.id_aa_receiptRequest).getAttrValues().getObjectAt(0));

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    // TODO: add KEMS to provider.
//    public void testRsaKEMS()
//        throws Exception
//    {
//        byte[]          data     = "WallaWallaWashington".getBytes();
//
//        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
//
//        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciKemsCert).setProvider(BC));
//
//        CMSEnvelopedData ed = edGen.generate(
//                                new CMSProcessableByteArray(data),
//                                new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());
//
//        RecipientInformationStore  recipients = ed.getRecipientInfos();
//
//
//        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);
//
//        Collection  c = recipients.getRecipients();
//
//        assertEquals(2, c.size());
//
//        Iterator    it = c.iterator();
//
//        while (it.hasNext())
//        {
//            RecipientInformation   recipient = (RecipientInformation)it.next();
//
//            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());
//
//            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));
//
//            assertEquals(true, Arrays.equals(data, recData));
//        }
//
//        RecipientId id = new JceKeyTransRecipientId(_reciCert);
//
//        Collection collection = recipients.getRecipients(id);
//        if (collection.size() != 2)
//        {
//            fail("recipients not matched using general recipient ID.");
//        }
//        assertTrue(collection.iterator().next() instanceof RecipientInformation);
//    }

    public void testKeyTrans()
        throws Exception
    {
        byte[] data = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));
        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(ASN1OctetString.getInstance(ASN1OctetString.getInstance(_reciCert.getExtensionValue(Extension.subjectKeyIdentifier.getId())).getOctets()).getOctets(), _reciCert.getPublicKey()).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();


        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        Collection c = recipients.getRecipients();

        assertEquals(2, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

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

    public void testKeyTransOAEPDefault()
        throws Exception
    {
        byte[] data = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
        JcaAlgorithmParametersConverter paramsConverter = new JcaAlgorithmParametersConverter();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert, paramsConverter.getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, OAEPParameterSpec.DEFAULT)).setProvider(BC));
        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(ASN1OctetString.getInstance(ASN1OctetString.getInstance(_reciCert.getExtensionValue(Extension.subjectKeyIdentifier.getId())).getOctets()).getOctets(), paramsConverter.getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, OAEPParameterSpec.DEFAULT), _reciCert.getPublicKey()).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();


        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        Collection c = recipients.getRecipients();

        assertEquals(2, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(PKCSObjectIdentifiers.id_RSAES_OAEP, recipient.getKeyEncryptionAlgorithm().getAlgorithm());

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

    public void testKeyTransOAEPSHA1()
        throws Exception
    {
        doTestKeyTransOAEPDefaultNamed("SHA-1");
    }

    public void testKeyTransOAEPSHA224()
        throws Exception
    {
        doTestKeyTransOAEPDefaultNamed("SHA-224");
    }

    public void testKeyTransOAEPSHA256()
        throws Exception
    {
        doTestKeyTransOAEPDefaultNamed("SHA-256");
    }

    public void testKeyTransOAEPSHA1AndSHA256()
        throws Exception
    {
        doTestKeyTransOAEPDefaultNamed("SHA-1", "SHA-256");
    }

    private void doTestKeyTransOAEPDefaultNamed(String digest)
        throws Exception
    {
        doTestKeyTransOAEPDefaultNamed(digest, digest);
    }

    private void doTestKeyTransOAEPDefaultNamed(String digest, String mgfDigest)
        throws Exception
    {
        byte[] data = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
        JcaAlgorithmParametersConverter paramsConverter = new JcaAlgorithmParametersConverter();

        OAEPParameterSpec oaepSpec = new OAEPParameterSpec(digest, "MGF1", new MGF1ParameterSpec(mgfDigest), new PSource.PSpecified(new byte[]{1, 2, 3, 4, 5}));
        AlgorithmIdentifier oaepAlgId = paramsConverter.getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, oaepSpec);

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert, oaepAlgId).setProvider(BC));
        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(ASN1OctetString.getInstance(ASN1OctetString.getInstance(_reciCert.getExtensionValue(Extension.subjectKeyIdentifier.getId())).getOctets()).getOctets(), oaepAlgId, _reciCert.getPublicKey()).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();


        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        Collection c = recipients.getRecipients();

        assertEquals(2, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(PKCSObjectIdentifiers.id_RSAES_OAEP, recipient.getKeyEncryptionAlgorithm().getAlgorithm());

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

    public void testKeyTransOAEPInCert()
        throws Exception
    {
        byte[] data = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCertOaep).setProvider(BC));
        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(ASN1OctetString.getInstance(ASN1OctetString.getInstance(_reciCertOaep.getExtensionValue(Extension.subjectKeyIdentifier.getId())).getOctets()).getOctets(), _reciCertOaep.getPublicKey()).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();


        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        Collection c = recipients.getRecipients();

        assertEquals(2, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(PKCSObjectIdentifiers.id_RSAES_OAEP, recipient.getKeyEncryptionAlgorithm().getAlgorithm());

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertEquals(true, Arrays.equals(data, recData));
        }

        RecipientId id = new JceKeyTransRecipientId(_reciCertOaep);

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
        byte[] data = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setAlgorithmMapping(PKCSObjectIdentifiers.rsaEncryption, "RSA/2/PKCS1Padding").setProvider(BC));

        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build();
        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            encryptor);

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

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

        ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(encryptor.getAlgorithmIdentifier()).setProvider(BC).build());

        recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        c = recipients.getRecipients();

        assertEquals(1, c.size());
        assertEquals(encryptor.getAlgorithmIdentifier(), ed.getContentEncryptionAlgorithm());
        
        it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setAlgorithmMapping(PKCSObjectIdentifiers.rsaEncryption, "RSA/2/PKCS1Padding").setProvider(BC));

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testOriginatorInfoGeneration()
        throws Exception
    {
        byte[] data = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        X509CertificateHolder origCert = new X509CertificateHolder(_origCert.getEncoded());

        edGen.setOriginatorInfo(new OriginatorInfoGenerator(origCert).generate());

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));
        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(ASN1OctetString.getInstance(ASN1OctetString.getInstance(_reciCert.getExtensionValue(Extension.subjectKeyIdentifier.getId())).getOctets()).getOctets(), _reciCert.getPublicKey()).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();


        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        assertTrue(ed.getOriginatorInfo().getCertificates().getMatches(null).contains(origCert));

        Collection c = recipients.getRecipients();

        assertEquals(2, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

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
        byte[] data = "WallaWallaBouncyCastle".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.RC2_CBC, 40).setProvider(BC).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getContentEncryptionAlgorithm().getAlgorithm(), CMSAlgorithm.RC2_CBC);

        RC2CBCParameter rc2P = RC2CBCParameter.getInstance(ed.getContentEncryptionAlgorithm().getParameters());
        assertEquals(160, rc2P.getRC2ParameterVersion().intValue());

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testKeyTransRC4()
        throws Exception
    {
        byte[] data = "WallaWallaBouncyCastle".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier("1.2.840.113549.3.4")).setProvider(BC).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), "1.2.840.113549.3.4");

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testKeyTrans128RC4()
        throws Exception
    {
        byte[] data = "WallaWallaBouncyCastle".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier("1.2.840.113549.3.4"), 128).setProvider(BC).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), "1.2.840.113549.3.4");

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

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
        byte[] data = "WallaWallaBouncyCastle".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new BcRSAKeyTransRecipientInfoGenerator(new JcaX509CertificateHolder(_reciCert)));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier("1.2.840.113549.3.4"), 128).setProvider(BC).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), "1.2.840.113549.3.4");

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

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
        byte[] data = "WallaWallaBouncyCastle".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier("1.3.14.3.2.7")).setProvider(BC).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), "1.3.14.3.2.7");

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

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
        byte[] data = new byte[]{0, 1, 2, 3};

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(),
            CMSEnvelopedDataGenerator.AES128_CBC);

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

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
        byte[] data = new byte[]{0, 1, 2, 3};
        KeyFactory kf = KeyFactory.getInstance("RSA", BC);
        PrivateKey kPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(tooShort3DESKey));

        CMSEnvelopedData ed = new CMSEnvelopedData(tooShort3DES);

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();
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
        byte[] data = new byte[]{0, 1, 2, 3};

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new BcRSAKeyTransRecipientInfoGenerator(new JcaX509CertificateHolder(_reciCert)));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new BcCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC, 192).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

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
        byte[] data = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(generatorOID).setProvider(BC).build();
        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            encryptor);

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(checkOID.getId(), ed.getEncryptionAlgOID());
        assertEquals(keySize, ((byte[])encryptor.getKey().getRepresentation()).length);

        if (asn1Params != null)
        {
            ASN1InputStream aIn = new ASN1InputStream(ed.getEncryptionAlgParams());

            assertTrue(asn1Params.isAssignableFrom(aIn.readObject().getClass()));
        }

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        if (!it.hasNext())
        {
            fail("no recipients found");
        }

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setKeySizeValidation(true).setProvider(BC));

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testErroneousKEK()
        throws Exception
    {
        byte[] data = "WallaWallaWashington".getBytes();
        SecretKey kek = new SecretKeySpec(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, "AES");

        CMSEnvelopedData ed = new CMSEnvelopedData(oldKEK);

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

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

        tryKekAlgorithmAEAD(CMSTestUtil.makeAESKey(128), NISTObjectIdentifiers.id_aes128_wrap, CMSAlgorithm.AES128_GCM, NISTObjectIdentifiers.id_aes128_GCM);
        tryKekAlgorithmAEAD(CMSTestUtil.makeAESKey(128), NISTObjectIdentifiers.id_aes128_wrap, CMSAlgorithm.AES192_GCM, NISTObjectIdentifiers.id_aes192_GCM);
        tryKekAlgorithmAEAD(CMSTestUtil.makeAESKey(128), NISTObjectIdentifiers.id_aes128_wrap, CMSAlgorithm.AES256_GCM, NISTObjectIdentifiers.id_aes256_GCM);

        byte[] nonce = Hex.decode("0102030405060708090a0b0c");
        tryKekAlgorithmAEAD(CMSTestUtil.makeAESKey(128), NISTObjectIdentifiers.id_aes128_wrap, CMSAlgorithm.AES128_GCM, NISTObjectIdentifiers.id_aes128_GCM, new GCMParameters(nonce, 11).getEncoded());

        tryKekAlgorithmAEAD(CMSTestUtil.makeAESKey(128), NISTObjectIdentifiers.id_aes128_wrap, CMSAlgorithm.AES128_CCM, NISTObjectIdentifiers.id_aes128_CCM);
        tryKekAlgorithmAEAD(CMSTestUtil.makeAESKey(128), NISTObjectIdentifiers.id_aes128_wrap, CMSAlgorithm.AES192_CCM, NISTObjectIdentifiers.id_aes192_CCM);
        tryKekAlgorithmAEAD(CMSTestUtil.makeAESKey(128), NISTObjectIdentifiers.id_aes128_wrap, CMSAlgorithm.AES256_CCM, NISTObjectIdentifiers.id_aes256_CCM);

        tryKekAlgorithmAEAD(CMSTestUtil.makeAESKey(128), NISTObjectIdentifiers.id_aes128_wrap, CMSAlgorithm.AES128_CCM, NISTObjectIdentifiers.id_aes128_CCM, new CCMParameters(nonce, 14).getEncoded());
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
        byte[] data = "WallaWallaWashington".getBytes();
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        byte[] kekId = new byte[]{1, 2, 3, 4, 5};

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

    private void tryKekAlgorithmAEAD(SecretKey kek, ASN1ObjectIdentifier algOid, ASN1ObjectIdentifier aeadAlgorithm, ASN1ObjectIdentifier baseOID)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException, IOException
    {
        byte[] data = "WallaWallaWashington".getBytes();
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        byte[] kekId = new byte[]{1, 2, 3, 4, 5};

        edGen.addRecipientInfoGenerator(new JceKEKRecipientInfoGenerator(kekId, kek).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(aeadAlgorithm).setProvider(BC).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        assertEquals(ed.getContentEncryptionAlgorithm().getAlgorithm(), baseOID);

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

        checkAlteredMAC(kek, algOid, ed.getEncoded());
    }

    private void tryKekAlgorithmAEAD(SecretKey kek, ASN1ObjectIdentifier algOid, ASN1ObjectIdentifier aeadAlgorithm, ASN1ObjectIdentifier baseOID, byte[] encodedParameters)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException, IOException
    {
        byte[] data = "WallaWallaWashington".getBytes();
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        byte[] kekId = new byte[]{1, 2, 3, 4, 5};

        edGen.addRecipientInfoGenerator(new JceKEKRecipientInfoGenerator(kekId, kek).setProvider(BC));

        AlgorithmParameters algParams = AlgorithmParameters.getInstance(aeadAlgorithm.getId(), BC);

        algParams.init(encodedParameters);

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(aeadAlgorithm).setProvider(BC).setAlgorithmParameters(algParams).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        assertEquals(ed.getContentEncryptionAlgorithm().getAlgorithm(), baseOID);
        assertEquals(ed.getContentEncryptionAlgorithm().getParameters(), ASN1Sequence.getInstance(encodedParameters));

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

        checkAlteredMAC(kek, algOid, ed.getEncoded());
    }

    private void checkAlteredMAC(SecretKey kek, ASN1ObjectIdentifier algOid, byte[] edData)
        throws CMSException, IOException
    {
        CMSEnvelopedData ed;
        RecipientInformationStore recipients;
        Collection c;
        Iterator it;

        // Locate the MAC within 'edData' and modify it to trigger failed authentication
        {
            ContentInfo eContentInfo = ContentInfo.getInstance(edData);
            EnvelopedData envD = EnvelopedData.getInstance(eContentInfo.getContent());
            EncryptedContentInfo eInfo = envD.getEncryptedContentInfo();

            int macPos = indexOf(edData, eInfo.getEncryptedContent().getOctets());
            if (macPos < 0)
            {
                fail("MAC not locatable");
            }
            edData[macPos + 10] ^= 0xFF;
        }

        ed = new CMSEnvelopedData(edData);

        recipients = ed.getRecipientInfos();

        c = recipients.getRecipients();
        it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(algOid.getId(), recipient.getKeyEncryptionAlgOID());

            try
            {
                byte[] recData = recipient.getContent(new JceKEKEnvelopedRecipient(kek).setKeySizeValidation(true).setProvider(BC));

                fail("MAC error not detected");
            }
            catch (CMSException e)
            {
                // expected
            }
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

    public void testFaultyAgreementRecipient()
        throws Exception
    {
        ASN1ObjectIdentifier algorithm = CMSAlgorithm.ECDH_SHA1KDF;
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyAgreeRecipientInfoGenerator(algorithm,
            _origEcKP.getPrivate(), _origEcKP.getPublic(),
            CMSAlgorithm.AES128_WRAP).setProvider(BC));

        try
        {
            edGen.generate(
                new CMSProcessableByteArray(data),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());
        }
        catch (CMSException e)
        {
            assertEquals(e.getMessage(), "No recipients associated with generator - use addRecipient()");
        }
    }

    public void testKeyWrapAlgorithmIdentifiers()
        throws Exception
    {
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        doVerifyKeyWrap(data, CMSAlgorithm.DES_EDE3_WRAP, false);
        doVerifyKeyWrap(data, CMSAlgorithm.AES128_WRAP, true);
        doVerifyKeyWrap(data, CMSAlgorithm.AES192_WRAP, true);
        doVerifyKeyWrap(data, CMSAlgorithm.AES256_WRAP, true);
        doVerifyKeyWrap(data, CMSAlgorithm.CAMELLIA128_WRAP, true);
        doVerifyKeyWrap(data, CMSAlgorithm.CAMELLIA192_WRAP, true);
        doVerifyKeyWrap(data, CMSAlgorithm.CAMELLIA256_WRAP, true);
        doVerifyKeyWrap(data, CMSAlgorithm.SEED_WRAP, true);
    }

    private void doVerifyKeyWrap(byte[] data, ASN1ObjectIdentifier wrapAlgorithm, boolean paramsAbsent)
        throws CertificateEncodingException, CMSException, NoSuchProviderException, IOException
    {
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECDH_SHA256KDF,
            _origEcKP.getPrivate(), _origEcKP.getPublic(),
            wrapAlgorithm).addRecipient(_reciEcCert).setProvider(BC));

        // DESEDE wrap should only be used with DES/TripleDES keys.
        ASN1ObjectIdentifier encAlg = wrapAlgorithm.equals(CMSAlgorithm.DES_EDE3_WRAP) ? CMSAlgorithm.DES_EDE3_CBC : CMSAlgorithm.AES128_CBC;
        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(encAlg).setProvider(BC).build());

        assertEquals(ed.getEncryptionAlgOID(), encAlg.getId());

        RecipientInformationStore recipients = ed.getRecipientInfos();

        KeyAgreeRecipientInformation recipientInformation = (KeyAgreeRecipientInformation)recipients.get(new JceKeyAgreeRecipientId(_reciEcCert));
        AlgorithmIdentifier keyWrapAlg = AlgorithmIdentifier.getInstance(recipientInformation.getKeyEncryptionAlgorithm().getParameters());

        assertEquals(wrapAlgorithm, keyWrapAlg.getAlgorithm());
        if (paramsAbsent)
        {
            assertNull(keyWrapAlg.getParameters());
        }
        else
        {
            assertNotNull(keyWrapAlg.getParameters());
        }

        assertEquals(ed.getEncryptionAlgOID(), encAlg.getId());

        confirmDataReceived(recipients, data, _reciEcCert, _reciEcKP.getPrivate(), BC);
        confirmNumberRecipients(recipients, 1);
    }

    public void testEphemeralStaticDHAgreement()
        throws Exception
    {
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyAgreeRecipientInfoGenerator(PKCSObjectIdentifiers.id_alg_ESDH,
            _origDhKP.getPrivate(), _origDhKP.getPublic(),
            CMSAlgorithm.AES128_WRAP).addRecipient(_reciDhCert).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.AES128_CBC);

        RecipientInformationStore recipients = ed.getRecipientInfos();

        confirmDataReceived(recipients, data, _reciDhCert, _reciDhKP.getPrivate(), BC);
        confirmNumberRecipients(recipients, 1);
    }

    public void testStaticStaticDHAgreement()
        throws Exception
    {
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyAgreeRecipientInfoGenerator(PKCSObjectIdentifiers.id_alg_SSDH,
            _origDhKP.getPrivate(), _origDhKP.getPublic(),
            CMSAlgorithm.AES128_WRAP)
            .setUserKeyingMaterial(data)
            .addRecipient(_reciDhCert)
            .setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.AES128_CBC);

        RecipientInformationStore recipients = ed.getRecipientInfos();

        confirmDataReceived(recipients, data, _reciDhCert, _reciDhKP.getPrivate(), BC);
        confirmNumberRecipients(recipients, 1);

        try
        {
            edGen = new CMSEnvelopedDataGenerator();

            edGen.addRecipientInfoGenerator(new JceKeyAgreeRecipientInfoGenerator(PKCSObjectIdentifiers.id_alg_SSDH,
                _origDhKP.getPrivate(), _origDhKP.getPublic(),
                CMSAlgorithm.AES128_WRAP).addRecipient(_reciDhCert).setProvider(BC));

            edGen.generate(
                new CMSProcessableByteArray(data),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());
            fail("no UKM uncaught");
        }
        catch (CMSException e)
        {
            Assert.assertEquals("User keying material must be set for static keys.", e.getMessage());
        }
    }

    public void testKDFAgreements()
        throws Exception
    {
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        doTryAgreement(data, CMSAlgorithm.ECDH_SHA1KDF);
        doTryAgreement(data, CMSAlgorithm.ECDH_SHA224KDF);
        doTryAgreement(data, CMSAlgorithm.ECDH_SHA256KDF);
        doTryAgreement(data, CMSAlgorithm.ECDH_SHA384KDF);
        doTryAgreement(data, CMSAlgorithm.ECDH_SHA512KDF);

        doTryAgreement(data, CMSAlgorithm.ECCDH_SHA1KDF);
        doTryAgreement(data, CMSAlgorithm.ECCDH_SHA224KDF);
        doTryAgreement(data, CMSAlgorithm.ECCDH_SHA256KDF);
        doTryAgreement(data, CMSAlgorithm.ECCDH_SHA384KDF);
        doTryAgreement(data, CMSAlgorithm.ECCDH_SHA512KDF);

        doTryAgreement(data, CMSAlgorithm.ECMQV_SHA1KDF);
        doTryAgreement(data, CMSAlgorithm.ECMQV_SHA224KDF);
        doTryAgreement(data, CMSAlgorithm.ECMQV_SHA256KDF);
        doTryAgreement(data, CMSAlgorithm.ECMQV_SHA384KDF);
        doTryAgreement(data, CMSAlgorithm.ECMQV_SHA512KDF);
    }

    private void doTryAgreement(byte[] data, ASN1ObjectIdentifier algorithm)
        throws CertificateEncodingException, CMSException, NoSuchProviderException, IOException
    {
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyAgreeRecipientInfoGenerator(algorithm,
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
        KeyFactory fact = KeyFactory.getInstance("ECDH", BC);
        PrivateKey privKey = fact.generatePrivate(privSpec);

        verifyECKeyAgreeVectors(privKey, "2.16.840.1.101.3.4.1.42", ecKeyAgreeMsgAES256);
        verifyECKeyAgreeVectors(privKey, "2.16.840.1.101.3.4.1.2", ecKeyAgreeMsgAES128);
        verifyECKeyAgreeVectors(privKey, "1.2.840.113549.3.7", ecKeyAgreeMsgDESEDE);
    }

    public void testECMQVKeyAgreeVectors()
        throws Exception
    {
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(ecKeyAgreeKey);
        KeyFactory fact = KeyFactory.getInstance("ECDH", BC);
        PrivateKey privKey = fact.generatePrivate(privSpec);

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

    public void testPasswordAES256WithPRF()
        throws Exception
    {
        passwordUTF8Test(CMSEnvelopedDataGenerator.AES256_CBC, PasswordRecipient.PRF.HMacSHA1);
        passwordUTF8Test(CMSEnvelopedDataGenerator.AES256_CBC, PasswordRecipient.PRF.HMacSHA224);
        passwordUTF8Test(CMSEnvelopedDataGenerator.AES256_CBC, PasswordRecipient.PRF.HMacSHA256);
        passwordUTF8Test(CMSEnvelopedDataGenerator.AES256_CBC, PasswordRecipient.PRF.HMacSHA384);
        passwordUTF8Test(CMSEnvelopedDataGenerator.AES256_CBC, PasswordRecipient.PRF.HMacSHA512);
    }

    public void testNoSaltOrIterationCount()
        throws Exception
    {
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JcePasswordRecipientInfoGenerator(CMSAlgorithm.AES256_CBC, "abc\u5639\u563b".toCharArray()).setProvider(BC).setPRF(PasswordRecipient.PRF.HMacSHA1));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(),
            CMSEnvelopedDataGenerator.AES128_CBC);

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        if (it.hasNext())
        {
            PasswordRecipientInformation recipient = (PasswordRecipientInformation)it.next();

            assertEquals(AlgorithmIdentifier.getInstance(recipient.getKeyEncryptionAlgorithm().getParameters()).getAlgorithm(), CMSAlgorithm.AES256_CBC);
            assertEquals(PBKDF2Params.getInstance(recipient.getKeyDerivationAlgorithm().getParameters()).getPrf(), PasswordRecipient.PRF.HMacSHA1.getAlgorithmID());

            byte[] recData = recipient.getContent(new JcePasswordEnvelopedRecipient("abc\u5639\u563b".toCharArray()).setProvider(BC));
            assertEquals(true, Arrays.equals(data, recData));

            // try lightweight recipient
            recData = recipient.getContent(new BcPasswordEnvelopedRecipient("abc\u5639\u563b".toCharArray()));
            assertEquals(true, Arrays.equals(data, recData));
        }
        else
        {
            fail("no recipient found");
        }
    }

    public void testRFC4134ex5_1()
        throws Exception
    {
        byte[] data = Hex.decode("5468697320697320736f6d652073616d706c6520636f6e74656e742e");

        KeyFactory kFact = KeyFactory.getInstance("RSA", BC);
        Key key = kFact.generatePrivate(new PKCS8EncodedKeySpec(bobPrivRsaEncrypt));

        CMSEnvelopedData ed = new CMSEnvelopedData(rfc4134ex5_1);

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals("1.2.840.113549.3.7", ed.getEncryptionAlgOID());

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

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

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals("1.2.840.113549.3.2", ed.getEncryptionAlgOID());

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        if (it.hasNext())
        {
            while (it.hasNext())
            {
                RecipientInformation recipient = (RecipientInformation)it.next();
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

        RecipientInformationStore recipients = env.getRecipientInfos();

        OriginatorInformation origInfo = env.getOriginatorInfo();

        assertEquals(new X500Name("C=US,O=U.S. Government,OU=HSPD12Lab,OU=Agents,CN=user1"), ((X509CertificateHolder)origInfo.getCertificates().getMatches(null).iterator().next()).getSubject());
        assertEquals(CMSEnvelopedDataGenerator.DES_EDE3_CBC, env.getEncryptionAlgOID());
    }

    public void testOpenSSLVectors()
        throws Exception
    {
        byte[] expected = Strings.toByteArray("abcdefghijklmnopqrstuvwxyz0123456789\r\n");

        PEMParser pemParser = new PEMParser(new InputStreamReader(getClass().getResourceAsStream("ecdh/ecc.key")));

        pemParser.readObject();  // skip the curve definition

        PEMKeyPair kp = (PEMKeyPair)pemParser.readObject();

        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");

        ECPrivateKey ecKey = (ECPrivateKey)keyFactory.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivateKeyInfo().getEncoded()));

        pemParser = new PEMParser(new InputStreamReader(getClass().getResourceAsStream("ecdh/ecc.crt")));

        X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate((X509CertificateHolder)pemParser.readObject());

        processInput(ecKey, expected, "ecdh/encSess1.asc", new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_CMS3DESwrap, DERNull.INSTANCE));
        processInput(ecKey, expected, "ecdh/encSess2.asc", new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_CMS3DESwrap, DERNull.INSTANCE));
        processInput(ecKey, expected, "ecdh/encSess3.asc", new AlgorithmIdentifier(CMSAlgorithm.AES128_WRAP, DERNull.INSTANCE));
        processInput(ecKey, expected, "ecdh/encSess4.asc", new AlgorithmIdentifier(CMSAlgorithm.AES128_WRAP, DERNull.INSTANCE));
        processInput(ecKey, expected, "ecdh/encSess5.asc", new AlgorithmIdentifier(CMSAlgorithm.AES192_WRAP, DERNull.INSTANCE));
        processInput(ecKey, expected, "ecdh/encSess6.asc", new AlgorithmIdentifier(CMSAlgorithm.AES192_WRAP, DERNull.INSTANCE));
        processInput(ecKey, expected, "ecdh/encSess7.asc", new AlgorithmIdentifier(CMSAlgorithm.AES256_WRAP, DERNull.INSTANCE));
        processInput(ecKey, expected, "ecdh/encSess8.asc", new AlgorithmIdentifier(CMSAlgorithm.AES256_WRAP, DERNull.INSTANCE));

        processInput(ecKey, expected, "ecdh/encSessA.asc", new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_CMS3DESwrap, DERNull.INSTANCE));
        processInput(ecKey, expected, "ecdh/encSessB.asc", new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_CMS3DESwrap, DERNull.INSTANCE));
        processInput(ecKey, expected, "ecdh/encSessC.asc", new AlgorithmIdentifier(CMSAlgorithm.AES128_WRAP));
        processInput(ecKey, expected, "ecdh/encSessD.asc", new AlgorithmIdentifier(CMSAlgorithm.AES128_WRAP));
        processInput(ecKey, expected, "ecdh/encSessE.asc", new AlgorithmIdentifier(CMSAlgorithm.AES192_WRAP));
        processInput(ecKey, expected, "ecdh/encSessF.asc", new AlgorithmIdentifier(CMSAlgorithm.AES192_WRAP));
        processInput(ecKey, expected, "ecdh/encSessG.asc", new AlgorithmIdentifier(CMSAlgorithm.AES256_WRAP));
        processInput(ecKey, expected, "ecdh/encSessH.asc", new AlgorithmIdentifier(CMSAlgorithm.AES256_WRAP));
    }

    public void testGost3410_2012_KeyTransGen()
        throws Exception
    {
        byte[] data = Strings.toByteArray("hello world!");


        CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();


        X509Certificate cert = (X509Certificate)CertificateFactory
                                                    .getInstance("X.509", "BC")
                                                    .generateCertificate(new ByteArrayInputStream(gost2012_512_Reci_Cert));
        JceKeyTransRecipientInfoGenerator jceKey = new JceKeyTransRecipientInfoGenerator(cert).setProvider("BC");
        cmsEnvelopedDataGenerator.addRecipientInfoGenerator(jceKey);
        CMSTypedData msg = new CMSProcessableByteArray(data);
        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.GOST28147_GCFB).setProvider("BC").build();
        CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator.generate(msg, encryptor);

        byte[] encryptedData = cmsEnvelopedData.getEncoded();

        CMSEnvelopedData ed = new CMSEnvelopedData(encryptedData);
        KeyFactory keyFact = KeyFactory.getInstance("ECGOST3410-2012", "BC");
        PrivateKey privKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(gost2012_512_Reci_Key));

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CryptoProObjectIdentifiers.gostR28147_gcfb.getId());

        Collection c = recipients.getRecipients();

        Iterator it = c.iterator();

         while (it.hasNext())
         {
             RecipientInformation recipient = (RecipientInformation)it.next();

             assertEquals(recipient.getKeyEncryptionAlgOID(), RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512.getId());

             byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(privKey).setProvider(BC));

             assertTrue(Arrays.equals(data, recData));
         }

    }

    public void testGost3410_2001_KeyTrans()
        throws Exception
    {
        KeyFactory keyFact = KeyFactory.getInstance("ECGOST3410", BC);

        PrivateKey privKey = keyFact.generatePrivate(new org.bouncycastle.jce.spec.ECPrivateKeySpec(
            new BigInteger("0B293BE050D0082BDAE785631A6BAB68F35B42786D6DDA56AFAF169891040F77", 16),
            ECGOST3410NamedCurveTable.getParameterSpec("GostR3410-2001-CryptoPro-XchA")));

        CMSEnvelopedData ed = new CMSEnvelopedData(gost3410_2001_KeyTrans);

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CryptoProObjectIdentifiers.gostR28147_gcfb.getId());

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), CryptoProObjectIdentifiers.gostR3410_2001.getId());

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(privKey).setProvider(BC));

            assertEquals("sample text\n", Strings.fromByteArray(recData));
        }

        CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);

        RecipientId id = new JceKeyTransRecipientId((X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(gost3410_RecipCert)));

        Collection<RecipientInformation> collection = recipients.getRecipients(id);
        if (collection.size() != 1)
        {
            fail("recipients not matched using general recipient ID.");
        }
        assertTrue(collection.iterator().next() instanceof RecipientInformation);
    }

    public void testGithub539_Gost3410_2012_KeyTrans()
        throws Exception
    {
        KeyFactory keyFact = KeyFactory.getInstance("ECGOST3410-2012", BC);

        PrivateKey privKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(github539_PrivKey));

        CMSEnvelopedData ed = new CMSEnvelopedData(github539_GostEnvData);

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CryptoProObjectIdentifiers.gostR28147_gcfb.getId());

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256.getId());

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(privKey).setProvider(BC));

            assertEquals(".", Strings.fromByteArray(recData));
        }
    }

    public void testGost3410_2012_KeyTrans()
        throws Exception
    {
        KeyFactory keyFact = KeyFactory.getInstance("ECGOST3410-2012", BC);

        PrivateKey privKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(gost2012_KeyTrans_Reci_Key));

        CMSEnvelopedData ed = new CMSEnvelopedData(gost2012_KeyTrans_Msg);

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CryptoProObjectIdentifiers.gostR28147_gcfb.getId());

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256.getId());

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(privKey).setProvider(BC));

            assertEquals("Hello World!", Strings.fromByteArray(recData));
        }

        CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);

        RecipientId id = new JceKeyTransRecipientId((X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(gost2012_KeyTrans_Reci_Cert)));

        Collection collection = recipients.getRecipients(id);
        if (collection.size() != 1)
        {
            fail("recipients not matched using general recipient ID.");
        }
        assertTrue(collection.iterator().next() instanceof RecipientInformation);
    }

    public void testGost3410_2001_KeyAgree()
        throws Exception
    {
        KeyFactory keyFact = KeyFactory.getInstance("ECGOST3410", BC);

        PrivateKey privKey = keyFact.generatePrivate(new org.bouncycastle.jce.spec.ECPrivateKeySpec(
            new BigInteger("0B293BE050D0082BDAE785631A6BAB68F35B42786D6DDA56AFAF169891040F77", 16),
            ECGOST3410NamedCurveTable.getParameterSpec("GostR3410-2001-CryptoPro-XchA")));

        CMSEnvelopedData ed = new CMSEnvelopedData(gost3410_2001_KeyAgree);

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CryptoProObjectIdentifiers.gostR28147_gcfb.getId());

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_ESDH.getId());

            byte[] recData = recipient.getContent(new JceKeyAgreeEnvelopedRecipient(privKey).setProvider(BC));

            assertEquals("sample text\n", Strings.fromByteArray(recData));
        }

        CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);

        RecipientId id = new JceKeyAgreeRecipientId((X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(gost3410_RecipCert)));

        Collection collection = recipients.getRecipients(id);
        if (collection.size() != 1)
        {
            fail("recipients not matched using general recipient ID.");
        }
        assertTrue(collection.iterator().next() instanceof RecipientInformation);
    }

    public void testGost3410_2001_KeyTransRand()
        throws Exception
    {
        KeyFactory keyFact = KeyFactory.getInstance("ECGOST3410", BC);

        PrivateKey privKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(gost2001_Rand_Key));

        CMSEnvelopedData ed = new CMSEnvelopedData(gost2001_Rand_Msg);

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CryptoProObjectIdentifiers.gostR28147_gcfb.getId());

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), CryptoProObjectIdentifiers.gostR3410_2001.getId());

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(privKey).setProvider(BC));

            assertEquals("Hello world!", Strings.fromByteArray(recData));
        }

        CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);

        RecipientId id = new JceKeyTransRecipientId((X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(gost2001_Rand_Cert)));

        Collection collection = recipients.getRecipients(id);
        if (collection.size() != 1)
        {
            fail("recipients not matched using general recipient ID.");
        }
        assertTrue(collection.iterator().next() instanceof RecipientInformation);
    }

    public void testGost3410_2001_KeyAgreeRand()
        throws Exception
    {
        KeyFactory keyFact = KeyFactory.getInstance("ECGOST3410", BC);

        PrivateKey privKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(gost2001_Rand_Reci_Key));

        CMSEnvelopedData ed = new CMSEnvelopedData(gost2001_Rand_Gen_Msg);

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CryptoProObjectIdentifiers.gostR28147_gcfb.getId());

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_ESDH.getId());

            byte[] recData = recipient.getContent(new JceKeyAgreeEnvelopedRecipient(privKey).setProvider(BC));

            assertEquals("Hello World!", Strings.fromByteArray(recData));
        }

        CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);

        RecipientId id = new JceKeyAgreeRecipientId((X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(gost2001_Rand_Reci_Cert)));

        Collection collection = recipients.getRecipients(id);
        if (collection.size() != 1)
        {
            fail("recipients not matched using general recipient ID.");
        }
        assertTrue(collection.iterator().next() instanceof RecipientInformation);
    }

    public void testGost3410_2012_KeyAgree()
        throws Exception
    {
        KeyFactory keyFact = KeyFactory.getInstance("ECGOST3410-2012", BC);

        PrivateKey privKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(gost2012_Reci_Key));

        CMSEnvelopedData ed = new CMSEnvelopedData(gost2012_Reci_Msg);

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CryptoProObjectIdentifiers.gostR28147_gcfb.getId());

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256.getId());

            byte[] recData = recipient.getContent(new JceKeyAgreeEnvelopedRecipient(privKey).setProvider(BC));

            assertEquals("Hello World!", Strings.fromByteArray(recData));
        }

        CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);

        RecipientId id = new JceKeyAgreeRecipientId((X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(gost2012_Reci_Cert)));

        Collection collection = recipients.getRecipients(id);
        if (collection.size() != 1)
        {
            fail("recipients not matched using general recipient ID.");
        }
        assertTrue(collection.iterator().next() instanceof RecipientInformation);
    }
     /*
     TODO: Something odd is going on with this one
    public void testGost3410_2012_512_KeyAgree()
        throws Exception
    {
        KeyFactory keyFact = KeyFactory.getInstance("ECGOST3410-2012", BC);

        PrivateKey privKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(gost2012_512_Reci_Key));

        CMSEnvelopedData ed = new CMSEnvelopedData(gost2012_512_Reci_Msg);

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CryptoProObjectIdentifiers.gostR28147_gcfb.getId());

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512.getId());

            byte[] recData = recipient.getContent(new JceKeyAgreeEnvelopedRecipient(privKey).setProvider(BC));

            assertEquals("Hello World!", Strings.fromByteArray(recData));
        }

        CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);

        RecipientId id = new JceKeyAgreeRecipientId((X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(gost2012_512_Reci_Cert)));

        Collection collection = recipients.getRecipients(id);
        if (collection.size() != 1)
        {
            fail("recipients not matched using general recipient ID.");
        }
        assertTrue(collection.iterator().next() instanceof RecipientInformation);
    }
    */
    
    public void testGost3410_2001_KeyAgree_Creation()
        throws Exception
    {
        SecureRandom random = new SecureRandom();
        CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);

        X509Certificate senderCert = (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(gost2001_Rand_Sender_Cert));
        X509Certificate reciCert = (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(gost2001_Rand_Reci_Cert));

        byte[] data = Strings.toByteArray("Hello World! Hello World!");
        KeyFactory keyFact = KeyFactory.getInstance("ECGOST3410", BC);

        PrivateKey senderKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(gost2001_Rand_Sender_Key));
        PrivateKey reciKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(gost2001_Rand_Reci_Key));

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        JceKeyAgreeRecipientInfoGenerator recipientGenerator = new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECDHGOST3410_2012_256,
            senderKey, senderCert.getPublicKey(), CMSAlgorithm.GOST28147_CRYPTOPRO_WRAP).setProvider(BC);

        byte[] ukm = new byte[8];
        random.nextBytes(ukm);

        recipientGenerator.addRecipient(reciCert);
        recipientGenerator.setUserKeyingMaterial(ukm);

        edGen.addRecipientInfoGenerator(recipientGenerator);

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.GOST28147_GCFB).setProvider(BC).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CryptoProObjectIdentifiers.gostR28147_gcfb.getId());

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256.getId());

            byte[] recData = recipient.getContent(new JceKeyAgreeEnvelopedRecipient(reciKey).setProvider(BC));

            assertEquals("Hello World! Hello World!", Strings.fromByteArray(recData));
        }

        RecipientId id = new JceKeyAgreeRecipientId(reciCert);

        Collection collection = recipients.getRecipients(id);
        if (collection.size() != 1)
        {
            fail("recipients not matched using general recipient ID.");
        }
        assertTrue(collection.iterator().next() instanceof RecipientInformation);
    }

    public void testGost3410_2012_256_KeyAgree_Creation()
        throws Exception
    {
        SecureRandom random = new SecureRandom();
        CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);

        X509Certificate senderCert = (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(gost2012_Sender_Cert));
        X509Certificate reciCert = (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(gost2012_Reci_Cert));

        byte[] data = Strings.toByteArray("Hello World!");
        KeyFactory keyFact = KeyFactory.getInstance("ECGOST3410-2012", BC);

        PrivateKey senderKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(gost2012_Sender_Key));
        PrivateKey reciKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(gost2012_Reci_Key));

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        JceKeyAgreeRecipientInfoGenerator recipientGenerator = new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECDHGOST3410_2012_256,
            senderKey, senderCert.getPublicKey(), CMSAlgorithm.GOST28147_CRYPTOPRO_WRAP).setProvider(BC);

        byte[] ukm = new byte[8];
        random.nextBytes(ukm);

        recipientGenerator.addRecipient(reciCert);
        recipientGenerator.setUserKeyingMaterial(ukm);

        edGen.addRecipientInfoGenerator(recipientGenerator);

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.GOST28147_GCFB).setProvider(BC).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CryptoProObjectIdentifiers.gostR28147_gcfb.getId());

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256.getId());

            byte[] recData = recipient.getContent(new JceKeyAgreeEnvelopedRecipient(reciKey).setProvider(BC));

            assertEquals("Hello World!", Strings.fromByteArray(recData));
        }

        RecipientId id = new JceKeyAgreeRecipientId(reciCert);

        Collection collection = recipients.getRecipients(id);
        if (collection.size() != 1)
        {
            fail("recipients not matched using general recipient ID.");
        }
        assertTrue(collection.iterator().next() instanceof RecipientInformation);
    }

    public void testGost3410_2012_512_KeyAgree_Creation()
        throws Exception
    {
        SecureRandom random = new SecureRandom();
        CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);

        X509Certificate senderCert = (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(gost2012_512_Sender_Cert));
        X509Certificate reciCert = (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(gost2012_512_Reci_Cert));

        byte[] data = Strings.toByteArray("Hello World!");
        KeyFactory keyFact = KeyFactory.getInstance("ECGOST3410-2012", BC);

        PrivateKey senderKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(gost2012_512_Sender_Key));
        PrivateKey reciKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(gost2012_512_Reci_Key));

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        JceKeyAgreeRecipientInfoGenerator recipientGenerator = new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECDHGOST3410_2012_512,
            senderKey, senderCert.getPublicKey(), CMSAlgorithm.GOST28147_CRYPTOPRO_WRAP).setProvider(BC);

        byte[] ukm = new byte[8];
        random.nextBytes(ukm);

        recipientGenerator.addRecipient(reciCert);
        recipientGenerator.setUserKeyingMaterial(ukm);

        edGen.addRecipientInfoGenerator(recipientGenerator);

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.GOST28147_GCFB).setProvider(BC).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CryptoProObjectIdentifiers.gostR28147_gcfb.getId());

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512.getId());

            byte[] recData = recipient.getContent(new JceKeyAgreeEnvelopedRecipient(reciKey).setProvider(BC));

            assertEquals("Hello World!", Strings.fromByteArray(recData));
        }

        RecipientId id = new JceKeyAgreeRecipientId(reciCert);

        Collection collection = recipients.getRecipients(id);
        if (collection.size() != 1)
        {
            fail("recipients not matched using general recipient ID.");
        }
        assertTrue(collection.iterator().next() instanceof RecipientInformation);
    }

    private int indexOf(byte[] data, byte[] subData)
    {
        byte subData0 = subData[0];
        for (int i = 0; i <= data.length - subData.length; ++i)
        {
            if (data[i] != subData0)
            {
                continue;
            }

            int matchPos = i;
            for (int j = 1; j < subData.length; ++j)
            {
                if (data[i + j] != subData[j])
                {
                    matchPos = -1;
                    break;
                }
            }

            if (matchPos >= 0)
            {
                return matchPos;
            }
        }
        return -1;
    }

    private void processInput(ECPrivateKey ecKey, byte[] expected, String input, AlgorithmIdentifier wrapAlg)
        throws CMSException, IOException
    {
        PEMParser pemParser;
        pemParser = new PEMParser(new InputStreamReader(getClass().getResourceAsStream(input)));

        CMSEnvelopedData envData = new CMSEnvelopedData((ContentInfo)pemParser.readObject());

        KeyAgreeRecipientInformation recip = (KeyAgreeRecipientInformation)envData.getRecipientInfos().getRecipients().iterator().next();

        TestCase.assertEquals(wrapAlg, AlgorithmIdentifier.getInstance(recip.getKeyEncryptionAlgorithm().getParameters()));

        byte[] decrypted = recip.getContent(new JceKeyAgreeEnvelopedRecipient(ecKey).setProvider("BC"));

        TestCase.assertTrue(Arrays.equals(expected, decrypted));
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

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(),
            CMSEnvelopedDataGenerator.AES128_CBC);

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

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

        RecipientInformation recipient = (RecipientInformation)it.next();

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

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(),
            CMSEnvelopedDataGenerator.AES128_CBC);

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

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

        RecipientInformation recipient = (RecipientInformation)it.next();

        byte[] recData = recipient.getContent(new JcePasswordEnvelopedRecipient("abc\u5639\u563b".toCharArray()).setProvider(BC));
        assertEquals(true, Arrays.equals(data, recData));
    }

    private void passwordUTF8Test(String algorithm, PasswordRecipient.PRF prf)
        throws Exception
    {
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JcePasswordRecipientInfoGenerator(new ASN1ObjectIdentifier(algorithm), "abc\u5639\u563b".toCharArray()).setProvider(BC).setPRF(prf).setSaltAndIterationCount(new byte[20], 5));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(),
            CMSEnvelopedDataGenerator.AES128_CBC);

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        if (it.hasNext())
        {
            PasswordRecipientInformation recipient = (PasswordRecipientInformation)it.next();

            assertEquals(AlgorithmIdentifier.getInstance(recipient.getKeyEncryptionAlgorithm().getParameters()).getAlgorithm().getId(), algorithm);
            assertEquals(PBKDF2Params.getInstance(recipient.getKeyDerivationAlgorithm().getParameters()).getPrf(), prf.getAlgorithmID());

            byte[] recData = recipient.getContent(new JcePasswordEnvelopedRecipient("abc\u5639\u563b".toCharArray()).setProvider(BC));
            assertEquals(true, Arrays.equals(data, recData));

            // try lightweight recipient
            recData = recipient.getContent(new BcPasswordEnvelopedRecipient("abc\u5639\u563b".toCharArray()));
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

        RecipientInformation recipient = (RecipientInformation)it.next();

        byte[] recData = recipient.getContent(new JcePasswordEnvelopedRecipient("abc\u5639\u563b".toCharArray()).setProvider(BC));
        assertEquals(true, Arrays.equals(data, recData));

        // try lightweight generator.
        edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new BcPasswordRecipientInfoGenerator(new ASN1ObjectIdentifier(algorithm), "abc\u5639\u563b".toCharArray()).setPRF(prf).setSaltAndIterationCount(new byte[20], 5));

        ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());

        recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(),
            CMSEnvelopedDataGenerator.AES128_CBC);

        c = recipients.getRecipients();
        it = c.iterator();

        if (it.hasNext())
        {
            PasswordRecipientInformation recipient1 = (PasswordRecipientInformation)it.next();

            assertEquals(AlgorithmIdentifier.getInstance(recipient1.getKeyEncryptionAlgorithm().getParameters()).getAlgorithm().getId(), algorithm);
            assertEquals(PBKDF2Params.getInstance(recipient1.getKeyDerivationAlgorithm().getParameters()).getPrf(), prf.getAlgorithmID());

            recData = recipient1.getContent(new JcePasswordEnvelopedRecipient("abc\u5639\u563b".toCharArray()).setProvider(BC));
            assertEquals(true, Arrays.equals(data, recData));

            // try lightweight recipient
            recData = recipient1.getContent(new BcPasswordEnvelopedRecipient("abc\u5639\u563b".toCharArray()));
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

        RecipientInformationStore recipients = ed.getRecipientInfos();

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        assertEquals(wrapAlg, ed.getEncryptionAlgOID());

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

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

        RecipientInformationStore recipients = ed.getRecipientInfos();

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        assertEquals(wrapAlg, ed.getEncryptionAlgOID());

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

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