package org.bouncycastle.cms.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import junit.framework.Assert;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1ApplicationSpecific;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCRLStore;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSAttributeTableGenerationException;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.SignerInformationVerifierProvider;
import org.bouncycastle.cms.bc.BcRSASignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaSignerId;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.Streams;

public class NewSignedDataTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    boolean DEBUG = true;

    private static String          _origDN;
    private static KeyPair         _origKP;
    private static X509Certificate _origCert;

    private static String          _signDN;
    private static KeyPair         _signKP;
    private static X509Certificate _signCert;

    private static KeyPair         _signGostKP;
    private static X509Certificate _signGostCert;

    private static KeyPair         _signEcDsaKP;
    private static X509Certificate _signEcDsaCert;

    private static KeyPair         _signEcGostKP;
    private static X509Certificate _signEcGostCert;

    private static KeyPair         _signDsaKP;
    private static X509Certificate _signDsaCert;

    private static KeyPair         _signEd25519KP;
    private static X509Certificate _signEd25519Cert;

    private static KeyPair         _signEd448KP;
    private static X509Certificate _signEd448Cert;

    private static String          _reciDN;
    private static KeyPair         _reciKP;
    private static X509Certificate _reciCert;

    private static X509CRL         _signCrl;

    private static boolean _initialised = false;

    private byte[] disorderedMessage = Base64.decode(
            "SU9fc3RkaW5fdXNlZABfX2xpYmNfc3RhcnRfbWFpbgBnZXRob3N0aWQAX19n"
          + "bW9uX3M=");

    private byte[] disorderedSet = Base64.decode(
            "MIIYXQYJKoZIhvcNAQcCoIIYTjCCGEoCAQExCzAJBgUrDgMCGgUAMAsGCSqG"
          + "SIb3DQEHAaCCFqswggJUMIIBwKADAgECAgMMg6wwCgYGKyQDAwECBQAwbzEL"
          + "MAkGA1UEBhMCREUxPTA7BgNVBAoUNFJlZ3VsaWVydW5nc2JlaMhvcmRlIGbI"
          + "dXIgVGVsZWtvbW11bmlrYXRpb24gdW5kIFBvc3QxITAMBgcCggYBCgcUEwEx"
          + "MBEGA1UEAxQKNFItQ0EgMTpQTjAiGA8yMDAwMDMyMjA5NDM1MFoYDzIwMDQw"
          + "MTIxMTYwNDUzWjBvMQswCQYDVQQGEwJERTE9MDsGA1UEChQ0UmVndWxpZXJ1"
          + "bmdzYmVoyG9yZGUgZsh1ciBUZWxla29tbXVuaWthdGlvbiB1bmQgUG9zdDEh"
          + "MAwGBwKCBgEKBxQTATEwEQYDVQQDFAo1Ui1DQSAxOlBOMIGhMA0GCSqGSIb3"
          + "DQEBAQUAA4GPADCBiwKBgQCKHkFTJx8GmoqFTxEOxpK9XkC3NZ5dBEKiUv0I"
          + "fe3QMqeGMoCUnyJxwW0k2/53duHxtv2yHSZpFKjrjvE/uGwdOMqBMTjMzkFg"
          + "19e9JPv061wyADOucOIaNAgha/zFt9XUyrHF21knKCvDNExv2MYIAagkTKaj"
          + "LMAw0bu1J0FadQIFAMAAAAEwCgYGKyQDAwECBQADgYEAgFauXpoTLh3Z3pT/"
          + "3bhgrxO/2gKGZopWGSWSJPNwq/U3x2EuctOJurj+y2inTcJjespThflpN+7Q"
          + "nvsUhXU+jL2MtPlObU0GmLvWbi47cBShJ7KElcZAaxgWMBzdRGqTOdtMv+ev"
          + "2t4igGF/q71xf6J2c3pTLWr6P8s6tzLfOCMwggJDMIIBr6ADAgECAgQAuzyu"
          + "MAoGBiskAwMBAgUAMG8xCzAJBgNVBAYTAkRFMT0wOwYDVQQKFDRSZWd1bGll"
          + "cnVuZ3NiZWjIb3JkZSBmyHVyIFRlbGVrb21tdW5pa2F0aW9uIHVuZCBQb3N0"
          + "MSEwDAYHAoIGAQoHFBMBMTARBgNVBAMUCjVSLUNBIDE6UE4wIhgPMjAwMTA4"
          + "MjAwODA4MjBaGA8yMDA1MDgyMDA4MDgyMFowSzELMAkGA1UEBhMCREUxEjAQ"
          + "BgNVBAoUCVNpZ250cnVzdDEoMAwGBwKCBgEKBxQTATEwGAYDVQQDFBFDQSBT"
          + "SUdOVFJVU1QgMTpQTjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAhV12"
          + "N2WhlR6f+3CXP57GrBM9la5Vnsu2b92zv5MZqQOPeEsYbZqDCFkYg1bSwsDE"
          + "XsGVQqXdQNAGUaapr/EUVVN+hNZ07GcmC1sPeQECgUkxDYjGi4ihbvzxlahj"
          + "L4nX+UTzJVBfJwXoIvJ+lMHOSpnOLIuEL3SRhBItvRECxN0CAwEAAaMSMBAw"
          + "DgYDVR0PAQH/BAQDAgEGMAoGBiskAwMBAgUAA4GBACDc9Pc6X8sK1cerphiV"
          + "LfFv4kpZb9ev4WPy/C6987Qw1SOTElhZAmxaJQBqmDHWlQ63wj1DEqswk7hG"
          + "LrvQk/iX6KXIn8e64uit7kx6DHGRKNvNGofPjr1WelGeGW/T2ZJKgmPDjCkf"
          + "sIKt2c3gwa2pDn4mmCz/DStUIqcPDbqLMIICVTCCAcGgAwIBAgIEAJ16STAK"
          + "BgYrJAMDAQIFADBvMQswCQYDVQQGEwJERTE9MDsGA1UEChQ0UmVndWxpZXJ1"
          + "bmdzYmVoyG9yZGUgZsh1ciBUZWxla29tbXVuaWthdGlvbiB1bmQgUG9zdDEh"
          + "MAwGBwKCBgEKBxQTATEwEQYDVQQDFAo1Ui1DQSAxOlBOMCIYDzIwMDEwMjAx"
          + "MTM0NDI1WhgPMjAwNTAzMjIwODU1NTFaMG8xCzAJBgNVBAYTAkRFMT0wOwYD"
          + "VQQKFDRSZWd1bGllcnVuZ3NiZWjIb3JkZSBmyHVyIFRlbGVrb21tdW5pa2F0"
          + "aW9uIHVuZCBQb3N0MSEwDAYHAoIGAQoHFBMBMTARBgNVBAMUCjZSLUNhIDE6"
          + "UE4wgaEwDQYJKoZIhvcNAQEBBQADgY8AMIGLAoGBAIOiqxUkzVyqnvthihnl"
          + "tsE5m1Xn5TZKeR/2MQPStc5hJ+V4yptEtIx+Fn5rOoqT5VEVWhcE35wdbPvg"
          + "JyQFn5msmhPQT/6XSGOlrWRoFummXN9lQzAjCj1sgTcmoLCVQ5s5WpCAOXFw"
          + "VWu16qndz3sPItn3jJ0F3Kh3w79NglvPAgUAwAAAATAKBgYrJAMDAQIFAAOB"
          + "gQBpSRdnDb6AcNVaXSmGo6+kVPIBhot1LzJOGaPyDNpGXxd7LV4tMBF1U7gr"
          + "4k1g9BO6YiMWvw9uiTZmn0CfV8+k4fWEuG/nmafRoGIuay2f+ILuT+C0rnp1"
          + "4FgMsEhuVNJJAmb12QV0PZII+UneyhAneZuQQzVUkTcVgYxogxdSOzCCAlUw"
          + "ggHBoAMCAQICBACdekowCgYGKyQDAwECBQAwbzELMAkGA1UEBhMCREUxPTA7"
          + "BgNVBAoUNFJlZ3VsaWVydW5nc2JlaMhvcmRlIGbIdXIgVGVsZWtvbW11bmlr"
          + "YXRpb24gdW5kIFBvc3QxITAMBgcCggYBCgcUEwExMBEGA1UEAxQKNlItQ2Eg"
          + "MTpQTjAiGA8yMDAxMDIwMTEzNDcwN1oYDzIwMDUwMzIyMDg1NTUxWjBvMQsw"
          + "CQYDVQQGEwJERTE9MDsGA1UEChQ0UmVndWxpZXJ1bmdzYmVoyG9yZGUgZsh1"
          + "ciBUZWxla29tbXVuaWthdGlvbiB1bmQgUG9zdDEhMAwGBwKCBgEKBxQTATEw"
          + "EQYDVQQDFAo1Ui1DQSAxOlBOMIGhMA0GCSqGSIb3DQEBAQUAA4GPADCBiwKB"
          + "gQCKHkFTJx8GmoqFTxEOxpK9XkC3NZ5dBEKiUv0Ife3QMqeGMoCUnyJxwW0k"
          + "2/53duHxtv2yHSZpFKjrjvE/uGwdOMqBMTjMzkFg19e9JPv061wyADOucOIa"
          + "NAgha/zFt9XUyrHF21knKCvDNExv2MYIAagkTKajLMAw0bu1J0FadQIFAMAA"
          + "AAEwCgYGKyQDAwECBQADgYEAV1yTi+2gyB7sUhn4PXmi/tmBxAfe5oBjDW8m"
          + "gxtfudxKGZ6l/FUPNcrSc5oqBYxKWtLmf3XX87LcblYsch617jtNTkMzhx9e"
          + "qxiD02ufcrxz2EVt0Akdqiz8mdVeqp3oLcNU/IttpSrcA91CAnoUXtDZYwb/"
          + "gdQ4FI9l3+qo/0UwggJVMIIBwaADAgECAgQAxIymMAoGBiskAwMBAgUAMG8x"
          + "CzAJBgNVBAYTAkRFMT0wOwYDVQQKFDRSZWd1bGllcnVuZ3NiZWjIb3JkZSBm"
          + "yHVyIFRlbGVrb21tdW5pa2F0aW9uIHVuZCBQb3N0MSEwDAYHAoIGAQoHFBMB"
          + "MTARBgNVBAMUCjZSLUNhIDE6UE4wIhgPMjAwMTEwMTUxMzMxNThaGA8yMDA1"
          + "MDYwMTA5NTIxN1owbzELMAkGA1UEBhMCREUxPTA7BgNVBAoUNFJlZ3VsaWVy"
          + "dW5nc2JlaMhvcmRlIGbIdXIgVGVsZWtvbW11bmlrYXRpb24gdW5kIFBvc3Qx"
          + "ITAMBgcCggYBCgcUEwExMBEGA1UEAxQKN1ItQ0EgMTpQTjCBoTANBgkqhkiG"
          + "9w0BAQEFAAOBjwAwgYsCgYEAiokD/j6lEP4FexF356OpU5teUpGGfUKjIrFX"
          + "BHc79G0TUzgVxqMoN1PWnWktQvKo8ETaugxLkP9/zfX3aAQzDW4Zki6x6GDq"
          + "fy09Agk+RJvhfbbIzRkV4sBBco0n73x7TfG/9NTgVr/96U+I+z/1j30aboM6"
          + "9OkLEhjxAr0/GbsCBQDAAAABMAoGBiskAwMBAgUAA4GBAHWRqRixt+EuqHhR"
          + "K1kIxKGZL2vZuakYV0R24Gv/0ZR52FE4ECr+I49o8FP1qiGSwnXB0SwjuH2S"
          + "iGiSJi+iH/MeY85IHwW1P5e+bOMvEOFhZhQXQixOD7totIoFtdyaj1XGYRef"
          + "0f2cPOjNJorXHGV8wuBk+/j++sxbd/Net3FtMIICVTCCAcGgAwIBAgIEAMSM"
          + "pzAKBgYrJAMDAQIFADBvMQswCQYDVQQGEwJERTE9MDsGA1UEChQ0UmVndWxp"
          + "ZXJ1bmdzYmVoyG9yZGUgZsh1ciBUZWxla29tbXVuaWthdGlvbiB1bmQgUG9z"
          + "dDEhMAwGBwKCBgEKBxQTATEwEQYDVQQDFAo3Ui1DQSAxOlBOMCIYDzIwMDEx"
          + "MDE1MTMzNDE0WhgPMjAwNTA2MDEwOTUyMTdaMG8xCzAJBgNVBAYTAkRFMT0w"
          + "OwYDVQQKFDRSZWd1bGllcnVuZ3NiZWjIb3JkZSBmyHVyIFRlbGVrb21tdW5p"
          + "a2F0aW9uIHVuZCBQb3N0MSEwDAYHAoIGAQoHFBMBMTARBgNVBAMUCjZSLUNh"
          + "IDE6UE4wgaEwDQYJKoZIhvcNAQEBBQADgY8AMIGLAoGBAIOiqxUkzVyqnvth"
          + "ihnltsE5m1Xn5TZKeR/2MQPStc5hJ+V4yptEtIx+Fn5rOoqT5VEVWhcE35wd"
          + "bPvgJyQFn5msmhPQT/6XSGOlrWRoFummXN9lQzAjCj1sgTcmoLCVQ5s5WpCA"
          + "OXFwVWu16qndz3sPItn3jJ0F3Kh3w79NglvPAgUAwAAAATAKBgYrJAMDAQIF"
          + "AAOBgQBi5W96UVDoNIRkCncqr1LLG9vF9SGBIkvFpLDIIbcvp+CXhlvsdCJl"
          + "0pt2QEPSDl4cmpOet+CxJTdTuMeBNXxhb7Dvualog69w/+K2JbPhZYxuVFZs"
          + "Zh5BkPn2FnbNu3YbJhE60aIkikr72J4XZsI5DxpZCGh6xyV/YPRdKSljFjCC"
          + "AlQwggHAoAMCAQICAwyDqzAKBgYrJAMDAQIFADBvMQswCQYDVQQGEwJERTE9"
          + "MDsGA1UEChQ0UmVndWxpZXJ1bmdzYmVoyG9yZGUgZsh1ciBUZWxla29tbXVu"
          + "aWthdGlvbiB1bmQgUG9zdDEhMAwGBwKCBgEKBxQTATEwEQYDVQQDFAo1Ui1D"
          + "QSAxOlBOMCIYDzIwMDAwMzIyMDk0MTI3WhgPMjAwNDAxMjExNjA0NTNaMG8x"
          + "CzAJBgNVBAYTAkRFMT0wOwYDVQQKFDRSZWd1bGllcnVuZ3NiZWjIb3JkZSBm"
          + "yHVyIFRlbGVrb21tdW5pa2F0aW9uIHVuZCBQb3N0MSEwDAYHAoIGAQoHFBMB"
          + "MTARBgNVBAMUCjRSLUNBIDE6UE4wgaEwDQYJKoZIhvcNAQEBBQADgY8AMIGL"
          + "AoGBAI8x26tmrFJanlm100B7KGlRemCD1R93PwdnG7svRyf5ZxOsdGrDszNg"
          + "xg6ouO8ZHQMT3NC2dH8TvO65Js+8bIyTm51azF6clEg0qeWNMKiiXbBXa+ph"
          + "hTkGbXiLYvACZ6/MTJMJ1lcrjpRF7BXtYeYMcEF6znD4pxOqrtbf9z5hAgUA"
          + "wAAAATAKBgYrJAMDAQIFAAOBgQB99BjSKlGPbMLQAgXlvA9jUsDNhpnVm3a1"
          + "YkfxSqS/dbQlYkbOKvCxkPGA9NBxisBM8l1zFynVjJoy++aysRmcnLY/sHaz"
          + "23BF2iU7WERy18H3lMBfYB6sXkfYiZtvQZcWaO48m73ZBySuiV3iXpb2wgs/"
          + "Cs20iqroAWxwq/W/9jCCAlMwggG/oAMCAQICBDsFZ9UwCgYGKyQDAwECBQAw"
          + "bzELMAkGA1UEBhMCREUxITAMBgcCggYBCgcUEwExMBEGA1UEAxQKNFItQ0Eg"
          + "MTpQTjE9MDsGA1UEChQ0UmVndWxpZXJ1bmdzYmVoyG9yZGUgZsh1ciBUZWxl"
          + "a29tbXVuaWthdGlvbiB1bmQgUG9zdDAiGA8xOTk5MDEyMTE3MzUzNFoYDzIw"
          + "MDQwMTIxMTYwMDAyWjBvMQswCQYDVQQGEwJERTE9MDsGA1UEChQ0UmVndWxp"
          + "ZXJ1bmdzYmVoyG9yZGUgZsh1ciBUZWxla29tbXVuaWthdGlvbiB1bmQgUG9z"
          + "dDEhMAwGBwKCBgEKBxQTATEwEQYDVQQDFAozUi1DQSAxOlBOMIGfMA0GCSqG"
          + "SIb3DQEBAQUAA4GNADCBiQKBgI4B557mbKQg/AqWBXNJhaT/6lwV93HUl4U8"
          + "u35udLq2+u9phns1WZkdM3gDfEpL002PeLfHr1ID/96dDYf04lAXQfombils"
          + "of1C1k32xOvxjlcrDOuPEMxz9/HDAQZA5MjmmYHAIulGI8Qg4Tc7ERRtg/hd"
          + "0QX0/zoOeXoDSEOBAgTAAAABMAoGBiskAwMBAgUAA4GBAIyzwfT3keHI/n2P"
          + "LrarRJv96mCohmDZNpUQdZTVjGu5VQjVJwk3hpagU0o/t/FkdzAjOdfEw8Ql"
          + "3WXhfIbNLv1YafMm2eWSdeYbLcbB5yJ1od+SYyf9+tm7cwfDAcr22jNRBqx8"
          + "wkWKtKDjWKkevaSdy99sAI8jebHtWz7jzydKMIID9TCCA16gAwIBAgICbMcw"
          + "DQYJKoZIhvcNAQEFBQAwSzELMAkGA1UEBhMCREUxEjAQBgNVBAoUCVNpZ250"
          + "cnVzdDEoMAwGBwKCBgEKBxQTATEwGAYDVQQDFBFDQSBTSUdOVFJVU1QgMTpQ"
          + "TjAeFw0wNDA3MzAxMzAyNDZaFw0wNzA3MzAxMzAyNDZaMDwxETAPBgNVBAMM"
          + "CFlhY29tOlBOMQ4wDAYDVQRBDAVZYWNvbTELMAkGA1UEBhMCREUxCjAIBgNV"
          + "BAUTATEwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAIWzLlYLQApocXIp"
          + "pgCCpkkOUVLgcLYKeOd6/bXAnI2dTHQqT2bv7qzfUnYvOqiNgYdF13pOYtKg"
          + "XwXMTNFL4ZOI6GoBdNs9TQiZ7KEWnqnr2945HYx7UpgTBclbOK/wGHuCdcwO"
          + "x7juZs1ZQPFG0Lv8RoiV9s6HP7POqh1sO0P/AgMBAAGjggH1MIIB8TCBnAYD"
          + "VR0jBIGUMIGRgBQcZzNghfnXoXRm8h1+VITC5caNRqFzpHEwbzELMAkGA1UE"
          + "BhMCREUxPTA7BgNVBAoUNFJlZ3VsaWVydW5nc2JlaMhvcmRlIGbIdXIgVGVs"
          + "ZWtvbW11bmlrYXRpb24gdW5kIFBvc3QxITAMBgcCggYBCgcUEwExMBEGA1UE"
          + "AxQKNVItQ0EgMTpQToIEALs8rjAdBgNVHQ4EFgQU2e5KAzkVuKaM9I5heXkz"
          + "bcAIuR8wDgYDVR0PAQH/BAQDAgZAMBIGA1UdIAQLMAkwBwYFKyQIAQEwfwYD"
          + "VR0fBHgwdjB0oCygKoYobGRhcDovL2Rpci5zaWdudHJ1c3QuZGUvbz1TaWdu"
          + "dHJ1c3QsYz1kZaJEpEIwQDEdMBsGA1UEAxMUQ1JMU2lnblNpZ250cnVzdDE6"
          + "UE4xEjAQBgNVBAoTCVNpZ250cnVzdDELMAkGA1UEBhMCREUwYgYIKwYBBQUH"
          + "AQEEVjBUMFIGCCsGAQUFBzABhkZodHRwOi8vZGlyLnNpZ250cnVzdC5kZS9T"
          + "aWdudHJ1c3QvT0NTUC9zZXJ2bGV0L2h0dHBHYXRld2F5LlBvc3RIYW5kbGVy"
          + "MBgGCCsGAQUFBwEDBAwwCjAIBgYEAI5GAQEwDgYHAoIGAQoMAAQDAQH/MA0G"
          + "CSqGSIb3DQEBBQUAA4GBAHn1m3GcoyD5GBkKUY/OdtD6Sj38LYqYCF+qDbJR"
          + "6pqUBjY2wsvXepUppEler+stH8mwpDDSJXrJyuzf7xroDs4dkLl+Rs2x+2tg"
          + "BjU+ABkBDMsym2WpwgA8LCdymmXmjdv9tULxY+ec2pjSEzql6nEZNEfrU8nt"
          + "ZCSCavgqW4TtMYIBejCCAXYCAQEwUTBLMQswCQYDVQQGEwJERTESMBAGA1UE"
          + "ChQJU2lnbnRydXN0MSgwDAYHAoIGAQoHFBMBMTAYBgNVBAMUEUNBIFNJR05U"
          + "UlVTVCAxOlBOAgJsxzAJBgUrDgMCGgUAoIGAMBgGCSqGSIb3DQEJAzELBgkq"
          + "hkiG9w0BBwEwIwYJKoZIhvcNAQkEMRYEFIYfhPoyfGzkLWWSSLjaHb4HQmaK"
          + "MBwGCSqGSIb3DQEJBTEPFw0wNTAzMjQwNzM4MzVaMCEGBSskCAYFMRgWFi92"
          + "YXIvZmlsZXMvdG1wXzEvdGVzdDEwDQYJKoZIhvcNAQEFBQAEgYA2IvA8lhVz"
          + "VD5e/itUxbFboKxeKnqJ5n/KuO/uBCl1N14+7Z2vtw1sfkIG+bJdp3OY2Cmn"
          + "mrQcwsN99Vjal4cXVj8t+DJzFG9tK9dSLvD3q9zT/GQ0kJXfimLVwCa4NaSf"
          + "Qsu4xtG0Rav6bCcnzabAkKuNNvKtH8amSRzk870DBg==");

    public static byte[] xtraCounterSig = Base64.decode(
                 "MIIR/AYJKoZIhvcNAQcCoIIR7TCCEekCAQExCzAJBgUrDgMCGgUAMBoGCSqG"
               + "SIb3DQEHAaANBAtIZWxsbyB3b3JsZKCCDnkwggTPMIIDt6ADAgECAgRDnYD3"
               + "MA0GCSqGSIb3DQEBBQUAMFgxCzAJBgNVBAYTAklUMRowGAYDVQQKExFJbi5U"
               + "ZS5TLkEuIFMucC5BLjEtMCsGA1UEAxMkSW4uVGUuUy5BLiAtIENlcnRpZmlj"
               + "YXRpb24gQXV0aG9yaXR5MB4XDTA4MDkxMjExNDMxMloXDTEwMDkxMjExNDMx"
               + "MlowgdgxCzAJBgNVBAYTAklUMSIwIAYDVQQKDBlJbnRlc2EgUy5wLkEuLzA1"
               + "MjYyODkwMDE0MSowKAYDVQQLDCFCdXNpbmVzcyBDb2xsYWJvcmF0aW9uICYg"
               + "U2VjdXJpdHkxHjAcBgNVBAMMFU1BU1NJTUlMSUFOTyBaSUNDQVJESTERMA8G"
               + "A1UEBAwIWklDQ0FSREkxFTATBgNVBCoMDE1BU1NJTUlMSUFOTzEcMBoGA1UE"
               + "BRMTSVQ6WkNDTVNNNzZIMTRMMjE5WTERMA8GA1UELhMIMDAwMDI1ODUwgaAw"
               + "DQYJKoZIhvcNAQEBBQADgY4AMIGKAoGBALeJTjmyFgx1SIP6c2AuB/kuyHo5"
               + "j/prKELTALsFDimre/Hxr3wOSet1TdQfFzU8Lu+EJqgfV9cV+cI1yeH1rZs7"
               + "lei7L3tX/VR565IywnguX5xwvteASgWZr537Fkws50bvTEMyYOj1Tf3FZvZU"
               + "z4n4OD39KI4mfR9i1eEVIxR3AgQAizpNo4IBoTCCAZ0wHQYDVR0RBBYwFIES"
               + "emljY2FyZGlAaW50ZXNhLml0MC8GCCsGAQUFBwEDBCMwITAIBgYEAI5GAQEw"
               + "CwYGBACORgEDAgEUMAgGBgQAjkYBBDBZBgNVHSAEUjBQME4GBgQAizABATBE"
               + "MEIGCCsGAQUFBwIBFjZodHRwOi8vZS10cnVzdGNvbS5pbnRlc2EuaXQvY2Ff"
               + "cHViYmxpY2EvQ1BTX0lOVEVTQS5odG0wDgYDVR0PAQH/BAQDAgZAMIGDBgNV"
               + "HSMEfDB6gBQZCQOW0bjFWBt+EORuxPagEgkQqKFcpFowWDELMAkGA1UEBhMC"
               + "SVQxGjAYBgNVBAoTEUluLlRlLlMuQS4gUy5wLkEuMS0wKwYDVQQDEyRJbi5U"
               + "ZS5TLkEuIC0gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHmCBDzRARMwOwYDVR0f"
               + "BDQwMjAwoC6gLIYqaHR0cDovL2UtdHJ1c3Rjb20uaW50ZXNhLml0L0NSTC9J"
               + "TlRFU0EuY3JsMB0GA1UdDgQWBBTf5ItL8KmQh541Dxt7YxcWI1254TANBgkq"
               + "hkiG9w0BAQUFAAOCAQEAgW+uL1CVWQepbC/wfCmR6PN37Sueb4xiKQj2mTD5"
               + "UZ5KQjpivy/Hbuf0NrfKNiDEhAvoHSPC31ebGiKuTMFNyZPHfPEUnyYGSxea"
               + "2w837aXJFr6utPNQGBRi89kH90sZDlXtOSrZI+AzJJn5QK3F9gjcayU2NZXQ"
               + "MJgRwYmFyn2w4jtox+CwXPQ9E5XgxiMZ4WDL03cWVXDLX00EOJwnDDMUNTRI"
               + "m9Zv+4SKTNlfFbi9UTBqWBySkDzAelsfB2U61oqc2h1xKmCtkGMmN9iZT+Qz"
               + "ZC/vaaT+hLEBFGAH2gwFrYc4/jTBKyBYeU1vsAxsibIoTs1Apgl6MH75qPDL"
               + "BzCCBM8wggO3oAMCAQICBEOdgPcwDQYJKoZIhvcNAQEFBQAwWDELMAkGA1UE"
               + "BhMCSVQxGjAYBgNVBAoTEUluLlRlLlMuQS4gUy5wLkEuMS0wKwYDVQQDEyRJ"
               + "bi5UZS5TLkEuIC0gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMDgwOTEy"
               + "MTE0MzEyWhcNMTAwOTEyMTE0MzEyWjCB2DELMAkGA1UEBhMCSVQxIjAgBgNV"
               + "BAoMGUludGVzYSBTLnAuQS4vMDUyNjI4OTAwMTQxKjAoBgNVBAsMIUJ1c2lu"
               + "ZXNzIENvbGxhYm9yYXRpb24gJiBTZWN1cml0eTEeMBwGA1UEAwwVTUFTU0lN"
               + "SUxJQU5PIFpJQ0NBUkRJMREwDwYDVQQEDAhaSUNDQVJESTEVMBMGA1UEKgwM"
               + "TUFTU0lNSUxJQU5PMRwwGgYDVQQFExNJVDpaQ0NNU003NkgxNEwyMTlZMREw"
               + "DwYDVQQuEwgwMDAwMjU4NTCBoDANBgkqhkiG9w0BAQEFAAOBjgAwgYoCgYEA"
               + "t4lOObIWDHVIg/pzYC4H+S7IejmP+msoQtMAuwUOKat78fGvfA5J63VN1B8X"
               + "NTwu74QmqB9X1xX5wjXJ4fWtmzuV6Lsve1f9VHnrkjLCeC5fnHC+14BKBZmv"
               + "nfsWTCznRu9MQzJg6PVN/cVm9lTPifg4Pf0ojiZ9H2LV4RUjFHcCBACLOk2j"
               + "ggGhMIIBnTAdBgNVHREEFjAUgRJ6aWNjYXJkaUBpbnRlc2EuaXQwLwYIKwYB"
               + "BQUHAQMEIzAhMAgGBgQAjkYBATALBgYEAI5GAQMCARQwCAYGBACORgEEMFkG"
               + "A1UdIARSMFAwTgYGBACLMAEBMEQwQgYIKwYBBQUHAgEWNmh0dHA6Ly9lLXRy"
               + "dXN0Y29tLmludGVzYS5pdC9jYV9wdWJibGljYS9DUFNfSU5URVNBLmh0bTAO"
               + "BgNVHQ8BAf8EBAMCBkAwgYMGA1UdIwR8MHqAFBkJA5bRuMVYG34Q5G7E9qAS"
               + "CRCooVykWjBYMQswCQYDVQQGEwJJVDEaMBgGA1UEChMRSW4uVGUuUy5BLiBT"
               + "LnAuQS4xLTArBgNVBAMTJEluLlRlLlMuQS4gLSBDZXJ0aWZpY2F0aW9uIEF1"
               + "dGhvcml0eYIEPNEBEzA7BgNVHR8ENDAyMDCgLqAshipodHRwOi8vZS10cnVz"
               + "dGNvbS5pbnRlc2EuaXQvQ1JML0lOVEVTQS5jcmwwHQYDVR0OBBYEFN/ki0vw"
               + "qZCHnjUPG3tjFxYjXbnhMA0GCSqGSIb3DQEBBQUAA4IBAQCBb64vUJVZB6ls"
               + "L/B8KZHo83ftK55vjGIpCPaZMPlRnkpCOmK/L8du5/Q2t8o2IMSEC+gdI8Lf"
               + "V5saIq5MwU3Jk8d88RSfJgZLF5rbDzftpckWvq6081AYFGLz2Qf3SxkOVe05"
               + "Ktkj4DMkmflArcX2CNxrJTY1ldAwmBHBiYXKfbDiO2jH4LBc9D0TleDGIxnh"
               + "YMvTdxZVcMtfTQQ4nCcMMxQ1NEib1m/7hIpM2V8VuL1RMGpYHJKQPMB6Wx8H"
               + "ZTrWipzaHXEqYK2QYyY32JlP5DNkL+9ppP6EsQEUYAfaDAWthzj+NMErIFh5"
               + "TW+wDGyJsihOzUCmCXowfvmo8MsHMIIEzzCCA7egAwIBAgIEQ52A9zANBgkq"
               + "hkiG9w0BAQUFADBYMQswCQYDVQQGEwJJVDEaMBgGA1UEChMRSW4uVGUuUy5B"
               + "LiBTLnAuQS4xLTArBgNVBAMTJEluLlRlLlMuQS4gLSBDZXJ0aWZpY2F0aW9u"
               + "IEF1dGhvcml0eTAeFw0wODA5MTIxMTQzMTJaFw0xMDA5MTIxMTQzMTJaMIHY"
               + "MQswCQYDVQQGEwJJVDEiMCAGA1UECgwZSW50ZXNhIFMucC5BLi8wNTI2Mjg5"
               + "MDAxNDEqMCgGA1UECwwhQnVzaW5lc3MgQ29sbGFib3JhdGlvbiAmIFNlY3Vy"
               + "aXR5MR4wHAYDVQQDDBVNQVNTSU1JTElBTk8gWklDQ0FSREkxETAPBgNVBAQM"
               + "CFpJQ0NBUkRJMRUwEwYDVQQqDAxNQVNTSU1JTElBTk8xHDAaBgNVBAUTE0lU"
               + "OlpDQ01TTTc2SDE0TDIxOVkxETAPBgNVBC4TCDAwMDAyNTg1MIGgMA0GCSqG"
               + "SIb3DQEBAQUAA4GOADCBigKBgQC3iU45shYMdUiD+nNgLgf5Lsh6OY/6ayhC"
               + "0wC7BQ4pq3vx8a98DknrdU3UHxc1PC7vhCaoH1fXFfnCNcnh9a2bO5Xouy97"
               + "V/1UeeuSMsJ4Ll+ccL7XgEoFma+d+xZMLOdG70xDMmDo9U39xWb2VM+J+Dg9"
               + "/SiOJn0fYtXhFSMUdwIEAIs6TaOCAaEwggGdMB0GA1UdEQQWMBSBEnppY2Nh"
               + "cmRpQGludGVzYS5pdDAvBggrBgEFBQcBAwQjMCEwCAYGBACORgEBMAsGBgQA"
               + "jkYBAwIBFDAIBgYEAI5GAQQwWQYDVR0gBFIwUDBOBgYEAIswAQEwRDBCBggr"
               + "BgEFBQcCARY2aHR0cDovL2UtdHJ1c3Rjb20uaW50ZXNhLml0L2NhX3B1YmJs"
               + "aWNhL0NQU19JTlRFU0EuaHRtMA4GA1UdDwEB/wQEAwIGQDCBgwYDVR0jBHww"
               + "eoAUGQkDltG4xVgbfhDkbsT2oBIJEKihXKRaMFgxCzAJBgNVBAYTAklUMRow"
               + "GAYDVQQKExFJbi5UZS5TLkEuIFMucC5BLjEtMCsGA1UEAxMkSW4uVGUuUy5B"
               + "LiAtIENlcnRpZmljYXRpb24gQXV0aG9yaXR5ggQ80QETMDsGA1UdHwQ0MDIw"
               + "MKAuoCyGKmh0dHA6Ly9lLXRydXN0Y29tLmludGVzYS5pdC9DUkwvSU5URVNB"
               + "LmNybDAdBgNVHQ4EFgQU3+SLS/CpkIeeNQ8be2MXFiNdueEwDQYJKoZIhvcN"
               + "AQEFBQADggEBAIFvri9QlVkHqWwv8Hwpkejzd+0rnm+MYikI9pkw+VGeSkI6"
               + "Yr8vx27n9Da3yjYgxIQL6B0jwt9XmxoirkzBTcmTx3zxFJ8mBksXmtsPN+2l"
               + "yRa+rrTzUBgUYvPZB/dLGQ5V7Tkq2SPgMySZ+UCtxfYI3GslNjWV0DCYEcGJ"
               + "hcp9sOI7aMfgsFz0PROV4MYjGeFgy9N3FlVwy19NBDicJwwzFDU0SJvWb/uE"
               + "ikzZXxW4vVEwalgckpA8wHpbHwdlOtaKnNodcSpgrZBjJjfYmU/kM2Qv72mk"
               + "/oSxARRgB9oMBa2HOP40wSsgWHlNb7AMbImyKE7NQKYJejB++ajwywcxggM8"
               + "MIIDOAIBATBgMFgxCzAJBgNVBAYTAklUMRowGAYDVQQKExFJbi5UZS5TLkEu"
               + "IFMucC5BLjEtMCsGA1UEAxMkSW4uVGUuUy5BLiAtIENlcnRpZmljYXRpb24g"
               + "QXV0aG9yaXR5AgRDnYD3MAkGBSsOAwIaBQAwDQYJKoZIhvcNAQEBBQAEgYB+"
               + "lH2cwLqc91mP8prvgSV+RRzk13dJdZvdoVjgQoFrPhBiZCNIEoHvIhMMA/sM"
               + "X6euSRZk7EjD24FasCEGYyd0mJVLEy6TSPmuW+wWz/28w3a6IWXBGrbb/ild"
               + "/CJMkPgLPGgOVD1WDwiNKwfasiQSFtySf5DPn3jFevdLeMmEY6GCAjIwggEV"
               + "BgkqhkiG9w0BCQYxggEGMIIBAgIBATBgMFgxCzAJBgNVBAYTAklUMRowGAYD"
               + "VQQKExFJbi5UZS5TLkEuIFMucC5BLjEtMCsGA1UEAxMkSW4uVGUuUy5BLiAt"
               + "IENlcnRpZmljYXRpb24gQXV0aG9yaXR5AgRDnYD3MAkGBSsOAwIaBQAwDQYJ"
               + "KoZIhvcNAQEBBQAEgYBHlOULfT5GDigIvxP0qZOy8VbpntmzaPF55VV4buKV"
               + "35J+uHp98gXKp0LrHM69V5IRKuyuQzHHFBqsXxsRI9o6KoOfgliD9Xc+BeMg"
               + "dKzQhBhBYoFREq8hQM0nSbqDNHYAQyNHMzUA/ZQUO5dlFuH8Dw3iDYAhNtfd"
               + "PrlchKJthDCCARUGCSqGSIb3DQEJBjGCAQYwggECAgEBMGAwWDELMAkGA1UE"
               + "BhMCSVQxGjAYBgNVBAoTEUluLlRlLlMuQS4gUy5wLkEuMS0wKwYDVQQDEyRJ"
               + "bi5UZS5TLkEuIC0gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkCBEOdgPcwCQYF"
               + "Kw4DAhoFADANBgkqhkiG9w0BAQEFAASBgEeU5Qt9PkYOKAi/E/Spk7LxVume"
               + "2bNo8XnlVXhu4pXfkn64en3yBcqnQusczr1XkhEq7K5DMccUGqxfGxEj2joq"
               + "g5+CWIP1dz4F4yB0rNCEGEFigVESryFAzSdJuoM0dgBDI0czNQD9lBQ7l2UW"
               + "4fwPDeINgCE2190+uVyEom2E");

    byte[] noSignedAttrSample2 = Base64.decode(
          "MIIIlAYJKoZIhvcNAQcCoIIIhTCCCIECAQExCzAJBgUrDgMCGgUAMAsGCSqG"
        + "SIb3DQEHAaCCB3UwggOtMIIDa6ADAgECAgEzMAsGByqGSM44BAMFADCBkDEL"
        + "MAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRIwEAYDVQQHEwlQYWxvIEFsdG8x"
        + "HTAbBgNVBAoTFFN1biBNaWNyb3N5c3RlbXMgSW5jMSMwIQYDVQQLExpKYXZh"
        + "IFNvZnR3YXJlIENvZGUgU2lnbmluZzEcMBoGA1UEAxMTSkNFIENvZGUgU2ln"
        + "bmluZyBDQTAeFw0wMTA1MjkxNjQ3MTFaFw0wNjA1MjgxNjQ3MTFaMG4xHTAb"
        + "BgNVBAoTFFN1biBNaWNyb3N5c3RlbXMgSW5jMSMwIQYDVQQLExpKYXZhIFNv"
        + "ZnR3YXJlIENvZGUgU2lnbmluZzEoMCYGA1UEAxMfVGhlIExlZ2lvbiBvZiB0"
        + "aGUgQm91bmN5IENhc3RsZTCCAbcwggEsBgcqhkjOOAQBMIIBHwKBgQD9f1OB"
        + "HXUSKVLfSpwu7OTn9hG3UjzvRADDHj+AtlEmaUVdQCJR+1k9jVj6v8X1ujD2"
        + "y5tVbNeBO4AdNG/yZmC3a5lQpaSfn+gEexAiwk+7qdf+t8Yb+DtX58aophUP"
        + "BPuD9tPFHsMCNVQTWhaRMvZ1864rYdcq7/IiAxmd0UgBxwIVAJdgUI8VIwvM"
        + "spK5gqLrhAvwWBz1AoGBAPfhoIXWmz3ey7yrXDa4V7l5lK+7+jrqgvlXTAs9"
        + "B4JnUVlXjrrUWU/mcQcQgYC0SRZxI+hMKBYTt88JMozIpuE8FnqLVHyNKOCj"
        + "rh4rs6Z1kW6jfwv6ITVi8ftiegEkO8yk8b6oUZCJqIPf4VrlnwaSi2ZegHtV"
        + "JWQBTDv+z0kqA4GEAAKBgBWry/FCAZ6miyy39+ftsa+h9lxoL+JtV0MJcUyQ"
        + "E4VAhpAwWb8vyjba9AwOylYQTktHX5sAkFvjBiU0LOYDbFSTVZSHMRJgfjxB"
        + "SHtICjOEvr1BJrrOrdzqdxcOUge5n7El124BCrv91x5Ol8UTwtiO9LrRXF/d"
        + "SyK+RT5n1klRo3YwdDARBglghkgBhvhCAQEEBAMCAIcwDgYDVR0PAQH/BAQD"
        + "AgHGMB0GA1UdDgQWBBQwMY4NRcco1AO3w1YsokfDLVseEjAPBgNVHRMBAf8E"
        + "BTADAQH/MB8GA1UdIwQYMBaAFGXi9IbJ007wkU5Yomr12HhamsGmMAsGByqG"
        + "SM44BAMFAAMvADAsAhRmigTu6QV0sTfEkVljgij/hhdVfAIUQZvMxAnIHc30"
        + "y/u0C1T5UEG9glUwggPAMIIDfqADAgECAgEQMAsGByqGSM44BAMFADCBkDEL"
        + "MAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRIwEAYDVQQHEwlQYWxvIEFsdG8x"
        + "HTAbBgNVBAoTFFN1biBNaWNyb3N5c3RlbXMgSW5jMSMwIQYDVQQLExpKYXZh"
        + "IFNvZnR3YXJlIENvZGUgU2lnbmluZzEcMBoGA1UEAxMTSkNFIENvZGUgU2ln"
        + "bmluZyBDQTAeFw0wMTA0MjUwNzAwMDBaFw0yMDA0MjUwNzAwMDBaMIGQMQsw"
        + "CQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExEjAQBgNVBAcTCVBhbG8gQWx0bzEd"
        + "MBsGA1UEChMUU3VuIE1pY3Jvc3lzdGVtcyBJbmMxIzAhBgNVBAsTGkphdmEg"
        + "U29mdHdhcmUgQ29kZSBTaWduaW5nMRwwGgYDVQQDExNKQ0UgQ29kZSBTaWdu"
        + "aW5nIENBMIIBtzCCASwGByqGSM44BAEwggEfAoGBAOuvNwQeylEeaV2w8o/2"
        + "tUkfxqSZBdcpv3S3avUZ2B7kG/gKAZqY/3Cr4kpWhmxTs/zhyIGMMfDE87CL"
        + "5nAG7PdpaNuDTHIpiSk2F1w7SgegIAIqRpdRHXDICBgLzgxum3b3BePn+9Nh"
        + "eeFgmiSNBpWDPFEg4TDPOFeCphpyDc7TAhUAhCVF4bq5qWKreehbMLiJaxv/"
        + "e3UCgYEAq8l0e3Tv7kK1alNNO92QBnJokQ8LpCl2LlU71a5NZVx+KjoEpmem"
        + "0HGqpde34sFyDaTRqh6SVEwgAAmisAlBGTMAssNcrkL4sYvKfJbYEH83RFuq"
        + "zHjI13J2N2tAmahVZvqoAx6LShECactMuCUGHKB30sms0j3pChD6dnC3+9wD"
        + "gYQAAoGALQmYXKy4nMeZfu4gGSo0kPnXq6uu3WtylQ1m+O8nj0Sy7ShEx/6v"
        + "sKYnbwBnRYJbB6hWVjvSKVFhXmk51y50dxLPGUr1LcjLcmHETm/6R0M/FLv6"
        + "vBhmKMLZZot6LS/CYJJLFP5YPiF/aGK+bEhJ+aBLXoWdGRD5FUVRG3HU9wuj"
        + "ZjBkMBEGCWCGSAGG+EIBAQQEAwIABzAPBgNVHRMBAf8EBTADAQH/MB8GA1Ud"
        + "IwQYMBaAFGXi9IbJ007wkU5Yomr12HhamsGmMB0GA1UdDgQWBBRl4vSGydNO"
        + "8JFOWKJq9dh4WprBpjALBgcqhkjOOAQDBQADLwAwLAIUKvfPPJdd+Xi2CNdB"
        + "tNkNRUzktJwCFEXNdWkOIfod1rMpsun3Mx0z/fxJMYHoMIHlAgEBMIGWMIGQ"
        + "MQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExEjAQBgNVBAcTCVBhbG8gQWx0"
        + "bzEdMBsGA1UEChMUU3VuIE1pY3Jvc3lzdGVtcyBJbmMxIzAhBgNVBAsTGkph"
        + "dmEgU29mdHdhcmUgQ29kZSBTaWduaW5nMRwwGgYDVQQDExNKQ0UgQ29kZSBT"
        + "aWduaW5nIENBAgEzMAkGBSsOAwIaBQAwCwYHKoZIzjgEAQUABC8wLQIVAIGV"
        + "khm+kbV4a/+EP45PHcq0hIViAhR4M9os6IrJnoEDS3Y3l7O6zrSosA==");

    private static final byte[] rawGost = Base64.decode(
        "MIIEBwYJKoZIhvcNAQcCoIID+DCCA/QCAQExDDAKBgYqhQMCAgkFADAfBgkq"
      + "hkiG9w0BBwGgEgQQU29tZSBEYXRhIEhFUkUhIaCCAuYwggLiMIICkaADAgEC"
      + "AgopoLG9AAIAArWeMAgGBiqFAwICAzBlMSAwHgYJKoZIhvcNAQkBFhFpbmZv"
      + "QGNyeXB0b3Byby5ydTELMAkGA1UEBhMCUlUxEzARBgNVBAoTCkNSWVBUTy1Q"
      + "Uk8xHzAdBgNVBAMTFlRlc3QgQ2VudGVyIENSWVBUTy1QUk8wHhcNMTIxMDE1"
      + "MTEwNDIzWhcNMTQxMDA0MDcwOTQxWjAhMRIwEAYDVQQDDAl0ZXN0IGdvc3Qx"
      + "CzAJBgNVBAYTAlJVMGMwHAYGKoUDAgITMBIGByqFAwICJAAGByqFAwICHgED"
      + "QwAEQPz/F99AG8wyMQz5uK3vJ3MdHk7ZyFzM4Ofnq8nAmDgI5/Nuzcu791/0"
      + "hRd+1i+fArRsiPMdQXOF0E7bEMHwWfWjggFjMIIBXzAOBgNVHQ8BAf8EBAMC"
      + "BPAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFO353ZD7sLCx6rVR"
      + "2o/IsSxuE1gAMB8GA1UdIwQYMBaAFG2PXgXZX6yRF5QelZoFMDg3ehAqMFUG"
      + "A1UdHwROMEwwSqBIoEaGRGh0dHA6Ly93d3cuY3J5cHRvcHJvLnJ1L0NlcnRF"
      + "bnJvbGwvVGVzdCUyMENlbnRlciUyMENSWVBUTy1QUk8oMikuY3JsMIGgBggr"
      + "BgEFBQcBAQSBkzCBkDAzBggrBgEFBQcwAYYnaHR0cDovL3d3dy5jcnlwdG9w"
      + "cm8ucnUvb2NzcG5jL29jc3Auc3JmMFkGCCsGAQUFBzAChk1odHRwOi8vd3d3"
      + "LmNyeXB0b3Byby5ydS9DZXJ0RW5yb2xsL3BraS1zaXRlX1Rlc3QlMjBDZW50"
      + "ZXIlMjBDUllQVE8tUFJPKDIpLmNydDAIBgYqhQMCAgMDQQBAR4mr69a62d3l"
      + "yK/UZ4Yz/Yi3jqURtbnJR2gugdzkG5pYHRwC41BbDaa1ItP+1gDp4s78+EiK"
      + "AJc17CHGZTz3MYHVMIHSAgEBMHMwZTEgMB4GCSqGSIb3DQEJARYRaW5mb0Bj"
      + "cnlwdG9wcm8ucnUxCzAJBgNVBAYTAlJVMRMwEQYDVQQKEwpDUllQVE8tUFJP"
      + "MR8wHQYDVQQDExZUZXN0IENlbnRlciBDUllQVE8tUFJPAgopoLG9AAIAArWe"
      + "MAoGBiqFAwICCQUAMAoGBiqFAwICEwUABED0Gs9zP9lSz/2/e3BUSpzCI3dx"
      + "39gfl/pFVkx4p5N/GW5o4gHIST9OhDSmdxwpMSK+39YSRD4R0Ue0faOqWEsj"
      + "AAAAAAAAAAAAAAAAAAAAAA==");

    private static final byte[] noAttrEncData = Base64.decode(
       "MIIFjwYJKoZIhvcNAQcCoIIFgDCCBXwCAQExDTALBglghkgBZQMEAgEwgdAG"
     + "CSqGSIb3DQEHAaCBwgSBv01JTUUtVmVyc2lvbjogMS4wCkNvbnRlbnQtVHlw"
     + "ZTogYXBwbGljYXRpb24vb2N0ZXQtc3RyZWFtCkNvbnRlbnQtVHJhbnNmZXIt"
     + "RW5jb2Rpbmc6IGJpbmFyeQpDb250ZW50LURpc3Bvc2l0aW9uOiBhdHRhY2ht"
     + "ZW50OyBmaWxlbmFtZT1kb2MuYmluCgpUaGlzIGlzIGEgdmVyeSBodWdlIHNl"
     + "Y3JldCwgbWFkZSB3aXRoIG9wZW5zc2wKCgoKoIIDNDCCAzAwggKZoAMCAQIC"
     + "AQEwDQYJKoZIhvcNAQEFBQAwgawxCzAJBgNVBAYTAkFUMRAwDgYDVQQIEwdB"
     + "dXN0cmlhMQ8wDQYDVQQHEwZWaWVubmExFTATBgNVBAoTDFRpYW5pIFNwaXJp"
     + "dDEUMBIGA1UECxMLSlVuaXQgdGVzdHMxGjAYBgNVBAMTEU1hc3NpbWlsaWFu"
     + "byBNYXNpMTEwLwYJKoZIhvcNAQkBFiJtYXNzaW1pbGlhbm8ubWFzaUB0aWFu"
     + "aS1zcGlyaXQuY29tMCAXDTEyMDEwMjA5MDAzNVoYDzIxOTEwNjA4MDkwMDM1"
     + "WjCBjzELMAkGA1UEBhMCQVQxEDAOBgNVBAgTB0F1c3RyaWExFTATBgNVBAoT"
     + "DFRpYW5pIFNwaXJpdDEUMBIGA1UECxMLSlVuaXQgVGVzdHMxDjAMBgNVBAMT"
     + "BWNlcnQxMTEwLwYJKoZIhvcNAQkBFiJtYXNzaW1pbGlhbm8ubWFzaUB0aWFu"
     + "aS1zcGlyaXQuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYHz8n"
     + "soeWpILn+5tK8XgJc3k5n0h0MOlRXLbZZVB7yuxKMBIZwl8kqqnehfqxX+hr"
     + "b2MXSCgKEstnVunJVPUGuNxnQ8Z0R9p1o/9gR0KTXmoJ+Epx5wdEofk4Phsi"
     + "MxjC8FVvt3sSnzal1/m0/9KntrPWksefumGm5XD3W43e5wIDAQABo3sweTAJ"
     + "BgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBD"
     + "ZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQU8mTZGl0EFv6aHo3bup144d6wYW8wHwYD"
     + "VR0jBBgwFoAUdHG2RdrchT0PFcUBiIiYcy5hAA4wDQYJKoZIhvcNAQEFBQAD"
     + "gYEATcc52eo73zEA4wmbyPv0lRrmyAxrHvZGIHiKpM8bP38WUB39lgmS8J0S"
     + "1ioj21bosiakGj/gXnxlk8M8O+mm4zzpYjy8gqGXiUt20+j3bm7MJYM8ePcq"
     + "dG/kReNuLUbRgIA6b0T4o+0WCELhrd9IlTk5IBKjHIjsP/GR1h0t//kxggFb"
     + "MIIBVwIBATCBsjCBrDELMAkGA1UEBhMCQVQxEDAOBgNVBAgTB0F1c3RyaWEx"
     + "DzANBgNVBAcTBlZpZW5uYTEVMBMGA1UEChMMVGlhbmkgU3Bpcml0MRQwEgYD"
     + "VQQLEwtKVW5pdCB0ZXN0czEaMBgGA1UEAxMRTWFzc2ltaWxpYW5vIE1hc2kx"
     + "MTAvBgkqhkiG9w0BCQEWIm1hc3NpbWlsaWFuby5tYXNpQHRpYW5pLXNwaXJp"
     + "dC5jb20CAQEwCwYJYIZIAWUDBAIBMA0GCSqGSIb3DQEBAQUABIGAEthqA7FK"
     + "V1i+MzzS4zz4DxT4lwUYkWfHaDtZADUyTD5lnP3Pf+t/ScpBEGkEtI7hDqOO"
     + "zE0WfkBshTx5B/uxDibc/jqjQpSYSz5cvBTgpocIalbqsErOkDYF1QP6UgaV"
     + "ZoVGwvGYIuIrFgWqgk08NsPHVVjYseTEhUDwkI1KSxU=");

    byte[] successResp = Base64.decode(
          "MIIFnAoBAKCCBZUwggWRBgkrBgEFBQcwAQEEggWCMIIFfjCCARehgZ8wgZwx"
        + "CzAJBgNVBAYTAklOMRcwFQYDVQQIEw5BbmRocmEgcHJhZGVzaDESMBAGA1UE"
        + "BxMJSHlkZXJhYmFkMQwwCgYDVQQKEwNUQ1MxDDAKBgNVBAsTA0FUQzEeMBwG"
        + "A1UEAxMVVENTLUNBIE9DU1AgUmVzcG9uZGVyMSQwIgYJKoZIhvcNAQkBFhVv"
        + "Y3NwQHRjcy1jYS50Y3MuY28uaW4YDzIwMDMwNDAyMTIzNDU4WjBiMGAwOjAJ"
        + "BgUrDgMCGgUABBRs07IuoCWNmcEl1oHwIak1BPnX8QQUtGyl/iL9WJ1VxjxF"
        + "j0hAwJ/s1AcCAQKhERgPMjAwMjA4MjkwNzA5MjZaGA8yMDAzMDQwMjEyMzQ1"
        + "OFowDQYJKoZIhvcNAQEFBQADgYEAfbN0TCRFKdhsmvOdUoiJ+qvygGBzDxD/"
        + "VWhXYA+16AphHLIWNABR3CgHB3zWtdy2j7DJmQ/R7qKj7dUhWLSqclAiPgFt"
        + "QQ1YvSJAYfEIdyHkxv4NP0LSogxrumANcDyC9yt/W9yHjD2ICPBIqCsZLuLk"
        + "OHYi5DlwWe9Zm9VFwCGgggPMMIIDyDCCA8QwggKsoAMCAQICAQYwDQYJKoZI"
        + "hvcNAQEFBQAwgZQxFDASBgNVBAMTC1RDUy1DQSBPQ1NQMSYwJAYJKoZIhvcN"
        + "AQkBFhd0Y3MtY2FAdGNzLWNhLnRjcy5jby5pbjEMMAoGA1UEChMDVENTMQww"
        + "CgYDVQQLEwNBVEMxEjAQBgNVBAcTCUh5ZGVyYWJhZDEXMBUGA1UECBMOQW5k"
        + "aHJhIHByYWRlc2gxCzAJBgNVBAYTAklOMB4XDTAyMDgyOTA3MTE0M1oXDTAz"
        + "MDgyOTA3MTE0M1owgZwxCzAJBgNVBAYTAklOMRcwFQYDVQQIEw5BbmRocmEg"
        + "cHJhZGVzaDESMBAGA1UEBxMJSHlkZXJhYmFkMQwwCgYDVQQKEwNUQ1MxDDAK"
        + "BgNVBAsTA0FUQzEeMBwGA1UEAxMVVENTLUNBIE9DU1AgUmVzcG9uZGVyMSQw"
        + "IgYJKoZIhvcNAQkBFhVvY3NwQHRjcy1jYS50Y3MuY28uaW4wgZ8wDQYJKoZI"
        + "hvcNAQEBBQADgY0AMIGJAoGBAM+XWW4caMRv46D7L6Bv8iwtKgmQu0SAybmF"
        + "RJiz12qXzdvTLt8C75OdgmUomxp0+gW/4XlTPUqOMQWv463aZRv9Ust4f8MH"
        + "EJh4ekP/NS9+d8vEO3P40ntQkmSMcFmtA9E1koUtQ3MSJlcs441JjbgUaVnm"
        + "jDmmniQnZY4bU3tVAgMBAAGjgZowgZcwDAYDVR0TAQH/BAIwADALBgNVHQ8E"
        + "BAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwkwNgYIKwYBBQUHAQEEKjAoMCYG"
        + "CCsGAQUFBzABhhpodHRwOi8vMTcyLjE5LjQwLjExMDo3NzAwLzAtBgNVHR8E"
        + "JjAkMCKgIKAehhxodHRwOi8vMTcyLjE5LjQwLjExMC9jcmwuY3JsMA0GCSqG"
        + "SIb3DQEBBQUAA4IBAQB6FovM3B4VDDZ15o12gnADZsIk9fTAczLlcrmXLNN4"
        + "PgmqgnwF0Ymj3bD5SavDOXxbA65AZJ7rBNAguLUo+xVkgxmoBH7R2sBxjTCc"
        + "r07NEadxM3HQkt0aX5XYEl8eRoifwqYAI9h0ziZfTNes8elNfb3DoPPjqq6V"
        + "mMg0f0iMS4W8LjNPorjRB+kIosa1deAGPhq0eJ8yr0/s2QR2/WFD5P4aXc8I"
        + "KWleklnIImS3zqiPrq6tl2Bm8DZj7vXlTOwmraSQxUwzCKwYob1yGvNOUQTq"
        + "pG6jxn7jgDawHU1+WjWQe4Q34/pWeGLysxTraMa+Ug9kPe+jy/qRX2xwvKBZ");

    private static byte[] mixedSignedData = Base64.decode(
              "d4IHBDCCBwAGCSqGSIb3DQEHAqCCBvEwggbtAgEDMQ8wDQYJYIZIAWUDBAID"
            + "BQAwgbcGCSqEEAGHbgEUAaCBqQSBpjCBowIBADANBglghkgBZQMEAgMFADCB"
            + "jjBFAgEBBEBIqiDnc0uJgjc1nZX/CyEaB3/j3fbR5Pjxs2/jSQhBy71N0Oh9"
            + "i5+ZbfvoeUjHeMz0Q4m71H6XuoCIlsQJOor0MEUCAQIEQHhPBcHkCK5QugOE"
            + "1GPQN/oRNpKlAp1l6Lr/LvSewiKbnWRKT2o3GmIZwuFflzblyiKZwxV+c8kj"
            + "i4oQmOEhQvSgggQKMIIEBjCCAm6gAwIBAgIBPTANBgkqhkiG9w0BAQsFADBw"
            + "MQswCQYDVQQGEwJQTDESMBAGA1UECgwJSUNBTyBDU0NBMQ4wDAYDVQQLDAVN"
            + "U1dpQTE9MDsGA1UEAww0U3lzdGVtIFd5ZGF3YW5pYSBQYXN6cG9ydMOzdyB6"
            + "IERhbnltaSBCaW9tZXRyeWN6bnltaTAeFw0wNzAzMjcwOTA4MDlaFw0xODAz"
            + "MjYyMzU5NTlaMFoxCzAJBgNVBAYTAlBMMRIwEAYDVQQKDAlJQ0FPIENTQ0Ex"
            + "ITAfBgNVBAsMGFBhc3Nwb3J0IERvY3VtZW50IFNpZ25lcjEUMBIGA1UEAwwL"
            + "Q1BEIE1TV0lBXzgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCP"
            + "IvVr66gZQUpLVLxwMedLZMkYqUFhR+qxrDjGYJgy0fVYvds8u6QF+WyLRvGQ"
            + "BJGjZ+hqXiDVtM2+ljmZm4C4wpDfZVE1e5w6lv8pKctnr1ZTorI0GsbdWIgi"
            + "oi21WIRdpY9Rwc6gxjVLVlhwqNGhp9NRS2RDnoqy5iCLWXQ7BzlvuALqK0E1"
            + "e/k96j3kCQ4SOES1fOreR6chFxOfhSrlo5ed6+z+YiM+rErtKAHZtYTUS6qk"
            + "uC5SMEMDchbPd6eoYJtN5g0IEyyREm9EdLSK38L2Ln29hnVPqlMJ3ewfIRG9"
            + "+LZ0mv3Bno9yle56tT9Vt2OBZs2MAOsFZQ66Q7+3AgMBAAGjQTA/MA4GA1Ud"
            + "DwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFEdS9KeSt+Ls"
            + "eDNSRSjve8QVpj2WMA0GCSqGSIb3DQEBCwUAA4IBgQA7NXSJWoYIuRJANJVR"
            + "+DhsvA/NOIE0c4W++xUZVY+2/abKXU7AJHdzI4pS6AOtYav2JxOnISITi3D6"
            + "s453T/Z0gwRY6p1kUjXtHiVj6iCIal8DCYB0voAZrKl1rZWyINiMKjugNGyy"
            + "vD6RHMuoKer07uKkgmusV23FIZaCQTPsP6sb2N5QDmfIp5lywJ+rMpJKXKoY"
            + "Dtu7Aouhveg7DgOpUvIKFdc4eY1MYAzPTD8w2vTGTDuNjaL5cZD2HHvYl9i+"
            + "vhD99nQWTbKStVI6Q0C2Dw3oFONKkH5O7L5bD38C6x9EBW5nGOWrSs+yP9Q1"
            + "FNEE49snnayvctrRga2qRBK9av8c406GyFOGfnJcl82cl9KWkLGf8aIfnSzq"
            + "FnhkDHKd9KocRX+dRFdBB5uxC0zm/XtIqB1TbTx3J88O5Ool55zFw0ECz/NX"
            + "ecpKwk42uKOEOUcN4Etx09OuSn2+WU2ngW/CHc/T5kS3U61U5vsoTVJT3uTS"
            + "1uRRYzcMcDc8+kwxggINMIICCQIBATB1MHAxCzAJBgNVBAYTAlBMMRIwEAYD"
            + "VQQKDAlJQ0FPIENTQ0ExDjAMBgNVBAsMBU1TV2lBMT0wOwYDVQQDDDRTeXN0"
            + "ZW0gV3lkYXdhbmlhIFBhc3pwb3J0w7N3IHogRGFueW1pIEJpb21ldHJ5Y3pu"
            + "eW1pAgE9MA0GCWCGSAFlAwQCAwUAoGswGAYJKoZIhvcNAQkDMQsGCSqEEAGH"
            + "bgEUATBPBgkqhkiG9w0BCQQxQgRAc6WCN4gqBWPSabO9SgkLfD2hTZeYU+cQ"
            + "vbMeZW/em0v4/r0ggaustPjLW1Qmx8QWnfMHgEuojCVpyPLOYEBpZzANBgkq"
            + "hkiG9w0BAQUFAASCAQAQBbSJOZFDx7uU2sQE1zkB5Vvds329kO+NY7ueWnGN"
            + "a5GaIs2ri1g1xZSDsz+QWRoT4sIIV5CmiWx6lPHxWv3be1xtfVux9KqRZgEy"
            + "xPQdANyDHaqqJr01ROQuKUJfqVSqiGe4/Udd0nFcBT9DyQWLn3HinOriEZga"
            + "HxxN0ZjpoIEiPa+NIth1W+W3Z7yt4JUM/zX0iyhza/bPHbPOLrsXZAhGy/qn"
            + "/JNmKBiVxuxZYYHI20CZHrgjb+ARczWuOJuBVEGEgbW/t7hMVX8X+MPAzZek"
            + "Ndi9ZfkurEeYdDpGluYBH910/P95ibG8nrJyTaoxhmOJhJ/o/SO54m8oDlI0");
                                                     List crlList = new ArrayList();
    private static final Set noParams = new HashSet();

    static
    {
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA1);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA224);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA256);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA384);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA512);
        noParams.add(X9ObjectIdentifiers.id_dsa_with_sha1);
        noParams.add(NISTObjectIdentifiers.dsa_with_sha224);
        noParams.add(NISTObjectIdentifiers.dsa_with_sha256);
        noParams.add(NISTObjectIdentifiers.dsa_with_sha384);
        noParams.add(NISTObjectIdentifiers.dsa_with_sha512);
        noParams.add(NISTObjectIdentifiers.id_dsa_with_sha3_224);
        noParams.add(NISTObjectIdentifiers.id_dsa_with_sha3_256);
        noParams.add(NISTObjectIdentifiers.id_dsa_with_sha3_384);
        noParams.add(NISTObjectIdentifiers.id_dsa_with_sha3_512);
        noParams.add(NISTObjectIdentifiers.id_ecdsa_with_sha3_224);
        noParams.add(NISTObjectIdentifiers.id_ecdsa_with_sha3_256);
        noParams.add(NISTObjectIdentifiers.id_ecdsa_with_sha3_384);
        noParams.add(NISTObjectIdentifiers.id_ecdsa_with_sha3_512);
        noParams.add(EdECObjectIdentifiers.id_Ed25519);
        noParams.add(EdECObjectIdentifiers.id_Ed448);
    }
    
    public NewSignedDataTest(String name)
    {
        super(name);
    }

    public static void main(String args[])
        throws Exception
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        init();

        junit.textui.TestRunner.run(NewSignedDataTest.class);
    }

    public static Test suite() 
        throws Exception
    {
        init();
        
        return new CMSTestSetup(new TestSuite(NewSignedDataTest.class));
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

            if (Security.getProvider(BC) == null)
            {
                Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            }

            _origDN   = "O=Bouncy Castle, C=AU";
            _origKP   = CMSTestUtil.makeKeyPair();  
            _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _origKP, _origDN);

            _signDN   = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            _signKP   = CMSTestUtil.makeKeyPair();
            _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _origKP, _origDN);

            _signGostKP   = CMSTestUtil.makeGostKeyPair();
            _signGostCert = CMSTestUtil.makeCertificate(_signGostKP, _signDN, _origKP, _origDN);
    
            _signDsaKP   = CMSTestUtil.makeDsaKeyPair();
            _signDsaCert = CMSTestUtil.makeCertificate(_signDsaKP, _signDN, _origKP, _origDN);

            _signEcDsaKP   = CMSTestUtil.makeEcDsaKeyPair();
            _signEcDsaCert = CMSTestUtil.makeCertificate(_signEcDsaKP, _signDN, _origKP, _origDN);

            _signEcGostKP = CMSTestUtil.makeEcGostKeyPair();
            _signEcGostCert = CMSTestUtil.makeCertificate(_signEcGostKP, _signDN, _origKP, _origDN);

            _signEd25519KP   = CMSTestUtil.makeEd25519KeyPair();
            _signEd25519Cert = CMSTestUtil.makeCertificate(_signEd25519KP, _signDN, _origKP, _origDN);

            _signEd448KP   = CMSTestUtil.makeEd448KeyPair();
            _signEd448Cert = CMSTestUtil.makeCertificate(_signEd448KP, _signDN, _origKP, _origDN);

            _reciDN   = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP   = CMSTestUtil.makeKeyPair();
            _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);

            _signCrl  = CMSTestUtil.makeCrl(_signKP);
        }
    }

    private void verifyRSASignatures(CMSSignedData s, byte[] contentDigest)
        throws Exception
    {
        Store                   certStore = s.getCertificates();
        SignerInformationStore  signers = s.getSignerInfos();

        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certStore.getMatches(signer.getSID());

            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new BcRSASignerInfoVerifierBuilder(new DefaultCMSSignatureAlgorithmNameGenerator(), new DefaultSignatureAlgorithmIdentifierFinder(), new DefaultDigestAlgorithmIdentifierFinder(), new BcDigestCalculatorProvider()).build(cert)));

            if (contentDigest != null)
            {
                assertTrue(MessageDigest.isEqual(contentDigest, signer.getContentDigest()));
            }
        }
    }

    private void verifySignatures(CMSSignedData s, byte[] contentDigest) 
        throws Exception
    {
        Store                   certStore = s.getCertificates();
        Store                   crlStore = s.getCRLs();
        SignerInformationStore  signers = s.getSignerInfos();
        
        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certStore.getMatches(signer.getSID());
    
            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));
            
            if (contentDigest != null)
            {
                assertTrue(MessageDigest.isEqual(contentDigest, signer.getContentDigest()));
            }
        }

        Collection certColl = certStore.getMatches(null);
        Collection crlColl = crlStore.getMatches(null);

        assertEquals(certColl.size(), s.getCertificates().getMatches(null).size());
        assertEquals(crlColl.size(), s.getCRLs().getMatches(null).size());
    }

    private void verifySignatures(CMSSignedData s) 
        throws Exception
    {
        verifySignatures(s, null);
    }

    public void testDetachedVerification()
        throws Exception
    {
        byte[]              data = "Hello World!".getBytes();
        List                certList = new ArrayList();
        CMSTypedData        msg = new CMSProcessableByteArray(data);

        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        DigestCalculatorProvider digProvider = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        JcaSignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(digProvider);
        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());
        ContentSigner md5Signer = new JcaContentSignerBuilder("MD5withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(signerInfoGeneratorBuilder.build(sha1Signer, _origCert));
        gen.addSignerInfoGenerator(signerInfoGeneratorBuilder.build(md5Signer, _origCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg);

        MessageDigest sha1 = MessageDigest.getInstance("SHA1", BC);
        MessageDigest md5 = MessageDigest.getInstance("MD5", BC);
        Map hashes = new HashMap();
        byte[] sha1Hash = sha1.digest(data);
        byte[] md5Hash = md5.digest(data);

        hashes.put(CMSAlgorithm.SHA1, sha1Hash);
        hashes.put(CMSAlgorithm.MD5, md5Hash);

        s = new CMSSignedData(hashes, s.getEncoded());

        verifySignatures(s, null);
    }

    public void testEmptyContent()
        throws Exception
    {
        
        try
        {
            new CMSSignedData(new byte[0]);
        }
        catch (CMSException e)
        {
            assertEquals("No content found.", e.getMessage());
        }

        try
        {
            new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().build(), new byte[0]);
        }
        catch (CMSException e)
        {
            assertEquals("No content found.", e.getMessage());
        }
    }

    public void testSHA1AndMD5WithRSAEncapsulatedRepeated()
        throws Exception
    {
        List              certList = new ArrayList();
        CMSTypedData      msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digCalcProv).build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate()), _origCert));

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digCalcProv).build(new JcaContentSignerBuilder("MD5withRSA").setProvider(BC).build(_origKP.getPrivate()), _origCert));
        
        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, true);

        ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
        ASN1InputStream      aIn = new ASN1InputStream(bIn);
        
        s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

        certs = s.getCertificates();

        SignerInformationStore  signers = s.getSignerInfos();
        
        assertEquals(2, signers.size());
        
        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();
        SignerId                sid = null;

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certs.getMatches(signer.getSID());

            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            sid = signer.getSID();
            
            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));

            //
            // check content digest
            //

            byte[] contentDigest = (byte[])gen.getGeneratedDigests().get(signer.getDigestAlgOID());

            AttributeTable table = signer.getSignedAttributes();
            Attribute hash = table.get(CMSAttributes.messageDigest);

            assertTrue(MessageDigest.isEqual(contentDigest, ((ASN1OctetString)hash.getAttrValues().getObjectAt(0)).getOctets()));
        }
        
        c = signers.getSigners(sid);
        
        assertEquals(2, c.size());


        //
        // try using existing signer
        //
        
        gen = new CMSSignedDataGenerator();
           
        gen.addSigners(s.getSignerInfos());
        
        gen.addCertificates(s.getCertificates());
           
        s = gen.generate(msg, true);

        bIn = new ByteArrayInputStream(s.getEncoded());
        aIn = new ASN1InputStream(bIn);

        s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

        certs = s.getCertificates();

        signers = s.getSignerInfos();
        c = signers.getSigners();
        it = c.iterator();

        assertEquals(2, c.size());
        
        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certs.getMatches(signer.getSID());

            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));
        }
        
        checkSignerStoreReplacement(s, signers);
    }
    
    public void testSHA1WithRSANoAttributes()
        throws Exception
    {
        List              certList = new ArrayList();
        CMSTypedData      msg = new CMSProcessableByteArray("Hello world!".getBytes());
    
        certList.add(_origCert);
        certList.add(_signCert);
    
        Store           certs = new JcaCertStore(certList);
    
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        builder.setDirectSignature(true);

        gen.addSignerInfoGenerator(builder.build(sha1Signer, _origCert));
    
        gen.addCertificates(certs);
    
        CMSSignedData s = gen.generate(msg, false);
    
        //
        // compute expected content digest
        //
        MessageDigest md = MessageDigest.getInstance("SHA1", BC);
        
        verifySignatures(s, md.digest("Hello world!".getBytes()));
    }

    public void testSHA1WithRSANoAttributesSimple()
        throws Exception
    {
        List              certList = new ArrayList();
        CMSTypedData      msg = new CMSProcessableByteArray("Hello world!".getBytes());

        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        
        JcaSimpleSignerInfoGeneratorBuilder builder = new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BC).setDirectSignature(true);

        gen.addSignerInfoGenerator(builder.build("SHA1withRSA", _origKP.getPrivate(), _origCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, false);

        //
        // compute expected content digest
        //
        MessageDigest md = MessageDigest.getInstance("SHA1", BC);

        verifySignatures(s, md.digest("Hello world!".getBytes()));
    }

    public void testSHA1WithRSAAndOtherRevocation()
        throws Exception
    {
        List              certList = new ArrayList();
        CMSTypedData      msg = new CMSProcessableByteArray("Hello world!".getBytes());

        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha1Signer, _origCert));

        gen.addCertificates(certs);

        List otherInfo = new ArrayList();
        OCSPResp response = new OCSPResp(successResp);

        otherInfo.add(response.toASN1Structure());

        gen.addOtherRevocationInfo(CMSObjectIdentifiers.id_ri_ocsp_response, new CollectionStore(otherInfo));

        CMSSignedData s;

        s = gen.generate(msg, false);

        //
        // check version
        //
        assertEquals(5, s.getVersion());

        //
        // compute expected content digest
        //
        MessageDigest md = MessageDigest.getInstance("SHA1", BC);

        verifySignatures(s, md.digest("Hello world!".getBytes()));

        Store dataOtherInfo = s.getOtherRevocationInfo(CMSObjectIdentifiers.id_ri_ocsp_response);

        assertEquals(1, dataOtherInfo.getMatches(null).size());

        OCSPResp dataResponse = new OCSPResp(OCSPResponse.getInstance(dataOtherInfo.getMatches(null).iterator().next()));

        assertEquals(response, dataResponse);
    }

    public void testSHA1WithRSAAndAttributeTableSimple()
        throws Exception
    {
        MessageDigest       md = MessageDigest.getInstance("SHA1", BC);
        List                certList = new ArrayList();
        CMSTypedData        msg = new CMSProcessableByteArray("Hello world!".getBytes());

        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        Attribute attr = new Attribute(CMSAttributes.messageDigest,
                                       new DERSet(
                                            new DEROctetString(
                                                md.digest("Hello world!".getBytes()))));

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(attr);

        JcaSimpleSignerInfoGeneratorBuilder builder = new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BC).setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(v)));

        gen.addSignerInfoGenerator(builder.build("SHA1withRSA", _origKP.getPrivate(), _origCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(new CMSAbsentContent(), false);

        //
        // the signature is detached, so need to add msg before passing on
        //
        s = new CMSSignedData(msg, s.getEncoded());
        //
        // compute expected content digest
        //

        assertTrue(s.isDetachedSignature());
        assertFalse(s.isCertificateManagementMessage());

        verifySignatures(s, md.digest("Hello world!".getBytes()));
        verifyRSASignatures(s, md.digest("Hello world!".getBytes()));
    }

    public void testCMSAlgorithmProtection()
        throws Exception
    {
        List                certList = new ArrayList();
        CMSTypedData        msg = new CMSProcessableByteArray("Hello world!".getBytes());

        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        JcaSimpleSignerInfoGeneratorBuilder builder = new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BC);

        gen.addSignerInfoGenerator(builder.build("SHA1withRSA", _origKP.getPrivate(), _origCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, true);

        s = new CMSSignedData(s.getEncoded());

        assertFalse(s.isDetachedSignature());
        assertFalse(s.isCertificateManagementMessage());

        verifySignatures(s, true, null);

        // tamper, change signerInfo message digest
        ContentInfo cI = s.toASN1Structure();
        SignedData  sd = SignedData.getInstance(cI.getContent());
        SignerInfo  sI = SignerInfo.getInstance(sd.getSignerInfos().getObjectAt(0));

        SignerInfo sInew = new SignerInfo(sI.getSID(), new AlgorithmIdentifier(TeleTrusTObjectIdentifiers.ripemd128, DERNull.INSTANCE), sI.getAuthenticatedAttributes(), sI.getDigestEncryptionAlgorithm(), sI.getEncryptedDigest(), sI.getUnauthenticatedAttributes());

        verifySignatures(getCorruptedSignedData(sd, sInew), false, "CMS Algorithm Identifier Protection check failed for digestAlgorithm");

        sInew = new SignerInfo(sI.getSID(), sI.getDigestAlgorithm(), sI.getAuthenticatedAttributes(), new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS), sI.getEncryptedDigest(), sI.getUnauthenticatedAttributes());

        verifySignatures(getCorruptedSignedData(sd, sInew), false, "CMS Algorithm Identifier Protection check failed for signatureAlgorithm");

        // check equivalence
        AlgorithmIdentifier newAlgId = new AlgorithmIdentifier(sI.getDigestAlgorithm().getAlgorithm());
        assertFalse(newAlgId.equals(sI.getDigestAlgorithm()));

        sInew = new SignerInfo(sI.getSID(), newAlgId, sI.getAuthenticatedAttributes(), sI.getDigestEncryptionAlgorithm(), sI.getEncryptedDigest(), sI.getUnauthenticatedAttributes());

        verifySignatures(getCorruptedSignedData(sd, sInew), true, null);

        newAlgId = new AlgorithmIdentifier(sI.getDigestEncryptionAlgorithm().getAlgorithm());
        assertFalse(newAlgId.equals(sI.getDigestEncryptionAlgorithm()));

        sInew = new SignerInfo(sI.getSID(), sI.getDigestAlgorithm(), sI.getAuthenticatedAttributes(), newAlgId, sI.getEncryptedDigest(), sI.getUnauthenticatedAttributes());

        verifySignatures(getCorruptedSignedData(sd, sInew), true, null);
    }

    private CMSSignedData getCorruptedSignedData(SignedData sd, SignerInfo sI)
        throws CMSException
    {
        return new CMSSignedData(new ContentInfo(CMSObjectIdentifiers.signedData, new SignedData(sd.getDigestAlgorithms(), sd.getEncapContentInfo(), sd.getCertificates(), sd.getCRLs(), new DERSet(sI))));
    }

    private void verifySignatures(CMSSignedData s, boolean shouldPass, String message)
        throws Exception
    {
        Store                   certStore = s.getCertificates();
        SignerInformationStore  signers = s.getSignerInfos();

        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certStore.getMatches(signer.getSID());

            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            if (shouldPass)
            {
                assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));
            }
            else
            {
                try
                {
                    assertEquals(false, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));
                    if (message != null)
                    {
                        fail("No exception thrown");
                    }
                }
                catch (CMSException e)
                {
                    assertEquals(message, e.getMessage());
                }
            }
        }
    }

    public void testSHA1WithRSAAndAttributeTable()
        throws Exception
    {
        MessageDigest       md = MessageDigest.getInstance("SHA1", BC);
        List                certList = new ArrayList();
        CMSTypedData        msg = new CMSProcessableByteArray("Hello world!".getBytes());

        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        Attribute attr = new Attribute(CMSAttributes.messageDigest,
                                       new DERSet(
                                            new DEROctetString(
                                                md.digest("Hello world!".getBytes()))));

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(attr);

        JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        builder.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(v)));
        
        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(builder.build(sha1Signer, _origCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(new CMSAbsentContent(), false);

        //
        // the signature is detached, so need to add msg before passing on
        //
        s = new CMSSignedData(msg, s.getEncoded());
        //
        // compute expected content digest
        //

        verifySignatures(s, md.digest("Hello world!".getBytes()));
        verifyRSASignatures(s, md.digest("Hello world!".getBytes()));
    }

    public void testRemoveAttribute()
        throws Exception
    {
        MessageDigest       md = MessageDigest.getInstance("SHA1", BC);
        List                certList = new ArrayList();
        CMSTypedData        msg = new CMSProcessableByteArray("Hello world!".getBytes());

        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        builder.setSignedAttributeGenerator(new CMSAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
                throws CMSAttributeTableGenerationException
            {
                AttributeTable table = new DefaultSignedAttributeTableGenerator().getAttributes(parameters);

                return table.remove(CMSAttributes.cmsAlgorithmProtect);
            }
        });

        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(builder.build(sha1Signer, _origCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, false);

        //
        // the signature is detached, so need to add msg before passing on
        //
        s = new CMSSignedData(msg, s.getEncoded());

        // for JDK1.4 build
        Assert.assertNull(((SignerInformation)s.getSignerInfos().iterator().next()).getSignedAttributes().get(CMSAttributes.cmsAlgorithmProtect));

        //
        // compute expected content digest
        //
        verifySignatures(s, md.digest("Hello world!".getBytes()));
        verifyRSASignatures(s, md.digest("Hello world!".getBytes()));
    }

    public void testSignerInformationExtension()
        throws Exception
    {
        List                certList = new ArrayList();
        CMSTypedData        msg = new CMSProcessableByteArray("Hello world!".getBytes());

        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(builder.build(sha1Signer, _origCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, true);

        //
        // the signature is detached, so need to add msg before passing on
        //
        s = new CMSSignedData(msg, s.getEncoded());

        Store                   certStore = s.getCertificates();
        SignerInformationStore  signers = s.getSignerInfos();

        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certStore.getMatches(signer.getSID());

            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert);

            assertEquals(false, new MyWrongSignerInformation(signer).verify(verifier));

            MyRightSignerInformation rSigner = new MyRightSignerInformation(signer);

            assertTrue(rSigner.verify(verifier));
            assertTrue(rSigner.isUsed());
        }
    }

    private class MyWrongSignerInformation
        extends SignerInformation
    {
        protected MyWrongSignerInformation(SignerInformation baseInfo)
        {
            super(baseInfo);
        }

        public byte[] getEncodedSignedAttributes()
            throws IOException
        {
            return new byte[signedAttributeSet.getEncoded(ASN1Encoding.DL).length];
        }
    }

    private class MyRightSignerInformation
        extends SignerInformation
    {
        private boolean used;

        protected MyRightSignerInformation(SignerInformation baseInfo)
        {
            super(baseInfo);
        }

        boolean isUsed()
        {
            return used;
        }

        public byte[] getEncodedSignedAttributes()
            throws IOException
        {
            used = true;
            return signedAttributeSet.getEncoded(ASN1Encoding.DL);
        }
    }

    public void testRawSHA256MissingNull()
        throws Exception
    {
        final byte[] document = getInput("rawsha256nonull.p7m");

        final CMSSignedData s = new CMSSignedData(document);

        final Store certStore = s.getCertificates();
        final SignerInformation signerInformation = (SignerInformation)s.getSignerInfos().getSigners().iterator().next();

        Collection          certCollection = certStore.getMatches(signerInformation.getSID());

        Iterator        certIt = certCollection.iterator();
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate((X509CertificateHolder)certIt.next());

        final SignerInformationVerifier signerInformationVerifier =
            new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert.getPublicKey());

        if (!signerInformation.verify(signerInformationVerifier))
        {
            fail("raw sig failed");
        }
    }

    public void testLwSHA1WithRSAAndAttributeTable()
        throws Exception
    {
        MessageDigest       md = MessageDigest.getInstance("SHA1", BC);
        List                certList = new ArrayList();
        CMSTypedData        msg = new CMSProcessableByteArray("Hello world!".getBytes());

        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        Attribute attr = new Attribute(CMSAttributes.messageDigest,
                                       new DERSet(
                                            new DEROctetString(
                                                md.digest("Hello world!".getBytes()))));

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(attr);

        AsymmetricKeyParameter privKey = PrivateKeyFactory.createKey(_origKP.getPrivate().getEncoded());
        
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

        BcContentSignerBuilder contentSignerBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);

        gen.addSignerInfoGenerator(
            new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider())
                .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(v)))
                .build(contentSignerBuilder.build(privKey), new JcaX509CertificateHolder(_origCert)));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(new CMSAbsentContent(), false);

        //
        // the signature is detached, so need to add msg before passing on
        //
        s = new CMSSignedData(msg, s.getEncoded());
        //
        // compute expected content digest
        //

        verifySignatures(s, md.digest("Hello world!".getBytes()));
        verifyRSASignatures(s, md.digest("Hello world!".getBytes()));
    }

    public void testLwSHA3_256WithRSAAndAttributeTable()
        throws Exception
    {
        MessageDigest       md = MessageDigest.getInstance("SHA3-256", BC);
        List                certList = new ArrayList();
        CMSTypedData        msg = new CMSProcessableByteArray("Hello world!".getBytes());

        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        Attribute attr = new Attribute(CMSAttributes.messageDigest,
                                       new DERSet(
                                            new DEROctetString(
                                                md.digest("Hello world!".getBytes()))));

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(attr);

        AsymmetricKeyParameter privKey = PrivateKeyFactory.createKey(_origKP.getPrivate().getEncoded());

        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA3-256withRSA");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

        BcContentSignerBuilder contentSignerBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);

        gen.addSignerInfoGenerator(
            new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider())
                .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(v)))
                .build(contentSignerBuilder.build(privKey), new JcaX509CertificateHolder(_origCert)));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(new CMSAbsentContent(), false);

        //
        // the signature is detached, so need to add msg before passing on
        //
        s = new CMSSignedData(msg, s.getEncoded());
        //
        // compute expected content digest
        //

        verifySignatures(s, md.digest("Hello world!".getBytes()));
        verifyRSASignatures(s, md.digest("Hello world!".getBytes()));
    }

    public void testSHA1WithRSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signKP, _signCert, "SHA1withRSA");
    }

    public void testSHA1WithRSAEncapsulatedSubjectKeyID()
        throws Exception
    {
        subjectKeyIDTest(_signKP, _signCert, "SHA1withRSA");
    }

    public void testSHA1WithRSAPSS()
        throws Exception
    {
        rsaPSSTest("SHA1withRSAandMGF1");
    }

    public void testSHA224WithRSAPSS()
        throws Exception
    {
        rsaPSSTest("SHA224withRSAandMGF1");
    }

    public void testSHA256WithRSAPSS()
        throws Exception
    {
        rsaPSSTest("SHA256withRSAandMGF1");
    }

    public void testSHA384WithRSAPSS()
        throws Exception
    {
        rsaPSSTest("SHA384withRSAandMGF1");
    }

    public void testSHA3_224WithRSAPSS()
        throws Exception
    {
        rsaPSSTest("SHA3-224withRSAandMGF1");
    }

    public void testSHA3_256WithRSAPSS()
        throws Exception
    {
        rsaPSSTest("SHA3-256withRSAandMGF1");
    }

    public void testSHA3_384WithRSAPSS()
        throws Exception
    {
        rsaPSSTest("SHA3-384withRSAandMGF1");
    }

    public void testEd25519()
        throws Exception
    {
        encapsulatedTest(_signEd25519KP, _signEd25519Cert, "Ed25519", EdECObjectIdentifiers.id_Ed25519, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512));
    }

    public void testEd448()
        throws Exception
    {
        encapsulatedTest(_signEd448KP, _signEd448Cert, "Ed448", EdECObjectIdentifiers.id_Ed448, new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256_len, new ASN1Integer(512)));
    }

    public void testDetachedEd25519()
        throws Exception
    {
        detachedTest(_signEd25519KP, _signEd25519Cert, "Ed25519", EdECObjectIdentifiers.id_Ed25519, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512));
    }

    public void testEdDetached448()
        throws Exception
    {
        detachedTest(_signEd448KP, _signEd448Cert, "Ed448", EdECObjectIdentifiers.id_Ed448, new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256_len, new ASN1Integer(512)));
    }

    public void testEd25519WithNoAttr()
        throws Exception
    {
        directSignatureTest(_signEd25519KP, _signEd25519Cert, "Ed25519", new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512));
    }

    public void testEd448WithNoAttr()
        throws Exception
    {
        directSignatureTest(_signEd448KP, _signEd448Cert, "Ed448", new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256));
    }

    public void testSHA3_224WithDSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signDsaKP, _signDsaCert, "SHA3-224withDSA", NISTObjectIdentifiers.id_dsa_with_sha3_224);
    }

    public void testSHA3_256WithDSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signDsaKP, _signDsaCert, "SHA3-256withDSA", NISTObjectIdentifiers.id_dsa_with_sha3_256);
    }

    public void testSHA3_384WithDSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signDsaKP, _signDsaCert, "SHA3-384withDSA", NISTObjectIdentifiers.id_dsa_with_sha3_384);
    }

    public void testSHA3_512WithDSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signDsaKP, _signDsaCert, "SHA3-512withDSA", NISTObjectIdentifiers.id_dsa_with_sha3_512);
    }

    // RFC 5754 update
    public void testSHA224WithRSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signKP, _signCert, "SHA224withRSA", PKCSObjectIdentifiers.sha224WithRSAEncryption);
    }

    // RFC 5754 update
    public void testSHA256WithRSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signKP, _signCert, "SHA256withRSA", PKCSObjectIdentifiers.sha256WithRSAEncryption);
    }

    public void testSHA3_224WithRSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signKP, _signCert, "SHA3-224withRSA", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224);
    }

    public void testSHA3_256WithRSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signKP, _signCert, "SHA3-256withRSA", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256);
    }

    public void testSHA3_384WithRSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signKP, _signCert, "SHA3-384withRSA", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384);
    }

    public void testSHA3_512WithRSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signKP, _signCert, "SHA3-512withRSA", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512);
    }

    public void testRIPEMD128WithRSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signKP, _signCert, "RIPEMD128withRSA");
    }

    public void testRIPEMD160WithRSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signKP, _signCert, "RIPEMD160withRSA");
    }

    public void testRIPEMD256WithRSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signKP, _signCert, "RIPEMD256withRSA");
    }

    public void testECDSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signEcDsaKP, _signEcDsaCert, "SHA1withECDSA");
    }

    public void testECDSAEncapsulatedSubjectKeyID()
        throws Exception
    {
        subjectKeyIDTest(_signEcDsaKP, _signEcDsaCert, "SHA1withECDSA");
    }

    public void testECDSASHA224Encapsulated()
        throws Exception
    {
        encapsulatedTest(_signEcDsaKP, _signEcDsaCert, "SHA224withECDSA");
    }

    public void testECDSASHA256Encapsulated()
        throws Exception
    {
        encapsulatedTest(_signEcDsaKP, _signEcDsaCert, "SHA256withECDSA");
    }

    public void testECDSASHA384Encapsulated()
        throws Exception
    {
        encapsulatedTest(_signEcDsaKP, _signEcDsaCert, "SHA384withECDSA");
    }

    public void testECDSASHA512Encapsulated()
        throws Exception
    {
        encapsulatedTest(_signEcDsaKP, _signEcDsaCert, "SHA512withECDSA");
    }

    public void testECDSASHA3_224Encapsulated()
        throws Exception
    {
        encapsulatedTest(_signEcDsaKP, _signEcDsaCert, "SHA3-224withECDSA");
    }

    public void testECDSASHA3_256Encapsulated()
        throws Exception
    {
        encapsulatedTest(_signEcDsaKP, _signEcDsaCert, "SHA3-256withECDSA");
    }

    public void testECDSASHA3_384Encapsulated()
        throws Exception
    {
        encapsulatedTest(_signEcDsaKP, _signEcDsaCert, "SHA3-384withECDSA");
    }

    public void testECDSASHA3_512Encapsulated()
        throws Exception
    {
        encapsulatedTest(_signEcDsaKP, _signEcDsaCert, "SHA3-512withECDSA");
    }

    public void testECDSASHA512EncapsulatedWithKeyFactoryAsEC()
        throws Exception
    {
        X509EncodedKeySpec  pubSpec = new X509EncodedKeySpec(_signEcDsaKP.getPublic().getEncoded());
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(_signEcDsaKP.getPrivate().getEncoded());
        KeyFactory          keyFact = KeyFactory.getInstance("EC", BC);
        KeyPair             kp = new KeyPair(keyFact.generatePublic(pubSpec), keyFact.generatePrivate(privSpec));
        
        encapsulatedTest(kp, _signEcDsaCert, "SHA512withECDSA");
    }

    public void testDSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signDsaKP, _signDsaCert, "SHA1withDSA");
    }

    public void testDSAEncapsulatedSubjectKeyID()
        throws Exception
    {
        subjectKeyIDTest(_signDsaKP, _signDsaCert, "SHA1withDSA");
    }
        
    public void testGOST3411WithGOST3410Encapsulated()
        throws Exception
    {
        encapsulatedTest(_signGostKP, _signGostCert, "GOST3411withGOST3410");
    }

    public void testGOST3411WithECGOST3410Encapsulated()
        throws Exception
    {
        encapsulatedTest(_signEcGostKP, _signEcGostCert, "GOST3411withECGOST3410");
    }

    public void testGostNoAttributesEncapsulated()
        throws Exception
    {
        CMSSignedData data = new CMSSignedData(rawGost);

        Store                   certStore = data.getCertificates();
        SignerInformationStore  signers = data.getSignerInfos();

        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certStore.getMatches(signer.getSID());

            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert)));
        }
    }

    public void testSHA1WithRSACounterSignature()
        throws Exception
    {
        List                certList = new ArrayList();
        List                crlList = new ArrayList();
        CMSTypedData        msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(_signCert);
        certList.add(_origCert);

        crlList.add(_signCrl);

        Store           certStore = new JcaCertStore(certList);
        Store           crlStore = new JcaCRLStore(crlList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_signKP.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha1Signer, _signCert));

        gen.addCertificates(certStore);
        gen.addCRLs(crlStore);
        
        CMSSignedData s = gen.generate(msg, true);
        SignerInformation origSigner = (SignerInformation)s.getSignerInfos().getSigners().toArray()[0];
        SignerInformationStore counterSigners1 = gen.generateCounterSigners(origSigner);
        SignerInformationStore counterSigners2 = gen.generateCounterSigners(origSigner);

        SignerInformation signer1 = SignerInformation.addCounterSigners(origSigner, counterSigners1);
        SignerInformation signer2 = SignerInformation.addCounterSigners(signer1, counterSigners2);

        SignerInformationStore cs = signer2.getCounterSignatures();
        Collection csSigners = cs.getSigners();
        assertEquals(2, csSigners.size());

        Iterator it = csSigners.iterator();
        while (it.hasNext())
        {
            SignerInformation   cSigner = (SignerInformation)it.next();
            Collection          certCollection = certStore.getMatches(cSigner.getSID());

            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertTrue(cSigner.isCounterSignature());
            assertNull(cSigner.getSignedAttributes().get(PKCSObjectIdentifiers.pkcs_9_at_contentType));
            assertEquals(true, cSigner.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));
        }
    }

    public void testSHA1WithRSACounterSignatureAndVerifierProvider()
        throws Exception
    {
        List                certList = new ArrayList();
        List                crlList = new ArrayList();
        CMSTypedData        msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(_signCert);
        certList.add(_origCert);

        crlList.add(_signCrl);

        Store           certStore = new JcaCertStore(certList);
        Store           crlStore = new JcaCRLStore(crlList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_signKP.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha1Signer, _signCert));

        gen.addCertificates(certStore);
        gen.addCRLs(crlStore);

        CMSSignedData s = gen.generate(msg, true);

        SignerInformationVerifierProvider vProv = new SignerInformationVerifierProvider()
        {
            public SignerInformationVerifier get(SignerId signerId)
                throws OperatorCreationException
            {
                return new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(_signCert);
            }
        };

        assertTrue(s.verifySignatures(vProv));

        SignerInformation origSigner = (SignerInformation)s.getSignerInfos().getSigners().toArray()[0];

        gen = new CMSSignedDataGenerator();

        sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha1Signer, _origCert));

        SignerInformationStore counterSigners = gen.generateCounterSigners(origSigner);

        final SignerInformation signer1 = SignerInformation.addCounterSigners(origSigner, counterSigners);

        List signers = new ArrayList();

        signers.add(signer1);

        s = CMSSignedData.replaceSigners(s, new SignerInformationStore(signers));

        assertTrue(s.verifySignatures(vProv, true));

        // provider can't handle counter sig
        assertFalse(s.verifySignatures(vProv, false));

        vProv = new SignerInformationVerifierProvider()
        {
            public SignerInformationVerifier get(SignerId signerId)
                throws OperatorCreationException
            {
                if (_signCert.getSerialNumber().equals(signerId.getSerialNumber()))
                {
                    return new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(_signCert);
                }
                else if (_origCert.getSerialNumber().equals(signerId.getSerialNumber()))
                {
                    return new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(_origCert);
                }
                else
                {
                    throw new IllegalStateException("no signerID matched");
                }
            }
        };

        // verify sig and counter sig.
        assertTrue(s.verifySignatures(vProv, false));
    }

    private void rsaPSSTest(String signatureAlgorithmName)
        throws Exception
    {
        List              certList = new ArrayList();
        CMSTypedData      msg = new CMSProcessableByteArray("Hello world!".getBytes());

        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithmName).setProvider(BC).build(_origKP.getPrivate());

        JcaSignerInfoGeneratorBuilder siBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        siBuilder.setDirectSignature(true);

        gen.addSignerInfoGenerator(siBuilder.build(contentSigner, _origCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, false);

        //
        // compute expected content digest
        //
        String digestName = signatureAlgorithmName.substring(0, signatureAlgorithmName.indexOf('w'));
        MessageDigest md = MessageDigest.getInstance(digestName, BC);

        verifySignatures(s, md.digest("Hello world!".getBytes()));
    }

    private void directSignatureTest(
        KeyPair signaturePair,
        X509Certificate signatureCert,
        String signatureAlgorithm,
        AlgorithmIdentifier digAlgId)
    throws Exception
    {
        List              certList = new ArrayList();
        CMSTypedData      msg = new CMSProcessableByteArray("Hello world!".getBytes());

        certList.add(signatureCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BC).build(signaturePair.getPrivate());

        JcaSignerInfoGeneratorBuilder siBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        siBuilder.setDirectSignature(true);

        gen.addSignerInfoGenerator(siBuilder.build(contentSigner, signatureCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, false);
     
        assertTrue(s.getDigestAlgorithmIDs().contains(digAlgId));

        verifySignatures(s, null);
    }

    private void subjectKeyIDTest(
        KeyPair         signaturePair,
        X509Certificate signatureCert,
        String          signatureAlgorithm)
        throws Exception
    {
        List              certList = new ArrayList();
        List              crlList = new ArrayList();
        CMSTypedData      msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(signatureCert);
        certList.add(_origCert);

        crlList.add(_signCrl);

        Store           certStore = new JcaCertStore(certList);
        Store           crlStore = new JcaCRLStore(crlList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BC).build(signaturePair.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(contentSigner, CMSTestUtil.createSubjectKeyId(signatureCert.getPublicKey()).getKeyIdentifier()));

        gen.addCertificates(certStore);
        gen.addCRLs(crlStore);

        CMSSignedData s = gen.generate(msg, true);

        assertEquals(3, s.getVersion());
        
        ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
        ASN1InputStream      aIn = new ASN1InputStream(bIn);

        s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

        certStore = s.getCertificates();

        SignerInformationStore  signers = s.getSignerInfos();
        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certStore.getMatches(signer.getSID());

            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));
        }

        //
        // check for CRLs
        //
        Collection crls = crlStore.getMatches(null);

        assertEquals(1, crls.size());

        assertTrue(crls.contains(new JcaX509CRLHolder(_signCrl)));

        //
        // try using existing signer
        //

        gen = new CMSSignedDataGenerator();

        gen.addSigners(s.getSignerInfos());

        gen.addCertificates(s.getCertificates());

        s = gen.generate(msg, true);

        bIn = new ByteArrayInputStream(s.getEncoded());
        aIn = new ASN1InputStream(bIn);

        s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

        certStore = s.getCertificates();

        signers = s.getSignerInfos();
        c = signers.getSigners();
        it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certStore.getMatches(signer.getSID());

            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));
        }

        checkSignerStoreReplacement(s, signers);
    }

    private void encapsulatedTest(
        KeyPair         signaturePair, 
        X509Certificate signatureCert,
        String          signatureAlgorithm)
        throws Exception
    {
        encapsulatedTest(signaturePair, signatureCert, signatureAlgorithm, null);
    }

    private void encapsulatedTest(
        KeyPair         signaturePair,
        X509Certificate signatureCert,
        String          signatureAlgorithm,
        ASN1ObjectIdentifier sigAlgOid)
        throws Exception
    {
        encapsulatedTest(signaturePair, signatureCert, signatureAlgorithm, sigAlgOid, null);
    }

    private void encapsulatedTest(
        KeyPair         signaturePair,
        X509Certificate signatureCert,
        String          signatureAlgorithm,
        ASN1ObjectIdentifier sigAlgOid,
        AlgorithmIdentifier digAlgId)
    throws Exception
    {
        List                certList = new ArrayList();
        List                crlList = new ArrayList();
        CMSTypedData        msg = new CMSProcessableByteArray("Hello World!".getBytes());
    
        certList.add(signatureCert);
        certList.add(_origCert);

        crlList.add(_signCrl);

        Store           certs = new JcaCertStore(certList);
        Store           crlStore = new JcaCRLStore(crlList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BC).build(signaturePair.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(contentSigner, signatureCert));

        gen.addCertificates(certs);
    
        CMSSignedData s = gen.generate(msg, true);

        ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
        ASN1InputStream      aIn = new ASN1InputStream(bIn);

        s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

        Set digestAlgorithms = new HashSet(s.getDigestAlgorithmIDs());

        assertTrue(digestAlgorithms.size() > 0);

        if (digAlgId != null)
        {
            assertTrue(digestAlgorithms.contains(digAlgId));
        }

        certs = s.getCertificates();
    
        SignerInformationStore  signers = s.getSignerInfos();
        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();
    
        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certs.getMatches(signer.getSID());
    
            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            if (sigAlgOid != null)
            {
                assertEquals(sigAlgOid.getId(), signer.getEncryptionAlgOID());
                if (noParams.contains(sigAlgOid))
                {
                    assertNull(signer.getEncryptionAlgParams());
                }
                else
                {
                    assertEquals(DERNull.INSTANCE, ASN1Primitive.fromByteArray(signer.getEncryptionAlgParams()));
                }
            }

            digestAlgorithms.remove(signer.getDigestAlgorithmID());

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));
        }

        assertTrue(digestAlgorithms.size() == 0);

        //
        // check signer information lookup
        //

        SignerId sid = new JcaSignerId(signatureCert);

        Collection collection = signers.getSigners(sid);

        assertEquals(1, collection.size());
        assertTrue(collection.iterator().next() instanceof SignerInformation);

        //
        // check for CRLs
        //
        Collection crls = crlStore.getMatches(null);

        assertEquals(1, crls.size());

        assertTrue(crls.contains(new JcaX509CRLHolder(_signCrl)));
        
        //
        // try using existing signer
        //
        
        gen = new CMSSignedDataGenerator();
           
        gen.addSigners(s.getSignerInfos());
        
        gen.addCertificates(s.getCertificates());
           
        s = gen.generate(msg, true);
    
        bIn = new ByteArrayInputStream(s.getEncoded());
        aIn = new ASN1InputStream(bIn);
    
        s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));
    
        certs = s.getCertificates();
    
        signers = s.getSignerInfos();
        c = signers.getSigners();
        it = c.iterator();
    
        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certs.getMatches(signer.getSID());
    
            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();
    
            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));
        }
        
        checkSignerStoreReplacement(s, signers);
    }

    private void detachedTest(
        KeyPair signaturePair,
        X509Certificate signatureCert,
        String signatureAlgorithm,
        ASN1ObjectIdentifier sigAlgOid)
        throws Exception
    {
        detachedTest(signaturePair, signatureCert, signatureAlgorithm, sigAlgOid, null);
    }

    private void detachedTest(
        KeyPair signaturePair,
        X509Certificate signatureCert,
        String signatureAlgorithm,
        ASN1ObjectIdentifier sigAlgOid,
        AlgorithmIdentifier digAlgId)
        throws Exception
    {
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(signatureCert);

        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BC).build(signaturePair.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(contentSigner, signatureCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, true);

        ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
        ASN1InputStream aIn = new ASN1InputStream(bIn);

        s = new CMSSignedData(msg, ContentInfo.getInstance(aIn.readObject()));

        Set digestAlgorithms = new HashSet(s.getDigestAlgorithmIDs());

        assertTrue(digestAlgorithms.size() > 0);

        if (digAlgId != null)
        {
            assertTrue(digestAlgorithms.contains(digAlgId));
        }
        certs = s.getCertificates();

        SignerInformationStore signers = s.getSignerInfos();
        Collection c = signers.getSigners();
        Iterator it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection certCollection = certs.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            if (sigAlgOid != null)
            {
                assertEquals(sigAlgOid.getId(), signer.getEncryptionAlgOID());
                if (noParams.contains(sigAlgOid))
                {
                    assertNull(signer.getEncryptionAlgParams());
                }
                else
                {
                    assertEquals(DERNull.INSTANCE, ASN1Primitive.fromByteArray(signer.getEncryptionAlgParams()));
                }
            }

            digestAlgorithms.remove(signer.getDigestAlgorithmID());

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));
        }

        assertTrue(digestAlgorithms.size() == 0);

        //
        // check signer information lookup
        //

        SignerId sid = new JcaSignerId(signatureCert);

        Collection collection = signers.getSigners(sid);

        assertEquals(1, collection.size());
        assertTrue(collection.iterator().next() instanceof SignerInformation);

        //
        // try using existing signer
        //

        gen = new CMSSignedDataGenerator();

        gen.addSigners(s.getSignerInfos());

        gen.addCertificates(s.getCertificates());

        s = gen.generate(msg);
        
        s = new CMSSignedData(msg, s.getEncoded());

        certs = s.getCertificates();

        signers = s.getSignerInfos();
        c = signers.getSigners();
        it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection certCollection = certs.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));
        }

        checkSignerStoreReplacement(s, signers);
    }

    //
    // signerInformation store replacement test.
    //
    private void checkSignerStoreReplacement(
        CMSSignedData orig, 
        SignerInformationStore signers) 
        throws Exception
    {
        CMSSignedData s = CMSSignedData.replaceSigners(orig, signers);
        
        Store certs = s.getCertificates();
        
        signers = s.getSignerInfos();
        Collection c = signers.getSigners();
        Iterator   it = c.iterator();
    
        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certs.getMatches(signer.getSID());
    
            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();
    
            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));
        }
    }
    
    public void testUnsortedAttributes()
        throws Exception
    {
        CMSSignedData s = new CMSSignedData(new CMSProcessableByteArray(disorderedMessage), disorderedSet);

        Store certs = s.getCertificates();

        SignerInformationStore  signers = s.getSignerInfos();
        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certs.getMatches(signer.getSID());
            Iterator              certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(false, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));

            Signature sig = Signature.getInstance("SHA1withRSA", BC);

            sig.initVerify(new JcaX509CertificateConverter().getCertificate(cert).getPublicKey());

            sig.update(signer.toASN1Structure().getAuthenticatedAttributes().getEncoded());

            assertEquals(true, sig.verify(signer.getSignature()));
        }
    }
    
    public void testNullContentWithSigner()
        throws Exception
    {
        List                certList = new ArrayList();

        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha1Signer, _origCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(new CMSAbsentContent(), false);

        ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
        ASN1InputStream      aIn = new ASN1InputStream(bIn);
        
        s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

        verifySignatures(s);
    }

    public void testWithAttributeCertificate()
        throws Exception
    {
        List                certList = new ArrayList();
        CMSTypedData        msg = new CMSProcessableByteArray("Hello World!".getBytes());


        certList.add(_signDsaCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());
        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(builder.build(sha1Signer, _origCert));

        gen.addCertificates(certs);

        X509AttributeCertificateHolder attrCert = CMSTestUtil.getAttributeCertificate();
        List attrList = new ArrayList();

        attrList.add(new X509AttributeCertificateHolder(attrCert.getEncoded()));

        Store store = new CollectionStore(attrList);

        gen.addAttributeCertificates(store);

        CMSSignedData sd = gen.generate(msg);

        assertEquals(4, sd.getVersion());

        store = sd.getAttributeCertificates();

        Collection coll = store.getMatches(null);

        assertEquals(1, coll.size());

        assertTrue(coll.contains(new X509AttributeCertificateHolder(attrCert.getEncoded())));
        
        //
        // create new certstore
        //
        certList = new ArrayList();
        certList.add(_origCert);
        certList.add(_signCert);

        certs = new JcaCertStore(certList);


        //
        // replace certs
        //
        sd = CMSSignedData.replaceCertificatesAndCRLs(sd, certs, null, null);

        verifySignatures(sd);
    }

    public void testCertStoreReplacement()
        throws Exception
    {
        List         certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray("Hello World!".getBytes());


        certList.add(_signDsaCert);

        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha1Signer, _origCert));

        gen.addCertificates(certs);

        CMSSignedData sd = gen.generate(msg);

        //
        // create new certstore
        //
        certList = new ArrayList();
        certList.add(_origCert);
        certList.add(_signCert);

        certs = new JcaCertStore(certList);

        //
        // replace certs
        //
        sd = CMSSignedData.replaceCertificatesAndCRLs(sd, certs, null, null);

        verifySignatures(sd);
    }

    public void testEncapsulatedCertStoreReplacement()
        throws Exception
    {
        List                certList = new ArrayList();
        CMSTypedData        msg = new CMSProcessableByteArray("Hello World!".getBytes());


        certList.add(_signDsaCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha1Signer, _origCert));

        gen.addCertificates(certs);

        CMSSignedData sd = gen.generate(msg, true);

        //
        // create new certstore
        //
        certList = new ArrayList();
        certList.add(_origCert);
        certList.add(_signCert);

        certs = new JcaCertStore(certList);


        //
        // replace certs
        //
        sd = CMSSignedData.replaceCertificatesAndCRLs(sd, certs, null, null);

        verifySignatures(sd);
    }

    public void testCertOrdering1()
        throws Exception
    {
        List            certList = new ArrayList();
        CMSTypedData    msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(_origCert);
        certList.add(_signCert);
        certList.add(_signDsaCert);

        Store      certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha1Signer, _origCert));

        gen.addCertificates(certs);

        CMSSignedData sd = gen.generate(msg, true);

        certs = sd.getCertificates();
        Iterator it = certs.getMatches(null).iterator();

        assertEquals(new JcaX509CertificateHolder(_origCert), it.next());
        assertEquals(new JcaX509CertificateHolder(_signCert), it.next());
        assertEquals(new JcaX509CertificateHolder(_signDsaCert), it.next());
    }

    public void testCertOrdering2()
        throws Exception
    {
        List               certList = new ArrayList();
        CMSTypedData       msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(_signCert);
        certList.add(_signDsaCert);
        certList.add(_origCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha1Signer, _origCert));

        gen.addCertificates(certs);

        CMSSignedData sd = gen.generate(msg, true);

        certs = sd.getCertificates();
        Iterator it = certs.getMatches(null).iterator();

        assertEquals(new JcaX509CertificateHolder(_signCert), it.next());
        assertEquals(new JcaX509CertificateHolder(_signDsaCert), it.next());
        assertEquals(new JcaX509CertificateHolder(_origCert), it.next());
    }

    public void testSignerStoreReplacement()
        throws Exception
    {
        List                  certList = new ArrayList();
        CMSTypedData        msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha1Signer, _origCert));

        gen.addCertificates(certs);

        CMSSignedData original = gen.generate(msg, true);

        //
        // create new Signer
        //
        gen = new CMSSignedDataGenerator();

        ContentSigner sha224Signer = new JcaContentSignerBuilder("SHA224withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha224Signer, _origCert));

        gen.addCertificates(certs);

        CMSSignedData newSD = gen.generate(msg, true);

        //
        // replace signer
        //
        CMSSignedData sd = CMSSignedData.replaceSigners(original, newSD.getSignerInfos());

        SignerInformation signer = (SignerInformation)sd.getSignerInfos().getSigners().iterator().next();

        assertEquals(CMSAlgorithm.SHA224.getId(), signer.getDigestAlgOID());

        // we use a parser here as it requires the digests to be correct in the digest set, if it
        // isn't we'll get a NullPointerException
        CMSSignedDataParser sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(), sd.getEncoded());

        sp.getSignedContent().drain();

        verifySignatures(sp);
    }

    public void testEncapsulatedSamples()
        throws Exception
    {
        testSample("PSSSignDataSHA1Enc.sig");
        testSample("PSSSignDataSHA256Enc.sig");
        testSample("PSSSignDataSHA512Enc.sig");
    }
    
    public void testSamples()
        throws Exception
    {
        testSample("PSSSignData.data", "PSSSignDataSHA1.sig");
        testSample("PSSSignData.data", "PSSSignDataSHA256.sig");
        testSample("PSSSignData.data", "PSSSignDataSHA512.sig");
    }

    public void testNoAttrEncapsulatedSample()
        throws Exception
    {
        CMSSignedData s = new CMSSignedData(noAttrEncData);

        Store certStore = s.getCertificates();

        assertNotNull(certStore);

        SignerInformationStore signers = s.getSignerInfos();

        assertNotNull(signers);

        Collection c = signers.getSigners();

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection certCollection = certStore.getMatches(signer.getSID());
            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)))
            {
                fail("Verification FAILED! ");
            }
        }
    }

    public void testCounterSig()
        throws Exception
    {
        CMSSignedData sig = new CMSSignedData(getInput("counterSig.p7m"));

        SignerInformationStore ss = sig.getSignerInfos();
        Collection signers = ss.getSigners();

        SignerInformationStore cs = ((SignerInformation)signers.iterator().next()).getCounterSignatures();
        Collection csSigners = cs.getSigners();
        assertEquals(1, csSigners.size());

        Iterator it = csSigners.iterator();
        while (it.hasNext())
        {
            SignerInformation   cSigner = (SignerInformation)it.next();
            Collection          certCollection = sig.getCertificates().getMatches(cSigner.getSID());

            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertTrue(cSigner.isCounterSignature());
            assertNull(cSigner.getSignedAttributes().get(PKCSObjectIdentifiers.pkcs_9_at_contentType));
            assertEquals(true, cSigner.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));
        }
        
        verifySignatures(sig);
    }

    public void testCertificateManagement()
        throws Exception
    {
        CMSSignedDataGenerator sGen = new CMSSignedDataGenerator();

        List                  certList = new ArrayList();

        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        sGen.addCertificates(certs);

        CMSSignedData sData = sGen.generate(new CMSAbsentContent(), true);

        CMSSignedData rsData = new CMSSignedData(sData.getEncoded());

        assertTrue(sData.isCertificateManagementMessage());
        assertFalse(sData.isDetachedSignature());

        assertEquals(2, rsData.getCertificates().getMatches(null).size());
    }

    public void testMixed()
        throws Exception
    {
        ASN1ApplicationSpecific derApplicationSpecific = (ASN1ApplicationSpecific)ASN1Primitive.fromByteArray(mixedSignedData);

        CMSSignedData s = new CMSSignedData(new ByteArrayInputStream(derApplicationSpecific.getContents()));

        Store certs = s.getCertificates();

        SignerInformationStore  signers = s.getSignerInfos();
        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certs.getMatches(signer.getSID());

            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));
        }
    }

    public void testMSPKCS7()
        throws Exception
    {
        byte[] data = getInput("SignedMSPkcs7.sig");

        CMSSignedData sData = new CMSSignedData(data);

        Store                   certStore = sData.getCertificates();
        SignerInformationStore  signers = sData.getSignerInfos();

        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        while (it.hasNext())
        {
          SignerInformation   signer = (SignerInformation)it.next();
          Collection          certCollection = certStore.getMatches(signer.getSID());

          Iterator        certIt = certCollection.iterator();
          X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert)));
        }

        // try generation from it.
        List                  certList = new ArrayList();
        CMSTypedData        msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha1Signer, _origCert));

        gen.addCertificates(certs);

        CMSSignedData local = gen.generate(sData.getSignedContent(), true);

        certStore = local.getCertificates();
        signers = local.getSignerInfos();

        c = signers.getSigners();
        it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection certCollection = certStore.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert)));
        }
    }

    private void testSample(String sigName)
        throws Exception
    {
        CMSSignedData sig = new CMSSignedData(getInput(sigName));

        verifySignatures(sig);
    }

    private void testSample(String messageName, String sigName)
        throws Exception
    {
        CMSSignedData sig = new CMSSignedData(new CMSProcessableByteArray(getInput(messageName)), getInput(sigName));

        verifySignatures(sig);
    }

    private byte[] getInput(String name)
        throws IOException
    {
        return Streams.readAll(getClass().getResourceAsStream(name));
    }

    public void testForMultipleCounterSignatures()
        throws Exception
    {
        CMSSignedData sd = new CMSSignedData(xtraCounterSig);

        for (Iterator sI = sd.getSignerInfos().getSigners().iterator(); sI.hasNext();)
        {
            SignerInformation sigI = (SignerInformation)sI.next();

            SignerInformationStore counter = sigI.getCounterSignatures();
            List                   sigs = new ArrayList(counter.getSigners());

            assertEquals(2, sigs.size());
        }
    }

    private void verifySignatures(CMSSignedDataParser sp)
        throws Exception
    {
        Store               certs = sp.getCertificates();
        SignerInformationStore  signers = sp.getSignerInfos();

        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certs.getMatches(signer.getSID());

            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));
        }
    }

    private class TestCMSSignatureAlgorithmNameGenerator
        extends DefaultCMSSignatureAlgorithmNameGenerator
    {
        void setDigestAlgorithmMapping(ASN1ObjectIdentifier oid, String algName)
        {
            super.setSigningDigestAlgorithmMapping(oid, algName);
        }

        void setEncryptionAlgorithmMapping(ASN1ObjectIdentifier oid, String algName)
        {
            super.setSigningEncryptionAlgorithmMapping(oid, algName);
        }
    }
}
