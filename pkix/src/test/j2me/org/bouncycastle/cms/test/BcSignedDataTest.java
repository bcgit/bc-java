package org.bouncycastle.cms.test;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.bc.BcRSASignerInfoVerifierBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class BcSignedDataTest
    extends SimpleTest
{
    private static String                   _origDN;
    private static AsymmetricCipherKeyPair  _origKP;
    private static X509CertificateHolder    _origCert;

    private static String                   _signDN;
    private static AsymmetricCipherKeyPair  _signKP;
    private static X509CertificateHolder    _signCert;

    private static boolean _initialised = false;

    private byte[] disorderedMessage = Base64.decode(
            "SU9fc3RkaW5fdXNlZABfX2xpYmNfc3RhcnRfbWFpbgBnZXRob3N0aWQAX19n"
          + "bW9uX3M=");

    private byte[] disorderedSet = Base64.decode(
            "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"
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

    public String getName()
    {
        return "BcSignedData";
    }

    private void init()
        throws Exception
    {
        if (!_initialised)
        {
            _initialised = true;

            _origDN   = "O=Bouncy Castle, C=AU";
            _origKP   = CMSTestUtil.makeKeyPair();  
            _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _origKP, _origDN);

            _signDN   = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            _signKP   = CMSTestUtil.makeKeyPair();
            _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _origKP, _origDN);
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

            if (!signer.verify(new BcRSASignerInfoVerifierBuilder(new DefaultCMSSignatureAlgorithmNameGenerator(), new DefaultSignatureAlgorithmIdentifierFinder(), new DefaultDigestAlgorithmIdentifierFinder(), new BcDigestCalculatorProvider()).build(cert)))
            {
                fail("signature verification failed");
            }

            if (contentDigest != null)
            {
                if (!Arrays.areEqual(contentDigest, signer.getContentDigest()))
                {
                    fail("digest verification failed");
                }
            }
        }
    }

    public void performTest()
        throws Exception
    {
        init();

        testDetachedRSA();
        testEncapsulatedRSA();
    }

    private void testDetachedRSA()
        throws Exception
    {
        Digest md = new SHA1Digest();
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray("Hello world!".getBytes());

        certList.add(_origCert);
        certList.add(_signCert);

        Store certs = new CollectionStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        byte[] digValue = new byte[md.getDigestSize()];
        byte[] data = "Hello world!".getBytes();

        md.update(data, 0, data.length);
        md.doFinal(digValue, 0);

        Attribute attr = new Attribute(CMSAttributes.messageDigest,
                                       new DERSet(
                                            new DEROctetString(
                                                digValue)));

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(attr);

        AsymmetricKeyParameter privKey = (AsymmetricKeyParameter)_origKP.getPrivate();

        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

        BcContentSignerBuilder contentSignerBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);

        gen.addSignerInfoGenerator(
            new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider())
                .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(v)))
                .build(contentSignerBuilder.build(privKey), _origCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(new CMSAbsentContent(), false);

        //
        // the signature is detached, so need to add msg before passing on
        //
        s = new CMSSignedData(msg, s.getEncoded());
        //
        // compute expected content digest
        //

        verifyRSASignatures(s, digValue);
    }

    private void testEncapsulatedRSA()
        throws Exception
    {
        Digest md = new SHA1Digest();
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray("Hello world!".getBytes());

        certList.add(_origCert);
        certList.add(_signCert);

        Store certs = new CollectionStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        byte[] digValue = new byte[md.getDigestSize()];
        byte[] data = "Hello world!".getBytes();

        md.update(data, 0, data.length);
        md.doFinal(digValue, 0);

        Attribute attr = new Attribute(CMSAttributes.messageDigest,
                                       new DERSet(
                                            new DEROctetString(
                                                digValue)));

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(attr);

        AsymmetricKeyParameter privKey = (AsymmetricKeyParameter)_origKP.getPrivate();

        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

        BcContentSignerBuilder contentSignerBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);

        gen.addSignerInfoGenerator(
            new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider())
                .build(contentSignerBuilder.build(privKey), _origCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(new CMSProcessableByteArray(data), true);

        //
        // the signature is encapsulated, so no need to add msg before passing on
        //
        s = new CMSSignedData(s.getEncoded());
        //
        // compute expected content digest
        //

        verifyRSASignatures(s, digValue);
    }


    public static void main(
        String[]    args)
    {
        runTest(new BcSignedDataTest());
    }
}
