package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.spec.RSAPrivateCrtKeySpec;

import org.bouncycastle.util.encoders.Base64;

public class AttrCertData
{
    private static final RSAPrivateCrtKeySpec RSA_PRIVATE_KEY_SPEC = new RSAPrivateCrtKeySpec(
                new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
                new BigInteger("11", 16),
                new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
                new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
                new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
                new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
                new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
                new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

    public static byte[]  attrCert = Base64.decode(
            "MIIHQDCCBqkCAQEwgZChgY2kgYowgYcxHDAaBgkqhkiG9w0BCQEWDW1sb3JjaEB2"
          + "dC5lZHUxHjAcBgNVBAMTFU1hcmt1cyBMb3JjaCAobWxvcmNoKTEbMBkGA1UECxMS"
          + "VmlyZ2luaWEgVGVjaCBVc2VyMRAwDgYDVQQLEwdDbGFzcyAyMQswCQYDVQQKEwJ2"
          + "dDELMAkGA1UEBhMCVVMwgYmkgYYwgYMxGzAZBgkqhkiG9w0BCQEWDHNzaGFoQHZ0"
          + "LmVkdTEbMBkGA1UEAxMSU3VtaXQgU2hhaCAoc3NoYWgpMRswGQYDVQQLExJWaXJn"
          + "aW5pYSBUZWNoIFVzZXIxEDAOBgNVBAsTB0NsYXNzIDExCzAJBgNVBAoTAnZ0MQsw"
          + "CQYDVQQGEwJVUzANBgkqhkiG9w0BAQQFAAIBBTAiGA8yMDAzMDcxODE2MDgwMloY"
          + "DzIwMDMwNzI1MTYwODAyWjCCBU0wggVJBgorBgEEAbRoCAEBMYIFORaCBTU8UnVs"
          + "ZSBSdWxlSWQ9IkZpbGUtUHJpdmlsZWdlLVJ1bGUiIEVmZmVjdD0iUGVybWl0Ij4K"
          + "IDxUYXJnZXQ+CiAgPFN1YmplY3RzPgogICA8U3ViamVjdD4KICAgIDxTdWJqZWN0"
          + "TWF0Y2ggTWF0Y2hJZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5j"
          + "dGlvbjpzdHJpbmctZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlw"
          + "ZT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjc3RyaW5nIj4KICAg"
          + "ICAgIENOPU1hcmt1cyBMb3JjaDwvQXR0cmlidXRlVmFsdWU+CiAgICAgPFN1Ympl"
          + "Y3RBdHRyaWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFt"
          + "ZXM6dGM6eGFjbWw6MS4wOnN1YmplY3Q6c3ViamVjdC1pZCIgRGF0YVR5cGU9Imh0"
          + "dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hI3N0cmluZyIgLz4gCiAgICA8"
          + "L1N1YmplY3RNYXRjaD4KICAgPC9TdWJqZWN0PgogIDwvU3ViamVjdHM+CiAgPFJl"
          + "c291cmNlcz4KICAgPFJlc291cmNlPgogICAgPFJlc291cmNlTWF0Y2ggTWF0Y2hJ"
          + "ZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5jdGlvbjpzdHJpbmct"
          + "ZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlwZT0iaHR0cDovL3d3"
          + "dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIj4KICAgICAgaHR0cDovL3p1"
          + "bmkuY3MudnQuZWR1PC9BdHRyaWJ1dGVWYWx1ZT4KICAgICA8UmVzb3VyY2VBdHRy"
          + "aWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6"
          + "eGFjbWw6MS4wOnJlc291cmNlOnJlc291cmNlLWlkIiBEYXRhVHlwZT0iaHR0cDov"
          + "L3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIiAvPiAKICAgIDwvUmVz"
          + "b3VyY2VNYXRjaD4KICAgPC9SZXNvdXJjZT4KICA8L1Jlc291cmNlcz4KICA8QWN0"
          + "aW9ucz4KICAgPEFjdGlvbj4KICAgIDxBY3Rpb25NYXRjaCBNYXRjaElkPSJ1cm46"
          + "b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmZ1bmN0aW9uOnN0cmluZy1lcXVhbCI+"
          + "CiAgICAgPEF0dHJpYnV0ZVZhbHVlIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9y"
          + "Zy8yMDAxL1hNTFNjaGVtYSNzdHJpbmciPgpEZWxlZ2F0ZSBBY2Nlc3MgICAgIDwv"
          + "QXR0cmlidXRlVmFsdWU+CgkgIDxBY3Rpb25BdHRyaWJ1dGVEZXNpZ25hdG9yIEF0"
          + "dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmFjdGlvbjph"
          + "Y3Rpb24taWQiIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNj"
          + "aGVtYSNzdHJpbmciIC8+IAogICAgPC9BY3Rpb25NYXRjaD4KICAgPC9BY3Rpb24+"
          + "CiAgPC9BY3Rpb25zPgogPC9UYXJnZXQ+CjwvUnVsZT4KMA0GCSqGSIb3DQEBBAUA"
          + "A4GBAGiJSM48XsY90HlYxGmGVSmNR6ZW2As+bot3KAfiCIkUIOAqhcphBS23egTr"
          + "6asYwy151HshbPNYz+Cgeqs45KkVzh7bL/0e1r8sDVIaaGIkjHK3CqBABnfSayr3"
          + "Rd1yBoDdEv8Qb+3eEPH6ab9021AsLEnJ6LWTmybbOpMNZ3tv");

    byte[]  signCert = Base64.decode(
            "MIIGjTCCBXWgAwIBAgICAPswDQYJKoZIhvcNAQEEBQAwaTEdMBsGCSqGSIb3DQEJ"
          + "ARYOaXJtaGVscEB2dC5lZHUxLjAsBgNVBAMTJVZpcmdpbmlhIFRlY2ggQ2VydGlm"
          + "aWNhdGlvbiBBdXRob3JpdHkxCzAJBgNVBAoTAnZ0MQswCQYDVQQGEwJVUzAeFw0w"
          + "MzAxMzExMzUyMTRaFw0wNDAxMzExMzUyMTRaMIGDMRswGQYJKoZIhvcNAQkBFgxz"
          + "c2hhaEB2dC5lZHUxGzAZBgNVBAMTElN1bWl0IFNoYWggKHNzaGFoKTEbMBkGA1UE"
          + "CxMSVmlyZ2luaWEgVGVjaCBVc2VyMRAwDgYDVQQLEwdDbGFzcyAxMQswCQYDVQQK"
          + "EwJ2dDELMAkGA1UEBhMCVVMwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAPDc"
          + "scgSKmsEp0VegFkuitD5j5PUkDuzLjlfaYONt2SN8WeqU4j2qtlCnsipa128cyKS"
          + "JzYe9duUdNxquh5BPIkMkHBw4jHoQA33tk0J/sydWdN74/AHPpPieK5GHwhU7GTG"
          + "rCCS1PJRxjXqse79ExAlul+gjQwHeldAC+d4A6oZAgMBAAGjggOmMIIDojAMBgNV"
          + "HRMBAf8EAjAAMBEGCWCGSAGG+EIBAQQEAwIFoDAOBgNVHQ8BAf8EBAMCA/gwHQYD"
          + "VR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMB0GA1UdDgQWBBRUIoWAzlXbzBYE"
          + "yVTjQFWyMMKo1jCBkwYDVR0jBIGLMIGIgBTgc3Fm+TGqKDhen+oKfbl+xVbj2KFt"
          + "pGswaTEdMBsGCSqGSIb3DQEJARYOaXJtaGVscEB2dC5lZHUxLjAsBgNVBAMTJVZp"
          + "cmdpbmlhIFRlY2ggQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxCzAJBgNVBAoTAnZ0"
          + "MQswCQYDVQQGEwJVU4IBADCBiwYJYIZIAYb4QgENBH4WfFZpcmdpbmlhIFRlY2gg"
          + "Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkgZGlnaXRhbCBjZXJ0aWZpY2F0ZXMgYXJl"
          + "IHN1YmplY3QgdG8gcG9saWNpZXMgbG9jYXRlZCBhdCBodHRwOi8vd3d3LnBraS52"
          + "dC5lZHUvY2EvY3BzLy4wFwYDVR0RBBAwDoEMc3NoYWhAdnQuZWR1MBkGA1UdEgQS"
          + "MBCBDmlybWhlbHBAdnQuZWR1MEMGCCsGAQUFBwEBBDcwNTAzBggrBgEFBQcwAoYn"
          + "aHR0cDovL2JveDE3Ny5jYy52dC5lZHUvY2EvaXNzdWVycy5odG1sMEQGA1UdHwQ9"
          + "MDswOaA3oDWGM2h0dHA6Ly9ib3gxNzcuY2MudnQuZWR1L2h0ZG9jcy1wdWJsaWMv"
          + "Y3JsL2NhY3JsLmNybDBUBgNVHSAETTBLMA0GCysGAQQBtGgFAQEBMDoGCysGAQQB"
          + "tGgFAQEBMCswKQYIKwYBBQUHAgEWHWh0dHA6Ly93d3cucGtpLnZ0LmVkdS9jYS9j"
          + "cHMvMD8GCWCGSAGG+EIBBAQyFjBodHRwOi8vYm94MTc3LmNjLnZ0LmVkdS9jZ2kt"
          + "cHVibGljL2NoZWNrX3Jldl9jYT8wPAYJYIZIAYb4QgEDBC8WLWh0dHA6Ly9ib3gx"
          + "NzcuY2MudnQuZWR1L2NnaS1wdWJsaWMvY2hlY2tfcmV2PzBLBglghkgBhvhCAQcE"
          + "PhY8aHR0cHM6Ly9ib3gxNzcuY2MudnQuZWR1L35PcGVuQ0E4LjAxMDYzMC9jZ2kt"
          + "cHVibGljL3JlbmV3YWw/MCwGCWCGSAGG+EIBCAQfFh1odHRwOi8vd3d3LnBraS52"
          + "dC5lZHUvY2EvY3BzLzANBgkqhkiG9w0BAQQFAAOCAQEAHJ2ls9yjpZVcu5DqiE67"
          + "r7BfkdMnm7IOj2v8cd4EAlPp6OPBmjwDMwvKRBb/P733kLBqFNWXWKTpT008R0KB"
          + "8kehbx4h0UPz9vp31zhGv169+5iReQUUQSIwTGNWGLzrT8kPdvxiSAvdAJxcbRBm"
          + "KzDic5I8PoGe48kSCkPpT1oNmnivmcu5j1SMvlx0IS2BkFMksr0OHiAW1elSnE/N"
          + "RuX2k73b3FucwVxB3NRo3vgoHPCTnh9r4qItAHdxFlF+pPtbw2oHESKRfMRfOIHz"
          + "CLQWSIa6Tvg4NIV3RRJ0sbCObesyg08lymalQMdkXwtRn5eGE00SHWwEUjSXP2gR"
          + "3g==");

    static byte[] certWithBaseCertificateID = Base64.decode(
            "MIIBqzCCARQCAQEwSKBGMD6kPDA6MQswCQYDVQQGEwJJVDEOMAwGA1UEChMFVU5JVE4xDDAKBgNV"
          + "BAsTA0RJVDENMAsGA1UEAxMEcm9vdAIEAVMVjqB6MHikdjB0MQswCQYDVQQGEwJBVTEoMCYGA1UE"
          + "ChMfVGhlIExlZ2lvbiBvZiB0aGUgQm91bmN5IENhc3RsZTEjMCEGA1UECxMaQm91bmN5IFByaW1h"
          + "cnkgQ2VydGlmaWNhdGUxFjAUBgNVBAMTDUJvdW5jeSBDYXN0bGUwDQYJKoZIhvcNAQEFBQACBQKW"
          + "RhnHMCIYDzIwMDUxMjEyMTIwMDQyWhgPMjAwNTEyMTkxMjAxMzJaMA8wDQYDVRhIMQaBBGVWSVAw"
          + "DQYJKoZIhvcNAQEFBQADgYEAUAVin9StDaA+InxtXq/av6rUQLI9p1X6louBcj4kYJnxRvTrHpsr"
          + "N3+i9Uq/uk5lRdAqmPFvcmSbuE3TRAsjrXON5uFiBBKZ1AouLqcr8nHbwcdwjJ9TyUNO9I4hfpSH"
          + "UHHXMtBKgp4MOkhhX8xTGyWg3hp23d3GaUeg/IYlXBI=");
    
    byte[] holderCertWithBaseCertificateID = Base64.decode(
            "MIIBwDCCASmgAwIBAgIEAVMVjjANBgkqhkiG9w0BAQUFADA6MQswCQYDVQQGEwJJVDEOMAwGA1UE"
          + "ChMFVU5JVE4xDDAKBgNVBAsTA0RJVDENMAsGA1UEAxMEcm9vdDAeFw0wNTExMTExMjAxMzJaFw0w"
          + "NjA2MTYxMjAxMzJaMD4xCzAJBgNVBAYTAklUMQ4wDAYDVQQKEwVVTklUTjEMMAoGA1UECxMDRElU"
          + "MREwDwYDVQQDEwhMdWNhQm9yejBaMA0GCSqGSIb3DQEBAQUAA0kAMEYCQQC0p+RhcFdPFqlwgrIr"
          + "5YtqKmKXmEGb4ShypL26Ymz66ZAPdqv7EhOdzl3lZWT6srZUMWWgQMYGiHQg4z2R7X7XAgERoxUw"
          + "EzARBglghkgBhvhCAQEEBAMCBDAwDQYJKoZIhvcNAQEFBQADgYEAsX50VPQQCWmHvPq9y9DeCpmS"
          + "4szcpFAhpZyn6gYRwY9CRZVtmZKH8713XhkGDWcIEMcG0u3oTz3tdKgPU5uyIPrDEWr6w8ClUj4x"
          + "5aVz5c2223+dVY7KES//JSB2bE/KCIchN3kAioQ4K8O3e0OL6oDVjsqKGw5bfahgKuSIk/Q=");

}
