package org.bouncycastle.cert.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.DeltaCertificateDescriptor;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.DeltaCertificateTool;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.DeltaCertAttributeUtils;
import org.bouncycastle.pkcs.DeltaCertificateRequestAttributeValue;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.util.encoders.Base64;

public class DeltaCertTest
    extends TestCase
{
    private static byte[] baseCertData = Base64.decode(
        "MIIREzCCELigAwIBAgIUSq2wnmbyhuz2O1DahpLbE0N075owCgYIKoZIzj0EAwIw\n" +
            "NTEzMDEGA1UEAwwqQkMgU0hBMjU2d2l0aEVDRFNBIFRlc3QgQ2hhbWVsZW9uIE91\n" +
            "dGVyIFRBMB4XDTIzMDgzMDAwNDAxOVoXDTI0MDgyOTAwNDExOVowNTEzMDEGA1UE\n" +
            "AwwqQkMgU0hBMjU2d2l0aEVDRFNBIFRlc3QgQ2hhbWVsZW9uIE91dGVyIFRBMFkw\n" +
            "EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9awTIuRdm93biCGi7O3DDopxiMa1lR0v\n" +
            "qdFNmf7vrjlAsB5BKyTeFpxqLOLwJAbDIkr9O1o7HDgU7DOs+nFCKKOCD6Qwgg+g\n" +
            "MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMIIPeAYKYIZIAYb6\n" +
            "a1AGAQSCD2gwgg9kAhRKrbCeZvKG7PY7UNqGktsTQ3TvmqANBgsrBgEEAQKCCwwE\n" +
            "BKEyMDAxLjAsBgNVBAMMJUJDIERpbGl0aGl1bTIgVGVzdCBDaGFtZWxlb24gSW5u\n" +
            "ZXIgVEGjMjAwMS4wLAYDVQQDDCVCQyBEaWxpdGhpdW0yIFRlc3QgQ2hhbWVsZW9u\n" +
            "IElubmVyIFRBMIIFNDANBgsrBgEEAQKCCwwEBAOCBSEAsPv1ri6Gd2zXktq/CPlP\n" +
            "cJbHy2Lra4mc/7PV5g0scKx3os5VS8RWZ7NrRjszXhKEU+uEAelmd6PuE2biKNv/\n" +
            "iZMHaXqdLYYYBNhC4j8ppBu0rXaIEtNEsmv2oV8X8fbA2HU63/ctz6GHdOY57mlJ\n" +
            "0l7cnyRCVmSofTGcLQjgjnfXhQeEvIqoDndyqbitSIsxyrnb46C3LbI5VElbuAOH\n" +
            "VPLaMw2c09f3c5Ab4YmJwgVBomk0yeePDUxYdbVFWAvN+Ez/PX8sickVm/zeFzYD\n" +
            "xQtwLl+CTCOIdiSn+dMEmM0fxrOUutHPVLoKqAxaTrSrKoe18o+ovj+tcNDBgd9I\n" +
            "K9yWHg9aJQwMHhlyzbe6AMOz4jK54JCn/GpX66tRBhrNKDa/jmZm5pNO7hiw3UUk\n" +
            "1OOy7mwMNuGJgMiMxi/Oh1zBtJnmJi+SvoNYEQrl/5P7hvM0oTalzLkRadIouGuy\n" +
            "2fjgyPF5N8IO+OHoSrpOnKv0pBEN/JXZzDETRvz6FQigY07a2RFCWZ43886oDol/\n" +
            "jSc2+z4IhMAb78Y+8gdZ08C25cle4xnZ00aEce9LOmu2SqvUEAt0doqOk9KxxOeq\n" +
            "gqUUMPqn70LQVb7RxQq6yOfIuNyigJWQJdbh5IpeLzmJUd01oGYxzbX7EMFOsNRu\n" +
            "nWisj9MxtuYb/QzyBCd23g0rXidcKmRXQnt1PUV6XAaHdH7LGPITivkIjAryY3Hu\n" +
            "gwLt74CzcyBL4FsXEe2nU+zvwGINc1cYP9E76Qh/OTdZysphWsDWm3Q2CP2RS0oc\n" +
            "I9eBboUwS+m7uV//nc+N+jfkTE0SaaFroZCYkmkmhVFMT2IatFBeDNXGyUp4EsyM\n" +
            "SVMIlS3HAhly+AuYOseA6JHLCvvLwEcm34B9Lg/9LuKuYZ22gqLdE7JqyC1lQ5KQ\n" +
            "waGb1vvmcGSQ8sRWDst6KjiXae7IKZbqTKUMQWf9GXxuCyHD7pHAIleFvvndsFq8\n" +
            "sgxdsFnTM5JWD9uqzdICMxh/5EUCaPgiGfmCFCAd3KhuqjtXSeRP1X67pMvBVTZ4\n" +
            "hF4JyNIvjb4L+VtByo20VuMijD6YNGJupI6eTBmYKsGcue6iVcPBgXgYnHFZHVM5\n" +
            "Lt/TecoUIkqaZNIM8cWorSAnRe4WvPUvmgW+BbvTkFJoq8UlTtfu688Rd7qbfblQ\n" +
            "pKW6m92tx9LnlaQBUoaGrq2CfFSERM0fSbxxJkKW7pcTzPoVsfUqqag9AiVA6Dmn\n" +
            "7kpIWWI+NB1gZIj28O0aZcXxycmuKxWkQlNFe4OcS6mRobZzZRU61HPZka84SID8\n" +
            "sDc4/a2foUk2MFgJLXuBJldq+N80/iCf1V6U60XdN68tH1PBkQzxfcC0EVkrudBu\n" +
            "yNSlkB3ZIBM7qHyQKf+y9+WnNoAQuUXucUhbpRPobXXo7WQstCJ18TDJMLys8bDj\n" +
            "X2EvPJgoqdsJXa4w9EKQHQdfkxLJC//8tgY4LwQTu9xGJ1s9zJIDW953dsmIZJxj\n" +
            "xdzn7ePdS9QiT/ioVbwBrVaMkHQeJzGhKMrn9AJE4rO8C1XkEqbHk9N4h5E9XPjh\n" +
            "82UM2/LOAwhyh/D1pVgPWKru5Xrkp5YTP5OnRWj3V45P2c2H5nA0thGx+JKdrTqW\n" +
            "GQW/UlTKnN6eo2V9dK56chjRqYK72sU8VmoKO/2eroj5s21uMPXfiePJLWtOqBkz\n" +
            "4N+KpkvvKCEBjlJJEq7mnxVemqtQ8QyadY+tCqkbeRLLdTLhsGtwL933B+vCYpy7\n" +
            "6KQkMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGA4IJdQDn8Wf+\n" +
            "2R9iyvWAzo6cjFGzkcNYPoTG1SCwCacMJVVKX5S8vf+zJjVuNX/7t5ckc/Swwp2J\n" +
            "0x7bcIFiDFv8gR1PtT1jkR7Fo7s2vgomkIgtXVGwK6Q/GGZQ/UUpcnceIuAlVe88\n" +
            "WS9otArc+ij5YTgsE9P9/49jPZAukn2T9XLaH9W30sEPpoPXVRcK2zlpkMmL3SHp\n" +
            "Cg6bzt7GN6OLdJqioBtuKY0TAZcrVwJ0Sj8fnF5j1fnQ5qU4bP0QGrkWQNl2p2IZ\n" +
            "340+PdYXYumPW0aU5KsQCcFnGz2TyoggUbKXyELj86rBTlzKrPlW2PQFZK9/FGfz\n" +
            "YZ6dHszRbcbuyu3eaikoW53OMxbpCrl9dCNEdyE9lwtGz+DvgDk8NJeCvZbeNf9Q\n" +
            "FaE65gOkG1DC46JCluChxa0hRNvxOK9P+M8tijz9JlsKlbtkSjpqWnUPoMdjAnJ0\n" +
            "+iN6kr7LVOW6mppErnazK5hmFiGPu3P8KvqWKaAR+71161S+tuPENWbKDyq4U1wg\n" +
            "Em3xgppCTGb6BHhGT+55oUr8syLHjk60rC9CsdZfdY4RhYtIKVjL8SUhLMELwK6R\n" +
            "Dq9RUiu6sJP8Z8XZEvnQ/y720lVVuA/7BKGB+y4+B//HUk+OLhGx7W7aF78aPSa9\n" +
            "ZwMPEaTv6bDPdSY/yKxlTCPGKbDU+RAepzk8GOw9g6Ku8MPZUH9BSjm5xRI/Qztl\n" +
            "xWN7MHlQaCSTlFpAPZEZU/v2VaXnAxRsxbYfIWxAjNUImE4L51u58juR97H/Fb7r\n" +
            "jfaM8M5jLfBQvSKHER7zvSHVBHcNTzBUsXdT3zAw/XbKwPwYOT+LCxqGaksKVVBV\n" +
            "MgAIWBVvPkX8rwSCDNHMH6U1AtadSF6WT4Lsz272l8ihfZ8py0QHBVtPvjySB+yA\n" +
            "Jwwcv2/DL9EO8ozBxyJDPhTTAmqYHNgPwZ8TpzhjfF3eKPOmNbTySNG8osrKONtJ\n" +
            "+2l2RpicqeuQg3q3CF362DyGSywrxkPkx4j/JObA7o0ZQPZQ6IddVaA3jMBA3lNq\n" +
            "YkuXgZ1NSH94F1TtoKrhd+50EtjrypK43kRwvVsWkXzpbhpzSEoTZQSbQjH0y/9+\n" +
            "ceBOTr2v5TdxXkEiceTto99QfutB1yhhVo/3V8lkmcFX03A8sOFtPaeWOyIpje12\n" +
            "P4v+fuRfolNYynEUTxyoHlohMwL9hwINqKT7IcIu/40N2guerUUDkS6AJdQ/Cpgt\n" +
            "8ojDki61EgvFRQm32WuN66Pp+DADM0vqNyXw9ZWtoM79lWrnRApuyJQ7YnNFWEe7\n" +
            "nclgNBqXEafaF2eRENGZg1VxruRGRgpa8Oj0Y1lJ9e6JGVi0uGyFDIM3bttuxs1e\n" +
            "6li+j6MB65aCk6bfX79Binzf6xjCQ3jSZXlfqj4aIpcPgzVNmSz8951/5QSnGWLm\n" +
            "ke4muuEUrz23g29+zEBHJ8Lnz2TF8Dnu7M0AvsgnPc02qO1H7tr+58uydeVvgGqE\n" +
            "RJv0Gdfb7wqqvw91DK+gVrfj8G5Jr52D7NANA7H6sq28lAxVDBDfIjbjqz1+cQai\n" +
            "79O9l7NNPoz38YvCnHJke9HGSX1s6X717DSpptYn7hZ6NBZVwGDAglPhDlx0MkbQ\n" +
            "uUs1pZ62SGCq50MImOq//lh2wDhAx32E0M5SMEHUSyHiWm9SLDx09sTZ1kiP0dXQ\n" +
            "BcDI6obBu0Y7/2GMN7gYkoKxL2+WNqSrxni+aCLNhyAlAJsr/5aAEqlWpWLQrFyB\n" +
            "WNPxCpj3+tm06kUTtrSqgHp6vclXkbPefTJuDP9losLG1DYu6n6Ylp5tVgEOi9mI\n" +
            "rJdMpRd6c0h8bZThTxCosR6230iKwBbfW3NEAurrALd7vEMrINCxia4yWCpH1v1t\n" +
            "wSdF1cuugzMr16MyBlUTJVf6jf5hTo44TzR+tGOAON+rNNJms9s61Ia/ZSDQqy+W\n" +
            "zIKucLvKUiAECoqLpMn1ZYAfg2iUjdVc6MiJAQh6bIVXzmTqH2RtIXMg9dOl7iLO\n" +
            "a5xgyH0kjrFPUt0ObOCLuF6RnL97XHwONEXskfAmK6qJOsFJnauYkxAHoQlz4xyY\n" +
            "mTDbcLH52T/jOD7o7t5FvxMZbu1DT8NYwnoVpC9YSDUWxGJUNX20ISFcGUJmHFWw\n" +
            "7anRgfyQ1hTlMncbaDpOepP9xMh6oVmDr+QT3KUjKGePMIKXhuTSrwczRAafnkp/\n" +
            "WxYxKWLGM30FJyAvf1o9Jk+jIFAXwXyeaCnHeCxtZbOO+oxug4oRipMMqE0IeG1a\n" +
            "fe1wZNwg6F6H7RHjayubHZZQLkQ5lsT0EX8o5FpzzfpuDFTQlWx9R3XIYZLJsIAE\n" +
            "8zDt5nV5N0ZepX2AURo0cW+fR0mn2aK3AqvApL9m3mgCtRR2NfVZCAXw3Wc+BmSl\n" +
            "rLAZH5Y2Lxmxi0m6q8AL6HPnVp/+LjlHhhnl8ZWTVdN7nDN5m+cnemR/LMv9IEZ9\n" +
            "3Jp4i5B0OD7p1rpYFAp0Ae/EPu1LQxn3htGNuBXTUq6zU723uVMjHaoX9IIUSg/W\n" +
            "1BgW9HnCgyafWn97m/IVUDFVvCVxI1m6ohLSeiY2/y7MvEsgJzotnXk21VsZBxxs\n" +
            "eIS3mqWCfbcH1R/8hLvDeulWgkz1rUHoYyZsBfBe2MpfYapkp2kwj/JCQ2Bse7bW\n" +
            "lI6cQJDjta3/fAqmCW6xrU5THGSCaoFnpLVx2Ya74XsywaKnXGFPBAcanFOm0/3n\n" +
            "JW5jYLorvjDYhoMcK4iUG4b58hZZckStm5ZrPsx4oJ8Fhk6IljrQVbFci0HPz74+\n" +
            "JnNDDif1yTVGQ8Mp4zwtj7yCVJWnkxvXOxy0T3GPFNlOPXlMcq0Waw2c50SgPOQk\n" +
            "upIuizdkXdB5IU89F76pKuW+cH71fn5qkOclVp99lcXfSsxBwBGO5iEc4+mjibYv\n" +
            "3DLoCLj/WnH3IHTx7l6809pxa7eFr1YkU+X36OJGs9sHUX5ohlE+LJHA1qfS5SRm\n" +
            "srbT93DNJlfgKXRY7vDwl1Ng253cqoytLg77LXl9R+yFn5C3DTFfXuiIBVI/it5Q\n" +
            "xiBmQ7++8vHJjr9nk41dlG/GFSOq2Yzc0at75O8VkJvY84PkhbdHrX+ZovCIU62q\n" +
            "qYX2tCcwch6qRNaIovJf5t89jyIbdyWBIjM+IgABCi82QE2QmJvLztbm5wQiKDlN\n" +
            "T151dnh+f4mcsgkfIEBRW2tudHeLjLXI8vr/CCQtNjg8Ql1qa2yNrrPD2ODo/wAA\n" +
            "AAAAAAAAAAAAAAAADx4vQjAKBggqhkjOPQQDAgNJADBGAiEA8LEHD5VbzlvCpRvi\n" +
            "rZ3JDSHcUEFHI3GeeOOhMN6isdACIQDPvRrMrkhjfT0SXlwnCShrK9QjnLjSAIIL\n" +
            "j7Gi9ZksbQ==");

    private static byte[] extracted = Base64.decode(
        "MIIPmjCCBg6gAwIBAgIUSq2wnmbyhuz2O1DahpLbE0N075owDQYLKwYBBAECggsMBAQw" +
            "MDEuMCwGA1UEAwwlQkMgRGlsaXRoaXVtMiBUZXN0IENoYW1lbGVvbiBJbm5lciBUQT" +
            "AeFw0yMzA4MzAwMDQwMTlaFw0yNDA4MjkwMDQxMTlaMDAxLjAsBgNVBAMMJUJDIERp" +
            "bGl0aGl1bTIgVGVzdCBDaGFtZWxlb24gSW5uZXIgVEEwggU0MA0GCysGAQQBAoILDA" +
            "QEA4IFIQCw+/WuLoZ3bNeS2r8I+U9wlsfLYutriZz/s9XmDSxwrHeizlVLxFZns2tG" +
            "OzNeEoRT64QB6WZ3o+4TZuIo2/+Jkwdpep0thhgE2ELiPymkG7StdogS00Sya/ahXx" +
            "fx9sDYdTrf9y3PoYd05jnuaUnSXtyfJEJWZKh9MZwtCOCOd9eFB4S8iqgOd3KpuK1I" +
            "izHKudvjoLctsjlUSVu4A4dU8tozDZzT1/dzkBvhiYnCBUGiaTTJ548NTFh1tUVYC8" +
            "34TP89fyyJyRWb/N4XNgPFC3AuX4JMI4h2JKf50wSYzR/Gs5S60c9UugqoDFpOtKsq" +
            "h7Xyj6i+P61w0MGB30gr3JYeD1olDAweGXLNt7oAw7PiMrngkKf8alfrq1EGGs0oNr" +
            "+OZmbmk07uGLDdRSTU47LubAw24YmAyIzGL86HXMG0meYmL5K+g1gRCuX/k/uG8zSh" +
            "NqXMuRFp0ii4a7LZ+ODI8Xk3wg744ehKuk6cq/SkEQ38ldnMMRNG/PoVCKBjTtrZEU" +
            "JZnjfzzqgOiX+NJzb7PgiEwBvvxj7yB1nTwLblyV7jGdnTRoRx70s6a7ZKq9QQC3R2" +
            "io6T0rHE56qCpRQw+qfvQtBVvtHFCrrI58i43KKAlZAl1uHkil4vOYlR3TWgZjHNtf" +
            "sQwU6w1G6daKyP0zG25hv9DPIEJ3beDSteJ1wqZFdCe3U9RXpcBod0fssY8hOK+QiM" +
            "CvJjce6DAu3vgLNzIEvgWxcR7adT7O/AYg1zVxg/0TvpCH85N1nKymFawNabdDYI/Z" +
            "FLShwj14FuhTBL6bu5X/+dz436N+RMTRJpoWuhkJiSaSaFUUxPYhq0UF4M1cbJSngS" +
            "zIxJUwiVLccCGXL4C5g6x4DokcsK+8vARybfgH0uD/0u4q5hnbaCot0TsmrILWVDkp" +
            "DBoZvW++ZwZJDyxFYOy3oqOJdp7sgplupMpQxBZ/0ZfG4LIcPukcAiV4W++d2wWryy" +
            "DF2wWdMzklYP26rN0gIzGH/kRQJo+CIZ+YIUIB3cqG6qO1dJ5E/Vfruky8FVNniEXg" +
            "nI0i+Nvgv5W0HKjbRW4yKMPpg0Ym6kjp5MGZgqwZy57qJVw8GBeBiccVkdUzku39N5" +
            "yhQiSppk0gzxxaitICdF7ha89S+aBb4Fu9OQUmirxSVO1+7rzxF3upt9uVCkpbqb3a" +
            "3H0ueVpAFShoaurYJ8VIREzR9JvHEmQpbulxPM+hWx9SqpqD0CJUDoOafuSkhZYj40" +
            "HWBkiPbw7RplxfHJya4rFaRCU0V7g5xLqZGhtnNlFTrUc9mRrzhIgPywNzj9rZ+hST" +
            "YwWAkte4EmV2r43zT+IJ/VXpTrRd03ry0fU8GRDPF9wLQRWSu50G7I1KWQHdkgEzuo" +
            "fJAp/7L35ac2gBC5Re5xSFulE+htdejtZCy0InXxMMkwvKzxsONfYS88mCip2wldrj" +
            "D0QpAdB1+TEskL//y2BjgvBBO73EYnWz3MkgNb3nd2yYhknGPF3Oft491L1CJP+KhV" +
            "vAGtVoyQdB4nMaEoyuf0AkTis7wLVeQSpseT03iHkT1c+OHzZQzb8s4DCHKH8PWlWA" +
            "9Yqu7leuSnlhM/k6dFaPdXjk/ZzYfmcDS2EbH4kp2tOpYZBb9SVMqc3p6jZX10rnpy" +
            "GNGpgrvaxTxWago7/Z6uiPmzbW4w9d+J48kta06oGTPg34qmS+8oIQGOUkkSruafFV" +
            "6aq1DxDJp1j60KqRt5Est1MuGwa3Av3fcH68JinLvooyYwJDASBgNVHRMBAf8ECDAG" +
            "AQH/AgEAMA4GA1UdDwEB/wQEAwIBBjANBgsrBgEEAQKCCwwEBAOCCXUA5/Fn/tkfYs" +
            "r1gM6OnIxRs5HDWD6ExtUgsAmnDCVVSl+UvL3/syY1bjV/+7eXJHP0sMKdidMe23CB" +
            "Ygxb/IEdT7U9Y5EexaO7Nr4KJpCILV1RsCukPxhmUP1FKXJ3HiLgJVXvPFkvaLQK3P" +
            "oo+WE4LBPT/f+PYz2QLpJ9k/Vy2h/Vt9LBD6aD11UXCts5aZDJi90h6QoOm87exjej" +
            "i3SaoqAbbimNEwGXK1cCdEo/H5xeY9X50OalOGz9EBq5FkDZdqdiGd+NPj3WF2Lpj1" +
            "tGlOSrEAnBZxs9k8qIIFGyl8hC4/OqwU5cyqz5Vtj0BWSvfxRn82GenR7M0W3G7srt" +
            "3mopKFudzjMW6Qq5fXQjRHchPZcLRs/g74A5PDSXgr2W3jX/UBWhOuYDpBtQwuOiQp" +
            "bgocWtIUTb8TivT/jPLYo8/SZbCpW7ZEo6alp1D6DHYwJydPojepK+y1TlupqaRK52" +
            "syuYZhYhj7tz/Cr6limgEfu9detUvrbjxDVmyg8quFNcIBJt8YKaQkxm+gR4Rk/uea" +
            "FK/LMix45OtKwvQrHWX3WOEYWLSClYy/ElISzBC8CukQ6vUVIrurCT/GfF2RL50P8u" +
            "9tJVVbgP+wShgfsuPgf/x1JPji4Rse1u2he/Gj0mvWcDDxGk7+mwz3UmP8isZUwjxi" +
            "mw1PkQHqc5PBjsPYOirvDD2VB/QUo5ucUSP0M7ZcVjezB5UGgkk5RaQD2RGVP79lWl" +
            "5wMUbMW2HyFsQIzVCJhOC+dbufI7kfex/xW+6432jPDOYy3wUL0ihxEe870h1QR3DU" +
            "8wVLF3U98wMP12ysD8GDk/iwsahmpLClVQVTIACFgVbz5F/K8EggzRzB+lNQLWnUhe" +
            "lk+C7M9u9pfIoX2fKctEBwVbT748kgfsgCcMHL9vwy/RDvKMwcciQz4U0wJqmBzYD8" +
            "GfE6c4Y3xd3ijzpjW08kjRvKLKyjjbSftpdkaYnKnrkIN6twhd+tg8hkssK8ZD5MeI" +
            "/yTmwO6NGUD2UOiHXVWgN4zAQN5TamJLl4GdTUh/eBdU7aCq4XfudBLY68qSuN5EcL" +
            "1bFpF86W4ac0hKE2UEm0Ix9Mv/fnHgTk69r+U3cV5BInHk7aPfUH7rQdcoYVaP91fJ" +
            "ZJnBV9NwPLDhbT2nljsiKY3tdj+L/n7kX6JTWMpxFE8cqB5aITMC/YcCDaik+yHCLv" +
            "+NDdoLnq1FA5EugCXUPwqYLfKIw5IutRILxUUJt9lrjeuj6fgwAzNL6jcl8PWVraDO" +
            "/ZVq50QKbsiUO2JzRVhHu53JYDQalxGn2hdnkRDRmYNVca7kRkYKWvDo9GNZSfXuiR" +
            "lYtLhshQyDN27bbsbNXupYvo+jAeuWgpOm31+/QYp83+sYwkN40mV5X6o+GiKXD4M1" +
            "TZks/Pedf+UEpxli5pHuJrrhFK89t4NvfsxARyfC589kxfA57uzNAL7IJz3NNqjtR+" +
            "7a/ufLsnXlb4BqhESb9BnX2+8Kqr8PdQyvoFa34/BuSa+dg+zQDQOx+rKtvJQMVQwQ" +
            "3yI246s9fnEGou/TvZezTT6M9/GLwpxyZHvRxkl9bOl+9ew0qabWJ+4WejQWVcBgwI" +
            "JT4Q5cdDJG0LlLNaWetkhgqudDCJjqv/5YdsA4QMd9hNDOUjBB1Esh4lpvUiw8dPbE" +
            "2dZIj9HV0AXAyOqGwbtGO/9hjDe4GJKCsS9vljakq8Z4vmgizYcgJQCbK/+WgBKpVq" +
            "Vi0KxcgVjT8QqY9/rZtOpFE7a0qoB6er3JV5Gz3n0ybgz/ZaLCxtQ2Lup+mJaebVYB" +
            "DovZiKyXTKUXenNIfG2U4U8QqLEett9IisAW31tzRALq6wC3e7xDKyDQsYmuMlgqR9" +
            "b9bcEnRdXLroMzK9ejMgZVEyVX+o3+YU6OOE80frRjgDjfqzTSZrPbOtSGv2Ug0Ksv" +
            "lsyCrnC7ylIgBAqKi6TJ9WWAH4NolI3VXOjIiQEIemyFV85k6h9kbSFzIPXTpe4izm" +
            "ucYMh9JI6xT1LdDmzgi7hekZy/e1x8DjRF7JHwJiuqiTrBSZ2rmJMQB6EJc+McmJkw" +
            "23Cx+dk/4zg+6O7eRb8TGW7tQ0/DWMJ6FaQvWEg1FsRiVDV9tCEhXBlCZhxVsO2p0Y" +
            "H8kNYU5TJ3G2g6TnqT/cTIeqFZg6/kE9ylIyhnjzCCl4bk0q8HM0QGn55Kf1sWMSli" +
            "xjN9BScgL39aPSZPoyBQF8F8nmgpx3gsbWWzjvqMboOKEYqTDKhNCHhtWn3tcGTcIO" +
            "heh+0R42srmx2WUC5EOZbE9BF/KORac836bgxU0JVsfUd1yGGSybCABPMw7eZ1eTdG" +
            "XqV9gFEaNHFvn0dJp9mitwKrwKS/Zt5oArUUdjX1WQgF8N1nPgZkpaywGR+WNi8ZsY" +
            "tJuqvAC+hz51af/i45R4YZ5fGVk1XTe5wzeZvnJ3pkfyzL/SBGfdyaeIuQdDg+6da6" +
            "WBQKdAHvxD7tS0MZ94bRjbgV01Kus1O9t7lTIx2qF/SCFEoP1tQYFvR5woMmn1p/e5" +
            "vyFVAxVbwlcSNZuqIS0nomNv8uzLxLICc6LZ15NtVbGQccbHiEt5qlgn23B9Uf/IS7" +
            "w3rpVoJM9a1B6GMmbAXwXtjKX2GqZKdpMI/yQkNgbHu21pSOnECQ47Wt/3wKpglusa" +
            "1OUxxkgmqBZ6S1cdmGu+F7MsGip1xhTwQHGpxTptP95yVuY2C6K74w2IaDHCuIlBuG" +
            "+fIWWXJErZuWaz7MeKCfBYZOiJY60FWxXItBz8++PiZzQw4n9ck1RkPDKeM8LY+8gl" +
            "SVp5Mb1zsctE9xjxTZTj15THKtFmsNnOdEoDzkJLqSLos3ZF3QeSFPPRe+qSrlvnB+" +
            "9X5+apDnJVaffZXF30rMQcARjuYhHOPpo4m2L9wy6Ai4/1px9yB08e5evNPacWu3ha" +
            "9WJFPl9+jiRrPbB1F+aIZRPiyRwNan0uUkZrK20/dwzSZX4Cl0WO7w8JdTYNud3KqM" +
            "rS4O+y15fUfshZ+Qtw0xX17oiAVSP4reUMYgZkO/vvLxyY6/Z5ONXZRvxhUjqtmM3N" +
            "Gre+TvFZCb2POD5IW3R61/maLwiFOtqqmF9rQnMHIeqkTWiKLyX+bfPY8iG3clgSIz" +
            "PiIAAQovNkBNkJiby87W5ucEIig5TU9edXZ4fn+JnLIJHyBAUVtrbnR3i4y1yPL6/w" +
            "gkLTY4PEJdamtsja6zw9jg6P8AAAAAAAAAAAAAAAAAAA8eL0I="
    );


    private static byte[] rsa_ec_cert = Base64.decode(
            "MIIFKzCCBBOgAwIBAgIIaLtn+ZoOPkAwDQYJKoZIhvcNAQELBQAwMTELMAkGA1UE\n" +
            "\n" +
            "BhMCY2ExCzAJBgNVBAsTAkNUMRUwEwYDVQQDEwxKb2huIEdyYXkgQ0EwHhcNMjMw\n" +
            "\n" +
            "NTIzMjI1MTU0WhcNMjQwNTIzMDA1MTU0WjAxMQswCQYDVQQGEwJjYTELMAkGA1UE\n" +
            "\n" +
            "CxMCQ1QxFTATBgNVBAMTDEpvaG4gR3JheSBDQTCCASIwDQYJKoZIhvcNAQEBBQAD\n" +
            "\n" +
            "ggEPADCCAQoCggEBAPTegns+vTNALyCqUhWCAe22B1hDi63F4orq48sgQDl98zLd\n" +
            "\n" +
            "xrr4BwpJ3Q+9y8f2SiRjH7rjMo8+Ry/o0H+etSzYi/7nf8sffc2+w3cVRzYd3GBV\n" +
            "\n" +
            "bXaFb+7OP0AlBS6lc2w4j7zm6thV2hz9L7XKEEt8O8MHCttbODVGXGihb3Dvw0XV\n" +
            "\n" +
            "UEDarspb4/zN1eKhK+6uZLyl+WkdX3Pev2RDbUH/Mz990YCpC5eWozDpA0NxgOP8\n" +
            "\n" +
            "RDxkBwx2TuUYwB2oCmyVsZ6vaGVCSL2kSWjdBVM6f60LgyMvneanx+PET5IX/znH\n" +
            "\n" +
            "+NQoiJz3Hb82KuPZLg+L/CIG0DiDEYJvD1yYY/UCAwEAAaOCAkUwggJBMBEGCWCG\n" +
            "\n" +
            "SAGG+EIBAQQEAwIABzBOBgNVHR8ERzBFMEOgQaA/pD0wOzELMAkGA1UEBhMCY2Ex\n" +
            "\n" +
            "EDAOBgNVBAoTB2VudHJ1c3QxCzAJBgNVBAMTAmNhMQ0wCwYDVQQDEwRDUkwxMCsG\n" +
            "\n" +
            "A1UdEAQkMCKADzIwMDkwNzA3MTg0NzU4WoEPMjAzNDA3MDcxOTE3NThaMAsGA1Ud\n" +
            "\n" +
            "DwQEAwIBBjAfBgNVHSMEGDAWgBSLhHJw3CWoK6tG+vDHA4+A3WZQfTAdBgNVHQ4E\n" +
            "\n" +
            "FgQUi4RycNwlqCurRvrwxwOPgN1mUH0wDAYDVR0TBAUwAwEB/zAdBgkqhkiG9n0H\n" +
            "\n" +
            "QQAEEDAOGwhWOC4wOjQuMAMCBJAwggEzBgpghkgBhvprUAYBBIIBIzCCAR8CCC8r\n" +
            "\n" +
            "86yn2wm8oAwGCCqGSM49BAMCBQCiHhcNMjMwNTIzMjI1MTU1WhcNMjQwNTIzMDA1\n" +
            "\n" +
            "MTU1WjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABENMAU79zHGMdY7BrUcoi10Y\n" +
            "\n" +
            "2v9yGwq6rF/el0HFrAVIW1f9GfPZZQI5OJnqf60/X2IRc4KecyfqiVjkD3GEWJyk\n" +
            "\n" +
            "QDAfBgNVHSMEGDAWgBTWuDKUFK1U61Y5aP6Gm9/hU/81LDAdBgNVHQ4EFgQU1rgy\n" +
            "\n" +
            "lBStVOtWOWj+hpvf4VP/NSwDSAAwRQIgH6haXFeIfy+TOPWFEsxfFzehVcQAy4NL\n" +
            "\n" +
            "gH1wiKp61ecCIQDGD0NqMadMAnrfIy8MiH6kkZ0LEKDVpbh3k1CvaXVB+jANBgkq\n" +
            "\n" +
            "hkiG9w0BAQsFAAOCAQEATtjhu3Yuy8mw0FIbvxm8LwE18OAb4De7XZXBBQrHHlA5\n" +
            "\n" +
            "HNkvcPPba7171LcpIZx/SW4C5sIxfwn0rFZ8uTUKdiQSmmqfwH1t2NZ1fF+oADF3\n" +
            "\n" +
            "goxuxEYHczqVUYSugllqMJx0T/7HgD3JEd3DOYrk4k2ksE557xVwEm5OBBNTiz0/\n" +
            "\n" +
            "2M72GRsSbma2xo6tFiQ6iYfI3B2NgW0jekN9wOlF7p+SZFeq1afSEDrfVSi0DkVQ\n" +
            "\n" +
            "zyn7PMrrZgyYpjWr1GpnvNBcZDEpH7TML9GUxchn31w0FvaLMMgYJJ2ha2ohPQxV\n" +
            "\n" +
            "tV9dNL7ivNP74nJQqT1x05vXhjrL86VOlwxa385geA==");

    private static byte[] deltaCertReq = Base64.decode(
        "MIIP2zCCD4ACAQAwDzENMAsGA1UEAwwEVGVzdDBZMBMGByqGSM49AgEGCCqGSM49\n" +
            "AwEHA0IABEqIRHVQv5GkHTHTBzPZFAiCVbMB8h+uTZ1gV58O2rnCBn4YNqpIj8j0\n" +
            "3w2myhahWFeyw/Yjq1CgyvbjbglieUuggg8NMIIFfAYKYIZIAYb6a1AGAjGCBWww\n" +
            "ggVooB8wHTEbMBkGA1UEAwwSRGlsMiBDZXJ0IFJlcSBUZXN0MIIFNDANBgsrBgEE\n" +
            "AQKCCwwEBAOCBSEA8FVxiaOOy6Q3iNLf6l0teGHOuJq8kXEd4uHXmVDBgZOvb90c\n" +
            "8frAULVblAD2Ky6c9Ra/BcjXtenWXDxrd18ky0s0E/YmT6tUVMDNCT0htbU2ONnl\n" +
            "8YDpsROlO1HHZwV9yYDolEeu2MJTwmQ42f+1udRt37KctrQ2OzvktRp1wvyz1EOm\n" +
            "0T0ORrHi3pS95d74ZEMlRdtG1KAW0vZ85SrNZu5TJ000ODBgvyIgsYPTwGDineMU\n" +
            "Vd2A/1DIhBpwFmv5lKeOLGVBZ9TqonlLuQYKVSWTt4MLW9BAl2S8AKP1XKqc8hsr\n" +
            "qpgcl6pokVYNbnwNfAKECtpy8yNJm8+5t254zwdcGMVPUFPcaincq1nYyc0OhBBZ\n" +
            "rd4tiVnv7anCOtapLewfuU/M60TWr83QKLfgiDb63OHrSLR1GSwPNcfY6GjttweQ\n" +
            "mHoQn/ymMxLF2aUB5KRN1J42r8tUYaLd4/NPIyrW3PuuD5xStnfP5Sm4kTxq3ZlB\n" +
            "Sg3kVIQW3k3Ue0a2fy83oT2nzasddu9ZaKzgox9cQN0eekm9LIzSjoLtDWqbSHpS\n" +
            "AwIvYtTRoORh/+pyJPefGo647yzvKnvyh7300d/OLPeMoErs3RptXRD8x9YiKnYg\n" +
            "uLfxMnIZB5Dmb+JSz3e4E3j3pl8/RkIbXpX4nU1Ng6PgVUiwu1/5swOL4tTsI8dN\n" +
            "7DJiY6WmjjNtkJX9YlWIAK7j2jZ6Bi7/s8saAXh0YmB94UI4opnuLbAJWVauSU22\n" +
            "TUR/qb6NNdHN9Db+EBkHnS5MAeve5jRZVsb0yTy4pmr4n85Go1h+KxZsd9MIJQu4\n" +
            "sN564qVeJ355hloKyXf7nApDWbkqCGAXjdSizhLkZ5hnm5tL/qTrgg7MldtlYEtH\n" +
            "ksmPGeeLEF3te2VKt1gSesJmeJkgvYczi0t4fAWpkZCbQe0rBp3J8SGRw7UuDAez\n" +
            "9rYvXdHIO+TSdUaWnhPZPTXEPJD8hodBok5Z5oJbKEtzb3kCkmz8OBf3sFGblLit\n" +
            "EHCTW25X/fRI3HpKqWy2J5wND5asyyPFzMXGYJJGx0eN3V3EFcs7pJXOmJlQfuJo\n" +
            "Q656TWsxzKJQGnwESqzOC/jnliYFX6ilab41CRJZXXJOMC0EYbcmaDsGouCQAJ8x\n" +
            "BacyWNzl3YCibK3SfCecXvMbOxx5xuNZju3KwYZtywmN9YBGqeht5FDH197KW7t1\n" +
            "lUA4H+cT+CUDSWQXfMHlOeJaLQFsOC+wACD3jIw8lObWTdssl6nLlf6L6xuCbGj3\n" +
            "pUgXLXa4VZNBXaoh6JgasuBsmXColmEwTmLNwxFrFKUl/DH1VW6zJRUc4RMD18kb\n" +
            "ys09EryX52vuTL23FOcqKqoIbQUkav1hEtGIGeArW1EpcQRRXEs++VOKSXr2Vm5m\n" +
            "efpKP1EShkjnBLuJxM5ybklnWp5Y9UIOIicl78nFq/yMTXrVZSnVcqC3ubnBg2O0\n" +
            "1++7R8XID0PUX6FK9FaK1Tu5D0I0X5p0Dntmf5VF/EsA7OF5Cmm+kPtLHn+XClEJ\n" +
            "w9SnrboMLa/Ltd0gML9mLanrv8UTKpVyFKD5B+Qiuzd+3HtxDbXZHjN5/AC7ibuZ\n" +
            "DuSWbi6U6N00VNmSzZ4IwmfNTdCkIPLGIFSJ2dhrp5P2oDfeIfapZtFukuWu/iA4\n" +
            "/iT43OeNMXwCg9wVb6cXBeJTifOAm/Rqm42UaDqsyk/za1M6YW/pYDNQzJBvvMqZ\n" +
            "p92GMQjDEqXv0dyIXzWBwDc+RUyATSY5mnn6O6INBgsrBgEEAQKCCwwEBDCCCYkG\n" +
            "CmCGSAGG+mtQBgMxggl5A4IJdQBmEI0USeb3jHLoswVnkl6bhVdCdu4YBoPWZMX1\n" +
            "4Ka4489Ns6pSgL5ex3r1W/4ZeI5XWqIqUXDIwwW2hp+OHLvFM3jbA3Weul/bL/yJ\n" +
            "pz9io3m++CKYP4KCMssDoyBwvTR5oX28yq9lc0L7uhgtWyACQP/x0kvci32pDQvb\n" +
            "GfcZcXGmgEmK4xRWOfnphwPSXGmyhH4+TeTua/u5+Ka1ShMjs7G/1G07CaM53Un4\n" +
            "mZm3gb6cbNGWxxRpfB7/lQs7ckjoA/Jx/r94uKz1wGHXkoyx9QEzjkHvR60i4REr\n" +
            "+Gk0kJhSaKmw15NMKJJJ0iMINWlzKZCnd2oL0eMIjHs2dx+H5Ea+DlveI9VNddDy\n" +
            "9bi/WeSySS3HdorakMCbIr862W3DLrIRupi4gPI+E/VKqD8cCLvzs1Ffgfe5MCi+\n" +
            "WDxu+7NGlGmd12LDr8NfwvvlvLioWsiSWWXRvONfgj2vrneRGGpP85COQbtzt+5h\n" +
            "N925iY3uD5qpKap0nQiWCjWVKMRFJXl7b2brouQu6qu7i1kyqpTOenNUXidgAtkM\n" +
            "5LC2Nsejyci1FPGbU/5JR+71tMA2aJ9Wku4hCI3IWfgQBNJ9YDCvahqSeILtHpTA\n" +
            "6IxjcQ6PCPAORFCyM+MHMrAr/y+SNMB7zoKkq/m9Rng2Z2artdZ5VtvigHbhg/FP\n" +
            "BP58laYE+LZ/NkVWp3BjQQow2MJujy9dzgOeU6ih0jjG3tg0QW0RuSloNhUfI1rZ\n" +
            "UAfqadFcy1nNtZMHEUM4F36Tx9kkPBeTaN/OJIa8ICNI9yNwxMOIRYmXlXldqQcM\n" +
            "lPzKuEeiHBwt5T/5piOynYSzNiE/1M9ILo87KjSLSv1BQZR+lI6kpmFZj7FFWyde\n" +
            "WFxvRCBeZNmMwQhIO9t1ZfqZzKCJ8ADqYhol9CZatyqVXNo8FR7BVnHFHcIM1JCf\n" +
            "A8/T4pTz9B6OZb+35fCeznyNe0XckfRYRmAtFrJOikMSF/YF6ZvYqd/eJLvs35it\n" +
            "cCE6Y/liPFS8QG2oPBunCGxLp3wWo11YsO4ViOfHjrV2aHhYM/aQvLWwgR+xqdXq\n" +
            "xrm3xWtLr1u3EpRLWouMDuiCyqCtAwsra4UyyO1tFRLsYuGAZTQZ+JCjO1TOYmdE\n" +
            "vk+CkS3fBTeajFbBIrMJY5WIFdHWcbjIQd6rRHkpNMN0RnytL9X9P7s1hxyhfOM3\n" +
            "BLAguLuuoIyWwmXkvxWOu52i0NIdAuv9PXv2d+l5LYd8Tqz9Uw2DUSHj6bIQZhdH\n" +
            "0k1rw8PkxYT0LXM5zmXPxlVKg1uHDkRn/rf7bkhQ16GV4evF2Pwfg0JS85aE6WA7\n" +
            "+3RjAi+pc2NhWHtNObVvEv/Cr7MT6jLk242TZBk7z9h/xsa6HHIM95bmpmqPMm1D\n" +
            "j4hT6eHosVynhgXQYYuJixV65mFQOjJFhzGi1mP4jLOggZ81Bjq1yg5+Kor1CGPT\n" +
            "ufbHkr60o0FTu49ASWgLLLr1k1RQBNjADcDQfmUio+XJJfZQlfTiYx25IaxX/uha\n" +
            "0WZYJo/8UNfjsw15pQSSQf/o+NQwvCs7pWJoa4D9mhzGlAakI+33A89nt+W7szbN\n" +
            "5f00CpJI5UUv/k5E1hDSVR1FeCq0DRruBEVF+YAHKWPEEdCGoc5x0QnHiiZeAQQ9\n" +
            "Z49VJSXxRjK+vzKl4mmQPYJtA2sAm2CrGYYYujJQ+hk6M3HL3iA+IyMczpTwtHCi\n" +
            "ImOZxNt8yt6xlpYhUoHhwD8+QVI1IPWiciIseCzfdYK9ZZVO1QeQTyqVLflXeMOK\n" +
            "snpuAQTPXEcxylVtG0Gqux7BQM7REYb1VEgIzEQ80CyL9CeXOzQRojlNB5k9tVZ7\n" +
            "cUIEaAzNrqX8iJtyhUkxuIlmodnMkMlMWDFMn+gz1SA3+nAGT1/ea6RS96R7xUAN\n" +
            "tzvMxqrQSctz/+EkGwnF7HVq5t+YG5rCWYm8w+ZuB/MXbFobvccChjBL0LE+sTqr\n" +
            "vkbKqzRgVgqkW27x+BVxRCXtAbgEknsvmVFWzb6/ez/6eyRvJX1WgwlWsS5X66CE\n" +
            "HD3W2rnCasL32g1iLVhb7GPfOi+37yjVwCpV+PHAVYEGvYeuNDovsHuYnPk2lh8Q\n" +
            "WWqj0ws0tniCXxaQxgC5QVbQsuideloPnJwWNDSSeTG2OALoiVC1mXNTbkLZyDbe\n" +
            "9m3VmCfWHXONtrICAaXk8Zrvy0rJWTkOK/yo1RIALJirZqAewcf+pr13k8ZZCUB+\n" +
            "rN74OwWsTztpBkHuFZjJc4FZXagvS+f+TtDvk12aR0ka6VvW+zLMdFiDiaPcub4B\n" +
            "11guEYLkqCg7yFuocqn+9UBA/Jued8HQDnmW13D498qvp5nWOz/Vnk5F6rf882iL\n" +
            "Ex0MDvXnEFfWPOnYQ0mETWWvmhYTzlVUGhrN0WHi9MTyRByWZ4m48+wfKhtyDbEV\n" +
            "on3X+dRqdlqdaGKtXjGAByForcym7mescUF9r5gu/EDICYtek9iPQqlXY0u2Yrp6\n" +
            "8Q5zMUOwjVoTjWHVDIgOVjHGBoBgCPUwzgrVQuOMy411yvm+DYUdtvoWpYTAGNo2\n" +
            "RX1yeDROevYe0p4Nk34HoYX2cj8+Ov9KoDNf2SgH3uAdz8SFl6U7F+ef6SpOxFSY\n" +
            "s+VV7H8V+XQ59WqNbZbf70vRPlNd1gpjI3iksBehGHX/n6L2hPIwQnvvVCJbffEC\n" +
            "DsFykZo9KpgvbRetwSwOLYoGUhQDb0dIx6WyATj3klJNtYJiLweb5PaelwZ8fkJV\n" +
            "+vksYRenfwm+VaMiLtFWd4oHR+zPtLwUMvKMzqOeEe3VhMvzxM356LzeZyfjz6uF\n" +
            "negEdIn8G0Xb+i91SKKZWVl+1jBXE6ov40/SFfneHi54uA1/9JPf5K4aES7yTtml\n" +
            "ffk6Nc5Z54zFkhO0ggWgEJt7CT/eQDz5jqAT40Q7lbIxvQcPdG90WmmhxjOGKfLF\n" +
            "Ug/FQuG+dlw4xBCIEC04zBjC5TrCbSjNm0xGkHCeKEIzIN3eIKbQ8S7Fs4zKqn1i\n" +
            "w3kRxcb928h6xfb2SsESKF/9U/8kOpNITE+XPug+WYLzfh8BS8kfxut3GGTArYAn\n" +
            "TCOOooJldukCPIxd5Nf1SAitlbUyfjY9i2xWDUiMdPxNYtSZ5f9HgDgcHSTrm9EB\n" +
            "SMAl1jtCUmN+hpmkp9Dh4+vx+0NfYmlzhomcqa271djb6e31AxEdJCYoMTZWb3uL\n" +
            "utjg5Ojr8v0BHiEoQ0tUjZGam6S7xcfP09vj+/0AAAAAAAAADyA0STAKBggqhkjO\n" +
            "PQQDAgNJADBGAiEA8Yi24L05Pkn0y6Umltpd6Hhw/TyFzB7SmaEEEcn9+iYCIQCA\n" +
            "ahofKFqOtfmLrzh+a8VCq30wqdJhqf+imN28KcziNA==");

    private static byte[] draft_dilithium_root = Base64.decode(
        "MIIZTzCCDFqgAwIBAgIUONT0zs5OI1dwa7N+gcOBNTQEwSAwDQYLKwYBBAECggsH\n" +
            "BgUwgY8xCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2Yg\n" +
            "UHVibGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1\n" +
            "bXAgUmVzZWFyY2ggRGVwYXJ0bWVudDEcMBoGA1UEAwwTRGlsaXRoaXVtIFJvb3Qg\n" +
            "LSBHMTAeFw0yMzA1MjUxNjUxMzhaFw0zMzA1MTIxNjUxMzhaMIGPMQswCQYDVQQG\n" +
            "EwJYWDE1MDMGA1UECgwsUm95YWwgSW5zdGl0dXRlIG9mIFB1YmxpYyBLZXkgSW5m\n" +
            "cmFzdHJ1Y3R1cmUxKzApBgNVBAsMIlBvc3QtSGVmZmFsdW1wIFJlc2VhcmNoIERl\n" +
            "cGFydG1lbnQxHDAaBgNVBAMME0RpbGl0aGl1bSBSb290IC0gRzEwgge0MA0GCysG\n" +
            "AQQBAoILBwYFA4IHoQBxNIVkcLajfd6f/9uOqGfiWPTxem6oTmbQ5N0TOS/j0tfI\n" +
            "qxjz2CW2h5wcbs4UYc4KylsmNbhy+lo/3s0jbRmOOPuBVmv8dG8NmDty2ZWK5m3Y\n" +
            "hJIaujOAYSNfzRPax/7pDX4+oDL0zfO0i6S71BmBzcamX/11WxdI9okKN3Z7NQns\n" +
            "CMmfBtWab1POC/eoRwQ4+Sk39xpp2NPlSEeLVoQtgdLvmc0DNL87Gcoao2YfxXbf\n" +
            "Gyx/HsKbi03o7/nmLuT0LvTe0YhQ1dE5c1fxCVQHUeXFwyW10TyHfZMK+0mT77ig\n" +
            "NSfsUeHMEjqNPNhO94QLds26awaJAbnZDR9LJQ//TvI91FlwruBxnZtp0+2DR6jN\n" +
            "4lTIuaKjEX+HzxZe6k+jjg35erc3PEXNH3+kzIEWHgjYmANftoI4wulK9FOf7RVD\n" +
            "6k/G1/vIupQUZQ7brIVbWsevwUWgxpxNs0+noedA02nLjjqZhkM1bIqOt8AKZJgX\n" +
            "5ie6btnrkMMUFocxG5yvuO4fn7rreWv2T/S+kmKGou7scEyUowwjYv4t3sgFw0tN\n" +
            "4iK6htNyNo/9jX1Tei9QUibhlcqcMkVw6dGZAGSxdAvH0hD5NXi/dweENCaOGCPn\n" +
            "9Wza/g44TnLpXLH97U47tC0Gg2+do8jspmBBu3CQ6i51qJUE5vJxUCmlZy44PRXc\n" +
            "E9K8VUwtlma44yyfGmg9tZdWwZggt+gv+PION2T35HGzA5Nih7zCRK8knn4yhKoR\n" +
            "0H4IV0f5JrtoS1QlqTkaCJ5cv7I71hPPjQ3Ghtq3pudHDL/taFUApcgcaIsHQTPO\n" +
            "Sicp5/yW6+8xjEwiW3p//XYlrB6tsLkSXAz5UyxiIjwdgnZra/225ORg2a+bvfHb\n" +
            "wEircmGzVQEAqem+60l+J44slM1pR+tWSKi/AUPHl2yK7W83/uz4uZmYrqO1GWCc\n" +
            "2cb7va/nWPCKFEcX3JbBXpT9Xvyy1VFDf8WV6CxRgIk3E7ZxK04hLnTRCYNLuTc4\n" +
            "Bp3Io6nWmE0VgJs+jl/n5kcimU76p7s3YfnF9TOCtoQbrfIRX2FhBFsOeKZsbMDQ\n" +
            "zlsBZroMOAQ+cr+UwohSYX+yXKKK1ARPFFYdyYgLaOYzYB5pFr1BeM4fQrCoF7EV\n" +
            "PvWvYcaeoBQ0y7mpGVsKbPsp2EIZUIt/HY519acbHjkbIoAgTijBKBZuXbHOm5xj\n" +
            "58bvUeZt9k61U/c+AzJc7NnNf3HfHEBaXhvT5pm4GiVoFKmQZ9v8kIRNhuJ/ZGu5\n" +
            "Jhw7s/E/kznehECO8/iKn/gwoNiBCHWdyYrokv08G7XzMVunma9EvZCYY0O6bZiq\n" +
            "n2r0m7rvhMLkLHTrzGm9Ar6W0aXBwm03yeFo+zQIBr4AdNWXpy2Tt4NJYa4iIW5x\n" +
            "RuIyA6yDiPICBrT0VAWadtalLNf+t2ZUgAB7QPX7Ixh5gUBlBRa6EUqCvQ05GzZP\n" +
            "o689fzDqej+HQcRO0mU9QELnD6GsvA/+FWPaI0Cx0ONN/fpq8F7/GscTQkxWocEp\n" +
            "nWgWnqGh2k7rIoPBSzZ4MRG9bqeYJkQrUv+Ky8gwnRD3sUTWs3DZgVKvhd2X8PRz\n" +
            "Q5Dmqv8XIcY7mpR5nBDdY4O6z7jc8pblnJsjWNBd/mx5j2DRlH9mF1z8pACIXYNY\n" +
            "/YJ5him7ZN8M0Wk9q/Dp1HK40EQMfRjg3budcRpg9a+sUMeq7cljfPaw/RPv06Lx\n" +
            "rtbege1o6va0AE0s9QUrPRUS46H+VmQmth/QW8+P0MDEGyPsOh92NUprbQmgVTf/\n" +
            "hACbb6sMeLEx3Kw0mndUz8PieOdt2d05RkfGE9SXjMLLV27NMRUocd9x4wCj2j7J\n" +
            "2kNp8ujQIg/CoYdVa5pEdmG7FlD4UBnRsoPjCgX6vC2Lnjl5y+AXtWzrQ4d6LSnI\n" +
            "dZpH+5kRPssNtIRdm70jZgRq+KDYWQwvKbu5+5lXdQn2Fodgj96cQJbFfKlC9kfh\n" +
            "efykwuSn8uE8bYRwegx32px9UkeDhaPwUcLF6OC0OGgpbxyfbcqhdWhGGvTFhh3G\n" +
            "oZrm8ssBJDiiLA6azYJs2pCh9CG43CCRoB+DwS4c6xLkCWU779Pi8gIovpUQBwUx\n" +
            "EdQu/d1GTN9J6Vy36ZEoc7KIiddC5sH+CHxju+LX2IIv2OzqLwFiwH6r+7NQ378z\n" +
            "aCOMMBTNMEQsyauJS1vfLkl/mnHyxVYpbwi9NoJCfAnUZntsEEP1mn7G3S4+IPYe\n" +
            "Qy7hBUQamFs3uT7xaOcbnoiHvlQ1rm88HrohWtVQV4FmODrKHut4meBLUdV/ZVIC\n" +
            "acel/kmq/767H28n8PaKiQOrXnPSpwpXxeKKtO+aMdvFhL9ytVOh3JTdX7y2rO6m\n" +
            "XmauwfpcEWh1P04kCSl39Q0fi1ZzNw2O3/fdEdn+k1hNd05utNuD4YPF8t3ph+Gm\n" +
            "fybXAgWaKx5qEyrBKPKGSpHNVCM++9nrVNzSlPcDcrtrGTd2E1iQ/eWdoN2hCi2v\n" +
            "m7EctANAg+XPcrCUYRqV8FDqP7BabLLXvl/2aJ4tEwYq2MkgA/K2svXK0NsUbzC/\n" +
            "703auA9NG0XnSGsM2ir4ZzHtrbb1jW6ipAvc3sdlDI+y6Mv8Ju/mJUPQouvsfaOC\n" +
            "AzAwggMsMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQW\n" +
            "BBQu8UGIwoTmWRQQ7brqObj6sy3nPjAfBgNVHSMEGDAWgBQu8UGIwoTmWRQQ7brq\n" +
            "Obj6sy3nPjCCAscGCmCGSAGG+mtQBgEEggK3MIICswIUTggpfah2kbN+5mHbCwF8\n" +
            "takhZ/ygCgYIKoZIzj0EAwShgY4wgYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxS\n" +
            "b3lhbCBJbnN0aXR1dGUgb2YgUHVibGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkG\n" +
            "A1UECwwiUG9zdC1IZWZmYWx1bXAgUmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UE\n" +
            "AwwPRUNEU0EgUm9vdCAtIEcxo4GOMIGLMQswCQYDVQQGEwJYWDE1MDMGA1UECgws\n" +
            "Um95YWwgSW5zdGl0dXRlIG9mIFB1YmxpYyBLZXkgSW5mcmFzdHJ1Y3R1cmUxKzAp\n" +
            "BgNVBAsMIlBvc3QtSGVmZmFsdW1wIFJlc2VhcmNoIERlcGFydG1lbnQxGDAWBgNV\n" +
            "BAMMD0VDRFNBIFJvb3QgLSBHMTCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEAdD9\n" +
            "cleoTHR/ViV1wHOF2+vy9SvqWAg9uC/dFTHYquPMh1/wL/f6LaJg2Oti1tL11kkn\n" +
            "jjIXNqBijLuzAwi25hjbAPYq0gTGRgNZvIGKuJYb8PD8DsWq6KQoFzzlbwDemxV8\n" +
            "HlyCxk9WL8re/EpMKPbTQs8+9hb8gtM7coXJIfK/Nv3YpEAwHQYDVR0OBBYEFI7C\n" +
            "FAlgduqQOOk5rhttUsQXfZ++MB8GA1UdIwQYMBaAFI7CFAlgduqQOOk5rhttUsQX\n" +
            "fZ++A4GMADCBiAJCAYVKnORbBIaDuB43sDb38eb4BB5y9o+wTLrIGV5DGA2yOUck\n" +
            "H56/L7H4yVFatiUZok6sRMOgGR7BY6BvuczFo22UAkIBGEMII9tQkwp/0oikSbkp\n" +
            "OMZH5UGlq8AL6TnD+YzMBgRq6dGZE/spGKLef6gyKQ1dKEatK/oLSgf9l7jgandU\n" +
            "ENswDQYLKwYBBAECggsHBgUDggzeAGjxVa2J1Vv0ogdEFtU61BqPvtG23l6GBrsg\n" +
            "kqPSt+6WHeHypIpiah5DKuCbbt27HvgnCe87G9+ktKlfx8N0+Sa8Y9QXfQ1gODHL\n" +
            "9GeDBx6AWrLFoZ9mcXcc2VrFgFwMqCgaUj9KqeQp69r4oHWsnm/1AaxdswKMakev\n" +
            "xqlYIeQDSspshGjWdxO8AuUd9ytW3f3P+IitJbG8wLnw98+LTotxgXwL4zOagkZW\n" +
            "KsIC0qCq/m/RUAA7SZIf1SXyJu5tdA/b1JK4NT6H74K47mk/j+RpF320DCrVPHkB\n" +
            "eyb/JmfEGuh4oJPyNL1Y5aYoGcX9c9WZpso8Hx6qndFeBpXsLGBU3XBwoKoUTiYb\n" +
            "JTmZmjcUHmYH3FXfHs+2HgtyoQ+tsnN9HaLkzJzwvbxZ4dYtGXm4uz3xj7mGGKkZ\n" +
            "j3LJyxzIuoW7yeOOKYXJTK+9pmmZTJw8m7qC4yXGesy7KhnoZ1/eujIFfZj5CP0E\n" +
            "RfRhj9wXS3YNLDvJ1LnKtA5syjR1oYuoQ/BkfdwULtTHeuzykf074/z+nqWGOpZU\n" +
            "K/Js+GJlVm+Hdi9YwS2c/QbzRkXj67gc2JNnRFid/omBJGt9bSqM04muf7kgn/FQ\n" +
            "ijcj9ANPvCs9Ltgnn5bYU7RpGJZQWO13u6KwYAkbYwGHyDm3WAH8CWUduxBPj2BB\n" +
            "GHyYhRV8hM0AVlOzGA2ZquzIDnnR+rzbBd6GjEuW41ZMTpKFPE1aUh8uC13biPjT\n" +
            "FpEptBLEsd/69umHSoME9EpQKAE57vV22NYtSqfPiiD4KFbKHn/hQ/VsIkLsi5Lo\n" +
            "9Ae5YVQoXMagHrl5R77s5fFKcjN+enRt6VyfC2mIWtBRU+QqTyd+cGTHgu9oKMsm\n" +
            "x8MAzsvKe+MjmQEUe2OdcRCYMqcf0m5bbpaeIBPdqHmdLAOepCGI43CAyJGPKzEq\n" +
            "+hz+iQZ1d3bG76qUErqDDGD+VEWlwcxf3qc3U5OJRb1SoA1ctLQ1d/Qp6u0MDFPN\n" +
            "O0yYoby4+ai3KCGGs6xPE8N/kqFpa8vyqlQzWeKkLPJ7rdJF/JWBWag4v1noHHdD\n" +
            "CvEA6x5z2UnntXr5FaZvbZV0SeDMIZz8bDeMOiHJ2np8hWoEFIqw+s7gz2IIxTvl\n" +
            "pFYiayZYy0Wjo+HfzetxOUFM5as7NmC1TClVy27+I1DgVZoBVjMkXYjlGmT4u0dc\n" +
            "GvIhkm5FE0o/BiNDRYB3UHAXW02Zzz6qa/xHLAQU4gdQyfIsv4D55NKlv4CoGhDf\n" +
            "+gj7AYa17InmHlbux7lgDoV88mUkf+po8iCX6EeyFmbBxH5p4zYjzECdJP/Sd36S\n" +
            "mj1qtSRA8oiV5q9gtW0wuXH94O9AHJjRdAqkyVhya4mzbVHZGz1MeRlUxZYUIX1k\n" +
            "Cfxf6JSxbz5yXYn5e3DD3cdCX5wUT+ueJHdNlvLPyc4/dzMovY5PGzGH8/yhSwD8\n" +
            "EAxFnSZEfUKdx/0crZ+nQn2AVDW+bGMPYMgCf86M35Jf0rk3AWUUwzQiGJ7Ifb/f\n" +
            "txfhbn5LdMzUnvFaMulf94YWBUMNPw2rFypSACWjYwN3JF03aDipiubDt+5O33pa\n" +
            "YRq5AfaFMNNRltdLfm0hZyyv8Qn7aNuDpVNsct0RrRl/lMAfLuCOv3tamh8Gsuci\n" +
            "hC/qORpytvzwDBwh8GTstiJ8T6IAKTjgPDmVW633YVS0YRAEB4lTGIRMchG2APek\n" +
            "qZ23L3JpHujColFHaQrHBSKh4ktZJwRjaaziwG0MEFQR0D/UBgjFCeIEj1ZaQb4C\n" +
            "UOAx2+A1qpoYmIRywEPLXyF28e+UmstIEMymLZy03AZknIK43KuMPpA4J+gxjsHF\n" +
            "/PjypAzKb07ey6xArZaW3PXIr7EGB16NDaAG1CdL8J2uDkt7vKNWL2Mxj2+JgzId\n" +
            "VsbZkQoOaCO94Uz69Yg3aoLIlWukWWcHYxIH2bBouvOpKOVr27PNKRoZ7KvCke/l\n" +
            "Sqa4BzPa0u23/oWqdrXrcaYdecDAv3Hdz29TSMu5Bzqz/XuCS/6ALCzzOPBzCmlB\n" +
            "JdeLADlS+Vj2BEA6/rtJjxXSMAaWnHZzcepsYxsKoUX3qY61JjxX14YHnQjJ54QR\n" +
            "DiKDhzmg1UahmdO0XaUqGnjYSf8sCGM4pkqik97GwgJWYy84QM/5YIvQBCJxWggd\n" +
            "00IG3rFm0XiwbVmhcVrXazh4q7YflE3eN00tQVznmiuFZS+l+o1Y0L0VulinBSJ3\n" +
            "bmyHn7TLIMCyZ5TN8Kbh6qTl+h/DPgKWkqIrACeTZ9gHOmzuxi6JppfKp17b0SLp\n" +
            "E2YM24TIHNxl5b/pHmivnH1QsbwrBRc9EydHrIlGTC+NZfOCQ8vdlQkNK/gxe4ta\n" +
            "O6bmloP0aryQWAB5C6RxLjA4Gh7zGsc16QovsZ5+BbdiW3XxQ/f/ESAkV77t3Luv\n" +
            "+X1sVLBlsXlFn45PpJ5br0ncnBx2p0yihy2wCBPq1Sa7JkR/0AlhNSf5e0G7Ii0M\n" +
            "4ZyKThRng3uy5Axu8H8F7TUE1gm8JAkkOl948JN4GutSypBbhiLABzbtmQOzE1E7\n" +
            "8gOZYtlxgtmxJcPsC7bUiwaDCGcI6hzb4hGyCEWzPlqK9QqUP3fjoXPN0rJ08qlc\n" +
            "rhFwTkrHuDn3KSvZTsJuyKeyI1MwYFEFyH2zA3rWY69QNvOgOp4J8qLNNByFWg5i\n" +
            "Z5bBe8ewqAh6Rqvco9kFp5IPbHM2ZTCJFKe0CJIuJ5x6zJdfpuAwoxXNJkgqzojS\n" +
            "MzjiU2HWsHUO3cU7T/qhDlKyVzXiz7SOq0j2+S0myeAz727WXPC4Ost6omCUDHqb\n" +
            "M/sRXzWjJ/Egg3UftE76/d8yes8FVT4hAohLxaTGeUh9X3BwYCtsLJt8uyxvSiIR\n" +
            "yE56oMVIcO/SpKHFQ+g9YRJgosYLZ0XOTSw9NM1T3eaAFjf18bLrH8VU5gbE4zul\n" +
            "oDP2gv8MwMPwZzsgWlZ2da5JBwkj3KVvaNAaWSZXiHl7rrpQwt3fD3v3cZHaVD4h\n" +
            "8/FQEyDA97cb/ZD4qU9KpR6rCM3GkZMy6ouAVd7/sQ6jhijBYd8wmc6IW+6uZ9kf\n" +
            "uq7eWp8jvKKeSoXLcp0cHwLGw5NX47t0Y/o3O0ZGJLnyjTOlqh1n8eWZ1LFOar1y\n" +
            "iEwsdw6HyemvrviZB1xSeAwentJFkq2V/GWDmlOnePWLT+uROA8FC5Qe59yLHem4\n" +
            "R8U7fMUvNEhVY3c4ROptveN6/58rd1X0xqdxjQrMxH3+Powj0ZORPe68vLGT/uKc\n" +
            "rwsgIGqzky+XHwT9HDOWEaKKctSqArRYqR5NdyoRb9zv6taByUjLkjgt3pXYsWjL\n" +
            "5LfKusuyrtGcMFaZxiIBYtr7Sm1zmXUxikcT3Dgzt8McjwDPyonh9EtkHSyk8GFj\n" +
            "cSQoNTOYPbteQpMeKbPYwkW3dCwxBABSVO7wTHXT4AxyUFMvFTIeG/mGG8KOsNsY\n" +
            "iH1DhqJecXaI8fu0mvlTELyZ+KeBBd6/nrCWVvnNYiRjJX/oKvos+wqQ/vxgYQX0\n" +
            "tnJnxvttNmHooO3GyQD+VOOZObpT2AhyIbVY3mxow5MnfYji8/jNwcUaGeqS5WQp\n" +
            "+y5NaQ7Dj/xzp4rQDfncHt3k0JJW9do714CsKvMM9uZfCuwwBXXA2ygB68oesbWi\n" +
            "QUpq65ClVmjwdzQunQb5gm1Bkwunx5wAKp1ipH2wl5XbOaG2cP0iw01pJrG/RveQ\n" +
            "TlWKIDbHd+82IsdvtKMOr9Vv/KEnT4N5Cc41li76PbvWo1O9scTJu17xCfw+D7Qd\n" +
            "Rghvih8CcZH2icbWncBdb79tIQUVA0vH7wSoE/HRu49OLewnZcTPy49DvMcabE+b\n" +
            "YkZQD8fzKsJZ1EtQz4bGCRppezLdepIiVhO0uYRQ2JAW34deFEd4dA6EYAjg3QRm\n" +
            "S5CZia8XIKguANXsX7Hl3Yqce9uERhs7XW9w7I7NT6WNYnLQXARwaDWMT20Sy029\n" +
            "ny4awNVQmqWSxdE3tL3BsN3KRuKyxSEdAqDSBOpOOXDn+7ola7sQje5v7beWjglD\n" +
            "4EHlMScraxoaHHPnqhB3AxbEslqArMKvF0rHJfYI03xMeYJDTBhOhbDax66NI64O\n" +
            "vZPiMcb6KcZqFmNBw0taYxWO90jBAL2mvmMuYrlFP4ymr3kEksj+lgB4Aawy1VBj\n" +
            "y1QVDimOJv27Fm1hDKeYavmrKgx4o7QV8mLu/xmdzS9rUKnj8ByX8thTW8/e9R9g\n" +
            "VlLsaegFmjV7v9mgTRl9hw+OsAKK+HSonuU/Uor/ZJzYIhT8iWYgA0/a7cW94VhN\n" +
            "CeFwA/1VH/19lcanYM58D+mnaJkSUnQzM1VupAAn8/nxthCMN7QNLjN/zvMoRFBs\n" +
            "e0V7qq1OZoOYnKvoR01jp7MTIi5UuwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgsP\n" +
            "Fhsg");

    private static byte[] draft_dilithium_end_entity = Base64.decode(
            "MIIYFjCCCyGgAwIBAgIUTVOt1yqx2TcoR2H+lxsPUk2gCzQwDQYLKwYBBAECggsH\n" +
            "BgUwgY8xCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2Yg\n" +
            "UHVibGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1\n" +
            "bXAgUmVzZWFyY2ggRGVwYXJ0bWVudDEcMBoGA1UEAwwTRGlsaXRoaXVtIFJvb3Qg\n" +
            "LSBHMTAeFw0yMzA1MjUxNjUxMzhaFw0yNjA1MjExNjUxMzhaMC8xCzAJBgNVBAYT\n" +
            "AlhYMQ8wDQYDVQQEDAZZYW1hZGExDzANBgNVBCoMBkhhbmFrbzCCB7QwDQYLKwYB\n" +
            "BAECggsHBgUDggehAA/E/9EKaexVsYAlE0FBfYaEOa/5RbzDfHLkzkymPIWn2uCy\n" +
            "TdSVMPHt3n9DjdYEAXZD+sAyKiRRXKmqtgN4Cl7o96+9V+zqDXNNuD+Ol3uJ1fUf\n" +
            "UxDQDoSHmEPSJFUl5sm9veB6g+CEymf6fHRVJmqMe5m3fo5SBj/v1WT8o6blqQhd\n" +
            "pOn5QdrGLkri2OHEBwyrfOrhRJuXLK7867q0rzCHGecHXb7M27GtY1JdsS3f6LR6\n" +
            "Xilrw77tEJTeXOw7wkEWTqVuWOQk0MteZpb4Bnyvpt6q1z/M8w8M/Xng5O9h6vEv\n" +
            "k2drOrJbtYWaAaemyW7oZq0OPDQSKJuV0BzhEc97cZEW1JG7CFyO8WutBnMVaD59\n" +
            "DbVu6I3UdSIeqmtGRpG5DiNn5OH8yw/6KcTB8C24GunblXbz/EBqhvaM2DGX5/4t\n" +
            "V/QvnWK3LwWraYD/tby44cRhhZ95Qtvo5nX+yQMDT2gNQX3Z1X3G6ttjey9nbFhf\n" +
            "vtAKXvD9n4bbNtKwXFDxIjNpf5dswLaG23eemRp06hX6TNefPIRbjcfpiaxwNs6r\n" +
            "XxNYCphrLNS8ul48D+GLaYs2lto42xhOzjdPlvsSQz+kItEWZ4tqoolQXcW4BNGK\n" +
            "syDtTxJQxLaUCNVoSoQ8PRcFXVGc18sk125/qp7TOKVFZ0ygGJ3RO34wjSIbqfaP\n" +
            "KV7o6eWPEFbYy545M8uUG+nDAlS/aj+TYi5nEmvnDYfzzQGfUQuEswu9IdYZSXhg\n" +
            "W4IPZU7TGayxNFNE1FTK0BnOyw256LD7yZvu30bAwOUphxo+8bWCgrYXe6hHLkx8\n" +
            "ceXSpCmKr8y2Pibzw5NrtqpstFj/SN1HMo1p3OZrALdTPBKqHmpWMXodNWUJ0H82\n" +
            "yLKxvZyTOKXpPzK1fKTQTriwnxSRiwXq83E0DJqGaukbBEEqAEa9DYkj37f3E1j+\n" +
            "pqtdEMmd+zmwY+zcPOPbzZHnHjICnNHlGQboNSXuGD9AOes1IUqDpnFh3MJYAjeP\n" +
            "nUAxLVjrUqTCaCZZHMutZeNT1IxuBNrkxOL+Fv/uw6XplXGUUvVl2frp6z4t+4uA\n" +
            "OyIt+aNtT+WRdMB8/dJT56TjkOvJXXZxS5KBE8ru+kIqTFTBG5+3qSPYVe35qXRS\n" +
            "XMpNZGZ2GJrcxdKpsAegAH+XCN0u+fIR6QrhXphVrE77/tISp+S3dQLrXpq9eDqa\n" +
            "xACaTtj0rxvIgzYp86lqtvNqcXjB9t3AsZxZzVyQT+Ih55Ak68YmPinnLHQxuSMC\n" +
            "XG88e1EQqPh1Tldt8n4xpY3z4aBJ9aH/4UPLBvYsm9N9eycf7uXZjOXYhqombmKn\n" +
            "KeR2c4pc3mqEAjsI6QvbxMtS8pnyNS6gIhtT2DQLVTMu3V4URxDFR8LU9Ky7NdRd\n" +
            "Z2KaUqwAaw9V4FmB4ycaPWyo9xaYH4hQldgk8/Zaf+Segz4llDEK6qcqeQaavvnZ\n" +
            "2a4r3DO87Yw8Vy9OCfmUXCtSOXCaZXqHnwXEMTIcThqEKdqkFxLEaPE0M0kTnXAd\n" +
            "uWb6JFELV3h0Q8QcxK9QLiWfNTjy/lVZ/r4eqAnrtBAIFQYYJBfA7rryu5MXIPmp\n" +
            "w2F1Ei3kP/2BnZ5XD+i5nRNOo6cOEcTUi8oPvidfj2LqQAOIlID8rKhtx1FmeJJ+\n" +
            "IH/wOkifcduGVlLDQKagJI7AXzkgkxFyQxnp5g34I0IRBXtsrZdmqOlv+JA08uPP\n" +
            "I+vaPzvRL66vG7djHCbiLjdumwTrqbfiXeIoZjF2nP4O+X3+fjSckPOT8Dr+OMSx\n" +
            "E2nEsb1lYiQcguoF52gn0Ltcf585pa6Lezey7S6Qc+3j7XdhLH2OczWgJ4zc5SBP\n" +
            "9t1EzOpVFiCMQ5V4GWS6OEizdkbaKDTAEY+9TyiXXwxU5nrMWxzGhwQ7XNaT4qpt\n" +
            "Z5TFEJBF94xciP4+4EkwbBFdPo02n5AD4K8PAbXj5MuySnPSYkBfMq6DwB/BlFfc\n" +
            "RKVz4Yt6KR//jJjiM93G80WhlL+DAYx3w2VtWrNXhn/W9VP0KK5Jfaecbl+tHWfQ\n" +
            "87HdXqx/Z8hmPEYDXidLNGOLLj7GIt2I2ZUtC7+49q6qQEL/8y78J2q1Ef1F/jUP\n" +
            "xsBMzMgGTolEyz1i6X7fO+yHY5CkJAnNVkZK2wvpSGFqIuyO3BjCJfNMlpUCmhMS\n" +
            "gmv6KQ9sEdF8tbYsk9ICVzqXV3O+03y4swUaIe6o0MIiL5X45SZv9HArhjs9Laku\n" +
            "BjgQ3BSWtyfFRqdsLZn+MWBX4H8YkhTxfJzofSJPqNuPUwdcdIxc7LOpkOGPkAfy\n" +
            "yI2uqo6YGcgMTGMBGk5iJ3SBelrz4k9YlVi3gy7gsW4FbIvXD97h3Gqd4tkM5S8L\n" +
            "A9FGl2nT/0RNag91vJ+89Zls55sm3d3Hi3ZxuNr9KgNiIuNuZaFSXdrHDo/ZinFV\n" +
            "BSn6YakeJCkUkqA4kqjcoxrIF6bQWu2LcM/7PeCBPhtVH6hMn5hAF+OymGCw62+m\n" +
            "ha72rqBrkUhdAMjrv3eubo0AdlUD9v1z45fs68kPEsZisHBbmAZWBcGGGieupmv2\n" +
            "VYkELI9mBUYJdnDhfFVSqdmqQ68xveMvb3VxIyo/eYTLuofVJp3DJ4IbhB6ro4IC\n" +
            "WDCCAlQwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFANK\n" +
            "iIG5mZXV+IMcuSPREB/od032MB8GA1UdIwQYMBaAFC7xQYjChOZZFBDtuuo5uPqz\n" +
            "Lec+MIIB8gYKYIZIAYb6a1AGAQSCAeIwggHeAhQs36ItK8bqD/FlXfx+e3IJLemk\n" +
            "uKAKBggqhkjOPQQDBKGBjjCBizELMAkGA1UEBhMCWFgxNTAzBgNVBAoMLFJveWFs\n" +
            "IEluc3RpdHV0ZSBvZiBQdWJsaWMgS2V5IEluZnJhc3RydWN0dXJlMSswKQYDVQQL\n" +
            "DCJQb3N0LUhlZmZhbHVtcCBSZXNlYXJjaCBEZXBhcnRtZW50MRgwFgYDVQQDDA9F\n" +
            "Q0RTQSBSb290IC0gRzEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARCJUj4j7eC\n" +
            "/7Xso3REUscqHlWPvW9zvl5I6TIyzEXFsWxM0QxMuNW4oXE56UiCyJklcpk0JfQU\n" +
            "Gat+kKQqSUJypEAwHQYDVR0OBBYEFFtwp5gX95/2N9L349xEbCEJ17vUMB8GA1Ud\n" +
            "IwQYMBaAFI7CFAlgduqQOOk5rhttUsQXfZ++A4GLADCBhwJBJyKG5vGDiDA8iddl\n" +
            "vY44yI0wK5D8ayYCx2aM8fuh5XjZA+14rI50v21a41uObnW1KXRHoQeW4SZTUBuz\n" +
            "yo/w7B8CQgCqwK1+cbH+YecTjnfWQHgSk1dqgPCDi0ezo+QVOHhtzfXbIs1y1z1k\n" +
            "SU/BF4spioFCeKIkkJaLs+8Evy5gdx+u6DANBgsrBgEEAQKCCwcGBQOCDN4Azno4\n" +
            "4bYnpwVdpeaWAaNjchhKdPxrpn4JresJGnrJnsLUrUFtUdzipe4ZhLsLRJKRC41b\n" +
            "Rg0zwf4eIxRBaERbWnWDzBl5x6LlnNNtkNsBzSVyc2OkyC6Js/AFKueK7348ZSAk\n" +
            "0CeWiWRCAvg8o3o1YX+Nk0J3BYcLWyf4ZH6fyExqjnikx2NgXZhPe48l8nqjAkct\n" +
            "f9tdKBkMOqP3GAKvQWhDtMNDMeUoUBXXJfJWdIfclgoGmqLe74N1wgIIDCMkMmZ1\n" +
            "+G8W2E9Xix7nvwzvjFZSqcnjP17yPizCAOeRAYP3FyaZb6lMZ1Pusc9Uun9c5E8P\n" +
            "8vJG7CXPYH8lVrhNpMG8y3jDAW30xphkeE8yxnYKa2k4nutAijt1XPb0p9ihTcM+\n" +
            "K56fSCnFFlgXZYsyEI4oCqJQFgUf+BKe+XVSR5K5hpjkH6WT+LoAgWhm5ocyUasz\n" +
            "2x2vvMeo282bdFhdnHAyaDCYBG/XjEggFpzXQ1G7Dv7ECiVjdbAnLREViMSu2sDv\n" +
            "dFgE+Hzmv6IpFdh1OynxkUJ2k22do/YDvo3x9008M5HjqMYGp1I4i1wfx6X9zCNZ\n" +
            "k+mzPX1QQpMoZFC9RK52XpgPECe4ssDA2vVIn3t9ZufE6M8Pzc7SgMk+gANs9yKy\n" +
            "1GZyTG6CxGjVpuupXtlWFyT40U9G/GZF/AYSG/qguFu4kG5QxtafpfD+g267pX4Z\n" +
            "eM2p7x0J+CCUlVr81vYs9jrhBSPnc2CVxDyj+9Jokn16ek7Ulmhu34mS5TWA9Qn2\n" +
            "h3eDpTDAILyPEyKEa5mWc8WnHKtfYBl4L13QUT9VScOHvGszmrN1evuqsXdblxgL\n" +
            "DH3u3cDWoF90M9Y7Avu4mS38q0bnbN8emUZRTbBlH2vHcWrOTuAWmhVpNDXlmPuM\n" +
            "KV/9l9cN2B2xn+vUXccGgzltZk2hjXTigi+/ZUXAeGAq8n74LkjBkwUh4RQCwH2e\n" +
            "p/5VyoAGAHwtFLOLVO+OJyE+SeRtEdV4hAeqSiXl7pwqJtO3/DcQX2bxEuolZirK\n" +
            "l/THY+2hm6FE8SyZwMfyj1yjzsgJ9fK/bm7pe1g7UmDNEfepnzntPUcrRYvzD1U4\n" +
            "BJ1UliWDehPf3qXolcFT0lrfxeutiFz9xkytlx/MFnDReqRKBNhZ36sq4p96o8V7\n" +
            "b9+X3SZrI3fF07R5C0SgBCcZK4W/p06ZUcAS9CX+g8g7H+4mupZxe1MXuetgBPZF\n" +
            "rYe6xOI6OoELchWdpuIrXq9UWLJUEUjS+Cr3HKlOJWp2+xJqV7qzMKN9ky6VgfnL\n" +
            "TC7smRxGPAViMsTHaJ8FnuzZeriYr6+2n2TmpL8Ubj5iYnSW7E5zFmCO1JZOPxWF\n" +
            "jwfZz6RmZUBzJCf7MBxoPdPGihpWWRheyQ9gPC3TjOBV8XRPKh+OsWkeYd2cvPSy\n" +
            "xNzpPgAhnpuU36kRUarmOEJANc+p7HoTENfwzQrydDmp4NXmJNV6yWNewD8knczL\n" +
            "Dp6uhlWMmm5K1o8LRWhf/BMvQkVhI92FbM7RJFwI7YoxwX+hdKX44z1cIPP+CNKJ\n" +
            "3YQ4GsAbWFkuDmGjKroTmFfMaDIUioci7k49YigCWgcWfCJq1YpMnUy6U31t0lPS\n" +
            "/AOAmkln/D3osf1OwQLHArH4c7rdRwrOwmzM6FaG2iyQPoF4xVWNSLYFP6tUA+JS\n" +
            "C2OiSFvrN1EzBfqWRXTwMjGlBXf3WQg2nEm2n/JU7i6QVXw5kQiQICN+koCHqoWc\n" +
            "0dAxxNoSq52byCXbn94aR2Hc9ycyxNLOB1om4uemIuE8JeoD6V+HQeaa113LsK06\n" +
            "U3ypdmZ8LMKuPMjQYG8iBC1NB+q9j2b1NRMi2DNZmDrpG5IGEh6KLISWN6cB4NOl\n" +
            "EA2D7o6SZ69emLjpwaO/IX2pS6vzZnraLvCqaWr5CJo8Exp37kAqHTU4Y0EO5h8V\n" +
            "Y3h8bpebYRgGIl6iypPlyDz4zzVj51zUudI+TH8z4t5eazXSkMcHiev8qpb5kVYH\n" +
            "JTtut0ndqY2u9Y5GcMc7uFHnKr2jen1DAVEFol86xikRL27nJtCpZ88IXTfrKloJ\n" +
            "k8vN8guI+PU1Wd7lEOnKwXScHhbmYSrz9FQqizACRtuYiqCUv5GrPX7E31bY+B0p\n" +
            "lhoVO4ZRMmFAOWNkgi9x6kMeJFhlS25t8vKspE+DJOuW+Enz7uneig5K3yiI00NW\n" +
            "GveQTkoVnO4eoSjwj5+JuVNlBlZdKbfX6T0ycS4QqnH+HOEF/SJvot4Coae0Fi0x\n" +
            "z8/11jAGU//CeCktsysFcUMd640JIrxb8EnB8AdG8CPp9Vpv13emPnORusIXPZKf\n" +
            "33B8n8MGl09c5fh9KhGtdYV9/bnNFTIxTlRi5tNBLdOQb1t3MVuv4csBI1SR2qLr\n" +
            "cWA+PUddLG9d+hoRdfy4uGb5uLkRM8ckPqtHhpOsrxdVlyDKMQt0HxniG7tZXmdo\n" +
            "LhdvDOZdDqRjh8Ms94WXf0TDLrlRfefEoZ4T96aZW4qeFukBvR2rEfItRd3os2Z7\n" +
            "JD7yS6RPUfBAqzGWSTsDcmjxWXZQZYO6ygd1rMkr7EbabS7FJXqb/VxVEMrMFKGx\n" +
            "BFy4ujJf+cJtIDw6y59rmnaVOyAD9b4a++Zz06PnymlFEi/jlLy92xYWxt+hOaJC\n" +
            "AeiUoKHLbH5KiSTWlwdbjshGytlZaAjLyuC0BxfGrQurl8VJ3OkfeDX20HgntkTu\n" +
            "wJhvZpbhzth9y0cpo1z/JLyMfZV6yGccEATgRP2gciEgssBFhB6FT8tWmf5IgjkS\n" +
            "pYUaCqnSn2gu3MmYZF8+h++tJGpH0hrq/MhXrqwJnx3e0c1nTC6IWbrR12s8RWig\n" +
            "RjEBlFt5cfgswMeWnb7UdM/vXkefNBjiWEiDGU5R+Od9N+siYh+ZyFVkrXeD1nab\n" +
            "YOTtolImcu1fP/jG2v62XVC4KoBGG53Ym2fIfkDwIjQFO6exl1/d6FoVsX3D90Hd\n" +
            "7+njwh8+2eJ9AU7XXwlNi8eOklxMxPeMcCFANAx+kRy9jqKvc6p1LziOXDT3yaqT\n" +
            "OPHnGffVXL966PtdGK4sP5Hf2BwMpIPv6fAjprndFKDcqUOYFjGEf9wyCnrWy/+U\n" +
            "TIY1PHwtgLPqVA3Rm7lThze+OAglbFG34ErkZEprLuNxtfei3hzWE5f13O47di35\n" +
            "OBnxlv/LtD190fZC1rKJjU5RT9q+foWeGtSca8McXVQ39fO1QdaGm5EGpRN0DyaK\n" +
            "JbVQkNDnXkHRvgZ78npwo8pmZ2Tcw8ocnHW4KCj6CT0lf4Q7THnS4BYfLtU622Nf\n" +
            "LcThYTR46ItceHlsB2Kksyx0oamRCj1kvUURCj9Pl1A9Z30xeFcJnHLaRA6BJutQ\n" +
            "J17N/gF4DNzAMQK8mLNEESocdeFe6l7cWWhpjZUY4QydooN2Cv1l0REehFNiDKNz\n" +
            "UUK0iJ/HbxfkI6IHtR31pq70mttHeJA4UIIdU9HbytqSehKXxSrSGeXMft0tqTG5\n" +
            "pu09xlcKbP800gVp680ZMye2Jsg6ebyxEz7AKmbTDoR+30o2n5IwR/wFyrSLYgp0\n" +
            "cAkBozlDWndEVdACXDCKcS/WWHhHMtU7CDUlM52UWQ9Ofsj9smfv0Q24bIEadsLX\n" +
            "WGiJdYWGU4iSyn6iwPqFpWFIIASuKCom6lRhNHpumcqWaNks8oGBfb2XNbFVerK6\n" +
            "WxuJhDU2d9MTtfbubfAS/ll7VFChbSML3WMfZuGEHILCwtc+MhuMsQkllii7APwv\n" +
            "kicHmTTTS3gg+3yLIZT0VkBcAQfAPW9WaHz28TIFhHPt8omBLP+oB+eGcYPZL4+1\n" +
            "biS3ulxNNQeV/xagXVBnQsW6NBermbpR04YHrRatkv6hddsHY7cAd+c28hMr+RLw\n" +
            "/aeOG2LyZw0nOuvDHYURFnarBaZJpehAZ2Im3IQjY4riBacR/nlLJy7rznZltAoP\n" +
            "A+2AdIXEWX7JfnpbtS1joXLB8kbCAsBVsQ46D4S5egFMmRDNlwPf1hrnbLR69lCR\n" +
            "ugT7T0IL1tbC67ieAh5QknesVLq17hPIPECQeYTOAJksr7eT9G6M8SAKevQVOipd\n" +
            "ANLVQ9/jLJUQUp5lUJOK+jduoWFUHGMV6lguHzUHT3KPXIFfQrpNOJoI1t4tEewC\n" +
            "7LlbOrHF2vFU3YPoltp/gpWDEfDqRUVBEgU9gMdVDkYVn+yZwxUpRhaxihKW61yx\n" +
            "P4AHo26WMuoNKJ0ALgxJ4zVYFa+O+kzdNP6Lul7ihUdAVjFXUVErhJ7d7tM+GL69\n" +
            "gvN0QJgd6aHYmSZ/7QjSfsVti9WcRzCh4LZHUbmW05In8LHxvNZ1/nNyVz0iUL4P\n" +
            "0C7Ox1btY/JsFYAcXRggSVR+qcDFO2J9J1CCz/Akk5W2vCktmaPtDx8nTX+s4QAA\n" +
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAICxAVGiE=");

    private static byte[] draft_p521_root = Base64.decode(
            "MIIDBTCCAmagAwIBAgIUTggpfah2kbN+5mHbCwF8takhZ/wwCgYIKoZIzj0EAwQw\n" +
            "gYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVi\n" +
            "bGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAg\n" +
            "UmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMB4X\n" +
            "DTIzMDUyNTE2NTEzOFoXDTMzMDUxMjE2NTEzOFowgYsxCzAJBgNVBAYTAlhYMTUw\n" +
            "MwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVibGljIEtleSBJbmZyYXN0cnVj\n" +
            "dHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAgUmVzZWFyY2ggRGVwYXJ0bWVu\n" +
            "dDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMIGbMBAGByqGSM49AgEGBSuBBAAj\n" +
            "A4GGAAQB0P1yV6hMdH9WJXXAc4Xb6/L1K+pYCD24L90VMdiq48yHX/Av9/otomDY\n" +
            "62LW0vXWSSeOMhc2oGKMu7MDCLbmGNsA9irSBMZGA1m8gYq4lhvw8PwOxaropCgX\n" +
            "POVvAN6bFXweXILGT1Yvyt78Skwo9tNCzz72FvyC0ztyhckh8r82/dijYzBhMA8G\n" +
            "A1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSOwhQJYHbq\n" +
            "kDjpOa4bbVLEF32fvjAfBgNVHSMEGDAWgBSOwhQJYHbqkDjpOa4bbVLEF32fvjAK\n" +
            "BggqhkjOPQQDBAOBjAAwgYgCQgGFSpzkWwSGg7geN7A29/Hm+AQecvaPsEy6yBle\n" +
            "QxgNsjlHJB+evy+x+MlRWrYlGaJOrETDoBkewWOgb7nMxaNtlAJCARhDCCPbUJMK\n" +
            "f9KIpEm5KTjGR+VBpavAC+k5w/mMzAYEaunRmRP7KRii3n+oMikNXShGrSv6C0oH\n" +
            "/Ze44Gp3VBDb\n");

    private static byte[] draft_ecdsa_signing_end_entity = Base64.decode(
        "MIICYTCCAcOgAwIBAgIULN+iLSvG6g/xZV38fntyCS3ppLgwCgYIKoZIzj0EAwQw\n" +
        "gYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVi\n" +
        "bGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAg\n" +
        "UmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMB4X\n" +
        "DTIzMDUyNTE2NTEzOFoXDTI2MDUyMTE2NTEzOFowLzELMAkGA1UEBhMCWFgxDzAN\n" +
        "BgNVBAQMBllhbWFkYTEPMA0GA1UEKgwGSGFuYWtvMFkwEwYHKoZIzj0CAQYIKoZI\n" +
        "zj0DAQcDQgAEQiVI+I+3gv+17KN0RFLHKh5Vj71vc75eSOkyMsxFxbFsTNEMTLjV\n" +
        "uKFxOelIgsiZJXKZNCX0FBmrfpCkKklCcqNgMF4wDAYDVR0TAQH/BAIwADAOBgNV\n" +
        "HQ8BAf8EBAMCB4AwHQYDVR0OBBYEFFtwp5gX95/2N9L349xEbCEJ17vUMB8GA1Ud\n" +
        "IwQYMBaAFI7CFAlgduqQOOk5rhttUsQXfZ++MAoGCCqGSM49BAMEA4GLADCBhwJB\n" +
        "JyKG5vGDiDA8iddlvY44yI0wK5D8ayYCx2aM8fuh5XjZA+14rI50v21a41uObnW1\n" +
        "KXRHoQeW4SZTUBuzyo/w7B8CQgCqwK1+cbH+YecTjnfWQHgSk1dqgPCDi0ezo+QV\n" +
        "OHhtzfXbIs1y1z1kSU/BF4spioFCeKIkkJaLs+8Evy5gdx+u6A==");

    private static byte[] draft_ecdsa_dual_use_end_entity = Base64.decode(
            "MIIDyzCCAyygAwIBAgIUHfGFg4ZrE6+0wdcuN8sDeelJ0vswCgYIKoZIzj0EAwQw\n" +
            "gYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVi\n" +
            "bGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAg\n" +
            "UmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMB4X\n" +
            "DTIzMDUyNTE2NTEzOFoXDTI2MDUyMTE2NTEzOFowLzELMAkGA1UEBhMCWFgxDzAN\n" +
            "BgNVBAQMBllhbWFkYTEPMA0GA1UEKgwGSGFuYWtvMHYwEAYHKoZIzj0CAQYFK4EE\n" +
            "ACIDYgAEWwkBuIUjKW65GdUP+hqcs3S8TUCVhigr/soRsdla27VHNK9XC/grcijP\n" +
            "ImvPTCXdvP47GjrTlDDv92Ph1o0uFR2Rcgt3lbWNprNGOWE6j7m1qNpIxnRxF/mR\n" +
            "noQk837Io4IBqjCCAaYwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCAwgwHQYD\n" +
            "VR0OBBYEFArjoP6d1CV2mLXrcuvKDOe/PfXxMB8GA1UdIwQYMBaAFI7CFAlgduqQ\n" +
            "OOk5rhttUsQXfZ++MIIBRAYKYIZIAYb6a1AGAQSCATQwggEwAhQs36ItK8bqD/Fl\n" +
            "Xfx+e3IJLemkuDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEIlSPiPt4L/teyj\n" +
            "dERSxyoeVY+9b3O+XkjpMjLMRcWxbEzRDEy41bihcTnpSILImSVymTQl9BQZq36Q\n" +
            "pCpJQnKkLzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFFtwp5gX95/2N9L349xE\n" +
            "bCEJ17vUA4GLADCBhwJBJyKG5vGDiDA8iddlvY44yI0wK5D8ayYCx2aM8fuh5XjZ\n" +
            "A+14rI50v21a41uObnW1KXRHoQeW4SZTUBuzyo/w7B8CQgCqwK1+cbH+YecTjnfW\n" +
            "QHgSk1dqgPCDi0ezo+QVOHhtzfXbIs1y1z1kSU/BF4spioFCeKIkkJaLs+8Evy5g\n" +
            "dx+u6DAKBggqhkjOPQQDBAOBjAAwgYgCQgDrJbcn+dLO5HqHlhaW6G1FuNWLz1h3\n" +
            "OXYNb92b7aSsa478EsE7hE40her99+33/ws5EJp4+mtWBb6+09Be8ARC0AJCAJ9C\n" +
            "q55HKUbwR5+sYUtXk1021jyjhTeRVzCXcq1AiVYriSSC9ZbBGjdzPmhtmuHWRXKY\n" +
            "5vbNh5DO/8/9ucvLiIrS\n");

    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider("BCPQC") == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    public void testDeltaExtract()
        throws Exception
    {
        X509CertificateHolder baseCert = new X509CertificateHolder(baseCertData);

        assertTrue(baseCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(baseCert.getSubjectPublicKeyInfo())));

        X509CertificateHolder deltaCert = DeltaCertificateTool.extractDeltaCertificate(baseCert);

        assertTrue(deltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BCPQC").build(deltaCert.getSubjectPublicKeyInfo())));

        X509CertificateHolder extCert = new X509CertificateHolder(extracted);

        assertTrue(extCert.equals(deltaCert));
    }

    public void testDeltaRsaEC()
        throws Exception
    {
        X509CertificateHolder baseCert = new X509CertificateHolder(rsa_ec_cert);

        assertTrue(baseCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(baseCert.getSubjectPublicKeyInfo())));

        X509CertificateHolder deltaCert = DeltaCertificateTool.extractDeltaCertificate(baseCert);

        assertTrue(deltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(deltaCert.getSubjectPublicKeyInfo())));
    }

    public void testDeltaCertRequest()
        throws Exception
    {
        PKCS10CertificationRequest pkcs10CertReq = new PKCS10CertificationRequest(deltaCertReq);

        assertTrue(pkcs10CertReq.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(pkcs10CertReq.getSubjectPublicKeyInfo())));

        Attribute[] attributes = pkcs10CertReq.getAttributes(new ASN1ObjectIdentifier("2.16.840.1.114027.80.6.2"));

        DeltaCertificateRequestAttributeValue deltaReq = new DeltaCertificateRequestAttributeValue(attributes[0]);

        assertTrue(DeltaCertAttributeUtils.isDeltaRequestSignatureValid(pkcs10CertReq, new JcaContentVerifierProviderBuilder().setProvider("BC").build(deltaReq.getSubjectPKInfo())));

        KeyPairGenerator kpgB = KeyPairGenerator.getInstance("EC", "BC");

        kpgB.initialize(new ECNamedCurveGenParameterSpec("P-256"));

        KeyPair kpB = kpgB.generateKeyPair();

        Date notBefore = new Date(System.currentTimeMillis() - 5000);
        Date notAfter = new Date(System.currentTimeMillis() + 1000 * 60 * 60);
        X509v3CertificateBuilder bldr = new X509v3CertificateBuilder(
            new X500Name("CN=Chameleon CA 1"),
            BigInteger.valueOf(System.currentTimeMillis()),
            notBefore,
            notAfter,
            pkcs10CertReq.getSubject(),
            pkcs10CertReq.getSubjectPublicKeyInfo());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(kpB.getPrivate());

        X509v3CertificateBuilder deltaBldr = new X509v3CertificateBuilder(
                    new X500Name("CN=Chameleon CA 2"),
                    BigInteger.valueOf(System.currentTimeMillis()),
                    notBefore,
                    notAfter,
                    deltaReq.getSubject(),
                    deltaReq.getSubjectPKInfo());
        if (deltaReq.getExtensions() != null)
        {
            Extensions extensions = deltaReq.getExtensions();
            for (Enumeration e = extensions.oids(); e.hasMoreElements();)
            {
                deltaBldr.addExtension(extensions.getExtension((ASN1ObjectIdentifier)e.nextElement()));
            }
        }

        X509CertificateHolder deltaCert = deltaBldr.build(signer);

        Extension deltaExt = DeltaCertificateTool.makeDeltaCertificateExtension(
            false,
            deltaCert);
        bldr.addExtension(deltaExt);
        
        X509CertificateHolder chameleonCert = bldr.build(signer);

        assertTrue(chameleonCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(kpB.getPublic())));

        X509CertificateHolder exDeltaCert = DeltaCertificateTool.extractDeltaCertificate(chameleonCert);
     
        assertTrue(exDeltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(kpB.getPublic())));
    }

    public void testDeltaCertWithExtensions()
        throws Exception
    {
        X500Name subject = new X500Name("CN=Test Subject");

        KeyPairGenerator kpgA = KeyPairGenerator.getInstance("RSA", "BC");

        kpgA.initialize(2048);

        KeyPair kpA = kpgA.generateKeyPair();

        KeyPairGenerator kpgB = KeyPairGenerator.getInstance("EC", "BC");

        kpgB.initialize(new ECNamedCurveGenParameterSpec("P-256"));

        KeyPair kpB = kpgB.generateKeyPair();

        ContentSigner signerA = new JcaContentSignerBuilder("SHA256withRSA").build(kpA.getPrivate());

        Date notBefore = new Date(System.currentTimeMillis() - 5000);
        Date notAfter = new Date(System.currentTimeMillis() + 1000 * 60 * 60);
        X509v3CertificateBuilder bldr = new X509v3CertificateBuilder(
            new X500Name("CN=Chameleon CA 1"),
            BigInteger.valueOf(System.currentTimeMillis()),
            notBefore,
            notAfter,
            subject,
            SubjectPublicKeyInfo.getInstance(kpA.getPublic().getEncoded()));

        bldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        ContentSigner signerB = new JcaContentSignerBuilder("SHA256withECDSA").build(kpB.getPrivate());

        X509v3CertificateBuilder deltaBldr = new X509v3CertificateBuilder(
                    new X500Name("CN=Chameleon CA 2"),
                    BigInteger.valueOf(System.currentTimeMillis()),
                    notBefore,
                    notAfter,
                    subject,
                    SubjectPublicKeyInfo.getInstance(kpB.getPublic().getEncoded()));
        
        deltaBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        X509CertificateHolder deltaCert = deltaBldr.build(signerB);

        Extension deltaExt = DeltaCertificateTool.makeDeltaCertificateExtension(
            false,
            deltaCert);
        bldr.addExtension(deltaExt);

        X509CertificateHolder chameleonCert = bldr.build(signerA);

        assertTrue(chameleonCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(kpA.getPublic())));

        DeltaCertificateDescriptor deltaCertDesc = DeltaCertificateDescriptor.fromExtensions(chameleonCert.getExtensions());

        assertNull(deltaCertDesc.getExtensions());
        assertNull(deltaCertDesc.getSubject());
        assertNotNull(deltaCertDesc.getIssuer());

        X509CertificateHolder exDeltaCert = DeltaCertificateTool.extractDeltaCertificate(chameleonCert);
      
        assertTrue(exDeltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(kpB.getPublic())));
    }

    public void testCheckCreationAltCertWithDelta()
        throws Exception
    {
        if (Security.getProvider("BCPQC") == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }

        KeyPairGenerator kpgB = KeyPairGenerator.getInstance("EC", "BC");

        kpgB.initialize(new ECNamedCurveGenParameterSpec("P-256"));

        KeyPair kpB = kpgB.generateKeyPair();

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("Dilithium", "BCPQC");

        kpGen.initialize(DilithiumParameterSpec.dilithium2, new SecureRandom());

        KeyPair kp = kpGen.generateKeyPair();

        PrivateKey privKey = kp.getPrivate();
        PublicKey pubKey = kp.getPublic();

        KeyPairGenerator ecKpGen = KeyPairGenerator.getInstance("EC", "BC");

        ecKpGen.initialize(new ECNamedCurveGenParameterSpec("P-256"), new SecureRandom());

        KeyPair ecKp = ecKpGen.generateKeyPair();

        PrivateKey ecPrivKey = ecKp.getPrivate();
        PublicKey ecPubKey = ecKp.getPublic();

        Date notBefore = new Date(System.currentTimeMillis() - 5000);
        Date notAfter = new Date(System.currentTimeMillis() + 1000 * 60 * 60);

        //
        // distinguished name table.
        //
        X500Name issuer = new X500Name("CN=Chameleon Base Issuer");
        X500Name subject = new X500Name("CN=Chameleon Base Subject");

        //
        // create base certificate - version 3
        //
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(ecPrivKey);

        ContentSigner altSigGen = new JcaContentSignerBuilder("Dilithium2").setProvider("BCPQC").build(privKey);

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
            issuer,
            BigInteger.valueOf(1),
            notBefore,
            notAfter,
            subject,
            ecPubKey)
            .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
            .addExtension(Extension.subjectAltPublicKeyInfo, false, SubjectAltPublicKeyInfo.getInstance(kp.getPublic().getEncoded()));

        ContentSigner signerB = new JcaContentSignerBuilder("SHA256withECDSA").build(kpB.getPrivate());

        X509v3CertificateBuilder deltaBldr = new X509v3CertificateBuilder(
                    new X500Name("CN=Chameleon CA 2"),
                    BigInteger.valueOf(System.currentTimeMillis()),
                    notBefore,
                    notAfter,
                    subject,
                    SubjectPublicKeyInfo.getInstance(kpB.getPublic().getEncoded()));

        deltaBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                 .addExtension(Extension.subjectAltPublicKeyInfo, false, SubjectAltPublicKeyInfo.getInstance(kp.getPublic().getEncoded()));
        
        X509CertificateHolder deltaCert = deltaBldr.build(signerB, false, altSigGen);

        assertTrue(deltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(kpB.getPublic())));

        Extension deltaExt = DeltaCertificateTool.makeDeltaCertificateExtension(
            false,
            deltaCert);
        certGen.addExtension(deltaExt);

        X509CertificateHolder certHldr = certGen.build(sigGen, false, altSigGen);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHldr);

        //
        // copy certificate           exDeltaCert
        //

        cert.checkValidity(new Date());

        cert.verify(cert.getPublicKey());

        // check encoded works
        cert.getEncoded();

        X509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);

       // assertTrue("alt sig value wrong", certHolder.isAlternativeSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BCPQC").build(pubKey)));

        X509CertificateHolder exDeltaCert = DeltaCertificateTool.extractDeltaCertificate(new X509CertificateHolder(cert.getEncoded()));

        assertTrue(exDeltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(kpB.getPublic())));
        assertTrue(exDeltaCert.isAlternativeSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(pubKey)));

        assertTrue(certHldr.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(ecPubKey)));
        assertTrue(certHldr.isAlternativeSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(pubKey)));
    }

    /*
    public void testDraftDilithiumRoot()
        throws Exception
    {
        X509CertificateHolder baseCert = new X509CertificateHolder(draft_dilithium_root);

        assertTrue(baseCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(baseCert.getSubjectPublicKeyInfo())));

        X509CertificateHolder deltaCert = DeltaCertificateTool.extractDeltaCertificate(baseCert);

        assertTrue(deltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(deltaCert.getSubjectPublicKeyInfo())));

        X509CertificateHolder extCert = new X509CertificateHolder(draft_p521_root);

        assertTrue(extCert.equals(deltaCert));
    }

    public void testDraftDilithiumEndEntity()
        throws Exception
    {
        X509CertificateHolder rootCert = new X509CertificateHolder(draft_dilithium_root);
        X509CertificateHolder ecRootCert = new X509CertificateHolder(draft_p521_root);
        X509CertificateHolder baseCert = new X509CertificateHolder(draft_dilithium_end_entity);

        assertTrue(baseCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(rootCert.getSubjectPublicKeyInfo())));

        X509CertificateHolder deltaCert = DeltaCertificateTool.extractDeltaCertificate(baseCert);

        assertTrue(deltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(ecRootCert.getSubjectPublicKeyInfo())));
        
        X509CertificateHolder extCert = new X509CertificateHolder(draft_ecdsa_signing_end_entity);

        assertTrue(extCert.equals(deltaCert));
    }

    public void testDraftDualUseEcDsaEndEntity()
        throws Exception
    {
        X509CertificateHolder ecRootCert = new X509CertificateHolder(draft_p521_root);
        X509CertificateHolder baseCert = new X509CertificateHolder(draft_ecdsa_dual_use_end_entity);

        assertTrue(baseCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(ecRootCert.getSubjectPublicKeyInfo())));

        X509CertificateHolder deltaCert = DeltaCertificateTool.extractDeltaCertificate(baseCert);

        X509CertificateHolder extCert = new X509CertificateHolder(draft_ecdsa_signing_end_entity);

        assertTrue(extCert.equals(deltaCert));
        
        assertTrue(deltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(ecRootCert.getSubjectPublicKeyInfo())));
    }
     */

//    public static void main(String[] args)
//        throws Exception
//    {
//        X509CertificateHolder x509cert = (X509CertificateHolder)new PEMParser(new FileReader("../bc-kotlin/ta_dil_cert.pem")).readObject();
//
//        Extension ext = x509cert.getExtension(new ASN1ObjectIdentifier("2.16.840.1.114027.80.6.1"));
//
//        System.err.println(ASN1Dump.dumpAsString(ext.getParsedValue()));
//    }
}