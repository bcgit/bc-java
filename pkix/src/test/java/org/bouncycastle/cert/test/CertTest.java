package org.bouncycastle.cert.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAValidationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.spec.CompositeAlgorithmSpec;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.interfaces.ECPointEncoder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.spec.GOST3410ParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.LMSKeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.QTESLAParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SPHINCS256KeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.XMSSMTParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.XMSSParameterSpec;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class CertTest
    extends SimpleTest
{
    private static final String BC = org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

    // test CA
    byte[] testCAp12 = Base64.decode(
        "MIACAQMwgAYJKoZIhvcNAQcBoIAkgASCA+gwgDCABgkqhkiG9w0BBwGggCSA"
            + "BIID6DCCCFIwggL/BgsqhkiG9w0BDAoBAqCCArIwggKuMCgGCiqGSIb3DQEM"
            + "AQMwGgQUjWJR94N+oDQ1XlXO/kUSwu3UOL0CAgQABIICgFjzMa65mpNKYQRA"
            + "+avbnOjYZ7JkTA5XY7CBcOVwNySY6/ye5Ms6VYl7mCgqzzdDQhT02Th8wXMr"
            + "fibaC5E/tJRfdWt1zYr9NTLxLG6iCNPXJGGV6aXznv+UFTnzbzGGIAf0zpYf"
            + "DOOUMusnBeJO2GVETk6DyjtVqx0sLAJKDZQadpao4K5mr5t4bz7zGoykoKNN"
            + "TRH1tcrb6FYIPy5cf9vAHbyEB6pBdRjFQMYt50fpQGdQ8az9vvf6fLgQe20x"
            + "e9PtDeqVU+5xNHeWauyVWIjp5penVkptAMYBr5qqNHfg1WuP2V1BO4SI/VWQ"
            + "+EBKzlOjbH84KDVPDtOQGtmGYmZElxvfpz+S5rHajfzgIKQDT6Y4PTKPtMuF"
            + "3OYcrVb7EKhTv1lXEQcNrR2+Apa4r2SZnTBq+1JeAGMNzwsMbAEcolljNiVs"
            + "Lbvxng/WYTBb7+v8EjhthVdyMIY9KoKLXWMtfadEchRPqHGcEJDJ0BlwaVcn"
            + "UQrexG/UILyVCaKc8yZOI9plAquDx2bGHi6FI4LdToAllX6gX2GncTeuCSuo"
            + "o0//DBO3Hj7Pj5sGPZsSqzVQ1kH90/jResUN3vm09WtXKo8TELmmjA1yMqXe"
            + "1r0mP6uN+yvjF1djC9SjovIh/jOG2RiqRy7bGtPRRchgIJCJlC1UoWygJpD6"
            + "5dlzKMnQLikJ5BhsCIx2F96rmQXXKd7pIwCH7tiKHefQrszHpYO7QvBhwLsk"
            + "y1bUnakLrgF3wdgwGGxbmuE9mNRVh3piVLGtVw6pH/9jOjmJ6JPbZ8idOpl5"
            + "fEXOc81CFHTwv/U4oTfjKej4PTCZr58tYO6DdhA5XoEGNmjv4rgZJH1m6iUx"
            + "OjATBgkqhkiG9w0BCRQxBh4EAGMAYTAjBgkqhkiG9w0BCRUxFgQUKBwy0CF7"
            + "51A+BhNFCrsws2AG0nYwggVLBgsqhkiG9w0BDAoBAqCCBPowggT2MCgGCiqG"
            + "SIb3DQEMAQMwGgQUf9t4IA/TP6OsH4GCiDg1BsRCqTwCAgQABIIEyHjGPJZg"
            + "zhkF93/jM4WTnQUgWOR3PlTmhUSKjyMCLUBSrICocLVsz316NHPT3lqr0Lu2"
            + "eKXlE5GRDp/c8RToTzMvEDdwi2PHP8sStrGJa1ruNRpOMnVAj8gnyd5KcyYJ"
            + "3j+Iv/56hzPFXsZMg8gtbPphRxb3xHEZj/xYXYfUhfdElezrBIID6LcWRZS2"
            + "MuuVddZToLOIdVWSTDZLscR6BIID6Ok+m+VC82JjvLNK4pZqO7Re9s/KAxV9"
            + "f3wfJ7C7kmr8ar4Mlp9jYfO11lCcBEL86sM93JypgayWp53NN2nYQjnQDafR"
            + "NrtlthQuR36ir2DEuSp4ySqsSXX/nD3AVOvrpbN88RUIK8Yx36tRaBOBL8tv"
            + "9aKDfgpWKK4NHxA7V3QkHCAVqLpUZlIvVqEcvjNpzn6ydDQLGk7x5itNlWdn"
            + "Kq/LfgMlXrTY/kKC4k7xogFS/FRIR10NP3lU+vAEa5T299QZv7c7n2OSVg6K"
            + "xEXwjYNhfsLP3PlaCppouc2xsq/zSvymZPWsVztuoMwEfVeTtoSEUU8cqOiw"
            + "Q1NpGtvrO1R28uRdelAVcrIu0qBAbdB5xb+xMfMhVhk7iuSZsYzKJVjK1CNK"
            + "4w+zNqfkZQQOdh1Qj1t5u/22HDTSzZKTot4brIywo6lxboFE0IDJwU8y62vF"
            + "4PEBPJDeXBuzbqurQhMS19J8h9wjw2quPAJ0E8dPR5B/1qPAuWYs1i2z2AtL"
            + "FwNU2B+u53EpI4kM/+Wh3wPZ7lxlXcooUc3+5tZdBqcN+s1A2JU5fkMu05/J"
            + "FSMG89+L5cwygPZssQ0uQFMqIpbbJp2IF76DYvVOdMnnWMgmw4n9sTcLb7Tf"
            + "GZAQEr3OLtXHxTAX6WnQ1rdDMiMGTvx4Kj1JrtENPI8Y7m6bhIfSuwUk4v3j"
            + "/DlPmCzGKsZHfjUvaqiZ/Kg+V4gdOMiIlhUwrR3jbxrX1xXNJ+RjwQzC0wX8"
            + "C8kGF4hK/DUil20EVZNmrTgqsBBqKLMKDNM7rGhyadlG1eg55rJL07ROmXfY"
            + "PbMtgPQBVVGcvM58jsW8NlCF5XUBNVSOfNSePUOOccPMTCt4VqRZobciIn7i"
            + "G6lGby6sS8KMRxmnviLWNVWqWyxjFhuv3S8zVplFmzJR7oXk8bcGW9QV93yN"
            + "fceR9ZVQdEITPTqVE3r2sgrzgFYZAJ+tMzDfkL4NcSBnivfCS1APRttG1RHJ"
            + "6nxjpf1Ya6CGkM17BdAeEtdXqBb/0B9n0hgPA8EIe5hfL+cGRx4aO8HldCMb"
            + "YQUFIOFmuj4xn83eFSlh2zllSVaVj0epIqtcXWWefVpjZKlOgoivrTy9JSGp"
            + "fbsDw/xZMPGYHehbtm60alZK/t4yrfyGLkeWq7FjK31WfIgx9KAEQM4G1cPx"
            + "dX6Jj0YdoWKrJh7GdqoCSdrwtR5NkG8ecuYPm9P+UUFg+nbcqR7zWVv0MulQ"
            + "X4LQoKN8iOXZYZDmKbgLYdh4BY8bqVELaHFZ3rU33EUoATO+43IQXHq5qyB5"
            + "xJVvT6AEggPo0DNHyUyRNMHoT3feYuDiQszN/4N5qVLZL6UeBIGGwmAQq7CK"
            + "2A2P67/7bjze+LZcvXgoBmkKPn9hVembyEPwow6wGVhrGDWiEvdNE/Tp3n6D"
            + "NqLIOhnWfTnsinWNXIlqxa6V/jE+MBcGCSqGSIb3DQEJFDEKHggAcgBvAG8A"
            + "dDAjBgkqhkiG9w0BCRUxFgQUioImRvGskdQCWPVdgD2wKGBiE/0AAAAAAAAw"
            + "gAYJKoZIhvcNAQcGoIAwgAIBADCABgkqhkiG9w0BBwEwKAYKKoZIhvcNAQwB"
            + "BjAaBBTOsaVE8IK7OpXHzfobYSfBfnKvTwICBACggASCCLirl2JOsxIiKwDT"
            + "/iW4D7qRq4W2mdXiLuH8RTJzfARcWtfWRrszakA6Fi0WAsslor3EYMgBpNtJ"
            + "yctpSfAO2ToEWNlzqRNffiy1UvxC7Pxo9coaDBfsD9hi253dxsCS+fkGlywA"
            + "eSlHJ2JEhDz7Y7CO6i95LzvZTzz7075UZvSP5FcVjNlKyfDMVVN3tPXl5/Ej"
            + "4l/rakdyg72d/ajx/VaG5S81Oy2sjTdG+j6G7aMgpAx7dkgiNr65f9rLU7M9"
            + "sm24II3RZzfUcjHHSZUvwtXIJSBnHkYft7GqzCFHnikLapFh9ObMdc4qTQQA"
            + "H7Upo0WD/rxgdKN0Bdj9BLZHm1Ixca6rBVOecg80t/kFXipwBihMUmPbHlWB"
            + "UGjX1kDRyfvqlcDDWr7elGenqNX1qTYCGi41ChLC9igaQRP48NI3aqgx0bu4"
            + "P2G19T+/E7UZrCc8VIlKUEGRNKSqVtC7IlqyoLdPms9TXzrYJkklB0m23VXI"
            + "PyJ5MmmRFXOAtLXwqnLGNLYcafbS2F4MPOjkclWgEtOHKmJctBRI14eMlpN2"
            + "gBMTYxVkOG7ehUtMbWnjTvivqRxsYPmRCC+m7wiHQodtm2fgJtfwhpRSmLu1"
            + "/KHohc6ESh62ACsn8nfBthsbzuDxV0fsCgbUDomjWpGs+nBgZFYGAkE1z2Ao"
            + "Xd7CvA3PZJ5HFtyJrEu8VAbCtU5ZLjXzbALiJ7BqJdzigqsxeieabsR+GCKz"
            + "Drwk1RltTIZnP3EeQbD+mGPa2BjchseaaLNMVDngkc91Zdg2j18dfIabG4AS"
            + "CvfM4DfwPdwD2UT48V8608u5OWc7O2sIcxVWv1IrbEFLSKchTPPnfKmdDji3"
            + "LEoD6t1VPYfn0Ch/NEANOLdncsOUDzQCWscA3+6pkfH8ZaCxfyUU/SHGYKkW"
            + "7twRpR9ka3Wr7rjMjmT0c24YNIUx9ZDt7iquCAdyRHHc13JQ+IWaoqo1z3b8"
            + "tz6AIfm1dWgcMlzEAc80Jg/SdASCA+g2sROpkVxAyhOY/EIp1Fm+PSIPQ5dE"
            + "r5wV7ne2gr40Zuxs5Mrra9Jm79hrErhe4nepA6/DkcHqVDW5sqDwSgLuwVui"
            + "I2yjBt4xBShc6jUxKTRN43cMlZa4rKaEF636gBMUZHDD+zTRE5rtHKFggvwc"
            + "LiitHXI+Fg9mH/h0cQRDYebc02bQikxKagfeUxm0DbEFH172VV+4L69MP6SY"
            + "eyMyRyBXNvLBKDVI5klORE7ZMJGCf2pi3vQr+tSM3W51QmK3HuL+tcish4QW"
            + "WOxVimmczo7tT/JPwSWcklTV4uvnAVLEfptl66Bu9I2/Kn3yPWElAoQvHjMD"
            + "O47+CVcuhgX5OXt0Sy8OX09j733FG4XFImnBneae6FrxNoi3tMRyHaIwBjIo"
            + "8VvqhWjPIJKytMT2/42TpsuD4Pj64m77sIx0rAjmU7s0kG4YdkgeSi+1R4X7"
            + "hkEFVJe3fId7/sItU2BMHkQGBDELAP7gJFzqTLDuSoiVNJ6kB6vkC+VQ7nmn"
            + "0xyzrOTNcrSBGc2dCXEI6eYi8/2K9y7ZS9dOEUi8SHfc4WNT4EJ8Qsvn61EW"
            + "jM8Ye5av/t3iE8NGtiMbbsIorEweL8y88vEMkgqZ7MpLbb2iiAv8Zm16GWAv"
            + "GRD7rUJfi/3dcXiskUCOg5rIRcn2ImVehqKAPArLbLAx7NJ6UZmB+99N3DpH"
            + "Jk81BkWPwQF8UlPdwjQh7qJUHTjEYAQI2wmL2jttToq59g3xbrLVUM/5X2Xy"
            + "Fy619lDydw0TZiGq8zA39lwT92WpziDeV5/vuj2gpcFs3f0cUSJlPsw7Y0mE"
            + "D/uPk7Arn/iP1oZboM9my/H3tm3rOP5xYxkXI/kVsNucTMLwd4WWdtKk3DLg"
            + "Ms1tcEdAUQ/ZJ938OJf1uzSixDhlMVedweIJMw72V9VpWUf+QC+SHOvGpdSz"
            + "2a7mU340J0rsQp7HnS71XWPjtxVCN0Mva+gnF+VTEnamQFEETrEydaqFYQEh"
            + "im5qr32YOiQiwdrIXJ+p9bNxAbaDBmBI/1bdDU9ffr+AGrxxgjvYGiUQk0d/"
            + "SDvxlE+S9EZlTWirRatglklVndYdkzJDte7ZJSgjlXkbTgy++QW/xRQ0Ya3o"
            + "ouQepoTkJ2b48ELe4KCKKTOfR0fTzd0578hSdpYuOCylYBZeuLIo6JH3VeoV"
            + "dggXMYHtYPuj+ABN3utwP/5s5LZ553sMkI/0bJq8ytE/+BFh1rTbRksAuT6B"
            + "d98lpDAXjyM1HcKD78YiXotdSISU+pYkIbyn4UG8SKzV9mCxAed1cgjE1BWW"
            + "DUB+xwlFMQTFpj8fhhYYMcwUF8tmv22Snemkaq3pjJKPBIIB7/jK7pfLMSSS"
            + "5ojMvWzu9mTegbl9v2K73XqZ/N4LZ5BqxnMdCBM4cCbA2LMwX8WAVlKper6X"
            + "zdTxRf4SWuzzlOXIyhWaH1g9Yp3PkaWh/BpPne/DXZmfyrTCPWGlbu1oqdKq"
            + "CgORN9B0+biTWiqgozvtbnCkK+LXqRYbghsWNlOhpm5NykUl7T2xRswYK8gz"
            + "5vq/xCY5hq+TvgZOT0Fzx426nbNqyGmdjbCpPf2t4s5o3C48WhNSg3vSSJes"
            + "RVJ4dV1TfXkytIKk/gzLafJfS+AcLeE48MyCOohhLFHdYC9f+lrk51xEANTc"
            + "xpn26JO1sO7iha8iccRmMYwi6tgDRVKFp6X5VVHXy8hXzxEbWWFL/GkUIjyD"
            + "hm0KXaarhP9Iah+/j6CI6eVLIhyMsA5itsYX+bJ0I8KmVkXelbwX7tcwSUAs"
            + "0Wq8oiV8Mi+DawkhTWE2etz07uMseR71jHEr7KE6WXo+SO995Xyop74fLtje"
            + "GLZroH91GWF4rDZvTJg9l8319oqF0DJ7bTukl3CJqVS3sVNrRIF33vRsmqWL"
            + "BaaZ1Q8Bt04L19Ka2HsEYLMfTLPGO7HSb9baHezRCQTnVoABm+8iZEXj3Od9"
            + "ga9TnxFa5KhXerqUscjdXPauElDwmqGhCgAAAAAAAAAAAAAAAAAAAAAAADA9"
            + "MCEwCQYFKw4DAhoFAAQUWT4N9h+ObRftdP8+GldXCQRf9JoEFDjO/tjAH7We"
            + "HLhcYQcQ1R+RucctAgIEAAAA");

    //
    // server.crt
    //
    byte[] cert1 = Base64.decode(
        "MIIDXjCCAsegAwIBAgIBBzANBgkqhkiG9w0BAQQFADCBtzELMAkGA1UEBhMCQVUx"
            + "ETAPBgNVBAgTCFZpY3RvcmlhMRgwFgYDVQQHEw9Tb3V0aCBNZWxib3VybmUxGjAY"
            + "BgNVBAoTEUNvbm5lY3QgNCBQdHkgTHRkMR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBB"
            + "dXRob3JpdHkxFTATBgNVBAMTDENvbm5lY3QgNCBDQTEoMCYGCSqGSIb3DQEJARYZ"
            + "d2VibWFzdGVyQGNvbm5lY3Q0LmNvbS5hdTAeFw0wMDA2MDIwNzU2MjFaFw0wMTA2"
            + "MDIwNzU2MjFaMIG4MQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExGDAW"
            + "BgNVBAcTD1NvdXRoIE1lbGJvdXJuZTEaMBgGA1UEChMRQ29ubmVjdCA0IFB0eSBM"
            + "dGQxFzAVBgNVBAsTDldlYnNlcnZlciBUZWFtMR0wGwYDVQQDExR3d3cyLmNvbm5l"
            + "Y3Q0LmNvbS5hdTEoMCYGCSqGSIb3DQEJARYZd2VibWFzdGVyQGNvbm5lY3Q0LmNv"
            + "bS5hdTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEArvDxclKAhyv7Q/Wmr2re"
            + "Gw4XL9Cnh9e+6VgWy2AWNy/MVeXdlxzd7QAuc1eOWQkGQEiLPy5XQtTY+sBUJ3AO"
            + "Rvd2fEVJIcjf29ey7bYua9J/vz5MG2KYo9/WCHIwqD9mmG9g0xLcfwq/s8ZJBswE"
            + "7sb85VU+h94PTvsWOsWuKaECAwEAAaN3MHUwJAYDVR0RBB0wG4EZd2VibWFzdGVy"
            + "QGNvbm5lY3Q0LmNvbS5hdTA6BglghkgBhvhCAQ0ELRYrbW9kX3NzbCBnZW5lcmF0"
            + "ZWQgY3VzdG9tIHNlcnZlciBjZXJ0aWZpY2F0ZTARBglghkgBhvhCAQEEBAMCBkAw"
            + "DQYJKoZIhvcNAQEEBQADgYEAotccfKpwSsIxM1Hae8DR7M/Rw8dg/RqOWx45HNVL"
            + "iBS4/3N/TO195yeQKbfmzbAA2jbPVvIvGgTxPgO1MP4ZgvgRhasaa0qCJCkWvpM4"
            + "yQf33vOiYQbpv4rTwzU8AmRlBG45WdjyNIigGV+oRc61aKCTnLq7zB8N3z1TF/bF"
            + "5/8=");

    //
    // ca.crt
    //
    byte[] cert2 = Base64.decode(
        "MIIDbDCCAtWgAwIBAgIBADANBgkqhkiG9w0BAQQFADCBtzELMAkGA1UEBhMCQVUx"
            + "ETAPBgNVBAgTCFZpY3RvcmlhMRgwFgYDVQQHEw9Tb3V0aCBNZWxib3VybmUxGjAY"
            + "BgNVBAoTEUNvbm5lY3QgNCBQdHkgTHRkMR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBB"
            + "dXRob3JpdHkxFTATBgNVBAMTDENvbm5lY3QgNCBDQTEoMCYGCSqGSIb3DQEJARYZ"
            + "d2VibWFzdGVyQGNvbm5lY3Q0LmNvbS5hdTAeFw0wMDA2MDIwNzU1MzNaFw0wMTA2"
            + "MDIwNzU1MzNaMIG3MQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExGDAW"
            + "BgNVBAcTD1NvdXRoIE1lbGJvdXJuZTEaMBgGA1UEChMRQ29ubmVjdCA0IFB0eSBM"
            + "dGQxHjAcBgNVBAsTFUNlcnRpZmljYXRlIEF1dGhvcml0eTEVMBMGA1UEAxMMQ29u"
            + "bmVjdCA0IENBMSgwJgYJKoZIhvcNAQkBFhl3ZWJtYXN0ZXJAY29ubmVjdDQuY29t"
            + "LmF1MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgs5ptNG6Qv1ZpCDuUNGmv"
            + "rhjqMDPd3ri8JzZNRiiFlBA4e6/ReaO1U8ASewDeQMH6i9R6degFdQRLngbuJP0s"
            + "xcEE+SksEWNvygfzLwV9J/q+TQDyJYK52utb++lS0b48A1KPLwEsyL6kOAgelbur"
            + "ukwxowprKUIV7Knf1ajetQIDAQABo4GFMIGCMCQGA1UdEQQdMBuBGXdlYm1hc3Rl"
            + "ckBjb25uZWN0NC5jb20uYXUwDwYDVR0TBAgwBgEB/wIBADA2BglghkgBhvhCAQ0E"
            + "KRYnbW9kX3NzbCBnZW5lcmF0ZWQgY3VzdG9tIENBIGNlcnRpZmljYXRlMBEGCWCG"
            + "SAGG+EIBAQQEAwICBDANBgkqhkiG9w0BAQQFAAOBgQCsGvfdghH8pPhlwm1r3pQk"
            + "msnLAVIBb01EhbXm2861iXZfWqGQjrGAaA0ZpXNk9oo110yxoqEoSJSzniZa7Xtz"
            + "soTwNUpE0SLHvWf/SlKdFWlzXA+vOZbzEv4UmjeelekTm7lc01EEa5QRVzOxHFtQ"
            + "DhkaJ8VqOMajkQFma2r9iA==");

    //
    // testx509.pem
    //
    byte[] cert3 = Base64.decode(
        "MIIBWzCCAQYCARgwDQYJKoZIhvcNAQEEBQAwODELMAkGA1UEBhMCQVUxDDAKBgNV"
            + "BAgTA1FMRDEbMBkGA1UEAxMSU1NMZWF5L3JzYSB0ZXN0IENBMB4XDTk1MDYxOTIz"
            + "MzMxMloXDTk1MDcxNzIzMzMxMlowOjELMAkGA1UEBhMCQVUxDDAKBgNVBAgTA1FM"
            + "RDEdMBsGA1UEAxMUU1NMZWF5L3JzYSB0ZXN0IGNlcnQwXDANBgkqhkiG9w0BAQEF"
            + "AANLADBIAkEAqtt6qS5GTxVxGZYWa0/4u+IwHf7p2LNZbcPBp9/OfIcYAXBQn8hO"
            + "/Re1uwLKXdCjIoaGs4DLdG88rkzfyK5dPQIDAQABMAwGCCqGSIb3DQIFBQADQQAE"
            + "Wc7EcF8po2/ZO6kNCwK/ICH6DobgLekA5lSLr5EvuioZniZp5lFzAw4+YzPQ7XKJ"
            + "zl9HYIMxATFyqSiD9jsx");

    //
    // v3-cert1.pem
    //
    byte[] cert4 = Base64.decode(
        "MIICjTCCAfigAwIBAgIEMaYgRzALBgkqhkiG9w0BAQQwRTELMAkGA1UEBhMCVVMx"
            + "NjA0BgNVBAoTLU5hdGlvbmFsIEFlcm9uYXV0aWNzIGFuZCBTcGFjZSBBZG1pbmlz"
            + "dHJhdGlvbjAmFxE5NjA1MjgxMzQ5MDUrMDgwMBcROTgwNTI4MTM0OTA1KzA4MDAw"
            + "ZzELMAkGA1UEBhMCVVMxNjA0BgNVBAoTLU5hdGlvbmFsIEFlcm9uYXV0aWNzIGFu"
            + "ZCBTcGFjZSBBZG1pbmlzdHJhdGlvbjEgMAkGA1UEBRMCMTYwEwYDVQQDEwxTdGV2"
            + "ZSBTY2hvY2gwWDALBgkqhkiG9w0BAQEDSQAwRgJBALrAwyYdgxmzNP/ts0Uyf6Bp"
            + "miJYktU/w4NG67ULaN4B5CnEz7k57s9o3YY3LecETgQ5iQHmkwlYDTL2fTgVfw0C"
            + "AQOjgaswgagwZAYDVR0ZAQH/BFowWDBWMFQxCzAJBgNVBAYTAlVTMTYwNAYDVQQK"
            + "Ey1OYXRpb25hbCBBZXJvbmF1dGljcyBhbmQgU3BhY2UgQWRtaW5pc3RyYXRpb24x"
            + "DTALBgNVBAMTBENSTDEwFwYDVR0BAQH/BA0wC4AJODMyOTcwODEwMBgGA1UdAgQR"
            + "MA8ECTgzMjk3MDgyM4ACBSAwDQYDVR0KBAYwBAMCBkAwCwYJKoZIhvcNAQEEA4GB"
            + "AH2y1VCEw/A4zaXzSYZJTTUi3uawbbFiS2yxHvgf28+8Js0OHXk1H1w2d6qOHH21"
            + "X82tZXd/0JtG0g1T9usFFBDvYK8O0ebgz/P5ELJnBL2+atObEuJy1ZZ0pBDWINR3"
            + "WkDNLCGiTkCKp0F5EWIrVDwh54NNevkCQRZita+z4IBO");

    //
    // v3-cert2.pem
    //
    byte[] cert5 = Base64.decode(
        "MIICiTCCAfKgAwIBAgIEMeZfHzANBgkqhkiG9w0BAQQFADB9MQswCQYDVQQGEwJD"
            + "YTEPMA0GA1UEBxMGTmVwZWFuMR4wHAYDVQQLExVObyBMaWFiaWxpdHkgQWNjZXB0"
            + "ZWQxHzAdBgNVBAoTFkZvciBEZW1vIFB1cnBvc2VzIE9ubHkxHDAaBgNVBAMTE0Vu"
            + "dHJ1c3QgRGVtbyBXZWIgQ0EwHhcNOTYwNzEyMTQyMDE1WhcNOTYxMDEyMTQyMDE1"
            + "WjB0MSQwIgYJKoZIhvcNAQkBExVjb29rZUBpc3NsLmF0bC5ocC5jb20xCzAJBgNV"
            + "BAYTAlVTMScwJQYDVQQLEx5IZXdsZXR0IFBhY2thcmQgQ29tcGFueSAoSVNTTCkx"
            + "FjAUBgNVBAMTDVBhdWwgQS4gQ29va2UwXDANBgkqhkiG9w0BAQEFAANLADBIAkEA"
            + "6ceSq9a9AU6g+zBwaL/yVmW1/9EE8s5you1mgjHnj0wAILuoB3L6rm6jmFRy7QZT"
            + "G43IhVZdDua4e+5/n1ZslwIDAQABo2MwYTARBglghkgBhvhCAQEEBAMCB4AwTAYJ"
            + "YIZIAYb4QgENBD8WPVRoaXMgY2VydGlmaWNhdGUgaXMgb25seSBpbnRlbmRlZCBm"
            + "b3IgZGVtb25zdHJhdGlvbiBwdXJwb3Nlcy4wDQYJKoZIhvcNAQEEBQADgYEAi8qc"
            + "F3zfFqy1sV8NhjwLVwOKuSfhR/Z8mbIEUeSTlnH3QbYt3HWZQ+vXI8mvtZoBc2Fz"
            + "lexKeIkAZXCesqGbs6z6nCt16P6tmdfbZF3I3AWzLquPcOXjPf4HgstkyvVBn0Ap"
            + "jAFN418KF/Cx4qyHB4cjdvLrRjjQLnb2+ibo7QU=");

    //
    // pem encoded pkcs7
    //
    byte[] cert6 = Base64.decode(
        "MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAQAAoIIJbzCCAj0w"
            + "ggGmAhEAzbp/VvDf5LxU/iKss3KqVTANBgkqhkiG9w0BAQIFADBfMQswCQYDVQQGEwJVUzEXMBUG"
            + "A1UEChMOVmVyaVNpZ24sIEluYy4xNzA1BgNVBAsTLkNsYXNzIDEgUHVibGljIFByaW1hcnkgQ2Vy"
            + "dGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNOTYwMTI5MDAwMDAwWhcNMjgwODAxMjM1OTU5WjBfMQsw"
            + "CQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xNzA1BgNVBAsTLkNsYXNzIDEgUHVi"
            + "bGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwgZ8wDQYJKoZIhvcNAQEBBQADgY0A"
            + "MIGJAoGBAOUZv22jVmEtmUhx9mfeuY3rt56GgAqRDvo4Ja9GiILlc6igmyRdDR/MZW4MsNBWhBiH"
            + "mgabEKFz37RYOWtuwfYV1aioP6oSBo0xrH+wNNePNGeICc0UEeJORVZpH3gCgNrcR5EpuzbJY1zF"
            + "4Ncth3uhtzKwezC6Ki8xqu6jZ9rbAgMBAAEwDQYJKoZIhvcNAQECBQADgYEATD+4i8Zo3+5DMw5d"
            + "6abLB4RNejP/khv0Nq3YlSI2aBFsfELM85wuxAc/FLAPT/+Qknb54rxK6Y/NoIAK98Up8YIiXbix"
            + "3YEjo3slFUYweRb46gVLlH8dwhzI47f0EEA8E8NfH1PoSOSGtHuhNbB7Jbq4046rPzidADQAmPPR"
            + "cZQwggMuMIICl6ADAgECAhEA0nYujRQMPX2yqCVdr+4NdTANBgkqhkiG9w0BAQIFADBfMQswCQYD"
            + "VQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xNzA1BgNVBAsTLkNsYXNzIDEgUHVibGlj"
            + "IFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNOTgwNTEyMDAwMDAwWhcNMDgwNTEy"
            + "MjM1OTU5WjCBzDEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRy"
            + "dXN0IE5ldHdvcmsxRjBEBgNVBAsTPXd3dy52ZXJpc2lnbi5jb20vcmVwb3NpdG9yeS9SUEEgSW5j"
            + "b3JwLiBCeSBSZWYuLExJQUIuTFREKGMpOTgxSDBGBgNVBAMTP1ZlcmlTaWduIENsYXNzIDEgQ0Eg"
            + "SW5kaXZpZHVhbCBTdWJzY3JpYmVyLVBlcnNvbmEgTm90IFZhbGlkYXRlZDCBnzANBgkqhkiG9w0B"
            + "AQEFAAOBjQAwgYkCgYEAu1pEigQWu1X9A3qKLZRPFXg2uA1Ksm+cVL+86HcqnbnwaLuV2TFBcHqB"
            + "S7lIE1YtxwjhhEKrwKKSq0RcqkLwgg4C6S/7wju7vsknCl22sDZCM7VuVIhPh0q/Gdr5FegPh7Yc"
            + "48zGmo5/aiSS4/zgZbqnsX7vyds3ashKyAkG5JkCAwEAAaN8MHowEQYJYIZIAYb4QgEBBAQDAgEG"
            + "MEcGA1UdIARAMD4wPAYLYIZIAYb4RQEHAQEwLTArBggrBgEFBQcCARYfd3d3LnZlcmlzaWduLmNv"
            + "bS9yZXBvc2l0b3J5L1JQQTAPBgNVHRMECDAGAQH/AgEAMAsGA1UdDwQEAwIBBjANBgkqhkiG9w0B"
            + "AQIFAAOBgQCIuDc73dqUNwCtqp/hgQFxHpJqbS/28Z3TymQ43BuYDAeGW4UVag+5SYWklfEXfWe0"
            + "fy0s3ZpCnsM+tI6q5QsG3vJWKvozx74Z11NMw73I4xe1pElCY+zCphcPXVgaSTyQXFWjZSAA/Rgg"
            + "5V+CprGoksVYasGNAzzrw80FopCubjCCA/gwggNhoAMCAQICEBbbn/1G1zppD6KsP01bwywwDQYJ"
            + "KoZIhvcNAQEEBQAwgcwxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2ln"
            + "biBUcnVzdCBOZXR3b3JrMUYwRAYDVQQLEz13d3cudmVyaXNpZ24uY29tL3JlcG9zaXRvcnkvUlBB"
            + "IEluY29ycC4gQnkgUmVmLixMSUFCLkxURChjKTk4MUgwRgYDVQQDEz9WZXJpU2lnbiBDbGFzcyAx"
            + "IENBIEluZGl2aWR1YWwgU3Vic2NyaWJlci1QZXJzb25hIE5vdCBWYWxpZGF0ZWQwHhcNMDAxMDAy"
            + "MDAwMDAwWhcNMDAxMjAxMjM1OTU5WjCCAQcxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYD"
            + "VQQLExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMUYwRAYDVQQLEz13d3cudmVyaXNpZ24uY29tL3Jl"
            + "cG9zaXRvcnkvUlBBIEluY29ycC4gYnkgUmVmLixMSUFCLkxURChjKTk4MR4wHAYDVQQLExVQZXJz"
            + "b25hIE5vdCBWYWxpZGF0ZWQxJzAlBgNVBAsTHkRpZ2l0YWwgSUQgQ2xhc3MgMSAtIE1pY3Jvc29m"
            + "dDETMBEGA1UEAxQKRGF2aWQgUnlhbjElMCMGCSqGSIb3DQEJARYWZGF2aWRAbGl2ZW1lZGlhLmNv"
            + "bS5hdTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAqxBsdeNmSvFqhMNwhQgNzM8mdjX9eSXb"
            + "DawpHtQHjmh0AKJSa3IwUY0VIsyZHuXWktO/CgaMBVPt6OVf/n0R2sQigMP6Y+PhEiS0vCJBL9aK"
            + "0+pOo2qXrjVBmq+XuCyPTnc+BOSrU26tJsX0P9BYorwySiEGxGanBNATdVL4NdUCAwEAAaOBnDCB"
            + "mTAJBgNVHRMEAjAAMEQGA1UdIAQ9MDswOQYLYIZIAYb4RQEHAQgwKjAoBggrBgEFBQcCARYcaHR0"
            + "cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYTARBglghkgBhvhCAQEEBAMCB4AwMwYDVR0fBCwwKjAo"
            + "oCagJIYiaHR0cDovL2NybC52ZXJpc2lnbi5jb20vY2xhc3MxLmNybDANBgkqhkiG9w0BAQQFAAOB"
            + "gQBC8yIIdVGpFTf8/YiL14cMzcmL0nIRm4kGR3U59z7UtcXlfNXXJ8MyaeI/BnXwG/gD5OKYqW6R"
            + "yca9vZOxf1uoTBl82gInk865ED3Tej6msCqFzZffnSUQvOIeqLxxDlqYRQ6PmW2nAnZeyjcnbI5Y"
            + "syQSM2fmo7n6qJFP+GbFezGCAkUwggJBAgEBMIHhMIHMMRcwFQYDVQQKEw5WZXJpU2lnbiwgSW5j"
            + "LjEfMB0GA1UECxMWVmVyaVNpZ24gVHJ1c3QgTmV0d29yazFGMEQGA1UECxM9d3d3LnZlcmlzaWdu"
            + "LmNvbS9yZXBvc2l0b3J5L1JQQSBJbmNvcnAuIEJ5IFJlZi4sTElBQi5MVEQoYyk5ODFIMEYGA1UE"
            + "AxM/VmVyaVNpZ24gQ2xhc3MgMSBDQSBJbmRpdmlkdWFsIFN1YnNjcmliZXItUGVyc29uYSBOb3Qg"
            + "VmFsaWRhdGVkAhAW25/9Rtc6aQ+irD9NW8MsMAkGBSsOAwIaBQCggbowGAYJKoZIhvcNAQkDMQsG"
            + "CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMDAxMDAyMTczNTE4WjAjBgkqhkiG9w0BCQQxFgQU"
            + "gZjSaBEY2oxGvlQUIMnxSXhivK8wWwYJKoZIhvcNAQkPMU4wTDAKBggqhkiG9w0DBzAOBggqhkiG"
            + "9w0DAgICAIAwDQYIKoZIhvcNAwICAUAwBwYFKw4DAgcwDQYIKoZIhvcNAwICASgwBwYFKw4DAh0w"
            + "DQYJKoZIhvcNAQEBBQAEgYAzk+PU91/ZFfoiuKOECjxEh9fDYE2jfDCheBIgh5gdcCo+sS1WQs8O"
            + "HreQ9Nop/JdJv1DQMBK6weNBBDoP0EEkRm1XCC144XhXZC82jBZohYmi2WvDbbC//YN58kRMYMyy"
            + "srrfn4Z9I+6kTriGXkrpGk9Q0LSGjmG2BIsqiF0dvwAAAAAAAA==");

    //
    // dsaWithSHA1 cert
    //
    byte[] cert7 = Base64.decode(
        "MIIEXAYJKoZIhvcNAQcCoIIETTCCBEkCAQExCzAJBgUrDgMCGgUAMAsGCSqG"
            + "SIb3DQEHAaCCAsMwggK/MIIB4AIBADCBpwYFKw4DAhswgZ0CQQEkJRHP+mN7"
            + "d8miwTMN55CUSmo3TO8WGCxgY61TX5k+7NU4XPf1TULjw3GobwaJX13kquPh"
            + "fVXk+gVy46n4Iw3hAhUBSe/QF4BUj+pJOF9ROBM4u+FEWA8CQQD4mSJbrABj"
            + "TUWrlnAte8pS22Tq4/FPO7jHSqjijUHfXKTrHL1OEqV3SVWcFy5j/cqBgX/z"
            + "m8Q12PFp/PjOhh+nMA4xDDAKBgNVBAMTA0lEMzAeFw05NzEwMDEwMDAwMDBa"
            + "Fw0zODAxMDEwMDAwMDBaMA4xDDAKBgNVBAMTA0lEMzCB8DCBpwYFKw4DAhsw"
            + "gZ0CQQEkJRHP+mN7d8miwTMN55CUSmo3TO8WGCxgY61TX5k+7NU4XPf1TULj"
            + "w3GobwaJX13kquPhfVXk+gVy46n4Iw3hAhUBSe/QF4BUj+pJOF9ROBM4u+FE"
            + "WA8CQQD4mSJbrABjTUWrlnAte8pS22Tq4/FPO7jHSqjijUHfXKTrHL1OEqV3"
            + "SVWcFy5j/cqBgX/zm8Q12PFp/PjOhh+nA0QAAkEAkYkXLYMtGVGWj9OnzjPn"
            + "sB9sefSRPrVegZJCZbpW+Iv0/1RP1u04pHG9vtRpIQLjzUiWvLMU9EKQTThc"
            + "eNMmWDCBpwYFKw4DAhswgZ0CQQEkJRHP+mN7d8miwTMN55CUSmo3TO8WGCxg"
            + "Y61TX5k+7NU4XPf1TULjw3GobwaJX13kquPhfVXk+gVy46n4Iw3hAhUBSe/Q"
            + "F4BUj+pJOF9ROBM4u+FEWA8CQQD4mSJbrABjTUWrlnAte8pS22Tq4/FPO7jH"
            + "SqjijUHfXKTrHL1OEqV3SVWcFy5j/cqBgX/zm8Q12PFp/PjOhh+nAy8AMCwC"
            + "FBY3dBSdeprGcqpr6wr3xbG+6WW+AhRMm/facKJNxkT3iKgJbp7R8Xd3QTGC"
            + "AWEwggFdAgEBMBMwDjEMMAoGA1UEAxMDSUQzAgEAMAkGBSsOAwIaBQCgXTAY"
            + "BgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0wMjA1"
            + "MjQyMzEzMDdaMCMGCSqGSIb3DQEJBDEWBBS4WMsoJhf7CVbZYCFcjoTRzPkJ"
            + "xjCBpwYFKw4DAhswgZ0CQQEkJRHP+mN7d8miwTMN55CUSmo3TO8WGCxgY61T"
            + "X5k+7NU4XPf1TULjw3GobwaJX13kquPhfVXk+gVy46n4Iw3hAhUBSe/QF4BU"
            + "j+pJOF9ROBM4u+FEWA8CQQD4mSJbrABjTUWrlnAte8pS22Tq4/FPO7jHSqji"
            + "jUHfXKTrHL1OEqV3SVWcFy5j/cqBgX/zm8Q12PFp/PjOhh+nBC8wLQIVALID"
            + "dt+MHwawrDrwsO1Z6sXBaaJsAhRaKssrpevmLkbygKPV07XiAKBG02Zvb2Jh"
            + "cg==");

    //
    // testcrl.pem
    //
    byte[] crl1 = Base64.decode(
        "MIICjTCCAfowDQYJKoZIhvcNAQECBQAwXzELMAkGA1UEBhMCVVMxIDAeBgNVBAoT"
            + "F1JTQSBEYXRhIFNlY3VyaXR5LCBJbmMuMS4wLAYDVQQLEyVTZWN1cmUgU2VydmVy"
            + "IENlcnRpZmljYXRpb24gQXV0aG9yaXR5Fw05NTA1MDIwMjEyMjZaFw05NTA2MDEw"
            + "MDAxNDlaMIIBaDAWAgUCQQAABBcNOTUwMjAxMTcyNDI2WjAWAgUCQQAACRcNOTUw"
            + "MjEwMDIxNjM5WjAWAgUCQQAADxcNOTUwMjI0MDAxMjQ5WjAWAgUCQQAADBcNOTUw"
            + "MjI1MDA0NjQ0WjAWAgUCQQAAGxcNOTUwMzEzMTg0MDQ5WjAWAgUCQQAAFhcNOTUw"
            + "MzE1MTkxNjU0WjAWAgUCQQAAGhcNOTUwMzE1MTk0MDQxWjAWAgUCQQAAHxcNOTUw"
            + "MzI0MTk0NDMzWjAWAgUCcgAABRcNOTUwMzI5MjAwNzExWjAWAgUCcgAAERcNOTUw"
            + "MzMwMDIzNDI2WjAWAgUCQQAAIBcNOTUwNDA3MDExMzIxWjAWAgUCcgAAHhcNOTUw"
            + "NDA4MDAwMjU5WjAWAgUCcgAAQRcNOTUwNDI4MTcxNzI0WjAWAgUCcgAAOBcNOTUw"
            + "NDI4MTcyNzIxWjAWAgUCcgAATBcNOTUwNTAyMDIxMjI2WjANBgkqhkiG9w0BAQIF"
            + "AAN+AHqOEJXSDejYy0UwxxrH/9+N2z5xu/if0J6qQmK92W0hW158wpJg+ovV3+wQ"
            + "wvIEPRL2rocL0tKfAsVq1IawSJzSNgxG0lrcla3MrJBnZ4GaZDu4FutZh72MR3Gt"
            + "JaAL3iTJHJD55kK2D/VoyY1djlsPuNh6AEgdVwFAyp0v");

    //
    // ecdsa cert with extra octet string.
    //
    byte[] oldEcdsa = Base64.decode(
        "MIICljCCAkCgAwIBAgIBATALBgcqhkjOPQQBBQAwgY8xCzAJBgNVBAYTAkFVMSgwJ"
            + "gYDVQQKEx9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIwEAYDVQQHEw"
            + "lNZWxib3VybmUxETAPBgNVBAgTCFZpY3RvcmlhMS8wLQYJKoZIhvcNAQkBFiBmZWV"
            + "kYmFjay1jcnlwdG9AYm91bmN5Y2FzdGxlLm9yZzAeFw0wMTEyMDcwMTAwMDRaFw0w"
            + "MTEyMDcwMTAxNDRaMIGPMQswCQYDVQQGEwJBVTEoMCYGA1UEChMfVGhlIExlZ2lvb"
            + "iBvZiB0aGUgQm91bmN5IENhc3RsZTESMBAGA1UEBxMJTWVsYm91cm5lMREwDwYDVQ"
            + "QIEwhWaWN0b3JpYTEvMC0GCSqGSIb3DQEJARYgZmVlZGJhY2stY3J5cHRvQGJvdW5"
            + "jeWNhc3RsZS5vcmcwgeQwgb0GByqGSM49AgEwgbECAQEwKQYHKoZIzj0BAQIef///"
            + "////////////f///////gAAAAAAAf///////MEAEHn///////////////3///////"
            + "4AAAAAAAH///////AQeawFsO9zxiUHQ1lSSFHXKcanbL7J9HTd5YYXClCwKBB8CD/"
            + "qWPNyogWzMM7hkK+35BcPTWFc9Pyf7vTs8uaqvAh5///////////////9///+eXpq"
            + "fXZBx+9FSJoiQnQsDIgAEHwJbbcU7xholSP+w9nFHLebJUhqdLSU05lq/y9X+DHAw"
            + "CwYHKoZIzj0EAQUAA0MAMEACHnz6t4UNoVROp74ma4XNDjjGcjaqiIWPZLK8Bdw3G"
            + "QIeLZ4j3a6ividZl344UH+UPUE7xJxlYGuy7ejTsqRR");

    byte[] uncompressedPtEC = Base64.decode(
        "MIIDKzCCAsGgAwIBAgICA+kwCwYHKoZIzj0EAQUAMGYxCzAJBgNVBAYTAkpQ"
            + "MRUwEwYDVQQKEwxuaXRlY2guYWMuanAxDjAMBgNVBAsTBWFpbGFiMQ8wDQYD"
            + "VQQDEwZ0ZXN0Y2ExHzAdBgkqhkiG9w0BCQEWEHRlc3RjYUBsb2NhbGhvc3Qw"
            + "HhcNMDExMDEzMTE1MzE3WhcNMjAxMjEyMTE1MzE3WjBmMQswCQYDVQQGEwJK"
            + "UDEVMBMGA1UEChMMbml0ZWNoLmFjLmpwMQ4wDAYDVQQLEwVhaWxhYjEPMA0G"
            + "A1UEAxMGdGVzdGNhMR8wHQYJKoZIhvcNAQkBFhB0ZXN0Y2FAbG9jYWxob3N0"
            + "MIIBczCCARsGByqGSM49AgEwggEOAgEBMDMGByqGSM49AQECKEdYWnajFmnZ"
            + "tzrukK2XWdle2v+GsD9l1ZiR6g7ozQDbhFH/bBiMDQcwVAQoJ5EQKrI54/CT"
            + "xOQ2pMsd/fsXD+EX8YREd8bKHWiLz8lIVdD5cBNeVwQoMKSc6HfI7vKZp8Q2"
            + "zWgIFOarx1GQoWJbMcSt188xsl30ncJuJT2OoARRBAqJ4fD+q6hbqgNSjTQ7"
            + "htle1KO3eiaZgcJ8rrnyN8P+5A8+5K+H9aQ/NbBR4Gs7yto5PXIUZEUgodHA"
            + "TZMSAcSq5ZYt4KbnSYaLY0TtH9CqAigEwZ+hglbT21B7ZTzYX2xj0x+qooJD"
            + "hVTLtIPaYJK2HrMPxTw6/zfrAgEPA1IABAnvfFcFDgD/JicwBGn6vR3N8MIn"
            + "mptZf/mnJ1y649uCF60zOgdwIyI7pVSxBFsJ7ohqXEHW0x7LrGVkdSEiipiH"
            + "LYslqh3xrqbAgPbl93GUo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB"
            + "/wQEAwIBxjAdBgNVHQ4EFgQUAEo62Xm9H6DcsE0zUDTza4BRG90wCwYHKoZI"
            + "zj0EAQUAA1cAMFQCKAQsCHHSNOqfJXLgt3bg5+k49hIBGVr/bfG0B9JU3rNt"
            + "Ycl9Y2zfRPUCKAK2ccOQXByAWfsasDu8zKHxkZv7LVDTFjAIffz3HaCQeVhD"
            + "z+fauEg=");

    byte[] keyUsage = Base64.decode(
        "MIIE7TCCBFagAwIBAgIEOAOR7jANBgkqhkiG9w0BAQQFADCByTELMAkGA1UE"
            + "BhMCVVMxFDASBgNVBAoTC0VudHJ1c3QubmV0MUgwRgYDVQQLFD93d3cuZW50"
            + "cnVzdC5uZXQvQ2xpZW50X0NBX0luZm8vQ1BTIGluY29ycC4gYnkgcmVmLiBs"
            + "aW1pdHMgbGlhYi4xJTAjBgNVBAsTHChjKSAxOTk5IEVudHJ1c3QubmV0IExp"
            + "bWl0ZWQxMzAxBgNVBAMTKkVudHJ1c3QubmV0IENsaWVudCBDZXJ0aWZpY2F0"
            + "aW9uIEF1dGhvcml0eTAeFw05OTEwMTIxOTI0MzBaFw0xOTEwMTIxOTU0MzBa"
            + "MIHJMQswCQYDVQQGEwJVUzEUMBIGA1UEChMLRW50cnVzdC5uZXQxSDBGBgNV"
            + "BAsUP3d3dy5lbnRydXN0Lm5ldC9DbGllbnRfQ0FfSW5mby9DUFMgaW5jb3Jw"
            + "LiBieSByZWYuIGxpbWl0cyBsaWFiLjElMCMGA1UECxMcKGMpIDE5OTkgRW50"
            + "cnVzdC5uZXQgTGltaXRlZDEzMDEGA1UEAxMqRW50cnVzdC5uZXQgQ2xpZW50"
            + "IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIGdMA0GCSqGSIb3DQEBAQUAA4GL"
            + "ADCBhwKBgQDIOpleMRffrCdvkHvkGf9FozTC28GoT/Bo6oT9n3V5z8GKUZSv"
            + "x1cDR2SerYIbWtp/N3hHuzeYEpbOxhN979IMMFGpOZ5V+Pux5zDeg7K6PvHV"
            + "iTs7hbqqdCz+PzFur5GVbgbUB01LLFZHGARS2g4Qk79jkJvh34zmAqTmT173"
            + "iwIBA6OCAeAwggHcMBEGCWCGSAGG+EIBAQQEAwIABzCCASIGA1UdHwSCARkw"
            + "ggEVMIHkoIHhoIHepIHbMIHYMQswCQYDVQQGEwJVUzEUMBIGA1UEChMLRW50"
            + "cnVzdC5uZXQxSDBGBgNVBAsUP3d3dy5lbnRydXN0Lm5ldC9DbGllbnRfQ0Ff"
            + "SW5mby9DUFMgaW5jb3JwLiBieSByZWYuIGxpbWl0cyBsaWFiLjElMCMGA1UE"
            + "CxMcKGMpIDE5OTkgRW50cnVzdC5uZXQgTGltaXRlZDEzMDEGA1UEAxMqRW50"
            + "cnVzdC5uZXQgQ2xpZW50IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MQ0wCwYD"
            + "VQQDEwRDUkwxMCygKqAohiZodHRwOi8vd3d3LmVudHJ1c3QubmV0L0NSTC9D"
            + "bGllbnQxLmNybDArBgNVHRAEJDAigA8xOTk5MTAxMjE5MjQzMFqBDzIwMTkx"
            + "MDEyMTkyNDMwWjALBgNVHQ8EBAMCAQYwHwYDVR0jBBgwFoAUxPucKXuXzUyW"
            + "/O5bs8qZdIuV6kwwHQYDVR0OBBYEFMT7nCl7l81MlvzuW7PKmXSLlepMMAwG"
            + "A1UdEwQFMAMBAf8wGQYJKoZIhvZ9B0EABAwwChsEVjQuMAMCBJAwDQYJKoZI"
            + "hvcNAQEEBQADgYEAP66K8ddmAwWePvrqHEa7pFuPeJoSSJn59DXeDDYHAmsQ"
            + "OokUgZwxpnyyQbJq5wcBoUv5nyU7lsqZwz6hURzzwy5E97BnRqqS5TvaHBkU"
            + "ODDV4qIxJS7x7EU47fgGWANzYrAQMY9Av2TgXD7FTx/aEkP/TOYGJqibGapE"
            + "PHayXOw=");

    byte[] nameCert = Base64.decode(
        "MIIEFjCCA3+gAwIBAgIEdS8BozANBgkqhkiG9w0BAQUFADBKMQswCQYDVQQGEwJE" +
            "RTERMA8GA1UEChQIREFURVYgZUcxKDAMBgcCggYBCgcUEwExMBgGA1UEAxQRQ0Eg" +
            "REFURVYgRDAzIDE6UE4wIhgPMjAwMTA1MTAxMDIyNDhaGA8yMDA0MDUwOTEwMjI0" +
            "OFowgYQxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIFAZCYXllcm4xEjAQBgNVBAcUCU7I" +
            "dXJuYmVyZzERMA8GA1UEChQIREFURVYgZUcxHTAbBgNVBAUTFDAwMDAwMDAwMDA4" +
            "OTU3NDM2MDAxMR4wHAYDVQQDFBVEaWV0bWFyIFNlbmdlbmxlaXRuZXIwgaEwDQYJ" +
            "KoZIhvcNAQEBBQADgY8AMIGLAoGBAJLI/LJLKaHoMk8fBECW/od8u5erZi6jI8Ug" +
            "C0a/LZyQUO/R20vWJs6GrClQtXB+AtfiBSnyZOSYzOdfDI8yEKPEv8qSuUPpOHps" +
            "uNCFdLZF1vavVYGEEWs2+y+uuPmg8q1oPRyRmUZ+x9HrDvCXJraaDfTEd9olmB/Z" +
            "AuC/PqpjAgUAwAAAAaOCAcYwggHCMAwGA1UdEwEB/wQCMAAwDwYDVR0PAQH/BAUD" +
            "AwdAADAxBgNVHSAEKjAoMCYGBSskCAEBMB0wGwYIKwYBBQUHAgEWD3d3dy56cy5k" +
            "YXRldi5kZTApBgNVHREEIjAggR5kaWV0bWFyLnNlbmdlbmxlaXRuZXJAZGF0ZXYu" +
            "ZGUwgYQGA1UdIwR9MHuhc6RxMG8xCzAJBgNVBAYTAkRFMT0wOwYDVQQKFDRSZWd1" +
            "bGllcnVuZ3NiZWjIb3JkZSBmyHVyIFRlbGVrb21tdW5pa2F0aW9uIHVuZCBQb3N0" +
            "MSEwDAYHAoIGAQoHFBMBMTARBgNVBAMUCjVSLUNBIDE6UE6CBACm8LkwDgYHAoIG" +
            "AQoMAAQDAQEAMEcGA1UdHwRAMD4wPKAUoBKGEHd3dy5jcmwuZGF0ZXYuZGWiJKQi" +
            "MCAxCzAJBgNVBAYTAkRFMREwDwYDVQQKFAhEQVRFViBlRzAWBgUrJAgDBAQNMAsT" +
            "A0VVUgIBBQIBATAdBgNVHQ4EFgQUfv6xFP0xk7027folhy+ziZvBJiwwLAYIKwYB" +
            "BQUHAQEEIDAeMBwGCCsGAQUFBzABhhB3d3cuZGlyLmRhdGV2LmRlMA0GCSqGSIb3" +
            "DQEBBQUAA4GBAEOVX6uQxbgtKzdgbTi6YLffMftFr2mmNwch7qzpM5gxcynzgVkg" +
            "pnQcDNlm5AIbS6pO8jTCLfCd5TZ5biQksBErqmesIl3QD+VqtB+RNghxectZ3VEs" +
            "nCUtcE7tJ8O14qwCb3TxS9dvIUFiVi4DjbxX46TdcTbTaK8/qr6AIf+l");

    byte[] probSelfSignedCert = Base64.decode(
        "MIICxTCCAi6gAwIBAgIQAQAAAAAAAAAAAAAAAAAAATANBgkqhkiG9w0BAQUFADBF"
            + "MScwJQYDVQQKEx4gRElSRUNUSU9OIEdFTkVSQUxFIERFUyBJTVBPVFMxGjAYBgNV"
            + "BAMTESBBQyBNSU5FRkkgQiBURVNUMB4XDTA0MDUwNzEyMDAwMFoXDTE0MDUwNzEy"
            + "MDAwMFowRTEnMCUGA1UEChMeIERJUkVDVElPTiBHRU5FUkFMRSBERVMgSU1QT1RT"
            + "MRowGAYDVQQDExEgQUMgTUlORUZJIEIgVEVTVDCBnzANBgkqhkiG9w0BAQEFAAOB"
            + "jQAwgYkCgYEAveoCUOAukZdcFCs2qJk76vSqEX0ZFzHqQ6faBPZWjwkgUNwZ6m6m"
            + "qWvvyq1cuxhoDvpfC6NXILETawYc6MNwwxsOtVVIjuXlcF17NMejljJafbPximEt"
            + "DQ4LcQeSp4K7FyFlIAMLyt3BQ77emGzU5fjFTvHSUNb3jblx0sV28c0CAwEAAaOB"
            + "tTCBsjAfBgNVHSMEGDAWgBSEJ4bLbvEQY8cYMAFKPFD1/fFXlzAdBgNVHQ4EFgQU"
            + "hCeGy27xEGPHGDABSjxQ9f3xV5cwDgYDVR0PAQH/BAQDAgEGMBEGCWCGSAGG+EIB"
            + "AQQEAwIBBjA8BgNVHR8ENTAzMDGgL6AthitodHRwOi8vYWRvbmlzLnBrNy5jZXJ0"
            + "cGx1cy5uZXQvZGdpLXRlc3QuY3JsMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcN"
            + "AQEFBQADgYEAmToHJWjd3+4zknfsP09H6uMbolHNGG0zTS2lrLKpzcmkQfjhQpT9"
            + "LUTBvfs1jdjo9fGmQLvOG+Sm51Rbjglb8bcikVI5gLbclOlvqLkm77otjl4U4Z2/"
            + "Y0vP14Aov3Sn3k+17EfReYUZI4liuB95ncobC4e8ZM++LjQcIM0s+Vs=");


    byte[] gost34102001base = Base64.decode(
        "MIIB1DCCAYECEEjpVKXP6Wn1yVz3VeeDQa8wCgYGKoUDAgIDBQAwbTEfMB0G"
            + "A1UEAwwWR29zdFIzNDEwLTIwMDEgZXhhbXBsZTESMBAGA1UECgwJQ3J5cHRv"
            + "UHJvMQswCQYDVQQGEwJSVTEpMCcGCSqGSIb3DQEJARYaR29zdFIzNDEwLTIw"
            + "MDFAZXhhbXBsZS5jb20wHhcNMDUwMjAzMTUxNjQ2WhcNMTUwMjAzMTUxNjQ2"
            + "WjBtMR8wHQYDVQQDDBZHb3N0UjM0MTAtMjAwMSBleGFtcGxlMRIwEAYDVQQK"
            + "DAlDcnlwdG9Qcm8xCzAJBgNVBAYTAlJVMSkwJwYJKoZIhvcNAQkBFhpHb3N0"
            + "UjM0MTAtMjAwMUBleGFtcGxlLmNvbTBjMBwGBiqFAwICEzASBgcqhQMCAiQA"
            + "BgcqhQMCAh4BA0MABECElWh1YAIaQHUIzROMMYks/eUFA3pDXPRtKw/nTzJ+"
            + "V4/rzBa5lYgD0Jp8ha4P5I3qprt+VsfLsN8PZrzK6hpgMAoGBiqFAwICAwUA"
            + "A0EAHw5dw/aw/OiNvHyOE65kvyo4Hp0sfz3csM6UUkp10VO247ofNJK3tsLb"
            + "HOLjUaqzefrlGb11WpHYrvWFg+FcLA==");

    byte[] gost341094base = Base64.decode(
        "MIICDzCCAbwCEBcxKsIb0ghYvAQeUjfQdFAwCgYGKoUDAgIEBQAwaTEdMBsG"
            + "A1UEAwwUR29zdFIzNDEwLTk0IGV4YW1wbGUxEjAQBgNVBAoMCUNyeXB0b1By"
            + "bzELMAkGA1UEBhMCUlUxJzAlBgkqhkiG9w0BCQEWGEdvc3RSMzQxMC05NEBl"
            + "eGFtcGxlLmNvbTAeFw0wNTAyMDMxNTE2NTFaFw0xNTAyMDMxNTE2NTFaMGkx"
            + "HTAbBgNVBAMMFEdvc3RSMzQxMC05NCBleGFtcGxlMRIwEAYDVQQKDAlDcnlw"
            + "dG9Qcm8xCzAJBgNVBAYTAlJVMScwJQYJKoZIhvcNAQkBFhhHb3N0UjM0MTAt"
            + "OTRAZXhhbXBsZS5jb20wgaUwHAYGKoUDAgIUMBIGByqFAwICIAIGByqFAwIC"
            + "HgEDgYQABIGAu4Rm4XmeWzTYLIB/E6gZZnFX/oxUJSFHbzALJ3dGmMb7R1W+"
            + "t7Lzk2w5tUI3JoTiDRCKJA4fDEJNKzsRK6i/ZjkyXJSLwaj+G2MS9gklh8x1"
            + "G/TliYoJgmjTXHemD7aQEBON4z58nJHWrA0ILD54wbXCtrcaqCqLRYGTMjJ2"
            + "+nswCgYGKoUDAgIEBQADQQBxKNhOmjgz/i5CEgLOyKyz9pFGkDcaymsWYQWV"
            + "v7CZ0pTM8IzMzkUBW3GHsUjCFpanFZDfg2zuN+3kT+694n9B");

    byte[] gost341094A = Base64.decode(
        "MIICSDCCAfWgAwIBAgIBATAKBgYqhQMCAgQFADCBgTEXMBUGA1UEAxMOZGVmYXVsdDM0MTAtOTQx"
            + "DTALBgNVBAoTBERpZ3QxDzANBgNVBAsTBkNyeXB0bzEOMAwGA1UEBxMFWS1vbGExDDAKBgNVBAgT"
            + "A01FTDELMAkGA1UEBhMCcnUxGzAZBgkqhkiG9w0BCQEWDHRlc3RAdGVzdC5ydTAeFw0wNTAzMjkx"
            + "MzExNTdaFw0wNjAzMjkxMzExNTdaMIGBMRcwFQYDVQQDEw5kZWZhdWx0MzQxMC05NDENMAsGA1UE"
            + "ChMERGlndDEPMA0GA1UECxMGQ3J5cHRvMQ4wDAYDVQQHEwVZLW9sYTEMMAoGA1UECBMDTUVMMQsw"
            + "CQYDVQQGEwJydTEbMBkGCSqGSIb3DQEJARYMdGVzdEB0ZXN0LnJ1MIGlMBwGBiqFAwICFDASBgcq"
            + "hQMCAiACBgcqhQMCAh4BA4GEAASBgIQACDLEuxSdRDGgdZxHmy30g/DUYkRxO9Mi/uSHX5NjvZ31"
            + "b7JMEMFqBtyhql1HC5xZfUwZ0aT3UnEFDfFjLP+Bf54gA+LPkQXw4SNNGOj+klnqgKlPvoqMGlwa"
            + "+hLPKbS561WpvB2XSTgbV+pqqXR3j6j30STmybelEV3RdS2Now8wDTALBgNVHQ8EBAMCB4AwCgYG"
            + "KoUDAgIEBQADQQBCFy7xWRXtNVXflKvDs0pBdBuPzjCMeZAXVxK8vUxsxxKu76d9CsvhgIFknFRi"
            + "wWTPiZenvNoJ4R1uzeX+vREm");

    byte[] gost341094B = Base64.decode(
        "MIICSDCCAfWgAwIBAgIBATAKBgYqhQMCAgQFADCBgTEXMBUGA1UEAxMOcGFyYW0xLTM0MTAtOTQx"
            + "DTALBgNVBAoTBERpZ3QxDzANBgNVBAsTBkNyeXB0bzEOMAwGA1UEBxMFWS1PbGExDDAKBgNVBAgT"
            + "A01lbDELMAkGA1UEBhMCcnUxGzAZBgkqhkiG9w0BCQEWDHRlc3RAdGVzdC5ydTAeFw0wNTAzMjkx"
            + "MzEzNTZaFw0wNjAzMjkxMzEzNTZaMIGBMRcwFQYDVQQDEw5wYXJhbTEtMzQxMC05NDENMAsGA1UE"
            + "ChMERGlndDEPMA0GA1UECxMGQ3J5cHRvMQ4wDAYDVQQHEwVZLU9sYTEMMAoGA1UECBMDTWVsMQsw"
            + "CQYDVQQGEwJydTEbMBkGCSqGSIb3DQEJARYMdGVzdEB0ZXN0LnJ1MIGlMBwGBiqFAwICFDASBgcq"
            + "hQMCAiADBgcqhQMCAh4BA4GEAASBgEa+AAcZmijWs1M9x5Pn9efE8D9ztG1NMoIt0/hNZNqln3+j"
            + "lMZjyqPt+kTLIjtmvz9BRDmIDk6FZz+4LhG2OTL7yGpWfrMxMRr56nxomTN9aLWRqbyWmn3brz9Y"
            + "AUD3ifnwjjIuW7UM84JNlDTOdxx0XRUfLQIPMCXe9cO02Xskow8wDTALBgNVHQ8EBAMCB4AwCgYG"
            + "KoUDAgIEBQADQQBzFcnuYc/639OTW+L5Ecjw9KxGr+dwex7lsS9S1BUgKa3m1d5c+cqI0B2XUFi5"
            + "4iaHHJG0dCyjtQYLJr0OZjRw");

    byte[] gost34102001A = Base64.decode(
        "MIICCzCCAbigAwIBAgIBATAKBgYqhQMCAgMFADCBhDEaMBgGA1UEAxMRZGVmYXVsdC0zNDEwLTIw"
            + "MDExDTALBgNVBAoTBERpZ3QxDzANBgNVBAsTBkNyeXB0bzEOMAwGA1UEBxMFWS1PbGExDDAKBgNV"
            + "BAgTA01lbDELMAkGA1UEBhMCcnUxGzAZBgkqhkiG9w0BCQEWDHRlc3RAdGVzdC5ydTAeFw0wNTAz"
            + "MjkxMzE4MzFaFw0wNjAzMjkxMzE4MzFaMIGEMRowGAYDVQQDExFkZWZhdWx0LTM0MTAtMjAwMTEN"
            + "MAsGA1UEChMERGlndDEPMA0GA1UECxMGQ3J5cHRvMQ4wDAYDVQQHEwVZLU9sYTEMMAoGA1UECBMD"
            + "TWVsMQswCQYDVQQGEwJydTEbMBkGCSqGSIb3DQEJARYMdGVzdEB0ZXN0LnJ1MGMwHAYGKoUDAgIT"
            + "MBIGByqFAwICIwEGByqFAwICHgEDQwAEQG/4c+ZWb10IpeHfmR+vKcbpmSOClJioYmCVgnojw0Xn"
            + "ned0KTg7TJreRUc+VX7vca4hLQaZ1o/TxVtfEApK/O6jDzANMAsGA1UdDwQEAwIHgDAKBgYqhQMC"
            + "AgMFAANBAN8y2b6HuIdkD3aWujpfQbS1VIA/7hro4vLgDhjgVmev/PLzFB8oTh3gKhExpDo82IEs"
            + "ZftGNsbbyp1NFg7zda0=");

    byte[] gostCA1 = Base64.decode(
        "MIIDNDCCAuGgAwIBAgIQZLcKDcWcQopF+jp4p9jylDAKBgYqhQMCAgQFADBm"
            + "MQswCQYDVQQGEwJSVTEPMA0GA1UEBxMGTW9zY293MRcwFQYDVQQKEw5PT08g"
            + "Q3J5cHRvLVBybzEUMBIGA1UECxMLRGV2ZWxvcG1lbnQxFzAVBgNVBAMTDkNQ"
            + "IENTUCBUZXN0IENBMB4XDTAyMDYwOTE1NTIyM1oXDTA5MDYwOTE1NTkyOVow"
            + "ZjELMAkGA1UEBhMCUlUxDzANBgNVBAcTBk1vc2NvdzEXMBUGA1UEChMOT09P"
            + "IENyeXB0by1Qcm8xFDASBgNVBAsTC0RldmVsb3BtZW50MRcwFQYDVQQDEw5D"
            + "UCBDU1AgVGVzdCBDQTCBpTAcBgYqhQMCAhQwEgYHKoUDAgIgAgYHKoUDAgIe"
            + "AQOBhAAEgYAYglywKuz1nMc9UiBYOaulKy53jXnrqxZKbCCBSVaJ+aCKbsQm"
            + "glhRFrw6Mwu8Cdeabo/ojmea7UDMZd0U2xhZFRti5EQ7OP6YpqD0alllo7za"
            + "4dZNXdX+/ag6fOORSLFdMpVx5ganU0wHMPk67j+audnCPUj/plbeyccgcdcd"
            + "WaOCASIwggEeMAsGA1UdDwQEAwIBxjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud"
            + "DgQWBBTe840gTo4zt2twHilw3PD9wJaX0TCBygYDVR0fBIHCMIG/MDygOqA4"
            + "hjYtaHR0cDovL2ZpZXdhbGwvQ2VydEVucm9sbC9DUCUyMENTUCUyMFRlc3Ql"
            + "MjBDQSgzKS5jcmwwRKBCoECGPmh0dHA6Ly93d3cuY3J5cHRvcHJvLnJ1L0Nl"
            + "cnRFbnJvbGwvQ1AlMjBDU1AlMjBUZXN0JTIwQ0EoMykuY3JsMDmgN6A1hjMt"
            + "ZmlsZTovL1xcZmlld2FsbFxDZXJ0RW5yb2xsXENQIENTUCBUZXN0IENBKDMp"
            + "LmNybC8wEgYJKwYBBAGCNxUBBAUCAwMAAzAKBgYqhQMCAgQFAANBAIJi7ni7"
            + "9rwMR5rRGTFftt2k70GbqyUEfkZYOzrgdOoKiB4IIsIstyBX0/ne6GsL9Xan"
            + "G2IN96RB7KrowEHeW+k=");

    byte[] gostCA2 = Base64.decode(
        "MIIC2DCCAoWgAwIBAgIQe9ZCugm42pRKNcHD8466zTAKBgYqhQMCAgMFADB+"
            + "MRowGAYJKoZIhvcNAQkBFgtzYmFAZGlndC5ydTELMAkGA1UEBhMCUlUxDDAK"
            + "BgNVBAgTA01FTDEUMBIGA1UEBxMLWW9zaGthci1PbGExDTALBgNVBAoTBERp"
            + "Z3QxDzANBgNVBAsTBkNyeXB0bzEPMA0GA1UEAxMGc2JhLUNBMB4XDTA0MDgw"
            + "MzEzMzE1OVoXDTE0MDgwMzEzNDAxMVowfjEaMBgGCSqGSIb3DQEJARYLc2Jh"
            + "QGRpZ3QucnUxCzAJBgNVBAYTAlJVMQwwCgYDVQQIEwNNRUwxFDASBgNVBAcT"
            + "C1lvc2hrYXItT2xhMQ0wCwYDVQQKEwREaWd0MQ8wDQYDVQQLEwZDcnlwdG8x"
            + "DzANBgNVBAMTBnNiYS1DQTBjMBwGBiqFAwICEzASBgcqhQMCAiMBBgcqhQMC"
            + "Ah4BA0MABEDMSy10CuOH+i8QKG2UWA4XmCt6+BFrNTZQtS6bOalyDY8Lz+G7"
            + "HybyipE3PqdTB4OIKAAPsEEeZOCZd2UXGQm5o4HaMIHXMBMGCSsGAQQBgjcU"
            + "AgQGHgQAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud"
            + "DgQWBBRJJl3LcNMxkZI818STfoi3ng1xoDBxBgNVHR8EajBoMDGgL6Athito"
            + "dHRwOi8vc2JhLmRpZ3QubG9jYWwvQ2VydEVucm9sbC9zYmEtQ0EuY3JsMDOg"
            + "MaAvhi1maWxlOi8vXFxzYmEuZGlndC5sb2NhbFxDZXJ0RW5yb2xsXHNiYS1D"
            + "QS5jcmwwEAYJKwYBBAGCNxUBBAMCAQAwCgYGKoUDAgIDBQADQQA+BRJHbc/p"
            + "q8EYl6iJqXCuR+ozRmH7hPAP3c4KqYSC38TClCgBloLapx/3/WdatctFJW/L"
            + "mcTovpq088927shE");

    byte[] inDirectCrl = Base64.decode(
        "MIIdXjCCHMcCAQEwDQYJKoZIhvcNAQEFBQAwdDELMAkGA1UEBhMCREUxHDAaBgNV"
            + "BAoUE0RldXRzY2hlIFRlbGVrb20gQUcxFzAVBgNVBAsUDlQtVGVsZVNlYyBUZXN0"
            + "MS4wDAYHAoIGAQoHFBMBMTAeBgNVBAMUF1QtVGVsZVNlYyBUZXN0IERJUiA4OlBO"
            + "Fw0wNjA4MDQwODQ1MTRaFw0wNjA4MDQxNDQ1MTRaMIIbfzB+AgQvrj/pFw0wMzA3"
            + "MjIwNTQxMjhaMGcwZQYDVR0dAQH/BFswWaRXMFUxCzAJBgNVBAYTAkRFMRwwGgYD"
            + "VQQKFBNEZXV0c2NoZSBUZWxla29tIEFHMSgwDAYHAoIGAQoHFBMBMTAYBgNVBAMU"
            + "EVNpZ0cgVGVzdCBDQSA0OlBOMH4CBC+uP+oXDTAzMDcyMjA1NDEyOFowZzBlBgNV"
            + "HR0BAf8EWzBZpFcwVTELMAkGA1UEBhMCREUxHDAaBgNVBAoUE0RldXRzY2hlIFRl"
            + "bGVrb20gQUcxKDAMBgcCggYBCgcUEwExMBgGA1UEAxQRU2lnRyBUZXN0IENBIDQ6"
            + "UE4wfgIEL64/5xcNMDQwNDA1MTMxODE3WjBnMGUGA1UdHQEB/wRbMFmkVzBVMQsw"
            + "CQYDVQQGEwJERTEcMBoGA1UEChQTRGV1dHNjaGUgVGVsZWtvbSBBRzEoMAwGBwKC"
            + "BgEKBxQTATEwGAYDVQQDFBFTaWdHIFRlc3QgQ0EgNDpQTjB+AgQvrj/oFw0wNDA0"
            + "MDUxMzE4MTdaMGcwZQYDVR0dAQH/BFswWaRXMFUxCzAJBgNVBAYTAkRFMRwwGgYD"
            + "VQQKFBNEZXV0c2NoZSBUZWxla29tIEFHMSgwDAYHAoIGAQoHFBMBMTAYBgNVBAMU"
            + "EVNpZ0cgVGVzdCBDQSA0OlBOMH4CBC+uP+UXDTAzMDExMzExMTgxMVowZzBlBgNV"
            + "HR0BAf8EWzBZpFcwVTELMAkGA1UEBhMCREUxHDAaBgNVBAoUE0RldXRzY2hlIFRl"
            + "bGVrb20gQUcxKDAMBgcCggYBCgcUEwExMBgGA1UEAxQRU2lnRyBUZXN0IENBIDQ6"
            + "UE4wfgIEL64/5hcNMDMwMTEzMTExODExWjBnMGUGA1UdHQEB/wRbMFmkVzBVMQsw"
            + "CQYDVQQGEwJERTEcMBoGA1UEChQTRGV1dHNjaGUgVGVsZWtvbSBBRzEoMAwGBwKC"
            + "BgEKBxQTATEwGAYDVQQDFBFTaWdHIFRlc3QgQ0EgNDpQTjB+AgQvrj/jFw0wMzAx"
            + "MTMxMTI2NTZaMGcwZQYDVR0dAQH/BFswWaRXMFUxCzAJBgNVBAYTAkRFMRwwGgYD"
            + "VQQKFBNEZXV0c2NoZSBUZWxla29tIEFHMSgwDAYHAoIGAQoHFBMBMTAYBgNVBAMU"
            + "EVNpZ0cgVGVzdCBDQSA0OlBOMH4CBC+uP+QXDTAzMDExMzExMjY1NlowZzBlBgNV"
            + "HR0BAf8EWzBZpFcwVTELMAkGA1UEBhMCREUxHDAaBgNVBAoUE0RldXRzY2hlIFRl"
            + "bGVrb20gQUcxKDAMBgcCggYBCgcUEwExMBgGA1UEAxQRU2lnRyBUZXN0IENBIDQ6"
            + "UE4wfgIEL64/4hcNMDQwNzEzMDc1ODM4WjBnMGUGA1UdHQEB/wRbMFmkVzBVMQsw"
            + "CQYDVQQGEwJERTEcMBoGA1UEChQTRGV1dHNjaGUgVGVsZWtvbSBBRzEoMAwGBwKC"
            + "BgEKBxQTATEwGAYDVQQDFBFTaWdHIFRlc3QgQ0EgNDpQTjB+AgQvrj/eFw0wMzAy"
            + "MTcwNjMzMjVaMGcwZQYDVR0dAQH/BFswWaRXMFUxCzAJBgNVBAYTAkRFMRwwGgYD"
            + "VQQKFBNEZXV0c2NoZSBUZWxla29tIEFHMSgwDAYHAoIGAQoHFBMBMTAYBgNVBAMU"
            + "EVNpZ0cgVGVzdCBDQSA0OlBOMH4CBC+uP98XDTAzMDIxNzA2MzMyNVowZzBlBgNV"
            + "HR0BAf8EWzBZpFcwVTELMAkGA1UEBhMCREUxHDAaBgNVBAoUE0RldXRzY2hlIFRl"
            + "bGVrb20gQUcxKDAMBgcCggYBCgcUEwExMBgGA1UEAxQRU2lnRyBUZXN0IENBIDQ6"
            + "UE4wfgIEL64/0xcNMDMwMjE3MDYzMzI1WjBnMGUGA1UdHQEB/wRbMFmkVzBVMQsw"
            + "CQYDVQQGEwJERTEcMBoGA1UEChQTRGV1dHNjaGUgVGVsZWtvbSBBRzEoMAwGBwKC"
            + "BgEKBxQTATEwGAYDVQQDFBFTaWdHIFRlc3QgQ0EgNDpQTjB+AgQvrj/dFw0wMzAx"
            + "MTMxMTI4MTRaMGcwZQYDVR0dAQH/BFswWaRXMFUxCzAJBgNVBAYTAkRFMRwwGgYD"
            + "VQQKFBNEZXV0c2NoZSBUZWxla29tIEFHMSgwDAYHAoIGAQoHFBMBMTAYBgNVBAMU"
            + "EVNpZ0cgVGVzdCBDQSA0OlBOMH4CBC+uP9cXDTAzMDExMzExMjcwN1owZzBlBgNV"
            + "HR0BAf8EWzBZpFcwVTELMAkGA1UEBhMCREUxHDAaBgNVBAoUE0RldXRzY2hlIFRl"
            + "bGVrb20gQUcxKDAMBgcCggYBCgcUEwExMBgGA1UEAxQRU2lnRyBUZXN0IENBIDQ6"
            + "UE4wfgIEL64/2BcNMDMwMTEzMTEyNzA3WjBnMGUGA1UdHQEB/wRbMFmkVzBVMQsw"
            + "CQYDVQQGEwJERTEcMBoGA1UEChQTRGV1dHNjaGUgVGVsZWtvbSBBRzEoMAwGBwKC"
            + "BgEKBxQTATEwGAYDVQQDFBFTaWdHIFRlc3QgQ0EgNDpQTjB+AgQvrj/VFw0wMzA0"
            + "MzAxMjI3NTNaMGcwZQYDVR0dAQH/BFswWaRXMFUxCzAJBgNVBAYTAkRFMRwwGgYD"
            + "VQQKFBNEZXV0c2NoZSBUZWxla29tIEFHMSgwDAYHAoIGAQoHFBMBMTAYBgNVBAMU"
            + "EVNpZ0cgVGVzdCBDQSA0OlBOMH4CBC+uP9YXDTAzMDQzMDEyMjc1M1owZzBlBgNV"
            + "HR0BAf8EWzBZpFcwVTELMAkGA1UEBhMCREUxHDAaBgNVBAoUE0RldXRzY2hlIFRl"
            + "bGVrb20gQUcxKDAMBgcCggYBCgcUEwExMBgGA1UEAxQRU2lnRyBUZXN0IENBIDQ6"
            + "UE4wfgIEL64/xhcNMDMwMjEyMTM0NTQwWjBnMGUGA1UdHQEB/wRbMFmkVzBVMQsw"
            + "CQYDVQQGEwJERTEcMBoGA1UEChQTRGV1dHNjaGUgVGVsZWtvbSBBRzEoMAwGBwKC"
            + "BgEKBxQTATEwGAYDVQQDFBFUVEMgVGVzdCBDQSAxMTpQTjCBkAIEL64/xRcNMDMw"
            + "MjEyMTM0NTQwWjB5MHcGA1UdHQEB/wRtMGukaTBnMQswCQYDVQQGEwJERTEcMBoG"
            + "A1UEChQTRGV1dHNjaGUgVGVsZWtvbSBBRzEQMA4GA1UECxQHVGVsZVNlYzEoMAwG"
            + "BwKCBgEKBxQTATEwGAYDVQQDFBFTaWdHIFRlc3QgQ0EgNTpQTjB+AgQvrj/CFw0w"
            + "MzAyMTIxMzA5MTZaMGcwZQYDVR0dAQH/BFswWaRXMFUxCzAJBgNVBAYTAkRFMRww"
            + "GgYDVQQKFBNEZXV0c2NoZSBUZWxla29tIEFHMSgwDAYHAoIGAQoHFBMBMTAYBgNV"
            + "BAMUEVRUQyBUZXN0IENBIDExOlBOMIGQAgQvrj/BFw0wMzAyMTIxMzA4NDBaMHkw"
            + "dwYDVR0dAQH/BG0wa6RpMGcxCzAJBgNVBAYTAkRFMRwwGgYDVQQKFBNEZXV0c2No"
            + "ZSBUZWxla29tIEFHMRAwDgYDVQQLFAdUZWxlU2VjMSgwDAYHAoIGAQoHFBMBMTAY"
            + "BgNVBAMUEVNpZ0cgVGVzdCBDQSA1OlBOMH4CBC+uP74XDTAzMDIxNzA2MzcyNVow"
            + "ZzBlBgNVHR0BAf8EWzBZpFcwVTELMAkGA1UEBhMCREUxHDAaBgNVBAoUE0RldXRz"
            + "Y2hlIFRlbGVrb20gQUcxKDAMBgcCggYBCgcUEwExMBgGA1UEAxQRVFRDIFRlc3Qg"
            + "Q0EgMTE6UE4wgZACBC+uP70XDTAzMDIxNzA2MzcyNVoweTB3BgNVHR0BAf8EbTBr"
            + "pGkwZzELMAkGA1UEBhMCREUxHDAaBgNVBAoUE0RldXRzY2hlIFRlbGVrb20gQUcx"
            + "EDAOBgNVBAsUB1RlbGVTZWMxKDAMBgcCggYBCgcUEwExMBgGA1UEAxQRU2lnRyBU"
            + "ZXN0IENBIDU6UE4wgZACBC+uP7AXDTAzMDIxMjEzMDg1OVoweTB3BgNVHR0BAf8E"
            + "bTBrpGkwZzELMAkGA1UEBhMCREUxHDAaBgNVBAoUE0RldXRzY2hlIFRlbGVrb20g"
            + "QUcxEDAOBgNVBAsUB1RlbGVTZWMxKDAMBgcCggYBCgcUEwExMBgGA1UEAxQRU2ln"
            + "RyBUZXN0IENBIDU6UE4wgZACBC+uP68XDTAzMDIxNzA2MzcyNVoweTB3BgNVHR0B"
            + "Af8EbTBrpGkwZzELMAkGA1UEBhMCREUxHDAaBgNVBAoUE0RldXRzY2hlIFRlbGVr"
            + "b20gQUcxEDAOBgNVBAsUB1RlbGVTZWMxKDAMBgcCggYBCgcUEwExMBgGA1UEAxQR"
            + "U2lnRyBUZXN0IENBIDU6UE4wfgIEL64/kxcNMDMwNDEwMDUyNjI4WjBnMGUGA1Ud"
            + "HQEB/wRbMFmkVzBVMQswCQYDVQQGEwJERTEcMBoGA1UEChQTRGV1dHNjaGUgVGVs"
            + "ZWtvbSBBRzEoMAwGBwKCBgEKBxQTATEwGAYDVQQDFBFUVEMgVGVzdCBDQSAxMTpQ"
            + "TjCBkAIEL64/khcNMDMwNDEwMDUyNjI4WjB5MHcGA1UdHQEB/wRtMGukaTBnMQsw"
            + "CQYDVQQGEwJERTEcMBoGA1UEChQTRGV1dHNjaGUgVGVsZWtvbSBBRzEQMA4GA1UE"
            + "CxQHVGVsZVNlYzEoMAwGBwKCBgEKBxQTATEwGAYDVQQDFBFTaWdHIFRlc3QgQ0Eg"
            + "NTpQTjB+AgQvrj8/Fw0wMzAyMjYxMTA0NDRaMGcwZQYDVR0dAQH/BFswWaRXMFUx"
            + "CzAJBgNVBAYTAkRFMRwwGgYDVQQKFBNEZXV0c2NoZSBUZWxla29tIEFHMSgwDAYH"
            + "AoIGAQoHFBMBMTAYBgNVBAMUEVRUQyBUZXN0IENBIDExOlBOMIGQAgQvrj8+Fw0w"
            + "MzAyMjYxMTA0NDRaMHkwdwYDVR0dAQH/BG0wa6RpMGcxCzAJBgNVBAYTAkRFMRww"
            + "GgYDVQQKFBNEZXV0c2NoZSBUZWxla29tIEFHMRAwDgYDVQQLFAdUZWxlU2VjMSgw"
            + "DAYHAoIGAQoHFBMBMTAYBgNVBAMUEVNpZ0cgVGVzdCBDQSA1OlBOMH4CBC+uPs0X"
            + "DTAzMDUyMDA1MjczNlowZzBlBgNVHR0BAf8EWzBZpFcwVTELMAkGA1UEBhMCREUx"
            + "HDAaBgNVBAoUE0RldXRzY2hlIFRlbGVrb20gQUcxKDAMBgcCggYBCgcUEwExMBgG"
            + "A1UEAxQRVFRDIFRlc3QgQ0EgMTE6UE4wgZACBC+uPswXDTAzMDUyMDA1MjczNlow"
            + "eTB3BgNVHR0BAf8EbTBrpGkwZzELMAkGA1UEBhMCREUxHDAaBgNVBAoUE0RldXRz"
            + "Y2hlIFRlbGVrb20gQUcxEDAOBgNVBAsUB1RlbGVTZWMxKDAMBgcCggYBCgcUEwEx"
            + "MBgGA1UEAxQRU2lnRyBUZXN0IENBIDY6UE4wfgIEL64+PBcNMDMwNjE3MTAzNDE2"
            + "WjBnMGUGA1UdHQEB/wRbMFmkVzBVMQswCQYDVQQGEwJERTEcMBoGA1UEChQTRGV1"
            + "dHNjaGUgVGVsZWtvbSBBRzEoMAwGBwKCBgEKBxQTATEwGAYDVQQDFBFUVEMgVGVz"
            + "dCBDQSAxMTpQTjCBkAIEL64+OxcNMDMwNjE3MTAzNDE2WjB5MHcGA1UdHQEB/wRt"
            + "MGukaTBnMQswCQYDVQQGEwJERTEcMBoGA1UEChQTRGV1dHNjaGUgVGVsZWtvbSBB"
            + "RzEQMA4GA1UECxQHVGVsZVNlYzEoMAwGBwKCBgEKBxQTATEwGAYDVQQDFBFTaWdH"
            + "IFRlc3QgQ0EgNjpQTjCBkAIEL64+OhcNMDMwNjE3MTAzNDE2WjB5MHcGA1UdHQEB"
            + "/wRtMGukaTBnMQswCQYDVQQGEwJERTEcMBoGA1UEChQTRGV1dHNjaGUgVGVsZWtv"
            + "bSBBRzEQMA4GA1UECxQHVGVsZVNlYzEoMAwGBwKCBgEKBxQTATEwGAYDVQQDFBFT"
            + "aWdHIFRlc3QgQ0EgNjpQTjB+AgQvrj45Fw0wMzA2MTcxMzAxMDBaMGcwZQYDVR0d"
            + "AQH/BFswWaRXMFUxCzAJBgNVBAYTAkRFMRwwGgYDVQQKFBNEZXV0c2NoZSBUZWxl"
            + "a29tIEFHMSgwDAYHAoIGAQoHFBMBMTAYBgNVBAMUEVRUQyBUZXN0IENBIDExOlBO"
            + "MIGQAgQvrj44Fw0wMzA2MTcxMzAxMDBaMHkwdwYDVR0dAQH/BG0wa6RpMGcxCzAJ"
            + "BgNVBAYTAkRFMRwwGgYDVQQKFBNEZXV0c2NoZSBUZWxla29tIEFHMRAwDgYDVQQL"
            + "FAdUZWxlU2VjMSgwDAYHAoIGAQoHFBMBMTAYBgNVBAMUEVNpZ0cgVGVzdCBDQSA2"
            + "OlBOMIGQAgQvrj43Fw0wMzA2MTcxMzAxMDBaMHkwdwYDVR0dAQH/BG0wa6RpMGcx"
            + "CzAJBgNVBAYTAkRFMRwwGgYDVQQKFBNEZXV0c2NoZSBUZWxla29tIEFHMRAwDgYD"
            + "VQQLFAdUZWxlU2VjMSgwDAYHAoIGAQoHFBMBMTAYBgNVBAMUEVNpZ0cgVGVzdCBD"
            + "QSA2OlBOMIGQAgQvrj42Fw0wMzA2MTcxMzAxMDBaMHkwdwYDVR0dAQH/BG0wa6Rp"
            + "MGcxCzAJBgNVBAYTAkRFMRwwGgYDVQQKFBNEZXV0c2NoZSBUZWxla29tIEFHMRAw"
            + "DgYDVQQLFAdUZWxlU2VjMSgwDAYHAoIGAQoHFBMBMTAYBgNVBAMUEVNpZ0cgVGVz"
            + "dCBDQSA2OlBOMIGQAgQvrj4zFw0wMzA2MTcxMDM3NDlaMHkwdwYDVR0dAQH/BG0w"
            + "a6RpMGcxCzAJBgNVBAYTAkRFMRwwGgYDVQQKFBNEZXV0c2NoZSBUZWxla29tIEFH"
            + "MRAwDgYDVQQLFAdUZWxlU2VjMSgwDAYHAoIGAQoHFBMBMTAYBgNVBAMUEVNpZ0cg"
            + "VGVzdCBDQSA2OlBOMH4CBC+uPjEXDTAzMDYxNzEwNDI1OFowZzBlBgNVHR0BAf8E"
            + "WzBZpFcwVTELMAkGA1UEBhMCREUxHDAaBgNVBAoUE0RldXRzY2hlIFRlbGVrb20g"
            + "QUcxKDAMBgcCggYBCgcUEwExMBgGA1UEAxQRVFRDIFRlc3QgQ0EgMTE6UE4wgZAC"
            + "BC+uPjAXDTAzMDYxNzEwNDI1OFoweTB3BgNVHR0BAf8EbTBrpGkwZzELMAkGA1UE"
            + "BhMCREUxHDAaBgNVBAoUE0RldXRzY2hlIFRlbGVrb20gQUcxEDAOBgNVBAsUB1Rl"
            + "bGVTZWMxKDAMBgcCggYBCgcUEwExMBgGA1UEAxQRU2lnRyBUZXN0IENBIDY6UE4w"
            + "gZACBC+uPakXDTAzMTAyMjExMzIyNFoweTB3BgNVHR0BAf8EbTBrpGkwZzELMAkG"
            + "A1UEBhMCREUxHDAaBgNVBAoUE0RldXRzY2hlIFRlbGVrb20gQUcxEDAOBgNVBAsU"
            + "B1RlbGVTZWMxKDAMBgcCggYBCgcUEwExMBgGA1UEAxQRU2lnRyBUZXN0IENBIDY6"
            + "UE4wgZACBC+uPLIXDTA1MDMxMTA2NDQyNFoweTB3BgNVHR0BAf8EbTBrpGkwZzEL"
            + "MAkGA1UEBhMCREUxHDAaBgNVBAoUE0RldXRzY2hlIFRlbGVrb20gQUcxEDAOBgNV"
            + "BAsUB1RlbGVTZWMxKDAMBgcCggYBCgcUEwExMBgGA1UEAxQRU2lnRyBUZXN0IENB"
            + "IDY6UE4wgZACBC+uPKsXDTA0MDQwMjA3NTQ1M1oweTB3BgNVHR0BAf8EbTBrpGkw"
            + "ZzELMAkGA1UEBhMCREUxHDAaBgNVBAoUE0RldXRzY2hlIFRlbGVrb20gQUcxEDAO"
            + "BgNVBAsUB1RlbGVTZWMxKDAMBgcCggYBCgcUEwExMBgGA1UEAxQRU2lnRyBUZXN0"
            + "IENBIDY6UE4wgZACBC+uOugXDTA1MDEyNzEyMDMyNFoweTB3BgNVHR0BAf8EbTBr"
            + "pGkwZzELMAkGA1UEBhMCREUxHDAaBgNVBAoUE0RldXRzY2hlIFRlbGVrb20gQUcx"
            + "EDAOBgNVBAsUB1RlbGVTZWMxKDAMBgcCggYBCgcUEwExMBgGA1UEAxQRU2lnRyBU"
            + "ZXN0IENBIDY6UE4wgZACBC+uOr4XDTA1MDIxNjA3NTcxNloweTB3BgNVHR0BAf8E"
            + "bTBrpGkwZzELMAkGA1UEBhMCREUxHDAaBgNVBAoUE0RldXRzY2hlIFRlbGVrb20g"
            + "QUcxEDAOBgNVBAsUB1RlbGVTZWMxKDAMBgcCggYBCgcUEwExMBgGA1UEAxQRU2ln"
            + "RyBUZXN0IENBIDY6UE4wgZACBC+uOqcXDTA1MDMxMDA1NTkzNVoweTB3BgNVHR0B"
            + "Af8EbTBrpGkwZzELMAkGA1UEBhMCREUxHDAaBgNVBAoUE0RldXRzY2hlIFRlbGVr"
            + "b20gQUcxEDAOBgNVBAsUB1RlbGVTZWMxKDAMBgcCggYBCgcUEwExMBgGA1UEAxQR"
            + "U2lnRyBUZXN0IENBIDY6UE4wgZACBC+uOjwXDTA1MDUxMTEwNDk0NloweTB3BgNV"
            + "HR0BAf8EbTBrpGkwZzELMAkGA1UEBhMCREUxHDAaBgNVBAoUE0RldXRzY2hlIFRl"
            + "bGVrb20gQUcxEDAOBgNVBAsUB1RlbGVTZWMxKDAMBgcCggYBCgcUEwExMBgGA1UE"
            + "AxQRU2lnRyBUZXN0IENBIDY6UE4wgaoCBC+sbdUXDTA1MTExMTEwMDMyMVowgZIw"
            + "gY8GA1UdHQEB/wSBhDCBgaR/MH0xCzAJBgNVBAYTAkRFMRwwGgYDVQQKFBNEZXV0"
            + "c2NoZSBUZWxla29tIEFHMR8wHQYDVQQLFBZQcm9kdWt0emVudHJ1bSBUZWxlU2Vj"
            + "MS8wDAYHAoIGAQoHFBMBMTAfBgNVBAMUGFRlbGVTZWMgUEtTIFNpZ0cgQ0EgMTpQ"
            + "TjCBlQIEL64uaBcNMDYwMTIzMTAyNTU1WjB+MHwGA1UdHQEB/wRyMHCkbjBsMQsw"
            + "CQYDVQQGEwJERTEcMBoGA1UEChQTRGV1dHNjaGUgVGVsZWtvbSBBRzEWMBQGA1UE"
            + "CxQNWmVudHJhbGUgQm9ubjEnMAwGBwKCBgEKBxQTATEwFwYDVQQDFBBUVEMgVGVz"
            + "dCBDQSA5OlBOMIGVAgQvribHFw0wNjA4MDEwOTQ4NDRaMH4wfAYDVR0dAQH/BHIw"
            + "cKRuMGwxCzAJBgNVBAYTAkRFMRwwGgYDVQQKFBNEZXV0c2NoZSBUZWxla29tIEFH"
            + "MRYwFAYDVQQLFA1aZW50cmFsZSBCb25uMScwDAYHAoIGAQoHFBMBMTAXBgNVBAMU"
            + "EFRUQyBUZXN0IENBIDk6UE6ggZswgZgwCwYDVR0UBAQCAhEMMB8GA1UdIwQYMBaA"
            + "FANbyNumDI9545HwlCF26NuOJC45MA8GA1UdHAEB/wQFMAOEAf8wVwYDVR0SBFAw"
            + "ToZMbGRhcDovL3Brc2xkYXAudHR0Yy5kZS9vdT1ULVRlbGVTZWMgVGVzdCBESVIg"
            + "ODpQTixvPURldXRzY2hlIFRlbGVrb20gQUcsYz1kZTANBgkqhkiG9w0BAQUFAAOB"
            + "gQBewL5gLFHpeOWO07Vk3Gg7pRDuAlvaovBH4coCyCWpk5jEhUfFSYEDuaQB7do4"
            + "IlJmeTHvkI0PIZWJ7bwQ2PVdipPWDx0NVwS/Cz5jUKiS3BbAmZQZOueiKLFpQq3A"
            + "b8aOHA7WHU4078/1lM+bgeu33Ln1CGykEbmSjA/oKPi/JA==");

    byte[] directCRL = Base64.decode(
        "MIIGXTCCBckCAQEwCgYGKyQDAwECBQAwdDELMAkGA1UEBhMCREUxHDAaBgNVBAoU"
            + "E0RldXRzY2hlIFRlbGVrb20gQUcxFzAVBgNVBAsUDlQtVGVsZVNlYyBUZXN0MS4w"
            + "DAYHAoIGAQoHFBMBMTAeBgNVBAMUF1QtVGVsZVNlYyBUZXN0IERJUiA4OlBOFw0w"
            + "NjA4MDQwODQ1MTRaFw0wNjA4MDQxNDQ1MTRaMIIElTAVAgQvrj/pFw0wMzA3MjIw"
            + "NTQxMjhaMBUCBC+uP+oXDTAzMDcyMjA1NDEyOFowFQIEL64/5xcNMDQwNDA1MTMx"
            + "ODE3WjAVAgQvrj/oFw0wNDA0MDUxMzE4MTdaMBUCBC+uP+UXDTAzMDExMzExMTgx"
            + "MVowFQIEL64/5hcNMDMwMTEzMTExODExWjAVAgQvrj/jFw0wMzAxMTMxMTI2NTZa"
            + "MBUCBC+uP+QXDTAzMDExMzExMjY1NlowFQIEL64/4hcNMDQwNzEzMDc1ODM4WjAV"
            + "AgQvrj/eFw0wMzAyMTcwNjMzMjVaMBUCBC+uP98XDTAzMDIxNzA2MzMyNVowFQIE"
            + "L64/0xcNMDMwMjE3MDYzMzI1WjAVAgQvrj/dFw0wMzAxMTMxMTI4MTRaMBUCBC+u"
            + "P9cXDTAzMDExMzExMjcwN1owFQIEL64/2BcNMDMwMTEzMTEyNzA3WjAVAgQvrj/V"
            + "Fw0wMzA0MzAxMjI3NTNaMBUCBC+uP9YXDTAzMDQzMDEyMjc1M1owFQIEL64/xhcN"
            + "MDMwMjEyMTM0NTQwWjAVAgQvrj/FFw0wMzAyMTIxMzQ1NDBaMBUCBC+uP8IXDTAz"
            + "MDIxMjEzMDkxNlowFQIEL64/wRcNMDMwMjEyMTMwODQwWjAVAgQvrj++Fw0wMzAy"
            + "MTcwNjM3MjVaMBUCBC+uP70XDTAzMDIxNzA2MzcyNVowFQIEL64/sBcNMDMwMjEy"
            + "MTMwODU5WjAVAgQvrj+vFw0wMzAyMTcwNjM3MjVaMBUCBC+uP5MXDTAzMDQxMDA1"
            + "MjYyOFowFQIEL64/khcNMDMwNDEwMDUyNjI4WjAVAgQvrj8/Fw0wMzAyMjYxMTA0"
            + "NDRaMBUCBC+uPz4XDTAzMDIyNjExMDQ0NFowFQIEL64+zRcNMDMwNTIwMDUyNzM2"
            + "WjAVAgQvrj7MFw0wMzA1MjAwNTI3MzZaMBUCBC+uPjwXDTAzMDYxNzEwMzQxNlow"
            + "FQIEL64+OxcNMDMwNjE3MTAzNDE2WjAVAgQvrj46Fw0wMzA2MTcxMDM0MTZaMBUC"
            + "BC+uPjkXDTAzMDYxNzEzMDEwMFowFQIEL64+OBcNMDMwNjE3MTMwMTAwWjAVAgQv"
            + "rj43Fw0wMzA2MTcxMzAxMDBaMBUCBC+uPjYXDTAzMDYxNzEzMDEwMFowFQIEL64+"
            + "MxcNMDMwNjE3MTAzNzQ5WjAVAgQvrj4xFw0wMzA2MTcxMDQyNThaMBUCBC+uPjAX"
            + "DTAzMDYxNzEwNDI1OFowFQIEL649qRcNMDMxMDIyMTEzMjI0WjAVAgQvrjyyFw0w"
            + "NTAzMTEwNjQ0MjRaMBUCBC+uPKsXDTA0MDQwMjA3NTQ1M1owFQIEL6466BcNMDUw"
            + "MTI3MTIwMzI0WjAVAgQvrjq+Fw0wNTAyMTYwNzU3MTZaMBUCBC+uOqcXDTA1MDMx"
            + "MDA1NTkzNVowFQIEL646PBcNMDUwNTExMTA0OTQ2WjAVAgQvrG3VFw0wNTExMTEx"
            + "MDAzMjFaMBUCBC+uLmgXDTA2MDEyMzEwMjU1NVowFQIEL64mxxcNMDYwODAxMDk0"
            + "ODQ0WqCBijCBhzALBgNVHRQEBAICEQwwHwYDVR0jBBgwFoAUA1vI26YMj3njkfCU"
            + "IXbo244kLjkwVwYDVR0SBFAwToZMbGRhcDovL3Brc2xkYXAudHR0Yy5kZS9vdT1U"
            + "LVRlbGVTZWMgVGVzdCBESVIgODpQTixvPURldXRzY2hlIFRlbGVrb20gQUcsYz1k"
            + "ZTAKBgYrJAMDAQIFAAOBgQArj4eMlbAwuA2aS5O4UUUHQMKKdK/dtZi60+LJMiMY"
            + "ojrMIf4+ZCkgm1Ca0Cd5T15MJxVHhh167Ehn/Hd48pdnAP6Dfz/6LeqkIHGWMHR+"
            + "z6TXpwWB+P4BdUec1ztz04LypsznrHcLRa91ixg9TZCb1MrOG+InNhleRs1ImXk8"
            + "MQ==");

    private final byte[] pkcs7CrlProblem = Base64.decode(
        "MIIwSAYJKoZIhvcNAQcCoIIwOTCCMDUCAQExCzAJBgUrDgMCGgUAMAsGCSqG"
            + "SIb3DQEHAaCCEsAwggP4MIIC4KADAgECAgF1MA0GCSqGSIb3DQEBBQUAMEUx"
            + "CzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMR4wHAYDVQQD"
            + "ExVHZW9UcnVzdCBDQSBmb3IgQWRvYmUwHhcNMDQxMjAyMjEyNTM5WhcNMDYx"
            + "MjMwMjEyNTM5WjBMMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMR2VvVHJ1c3Qg"
            + "SW5jMSYwJAYDVQQDEx1HZW9UcnVzdCBBZG9iZSBPQ1NQIFJlc3BvbmRlcjCB"
            + "nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA4gnNYhtw7U6QeVXZODnGhHMj"
            + "+OgZ0DB393rEk6a2q9kq129IA2e03yKBTfJfQR9aWKc2Qj90dsSqPjvTDHFG"
            + "Qsagm2FQuhnA3fb1UWhPzeEIdm6bxDsnQ8nWqKqxnWZzELZbdp3I9bBLizIq"
            + "obZovzt60LNMghn/unvvuhpeVSsCAwEAAaOCAW4wggFqMA4GA1UdDwEB/wQE"
            + "AwIE8DCB5QYDVR0gAQH/BIHaMIHXMIHUBgkqhkiG9y8BAgEwgcYwgZAGCCsG"
            + "AQUFBwICMIGDGoGAVGhpcyBjZXJ0aWZpY2F0ZSBoYXMgYmVlbiBpc3N1ZWQg"
            + "aW4gYWNjb3JkYW5jZSB3aXRoIHRoZSBBY3JvYmF0IENyZWRlbnRpYWxzIENQ"
            + "UyBsb2NhdGVkIGF0IGh0dHA6Ly93d3cuZ2VvdHJ1c3QuY29tL3Jlc291cmNl"
            + "cy9jcHMwMQYIKwYBBQUHAgEWJWh0dHA6Ly93d3cuZ2VvdHJ1c3QuY29tL3Jl"
            + "c291cmNlcy9jcHMwEwYDVR0lBAwwCgYIKwYBBQUHAwkwOgYDVR0fBDMwMTAv"
            + "oC2gK4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9hZG9iZWNhMS5j"
            + "cmwwHwYDVR0jBBgwFoAUq4BZw2WDbR19E70Zw+wajw1HaqMwDQYJKoZIhvcN"
            + "AQEFBQADggEBAENJf1BD7PX5ivuaawt90q1OGzXpIQL/ClzEeFVmOIxqPc1E"
            + "TFRq92YuxG5b6+R+k+tGkmCwPLcY8ipg6ZcbJ/AirQhohzjlFuT6YAXsTfEj"
            + "CqEZfWM2sS7crK2EYxCMmKE3xDfPclYtrAoz7qZvxfQj0TuxHSstHZv39wu2"
            + "ZiG1BWiEcyDQyTgqTOXBoZmfJtshuAcXmTpgkrYSrS37zNlPTGh+pMYQ0yWD"
            + "c8OQRJR4OY5ZXfdna01mjtJTOmj6/6XPoLPYTq2gQrc2BCeNJ4bEhLb7sFVB"
            + "PbwPrpzTE/HRbQHDrzj0YimDxeOUV/UXctgvYwHNtEkcBLsOm/uytMYwggSh"
            + "MIIDiaADAgECAgQ+HL0oMA0GCSqGSIb3DQEBBQUAMGkxCzAJBgNVBAYTAlVT"
            + "MSMwIQYDVQQKExpBZG9iZSBTeXN0ZW1zIEluY29ycG9yYXRlZDEdMBsGA1UE"
            + "CxMUQWRvYmUgVHJ1c3QgU2VydmljZXMxFjAUBgNVBAMTDUFkb2JlIFJvb3Qg"
            + "Q0EwHhcNMDMwMTA4MjMzNzIzWhcNMjMwMTA5MDAwNzIzWjBpMQswCQYDVQQG"
            + "EwJVUzEjMCEGA1UEChMaQWRvYmUgU3lzdGVtcyBJbmNvcnBvcmF0ZWQxHTAb"
            + "BgNVBAsTFEFkb2JlIFRydXN0IFNlcnZpY2VzMRYwFAYDVQQDEw1BZG9iZSBS"
            + "b290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzE9UhPen"
            + "ouczU38/nBKIayyZR2d+Dx65rRSI+cMQ2B3w8NWfaQovWTWwzGypTJwVoJ/O"
            + "IL+gz1Ti4CBmRT85hjh+nMSOByLGJPYBErA131XqaZCw24U3HuJOB7JCoWoT"
            + "aaBm6oCREVkqmwh5WiBELcm9cziLPC/gQxtdswvwrzUaKf7vppLdgUydPVmO"
            + "rTE8QH6bkTYG/OJcjdGNJtVcRc+vZT+xqtJilvSoOOq6YEL09BxKNRXO+E4i"
            + "Vg+VGMX4lp+f+7C3eCXpgGu91grwxnSUnfMPUNuad85LcIMjjaDKeCBEXDxU"
            + "ZPHqojAZn+pMBk0GeEtekt8i0slns3rSAQIDAQABo4IBTzCCAUswEQYJYIZI"
            + "AYb4QgEBBAQDAgAHMIGOBgNVHR8EgYYwgYMwgYCgfqB8pHoweDELMAkGA1UE"
            + "BhMCVVMxIzAhBgNVBAoTGkFkb2JlIFN5c3RlbXMgSW5jb3Jwb3JhdGVkMR0w"
            + "GwYDVQQLExRBZG9iZSBUcnVzdCBTZXJ2aWNlczEWMBQGA1UEAxMNQWRvYmUg"
            + "Um9vdCBDQTENMAsGA1UEAxMEQ1JMMTArBgNVHRAEJDAigA8yMDAzMDEwODIz"
            + "MzcyM1qBDzIwMjMwMTA5MDAwNzIzWjALBgNVHQ8EBAMCAQYwHwYDVR0jBBgw"
            + "FoAUgrc4SpOqmxDvgLvZVOLxD/uAnN4wHQYDVR0OBBYEFIK3OEqTqpsQ74C7"
            + "2VTi8Q/7gJzeMAwGA1UdEwQFMAMBAf8wHQYJKoZIhvZ9B0EABBAwDhsIVjYu"
            + "MDo0LjADAgSQMA0GCSqGSIb3DQEBBQUAA4IBAQAy2p9DdcH6b8lv26sdNjc+"
            + "vGEZNrcCPB0jWZhsnu5NhedUyCAfp9S74r8Ad30ka3AvXME6dkm10+AjhCpx"
            + "aiLzwScpmBX2NZDkBEzDjbyfYRzn/SSM0URDjBa6m02l1DUvvBHOvfdRN42f"
            + "kOQU8Rg/vulZEjX5M5LznuDVa5pxm5lLyHHD4bFhCcTl+pHwQjo3fTT5cujN"
            + "qmIcIenV9IIQ43sFti1oVgt+fpIsb01yggztVnSynbmrLSsdEF/bJ3Vwj/0d"
            + "1+ICoHnlHOX/r2RAUS2em0fbQqV8H8KmSLDXvpJpTaT2KVfFeBEY3IdRyhOy"
            + "Yp1PKzK9MaXB+lKrBYjIMIIEyzCCA7OgAwIBAgIEPhy9tTANBgkqhkiG9w0B"
            + "AQUFADBpMQswCQYDVQQGEwJVUzEjMCEGA1UEChMaQWRvYmUgU3lzdGVtcyBJ"
            + "bmNvcnBvcmF0ZWQxHTAbBgNVBAsTFEFkb2JlIFRydXN0IFNlcnZpY2VzMRYw"
            + "FAYDVQQDEw1BZG9iZSBSb290IENBMB4XDTA0MDExNzAwMDMzOVoXDTE1MDEx"
            + "NTA4MDAwMFowRTELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUdlb1RydXN0IElu"
            + "Yy4xHjAcBgNVBAMTFUdlb1RydXN0IENBIGZvciBBZG9iZTCCASIwDQYJKoZI"
            + "hvcNAQEBBQADggEPADCCAQoCggEBAKfld+BkeFrnOYW8r9L1WygTDlTdSfrO"
            + "YvWS/Z6Ye5/l+HrBbOHqQCXBcSeCpz7kB2WdKMh1FOE4e9JlmICsHerBLdWk"
            + "emU+/PDb69zh8E0cLoDfxukF6oVPXj6WSThdSG7H9aXFzRr6S3XGCuvgl+Qw"
            + "DTLiLYW+ONF6DXwt3TQQtKReJjOJZk46ZZ0BvMStKyBaeB6DKZsmiIo89qso"
            + "13VDZINH2w1KvXg0ygDizoNtbvgAPFymwnsINS1klfQlcvn0x0RJm9bYQXK3"
            + "5GNZAgL3M7Lqrld0jMfIUaWvuHCLyivytRuzq1dJ7E8rmidjDEk/G+27pf13"
            + "fNZ7vR7M+IkCAwEAAaOCAZ0wggGZMBIGA1UdEwEB/wQIMAYBAf8CAQEwUAYD"
            + "VR0gBEkwRzBFBgkqhkiG9y8BAgEwODA2BggrBgEFBQcCARYqaHR0cHM6Ly93"
            + "d3cuYWRvYmUuY29tL21pc2MvcGtpL2Nkc19jcC5odG1sMBQGA1UdJQQNMAsG"
            + "CSqGSIb3LwEBBTCBsgYDVR0fBIGqMIGnMCKgIKAehhxodHRwOi8vY3JsLmFk"
            + "b2JlLmNvbS9jZHMuY3JsMIGAoH6gfKR6MHgxCzAJBgNVBAYTAlVTMSMwIQYD"
            + "VQQKExpBZG9iZSBTeXN0ZW1zIEluY29ycG9yYXRlZDEdMBsGA1UECxMUQWRv"
            + "YmUgVHJ1c3QgU2VydmljZXMxFjAUBgNVBAMTDUFkb2JlIFJvb3QgQ0ExDTAL"
            + "BgNVBAMTBENSTDEwCwYDVR0PBAQDAgEGMB8GA1UdIwQYMBaAFIK3OEqTqpsQ"
            + "74C72VTi8Q/7gJzeMB0GA1UdDgQWBBSrgFnDZYNtHX0TvRnD7BqPDUdqozAZ"
            + "BgkqhkiG9n0HQQAEDDAKGwRWNi4wAwIEkDANBgkqhkiG9w0BAQUFAAOCAQEA"
            + "PzlZLqIAjrFeEWEs0uC29YyJhkXOE9mf3YSaFGsITF+Gl1j0pajTjyH4R35Q"
            + "r3floW2q3HfNzTeZ90Jnr1DhVERD6zEMgJpCtJqVuk0sixuXJHghS/KicKf4"
            + "YXJJPx9epuIRF1siBRnznnF90svmOJMXApc0jGnYn3nQfk4kaShSnDaYaeYR"
            + "DJKcsiWhl6S5zfwS7Gg8hDeyckhMQKKWnlG1CQrwlSFisKCduoodwRtWgft8"
            + "kx13iyKK3sbalm6vnVc+5nufS4vI+TwMXoV63NqYaSroafBWk0nL53zGXPEy"
            + "+A69QhzEViJKn2Wgqt5gt++jMMNImbRObIqgfgF1VjCCBUwwggQ0oAMCAQIC"
            + "AgGDMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1H"
            + "ZW9UcnVzdCBJbmMuMR4wHAYDVQQDExVHZW9UcnVzdCBDQSBmb3IgQWRvYmUw"
            + "HhcNMDYwMzI0MTU0MjI5WhcNMDkwNDA2MTQ0MjI5WjBzMQswCQYDVQQGEwJV"
            + "UzELMAkGA1UECBMCTUExETAPBgNVBAoTCEdlb1RydXN0MR0wGwYDVQQDExRN"
            + "YXJrZXRpbmcgRGVwYXJ0bWVudDElMCMGCSqGSIb3DQEJARYWbWFya2V0aW5n"
            + "QGdlb3RydXN0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB"
            + "ANmvajTO4XJvAU2nVcLmXeCnAQX7RZt+7+ML3InmqQ3LCGo1weop09zV069/"
            + "1x/Nmieol7laEzeXxd2ghjGzwfXafqQEqHn6+vBCvqdNPoSi63fSWhnuDVWp"
            + "KVDOYgxOonrXl+Cc43lu4zRSq+Pi5phhrjDWcH74a3/rdljUt4c4GFezFXfa"
            + "w2oTzWkxj2cTSn0Szhpr17+p66UNt8uknlhmu4q44Speqql2HwmCEnpLYJrK"
            + "W3fOq5D4qdsvsLR2EABLhrBezamLI3iGV8cRHOUTsbTMhWhv/lKfHAyf4XjA"
            + "z9orzvPN5jthhIfICOFq/nStTgakyL4Ln+nFAB/SMPkCAwEAAaOCAhYwggIS"
            + "MA4GA1UdDwEB/wQEAwIF4DCB5QYDVR0gAQH/BIHaMIHXMIHUBgkqhkiG9y8B"
            + "AgEwgcYwgZAGCCsGAQUFBwICMIGDGoGAVGhpcyBjZXJ0aWZpY2F0ZSBoYXMg"
            + "YmVlbiBpc3N1ZWQgaW4gYWNjb3JkYW5jZSB3aXRoIHRoZSBBY3JvYmF0IENy"
            + "ZWRlbnRpYWxzIENQUyBsb2NhdGVkIGF0IGh0dHA6Ly93d3cuZ2VvdHJ1c3Qu"
            + "Y29tL3Jlc291cmNlcy9jcHMwMQYIKwYBBQUHAgEWJWh0dHA6Ly93d3cuZ2Vv"
            + "dHJ1c3QuY29tL3Jlc291cmNlcy9jcHMwOgYDVR0fBDMwMTAvoC2gK4YpaHR0"
            + "cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9hZG9iZWNhMS5jcmwwHwYDVR0j"
            + "BBgwFoAUq4BZw2WDbR19E70Zw+wajw1HaqMwRAYIKwYBBQUHAQEEODA2MDQG"
            + "CCsGAQUFBzABhihodHRwOi8vYWRvYmUtb2NzcC5nZW90cnVzdC5jb20vcmVz"
            + "cG9uZGVyMBQGA1UdJQQNMAsGCSqGSIb3LwEBBTA8BgoqhkiG9y8BAQkBBC4w"
            + "LAIBAYYnaHR0cDovL2Fkb2JlLXRpbWVzdGFtcC5nZW90cnVzdC5jb20vdHNh"
            + "MBMGCiqGSIb3LwEBCQIEBTADAgEBMAwGA1UdEwQFMAMCAQAwDQYJKoZIhvcN"
            + "AQEFBQADggEBAAOhy6QxOo+i3h877fvDvTa0plGD2bIqK7wMdNqbMDoSWied"
            + "FIcgcBOIm2wLxOjZBAVj/3lDq59q2rnVeNnfXM0/N0MHI9TumHRjU7WNk9e4"
            + "+JfJ4M+c3anrWOG3NE5cICDVgles+UHjXetHWql/LlP04+K2ZOLb6LE2xGnI"
            + "YyLW9REzCYNAVF+/WkYdmyceHtaBZdbyVAJq0NAJPsfgY1pWcBo31Mr1fpX9"
            + "WrXNTYDCqMyxMImJTmN3iI68tkXlNrhweQoArKFqBysiBkXzG/sGKYY6tWKU"
            + "pzjLc3vIp/LrXC5zilROes8BSvwu1w9qQrJNcGwo7O4uijoNtyYil1Exgh1Q"
            + "MIIdTAIBATBLMEUxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1HZW9UcnVzdCBJ"
            + "bmMuMR4wHAYDVQQDExVHZW9UcnVzdCBDQSBmb3IgQWRvYmUCAgGDMAkGBSsO"
            + "AwIaBQCgggxMMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwIwYJKoZIhvcN"
            + "AQkEMRYEFP4R6qIdpQJzWyzrqO8X1ZfJOgChMIIMCQYJKoZIhvcvAQEIMYIL"
            + "+jCCC/agggZ5MIIGdTCCA6gwggKQMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV"
            + "BAYTAlVTMRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMR4wHAYDVQQDExVHZW9U"
            + "cnVzdCBDQSBmb3IgQWRvYmUXDTA2MDQwNDE3NDAxMFoXDTA2MDQwNTE3NDAx"
            + "MFowggIYMBMCAgC5Fw0wNTEwMTEyMDM2MzJaMBICAVsXDTA0MTEwNDE1MDk0"
            + "MVowEwICALgXDTA1MTIxMjIyMzgzOFowEgIBWhcNMDQxMTA0MTUwOTMzWjAT"
            + "AgIA5hcNMDUwODI3MDQwOTM4WjATAgIAtxcNMDYwMTE2MTc1NTEzWjATAgIA"
            + "hhcNMDUxMjEyMjIzODU1WjATAgIAtRcNMDUwNzA2MTgzODQwWjATAgIA4BcN"
            + "MDYwMzIwMDc0ODM0WjATAgIAgRcNMDUwODAyMjIzMTE1WjATAgIA3xcNMDUx"
            + "MjEyMjIzNjUwWjASAgFKFw0wNDExMDQxNTA5MTZaMBICAUQXDTA0MTEwNDE1"
            + "MDg1M1owEgIBQxcNMDQxMDAzMDEwMDQwWjASAgFsFw0wNDEyMDYxOTQ0MzFa"
            + "MBMCAgEoFw0wNjAzMDkxMjA3MTJaMBMCAgEkFw0wNjAxMTYxNzU1MzRaMBIC"
            + "AWcXDTA1MDMxODE3NTYxNFowEwICAVEXDTA2MDEzMTExMjcxMVowEgIBZBcN"
            + "MDQxMTExMjI0ODQxWjATAgIA8RcNMDUwOTE2MTg0ODAxWjATAgIBThcNMDYw"
            + "MjIxMjAxMDM2WjATAgIAwRcNMDUxMjEyMjIzODE2WjASAgFiFw0wNTAxMTAx"
            + "NjE5MzRaMBICAWAXDTA1MDExMDE5MDAwNFowEwICAL4XDTA1MDUxNzE0NTYx"
            + "MFowDQYJKoZIhvcNAQEFBQADggEBAEKhRMS3wVho1U3EvEQJZC8+JlUngmZQ"
            + "A78KQbHPWNZWFlNvPuf/b0s7Lu16GfNHXh1QAW6Y5Hi1YtYZ3YOPyMd4Xugt"
            + "gCdumbB6xtKsDyN5RvTht6ByXj+CYlYqsL7RX0izJZ6mJn4fjMkqzPKNOjb8"
            + "kSn5T6rn93BjlATtCE8tPVOM8dnqGccRE0OV59+nDBXc90UMt5LdEbwaUOap"
            + "snVB0oLcNm8d/HnlVH6RY5LnDjrT4vwfe/FApZtTecEWsllVUXDjSpwfcfD/"
            + "476/lpGySB2otALqzImlA9R8Ok3hJ8dnF6hhQ5Oe6OJMnGYgdhkKbxsKkdib"
            + "tTVl3qmH5QAwggLFMIIBrQIBATANBgkqhkiG9w0BAQUFADBpMQswCQYDVQQG"
            + "EwJVUzEjMCEGA1UEChMaQWRvYmUgU3lzdGVtcyBJbmNvcnBvcmF0ZWQxHTAb"
            + "BgNVBAsTFEFkb2JlIFRydXN0IFNlcnZpY2VzMRYwFAYDVQQDEw1BZG9iZSBS"
            + "b290IENBFw0wNjAxMjcxODMzMzFaFw0wNzAxMjcwMDAwMDBaMIHeMCMCBD4c"
            + "vUAXDTAzMDEyMTIzNDY1NlowDDAKBgNVHRUEAwoBBDAjAgQ+HL1BFw0wMzAx"
            + "MjEyMzQ3MjJaMAwwCgYDVR0VBAMKAQQwIwIEPhy9YhcNMDMwMTIxMjM0NzQy"
            + "WjAMMAoGA1UdFQQDCgEEMCMCBD4cvWEXDTA0MDExNzAxMDg0OFowDDAKBgNV"
            + "HRUEAwoBBDAjAgQ+HL2qFw0wNDAxMTcwMTA5MDVaMAwwCgYDVR0VBAMKAQQw"
            + "IwIEPhy9qBcNMDQwMTE3MDEzOTI5WjAMMAoGA1UdFQQDCgEEoC8wLTAKBgNV"
            + "HRQEAwIBDzAfBgNVHSMEGDAWgBSCtzhKk6qbEO+Au9lU4vEP+4Cc3jANBgkq"
            + "hkiG9w0BAQUFAAOCAQEAwtXF9042wG39icUlsotn5tpE3oCusLb/hBpEONhx"
            + "OdfEQOq0w5hf/vqaxkcf71etA+KpbEUeSVaHMHRPhx/CmPrO9odE139dJdbt"
            + "9iqbrC9iZokFK3h/es5kg73xujLKd7C/u5ngJ4mwBtvhMLjFjF2vJhPKHL4C"
            + "IgMwdaUAhrcNzy16v+mw/VGJy3Fvc6oCESW1K9tvFW58qZSNXrMlsuidgunM"
            + "hPKG+z0SXVyCqL7pnqKiaGddcgujYGOSY4S938oVcfZeZQEODtSYGlzldojX"
            + "C1U1hCK5+tHAH0Ox/WqRBIol5VCZQwJftf44oG8oviYq52aaqSejXwmfT6zb"
            + "76GCBXUwggVxMIIFbQoBAKCCBWYwggViBgkrBgEFBQcwAQEEggVTMIIFTzCB"
            + "taIWBBS+8EpykfXdl4h3z7m/NZfdkAQQERgPMjAwNjA0MDQyMDIwMTVaMGUw"
            + "YzA7MAkGBSsOAwIaBQAEFEb4BuZYkbjBjOjT6VeA/00fBvQaBBT3fTSQniOp"
            + "BbHBSkz4xridlX0bsAICAYOAABgPMjAwNjA0MDQyMDIwMTVaoBEYDzIwMDYw"
            + "NDA1MDgyMDE1WqEjMCEwHwYJKwYBBQUHMAECBBIEEFqooq/R2WltD7TposkT"
            + "BhMwDQYJKoZIhvcNAQEFBQADgYEAMig6lty4b0JDsT/oanfQG5x6jVKPACpp"
            + "1UA9SJ0apJJa7LeIdDFmu5C2S/CYiKZm4A4P9cAu0YzgLHxE4r6Op+HfVlAG"
            + "6bzUe1P/hi1KCJ8r8wxOZAktQFPSzs85RAZwkHMfB0lP2e/h666Oye+Zf8VH"
            + "RaE+/xZ7aswE89HXoumgggQAMIID/DCCA/gwggLgoAMCAQICAXUwDQYJKoZI"
            + "hvcNAQEFBQAwRTELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUdlb1RydXN0IElu"
            + "Yy4xHjAcBgNVBAMTFUdlb1RydXN0IENBIGZvciBBZG9iZTAeFw0wNDEyMDIy"
            + "MTI1MzlaFw0wNjEyMzAyMTI1MzlaMEwxCzAJBgNVBAYTAlVTMRUwEwYDVQQK"
            + "EwxHZW9UcnVzdCBJbmMxJjAkBgNVBAMTHUdlb1RydXN0IEFkb2JlIE9DU1Ag"
            + "UmVzcG9uZGVyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDiCc1iG3Dt"
            + "TpB5Vdk4OcaEcyP46BnQMHf3esSTprar2SrXb0gDZ7TfIoFN8l9BH1pYpzZC"
            + "P3R2xKo+O9MMcUZCxqCbYVC6GcDd9vVRaE/N4Qh2bpvEOydDydaoqrGdZnMQ"
            + "tlt2ncj1sEuLMiqhtmi/O3rQs0yCGf+6e++6Gl5VKwIDAQABo4IBbjCCAWow"
            + "DgYDVR0PAQH/BAQDAgTwMIHlBgNVHSABAf8EgdowgdcwgdQGCSqGSIb3LwEC"
            + "ATCBxjCBkAYIKwYBBQUHAgIwgYMagYBUaGlzIGNlcnRpZmljYXRlIGhhcyBi"
            + "ZWVuIGlzc3VlZCBpbiBhY2NvcmRhbmNlIHdpdGggdGhlIEFjcm9iYXQgQ3Jl"
            + "ZGVudGlhbHMgQ1BTIGxvY2F0ZWQgYXQgaHR0cDovL3d3dy5nZW90cnVzdC5j"
            + "b20vcmVzb3VyY2VzL2NwczAxBggrBgEFBQcCARYlaHR0cDovL3d3dy5nZW90"
            + "cnVzdC5jb20vcmVzb3VyY2VzL2NwczATBgNVHSUEDDAKBggrBgEFBQcDCTA6"
            + "BgNVHR8EMzAxMC+gLaArhilodHRwOi8vY3JsLmdlb3RydXN0LmNvbS9jcmxz"
            + "L2Fkb2JlY2ExLmNybDAfBgNVHSMEGDAWgBSrgFnDZYNtHX0TvRnD7BqPDUdq"
            + "ozANBgkqhkiG9w0BAQUFAAOCAQEAQ0l/UEPs9fmK+5prC33SrU4bNekhAv8K"
            + "XMR4VWY4jGo9zURMVGr3Zi7Eblvr5H6T60aSYLA8txjyKmDplxsn8CKtCGiH"
            + "OOUW5PpgBexN8SMKoRl9YzaxLtysrYRjEIyYoTfEN89yVi2sCjPupm/F9CPR"
            + "O7EdKy0dm/f3C7ZmIbUFaIRzINDJOCpM5cGhmZ8m2yG4BxeZOmCSthKtLfvM"
            + "2U9MaH6kxhDTJYNzw5BElHg5jlld92drTWaO0lM6aPr/pc+gs9hOraBCtzYE"
            + "J40nhsSEtvuwVUE9vA+unNMT8dFtAcOvOPRiKYPF45RX9Rdy2C9jAc20SRwE"
            + "uw6b+7K0xjANBgkqhkiG9w0BAQEFAASCAQC7a4yICFGCEMPlJbydK5qLG3rV"
            + "sip7Ojjz9TB4nLhC2DgsIHds8jjdq2zguInluH2nLaBCVS+qxDVlTjgbI2cB"
            + "TaWS8nglC7nNjzkKAsa8vThA8FZUVXTW0pb74jNJJU2AA27bb4g+4WgunCrj"
            + "fpYp+QjDyMmdrJVqRmt5eQN+dpVxMS9oq+NrhOSEhyIb4/rejgNg9wnVK1ms"
            + "l5PxQ4x7kpm7+Ua41//owkJVWykRo4T1jo4eHEz1DolPykAaKie2VKH/sMqR"
            + "Spjh4E5biKJLOV9fKivZWKAXByXfwUbbMsJvz4v/2yVHFy9xP+tqB5ZbRoDK"
            + "k8PzUyCprozn+/22oYIPijCCD4YGCyqGSIb3DQEJEAIOMYIPdTCCD3EGCSqG"
            + "SIb3DQEHAqCCD2Iwgg9eAgEDMQswCQYFKw4DAhoFADCB+gYLKoZIhvcNAQkQ"
            + "AQSggeoEgecwgeQCAQEGAikCMCEwCQYFKw4DAhoFAAQUoT97qeCv3FXYaEcS"
            + "gY8patCaCA8CAiMHGA8yMDA2MDQwNDIwMjA1N1owAwIBPAEB/wIIO0yRre3L"
            + "8/6ggZCkgY0wgYoxCzAJBgNVBAYTAlVTMRYwFAYDVQQIEw1NYXNzYWNodXNl"
            + "dHRzMRAwDgYDVQQHEwdOZWVkaGFtMRUwEwYDVQQKEwxHZW9UcnVzdCBJbmMx"
            + "EzARBgNVBAsTClByb2R1Y3Rpb24xJTAjBgNVBAMTHGFkb2JlLXRpbWVzdGFt"
            + "cC5nZW90cnVzdC5jb22gggzJMIIDUTCCAjmgAwIBAgICAI8wDQYJKoZIhvcN"
            + "AQEFBQAwRTELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUdlb1RydXN0IEluYy4x"
            + "HjAcBgNVBAMTFUdlb1RydXN0IENBIGZvciBBZG9iZTAeFw0wNTAxMTAwMTI5"
            + "MTBaFw0xNTAxMTUwODAwMDBaMIGKMQswCQYDVQQGEwJVUzEWMBQGA1UECBMN"
            + "TWFzc2FjaHVzZXR0czEQMA4GA1UEBxMHTmVlZGhhbTEVMBMGA1UEChMMR2Vv"
            + "VHJ1c3QgSW5jMRMwEQYDVQQLEwpQcm9kdWN0aW9uMSUwIwYDVQQDExxhZG9i"
            + "ZS10aW1lc3RhbXAuZ2VvdHJ1c3QuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GN"
            + "ADCBiQKBgQDRbxJotLFPWQuuEDhKtOMaBUJepGxIvWxeahMbq1DVmqnk88+j"
            + "w/5lfPICPzQZ1oHrcTLSAFM7Mrz3pyyQKQKMqUyiemzuG/77ESUNfBNSUfAF"
            + "PdtHuDMU8Is8ABVnFk63L+wdlvvDIlKkE08+VTKCRdjmuBVltMpQ6QcLFQzm"
            + "AQIDAQABo4GIMIGFMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly9jcmwuZ2Vv"
            + "dHJ1c3QuY29tL2NybHMvYWRvYmVjYTEuY3JsMB8GA1UdIwQYMBaAFKuAWcNl"
            + "g20dfRO9GcPsGo8NR2qjMA4GA1UdDwEB/wQEAwIGwDAWBgNVHSUBAf8EDDAK"
            + "BggrBgEFBQcDCDANBgkqhkiG9w0BAQUFAAOCAQEAmnyXjdtX+F79Nf0KggTd"
            + "6YC2MQD9s09IeXTd8TP3rBmizfM+7f3icggeCGakNfPRmIUMLoa0VM5Kt37T"
            + "2X0TqzBWusfbKx7HnX4v1t/G8NJJlT4SShSHv+8bjjU4lUoCmW2oEcC5vXwP"
            + "R5JfjCyois16npgcO05ZBT+LLDXyeBijE6qWmwLDfEpLyILzVRmyU4IE7jvm"
            + "rgb3GXwDUvd3yQXGRRHbPCh3nj9hBGbuzyt7GnlqnEie3wzIyMG2ET/wvTX5"
            + "4BFXKNe7lDLvZj/MXvd3V7gMTSVW0kAszKao56LfrVTgp1VX3UBQYwmQqaoA"
            + "UwFezih+jEvjW6cYJo/ErDCCBKEwggOJoAMCAQICBD4cvSgwDQYJKoZIhvcN"
            + "AQEFBQAwaTELMAkGA1UEBhMCVVMxIzAhBgNVBAoTGkFkb2JlIFN5c3RlbXMg"
            + "SW5jb3Jwb3JhdGVkMR0wGwYDVQQLExRBZG9iZSBUcnVzdCBTZXJ2aWNlczEW"
            + "MBQGA1UEAxMNQWRvYmUgUm9vdCBDQTAeFw0wMzAxMDgyMzM3MjNaFw0yMzAx"
            + "MDkwMDA3MjNaMGkxCzAJBgNVBAYTAlVTMSMwIQYDVQQKExpBZG9iZSBTeXN0"
            + "ZW1zIEluY29ycG9yYXRlZDEdMBsGA1UECxMUQWRvYmUgVHJ1c3QgU2Vydmlj"
            + "ZXMxFjAUBgNVBAMTDUFkb2JlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUA"
            + "A4IBDwAwggEKAoIBAQDMT1SE96ei5zNTfz+cEohrLJlHZ34PHrmtFIj5wxDY"
            + "HfDw1Z9pCi9ZNbDMbKlMnBWgn84gv6DPVOLgIGZFPzmGOH6cxI4HIsYk9gES"
            + "sDXfVeppkLDbhTce4k4HskKhahNpoGbqgJERWSqbCHlaIEQtyb1zOIs8L+BD"
            + "G12zC/CvNRop/u+mkt2BTJ09WY6tMTxAfpuRNgb84lyN0Y0m1VxFz69lP7Gq"
            + "0mKW9Kg46rpgQvT0HEo1Fc74TiJWD5UYxfiWn5/7sLd4JemAa73WCvDGdJSd"
            + "8w9Q25p3zktwgyONoMp4IERcPFRk8eqiMBmf6kwGTQZ4S16S3yLSyWezetIB"
            + "AgMBAAGjggFPMIIBSzARBglghkgBhvhCAQEEBAMCAAcwgY4GA1UdHwSBhjCB"
            + "gzCBgKB+oHykejB4MQswCQYDVQQGEwJVUzEjMCEGA1UEChMaQWRvYmUgU3lz"
            + "dGVtcyBJbmNvcnBvcmF0ZWQxHTAbBgNVBAsTFEFkb2JlIFRydXN0IFNlcnZp"
            + "Y2VzMRYwFAYDVQQDEw1BZG9iZSBSb290IENBMQ0wCwYDVQQDEwRDUkwxMCsG"
            + "A1UdEAQkMCKADzIwMDMwMTA4MjMzNzIzWoEPMjAyMzAxMDkwMDA3MjNaMAsG"
            + "A1UdDwQEAwIBBjAfBgNVHSMEGDAWgBSCtzhKk6qbEO+Au9lU4vEP+4Cc3jAd"
            + "BgNVHQ4EFgQUgrc4SpOqmxDvgLvZVOLxD/uAnN4wDAYDVR0TBAUwAwEB/zAd"
            + "BgkqhkiG9n0HQQAEEDAOGwhWNi4wOjQuMAMCBJAwDQYJKoZIhvcNAQEFBQAD"
            + "ggEBADLan0N1wfpvyW/bqx02Nz68YRk2twI8HSNZmGye7k2F51TIIB+n1Lvi"
            + "vwB3fSRrcC9cwTp2SbXT4COEKnFqIvPBJymYFfY1kOQETMONvJ9hHOf9JIzR"
            + "REOMFrqbTaXUNS+8Ec6991E3jZ+Q5BTxGD++6VkSNfkzkvOe4NVrmnGbmUvI"
            + "ccPhsWEJxOX6kfBCOjd9NPly6M2qYhwh6dX0ghDjewW2LWhWC35+kixvTXKC"
            + "DO1WdLKduastKx0QX9sndXCP/R3X4gKgeeUc5f+vZEBRLZ6bR9tCpXwfwqZI"
            + "sNe+kmlNpPYpV8V4ERjch1HKE7JinU8rMr0xpcH6UqsFiMgwggTLMIIDs6AD"
            + "AgECAgQ+HL21MA0GCSqGSIb3DQEBBQUAMGkxCzAJBgNVBAYTAlVTMSMwIQYD"
            + "VQQKExpBZG9iZSBTeXN0ZW1zIEluY29ycG9yYXRlZDEdMBsGA1UECxMUQWRv"
            + "YmUgVHJ1c3QgU2VydmljZXMxFjAUBgNVBAMTDUFkb2JlIFJvb3QgQ0EwHhcN"
            + "MDQwMTE3MDAwMzM5WhcNMTUwMTE1MDgwMDAwWjBFMQswCQYDVQQGEwJVUzEW"
            + "MBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEeMBwGA1UEAxMVR2VvVHJ1c3QgQ0Eg"
            + "Zm9yIEFkb2JlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp+V3"
            + "4GR4Wuc5hbyv0vVbKBMOVN1J+s5i9ZL9nph7n+X4esFs4epAJcFxJ4KnPuQH"
            + "ZZ0oyHUU4Th70mWYgKwd6sEt1aR6ZT788Nvr3OHwTRwugN/G6QXqhU9ePpZJ"
            + "OF1Ibsf1pcXNGvpLdcYK6+CX5DANMuIthb440XoNfC3dNBC0pF4mM4lmTjpl"
            + "nQG8xK0rIFp4HoMpmyaIijz2qyjXdUNkg0fbDUq9eDTKAOLOg21u+AA8XKbC"
            + "ewg1LWSV9CVy+fTHREmb1thBcrfkY1kCAvczsuquV3SMx8hRpa+4cIvKK/K1"
            + "G7OrV0nsTyuaJ2MMST8b7bul/Xd81nu9Hsz4iQIDAQABo4IBnTCCAZkwEgYD"
            + "VR0TAQH/BAgwBgEB/wIBATBQBgNVHSAESTBHMEUGCSqGSIb3LwECATA4MDYG"
            + "CCsGAQUFBwIBFipodHRwczovL3d3dy5hZG9iZS5jb20vbWlzYy9wa2kvY2Rz"
            + "X2NwLmh0bWwwFAYDVR0lBA0wCwYJKoZIhvcvAQEFMIGyBgNVHR8Egaowgacw"
            + "IqAgoB6GHGh0dHA6Ly9jcmwuYWRvYmUuY29tL2Nkcy5jcmwwgYCgfqB8pHow"
            + "eDELMAkGA1UEBhMCVVMxIzAhBgNVBAoTGkFkb2JlIFN5c3RlbXMgSW5jb3Jw"
            + "b3JhdGVkMR0wGwYDVQQLExRBZG9iZSBUcnVzdCBTZXJ2aWNlczEWMBQGA1UE"
            + "AxMNQWRvYmUgUm9vdCBDQTENMAsGA1UEAxMEQ1JMMTALBgNVHQ8EBAMCAQYw"
            + "HwYDVR0jBBgwFoAUgrc4SpOqmxDvgLvZVOLxD/uAnN4wHQYDVR0OBBYEFKuA"
            + "WcNlg20dfRO9GcPsGo8NR2qjMBkGCSqGSIb2fQdBAAQMMAobBFY2LjADAgSQ"
            + "MA0GCSqGSIb3DQEBBQUAA4IBAQA/OVkuogCOsV4RYSzS4Lb1jImGRc4T2Z/d"
            + "hJoUawhMX4aXWPSlqNOPIfhHflCvd+Whbarcd83NN5n3QmevUOFUREPrMQyA"
            + "mkK0mpW6TSyLG5ckeCFL8qJwp/hhckk/H16m4hEXWyIFGfOecX3Sy+Y4kxcC"
            + "lzSMadifedB+TiRpKFKcNphp5hEMkpyyJaGXpLnN/BLsaDyEN7JySExAopae"
            + "UbUJCvCVIWKwoJ26ih3BG1aB+3yTHXeLIorextqWbq+dVz7me59Li8j5PAxe"
            + "hXrc2phpKuhp8FaTScvnfMZc8TL4Dr1CHMRWIkqfZaCq3mC376Mww0iZtE5s"
            + "iqB+AXVWMYIBgDCCAXwCAQEwSzBFMQswCQYDVQQGEwJVUzEWMBQGA1UEChMN"
            + "R2VvVHJ1c3QgSW5jLjEeMBwGA1UEAxMVR2VvVHJ1c3QgQ0EgZm9yIEFkb2Jl"
            + "AgIAjzAJBgUrDgMCGgUAoIGMMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB"
            + "BDAcBgkqhkiG9w0BCQUxDxcNMDYwNDA0MjAyMDU3WjAjBgkqhkiG9w0BCQQx"
            + "FgQUp7AnXBqoNcarvO7fMJut1og2U5AwKwYLKoZIhvcNAQkQAgwxHDAaMBgw"
            + "FgQU1dH4eZTNhgxdiSABrat6zsPdth0wDQYJKoZIhvcNAQEBBQAEgYCinr/F"
            + "rMiQz/MRm9ZD5YGcC0Qo2dRTPd0Aop8mZ4g1xAhKFLnp7lLsjCbkSDpVLDBh"
            + "cnCk7CV+3FT5hlvt8OqZlR0CnkSnCswLFhrppiWle6cpxlwGqyAteC8uKtQu"
            + "wjE5GtBKLcCOAzQYyyuNZZeB6oCZ+3mPhZ62FxrvvEGJCgAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==");

    private final byte[] emptyDNCert = Base64.decode(
        "MIICfTCCAeagAwIBAgIBajANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJVUzEMMAoGA1UEChMD"
            + "Q0RXMQkwBwYDVQQLEwAxCTAHBgNVBAcTADEJMAcGA1UECBMAMRowGAYDVQQDExFUZW1wbGFyIFRl"
            + "c3QgMTAyNDEiMCAGCSqGSIb3DQEJARYTdGVtcGxhcnRlc3RAY2R3LmNvbTAeFw0wNjA1MjIwNTAw"
            + "MDBaFw0xMDA1MjIwNTAwMDBaMHwxCzAJBgNVBAYTAlVTMQwwCgYDVQQKEwNDRFcxCTAHBgNVBAsT"
            + "ADEJMAcGA1UEBxMAMQkwBwYDVQQIEwAxGjAYBgNVBAMTEVRlbXBsYXIgVGVzdCAxMDI0MSIwIAYJ"
            + "KoZIhvcNAQkBFhN0ZW1wbGFydGVzdEBjZHcuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB"
            + "gQDH3aJpJBfM+A3d84j5YcU6zEQaQ76u5xO9NSBmHjZykKS2kCcUqPpvVOPDA5WgV22dtKPh+lYV"
            + "iUp7wyCVwAKibq8HIbihHceFqMKzjwC639rMoDJ7bi/yzQWz1Zg+075a4FGPlUKn7Yfu89wKkjdW"
            + "wDpRPXc/agqBnrx5pJTXzQIDAQABow8wDTALBgNVHQ8EBAMCALEwDQYJKoZIhvcNAQEEBQADgYEA"
            + "RRsRsjse3i2/KClFVd6YLZ+7K1BE0WxFyY2bbytkwQJSxvv3vLSuweFUbhNxutb68wl/yW4GLy4b"
            + "1QdyswNxrNDXTuu5ILKhRDDuWeocz83aG2KGtr3JlFyr3biWGEyn5WUOE6tbONoQDJ0oPYgI6CAc"
            + "EHdUp0lioOCt6UOw7Cs=");

    private final byte[] gostRFC4491_94 = Base64.decode(
        "MIICCzCCAboCECMO42BGlSTOxwvklBgufuswCAYGKoUDAgIEMGkxHTAbBgNVBAMM" +
            "FEdvc3RSMzQxMC05NCBleGFtcGxlMRIwEAYDVQQKDAlDcnlwdG9Qcm8xCzAJBgNV" +
            "BAYTAlJVMScwJQYJKoZIhvcNAQkBFhhHb3N0UjM0MTAtOTRAZXhhbXBsZS5jb20w" +
            "HhcNMDUwODE2MTIzMjUwWhcNMTUwODE2MTIzMjUwWjBpMR0wGwYDVQQDDBRHb3N0" +
            "UjM0MTAtOTQgZXhhbXBsZTESMBAGA1UECgwJQ3J5cHRvUHJvMQswCQYDVQQGEwJS" +
            "VTEnMCUGCSqGSIb3DQEJARYYR29zdFIzNDEwLTk0QGV4YW1wbGUuY29tMIGlMBwG" +
            "BiqFAwICFDASBgcqhQMCAiACBgcqhQMCAh4BA4GEAASBgLuEZuF5nls02CyAfxOo" +
            "GWZxV/6MVCUhR28wCyd3RpjG+0dVvrey85NsObVCNyaE4g0QiiQOHwxCTSs7ESuo" +
            "v2Y5MlyUi8Go/htjEvYJJYfMdRv05YmKCYJo01x3pg+2kBATjeM+fJyR1qwNCCw+" +
            "eMG1wra3Gqgqi0WBkzIydvp7MAgGBiqFAwICBANBABHHCH4S3ALxAiMpR3aPRyqB" +
            "g1DjB8zy5DEjiULIc+HeIveF81W9lOxGkZxnrFjXBSqnjLeFKgF1hffXOAP7zUM=");

    private final byte[] gostRFC4491_2001 = Base64.decode(
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

    private final byte[] sha3Cert = Base64.decode(
        "MIID8jCCAqagAwIBAgIICfBykpzUT+IwQQYJKoZIhvcNAQEKMDSgDzANBglg"
            + "hkgBZQMEAggFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAggFAKIDAgEg"
            + "MCwxCzAJBgNVBAYTAkRFMQ4wDAYDVQQKDAV4aXBraTENMAsGA1UEAwwEUkNB"
            + "MTAeFw0xNjEwMTgxODQzMjhaFw0yNjEwMTgxODQzMjdaMCwxCzAJBgNVBAYT"
            + "AkRFMQ4wDAYDVQQKDAV4aXBraTENMAsGA1UEAwwEUkNBMTCCASIwDQYJKoZI"
            + "hvcNAQEBBQADggEPADCCAQoCggEBAK/pzm1RASDYDg3WBXyW3AnAESRF/+li"
            + "qh0X8Y89m+JFJeOi1u89bOSPjsFfo5SbRSElyRXedh/d37KrONg39NEKIcC6"
            + "iSuiNfXu0D6nlSzhrQzmvHIyfLnm8N2JtHDr/hZIprOcFO+lZTJIjjrOVe9y"
            + "lFGgGDd/uQCEJk1Cmi5Ivi9odeiN3z8lVlGNeN9/Q5n47ijuYWr73z/FyyAK"
            + "gAG3B5nhAYWs4ft0O3JWBc0QJZzShqsRjm3SNhAqMDnRoTq04PFgbDYizV8T"
            + "ydz2kCne79TDwsY4MckYYaGoNcPoQXVS+9YjQjI72ktSlxiJxodL9WMFl+ED"
            + "5ZLBRIRsDJECAwEAAaOBrzCBrDAPBgNVHRMBAf8EBTADAQH/MGoGCCsGAQUF"
            + "BwEBBF4wXDAnBggrBgEFBQcwAoYbaHR0cDovL2V4YW1wbGUub3JnL1JDQTEu"
            + "ZGVyMDEGCCsGAQUFBzABhiVodHRwOi8vbG9jYWxob3N0OjgwODAvb2NzcC9y"
            + "ZXNwb25kZXIxMB0GA1UdDgQWBBRTXKdJI3P1kveLlRxPvzUfDnC8JjAOBgNV"
            + "HQ8BAf8EBAMCAQYwQQYJKoZIhvcNAQEKMDSgDzANBglghkgBZQMEAggFAKEc"
            + "MBoGCSqGSIb3DQEBCDANBglghkgBZQMEAggFAKIDAgEgA4IBAQCpSVaqOMKz"
            + "6NT0+mivEhig9cKsglFhnWStKUtdhrG4HqOf6Qjny9Xvq1nE7x8e2xAoaZLd"
            + "GMsNAWFCbwzoJrDL7Ct6itQ5ymxi2haN+Urc5UWJd/8C0R74OdP1uPCiljZ9"
            + "DdjbNk/hS36UPYi+FT5r6Jr/1X/EqgL1MOUsSTEXdYlZH662zjbV4D9QSBzx"
            + "ul9bYyWrqSZFKvKef4UQwUy8yXtChwiwp50mfJQBdVcIqPBYCgmLYclamjQx"
            + "hlkk5VbZb4D/Cv4HxrdxpJfy/ewUZR7uHlzDx0/m4qjzNzWgq+sh3ZbveDrV"
            + "wd/FDMFOxSIno9qgHtdfgXRwZJ+l07fF");

    private static byte[] sm_root = Base64.decode(
        "MIICwzCCAmmgAwIBAgIIIBQGIgAAAAMwCgYIKoEcz1UBg3UwgdgxCzAJBgNVBAYT" +
            "AkNOMRIwEAYDVQQIDAnmsZ/oi4/nnIExEjAQBgNVBAcMCeWNl+S6rOW4gjE8MDoG" +
            "A1UECgwz5rGf6IuP55yB55S15a2Q5ZWG5Yqh5pyN5Yqh5Lit5b+D5pyJ6ZmQ6LSj" +
            "5Lu75YWs5Y+4MUswSQYDVQQLDELmsZ/oi4/nnIHnlLXlrZDllYbliqHmnI3liqHk" +
            "uK3lv4PmnInpmZDotKPku7vlhazlj7jlronlhajkuovkuJrpg6gxFjAUBgNVBAMM" +
            "DUpTQ0FfUk9PVF9TTTIwHhcNMTQwNjIyMDQ1MzAyWhcNMzQwNjIyMDQ1MzAyWjCB" +
            "1jELMAkGA1UEBhMCQ04xEjAQBgNVBAgMCeaxn+iLj+ecgTESMBAGA1UEBwwJ5Y2X" +
            "5Lqs5biCMTwwOgYDVQQKDDPmsZ/oi4/nnIHnlLXlrZDllYbliqHmnI3liqHkuK3l" +
            "v4PmnInpmZDotKPku7vlhazlj7gxSzBJBgNVBAsMQuaxn+iLj+ecgeeUteWtkOWV" +
            "huWKoeacjeWKoeS4reW/g+aciemZkOi0o+S7u+WFrOWPuOWuieWFqOS6i+S4mumD" +
            "qDEUMBIGA1UEAwwLSlNDQV9DQV9TTTIwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNC" +
            "AAS/gvW90+LvyXPgpR7L0pwlVoZQdan7V5YQMEpxt47tzer31/8WJIfldx9NL/1A" +
            "swkk6ItveCVW5k0u+IIk6crLox0wGzAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIB" +
            "BjAKBggqgRzPVQGDdQNIADBFAiEAy9NkogihHCj9Jx0ZiHdkMyCHF0wHWX58KZco" +
            "CW5mjbgCIC9cAyuVV91ygLWk14PDuIAPFWKm6rJPXbiZL6KzwHQA");

    private static byte[] sm_sign = Base64.decode(
        "MIID9zCCA5ygAwIBAgIIIBcEJwKSCCMwCgYIKoEcz1UBg3UwgccxCzAJBgNVBAYT" +
            "AkNOMRIwEAYDVQQIDAnmsZ/oi4/nnIExEjAQBgNVBAcMCeWNl+S6rOW4gjE8MDoG" +
            "A1UECgwz5rGf6IuP55yB55S15a2Q5ZWG5Yqh5pyN5Yqh5Lit5b+D5pyJ6ZmQ6LSj" +
            "5Lu75YWs5Y+4MTwwOgYDVQQLDDPmsZ/oi4/nnIHnlLXlrZDllYbliqHmnI3liqHk" +
            "uK3lv4PmnInpmZDotKPku7vlhazlj7gxFDASBgNVBAMMC0pTQ0FfQ0FfU00yMB4X" +
            "DTE3MDQyNzAwMzkwNVoXDTE4MDQyNzAwMzkwNVowggEdMQ4wDAYDVQRYDAUwMDAw" +
            "MTESMBAGA1UEGgwJ5biC6L6W5Yy6MRswGQYDVQQBDBIzMjAxMTIxOTgxMDUxMTAw" +
            "MTQxDTALBgRVBIhYDAM0NTYxDTALBgRVBIhXDAMxMjMxEjAQBgNVBC0MCXVzZXJD" +
            "ZXJ0MjELMAkGA1UEBhMCQ04xEjAQBgNVBAgMCeaxn+iLj+ecgTESMBAGA1UEBwwJ" +
            "5Y2X5Lqs5biCMQwwCgYDVQQLDAMwMDgxHzAdBgkqhkiG9w0BCQEWEDMyNzMyMTU2" +
            "OEBxcS5jb20xITAfBgNVBCoMGOa1i+ivlee9keWFs1NNMueul+azlTEyMzEhMB8G" +
            "A1UEAwwY5rWL6K+V572R5YWzU00y566X5rOVMTIzMFkwEwYHKoZIzj0CAQYIKoEc" +
            "z1UBgi0DQgAEdbrBzy2y8Gz4grOF23iaDipPhRPQRApAMIAP0cAuL1tATFjFuWJs" +
            "pBc1cnCZmsOJnVpV4W7VF8hNOaqv3Tq4NqOCARcwggETMAkGA1UdEwQCMAAwCwYD" +
            "VR0PBAQDAgbAMB0GA1UdDgQWBBRsWSOQDniy75t7UEvTXugwfq0HpzAfBgNVHSME" +
            "GDAWgBT/02hyCI7lesT55ixTRU6RpLF6AzAxBgNVHSUEKjAoBggrBgEFBQcDAgYI" +
            "KwYBBQUHAwgGCCsGAQUFBwMEBggrBgEFBQcDCDA9BgNVHR8ENjA0MDKgMKAuhixo" +
            "dHRwOi8vY3JsLmpzY2EuY29tLmNuL2NybC9TTTJDUkxfRU5USVRZLmNybDBHBggr" +
            "BgEFBQcBAQQ7MDkwNwYIKwYBBQUHMAKBK2h0dHA6Ly8xMC4xMDguNS4yOjg4ODAv" +
            "ZG93bmxvYWQvSlNDQV9DQS5jZXIwCgYIKoEcz1UBg3UDSQAwRgIhALFoMoA1+uO4" +
            "tXfmoyePz1pmv0CWPBgEP1EfDeS6FPitAiEAjHJYq7ryHKULqpRg6ph9r+xUDoWd" +
            "0TPMOQ9jj4XJPO4=");

    private static byte[] gost_2012_cert = Base64.decode(
        "MIIEfDCCBCmgAwIBAgIECiew2zAKBggqhQMHAQEDAjCB8TELMAkGA1UEBhMCUlUxKjAoBgNVBAgMIdCh0LDQvdC60YLRii3Q" +
            "n9C10YLQtdGA0LHRg9GA0LPRijEuMCwGA1UECgwl0JbRg9GA0L3QsNC7ICLQodC+0LLRgNC10LzQtdC90L3QuNC6IjEfMB0G" +
            "A1UECwwW0KDRg9C60L7QstC+0LTRgdGC0LLQvjEoMCYGA1UEDAwf0JPQu9Cw0LLQvdGL0Lkg0YDQtdC00LDQutGC0L7RgDE7" +
            "MDkGA1UEAwwy0JDQu9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhyDQn9GD0YjQutC40L0wHhcNMTcwNzAyMTQw" +
            "MDAwWhcNMzcwNzAyMTQwMDAwWjCB8TELMAkGA1UEBhMCUlUxKjAoBgNVBAgMIdCh0LDQvdC60YLRii3Qn9C10YLQtdGA0LHR" +
            "g9GA0LPRijEuMCwGA1UECgwl0JbRg9GA0L3QsNC7ICLQodC+0LLRgNC10LzQtdC90L3QuNC6IjEfMB0GA1UECwwW0KDRg9C6" +
            "0L7QstC+0LTRgdGC0LLQvjEoMCYGA1UEDAwf0JPQu9Cw0LLQvdGL0Lkg0YDQtdC00LDQutGC0L7RgDE7MDkGA1UEAwwy0JDQ" +
            "u9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhyDQn9GD0YjQutC40L0wZjAfBggqhQMHAQEBATATBgcqhQMCAiQA" +
            "BggqhQMHAQECAgNDAARA6UpRcgr4pVAKuYkEQ0XKicUxjhd8jbCEz3OFYQ/wSQnuXR5RquASztlnnmnb5W/PKEAnElAUxW0j" +
            "ROLOGZrDWaOCAZ4wggGaMA4GA1UdDwEB/wQEAwIB/jAxBgNVHSUEKjAoBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMD" +
            "BggrBgEFBQcDBDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQLWqbXBTDJanrRowAoQbAaXbKRDTCCASMGA1UdIwSCARow" +
            "ggEWgBQLWqbXBTDJanrRowAoQbAaXbKRDaGB96SB9DCB8TELMAkGA1UEBhMCUlUxKjAoBgNVBAgMIdCh0LDQvdC60YLRii3Q" +
            "n9C10YLQtdGA0LHRg9GA0LPRijEuMCwGA1UECgwl0JbRg9GA0L3QsNC7ICLQodC+0LLRgNC10LzQtdC90L3QuNC6IjEfMB0G" +
            "A1UECwwW0KDRg9C60L7QstC+0LTRgdGC0LLQvjEoMCYGA1UEDAwf0JPQu9Cw0LLQvdGL0Lkg0YDQtdC00LDQutGC0L7RgDE7" +
            "MDkGA1UEAwwy0JDQu9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhyDQn9GD0YjQutC40L2CBAonsNswCgYIKoUD" +
            "BwEBAwIDQQDL2un6Wxn0frStAheZsd34ANDFwAb0rCOInrXsi6HOAxgIuS+9iICiQNTRlQ6x9LSWOUf+aa7kDDU5P4Ovd5od");

    private byte[] x25519Cert = Base64.decode(
        "MIIBLDCB36ADAgECAghWAUdKKo3DMDAFBgMrZXAwGTEXMBUGA1UEAwwOSUVURiBUZX" +
            "N0IERlbW8wHhcNMTYwODAxMTIxOTI0WhcNNDAxMjMxMjM1OTU5WjAZMRcwFQYDVQQD" +
            "DA5JRVRGIFRlc3QgRGVtbzAqMAUGAytlbgMhAIUg8AmJMKdUdIt93LQ+91oNvzoNJj" +
            "ga9OukqY6qm05qo0UwQzAPBgNVHRMBAf8EBTADAQEAMA4GA1UdDwEBAAQEAwIDCDAg" +
            "BgNVHQ4BAQAEFgQUmx9e7e0EM4Xk97xiPFl1uQvIuzswBQYDK2VwA0EAryMB/t3J5v" +
            "/BzKc9dNZIpDmAgs3babFOTQbs+BolzlDUwsPrdGxO3YNGhW7Ibz3OGhhlxXrCe1Cg" +
            "w1AH9efZBw=="
    );

    private static byte[] gost_2012_privateKey = Base64.decode(
        "MEgCAQAwHwYIKoUDBwEBBgEwEwYHKoUDAgIkAAYIKoUDBwEBAgIEIgQg0MVlKYHb5/AwO1ZjNW8nhjyX3IgHo7nPSKuvKf87" +
            "tTU=");

    private static DSAParameters def2048Params = new DSAParameters(
        new BigInteger("95475cf5d93e596c3fcd1d902add02f427f5f3c7210313bb45fb4d5b" +
            "b2e5fe1cbd678cd4bbdd84c9836be1f31c0777725aeb6c2fc38b85f4" +
            "8076fa76bcd8146cc89a6fb2f706dd719898c2083dc8d896f84062e2" +
            "c9c94d137b054a8d8096adb8d51952398eeca852a0af12df83e475aa" +
            "65d4ec0c38a9560d5661186ff98b9fc9eb60eee8b030376b236bc73b" +
            "e3acdbd74fd61c1d2475fa3077b8f080467881ff7e1ca56fee066d79" +
            "506ade51edbb5443a563927dbc4ba520086746175c8885925ebc64c6" +
            "147906773496990cb714ec667304e261faee33b3cbdf008e0c3fa906" +
            "50d97d3909c9275bf4ac86ffcb3d03e6dfc8ada5934242dd6d3bcca2" +
            "a406cb0b", 16),
        new BigInteger("f8183668ba5fc5bb06b5981e6d8b795d30b8978d43ca0ec572e37e09939a9773", 16),
        new BigInteger("42debb9da5b3d88cc956e08787ec3f3a09bba5f48b889a74aaf53174" +
            "aa0fbe7e3c5b8fcd7a53bef563b0e98560328960a9517f4014d3325f" +
            "c7962bf1e049370d76d1314a76137e792f3f0db859d095e4a5b93202" +
            "4f079ecf2ef09c797452b0770e1350782ed57ddf794979dcef23cb96" +
            "f183061965c4ebc93c9c71c56b925955a75f94cccf1449ac43d586d0" +
            "beee43251b0b2287349d68de0d144403f13e802f4146d882e057af19" +
            "b6f6275c6676c8fa0e3ca2713a3257fd1b27d0639f695e347d8d1cf9" +
            "ac819a26ca9b04cb0eb9b7b035988d15bbac65212a55239cfc7e58fa" +
            "e38d7250ab9991ffbc97134025fe8ce04c4399ad96569be91a546f49" +
            "78693c7a", 16),
        new DSAValidationParameters(Hex.decode("b0b4417601b59cbc9d8ac8f935cadaec4f5fbb2f23785609ae466748d9b5a536"), 497));

    private PublicKey dudPublicKey = new PublicKey()
    {
        public String getAlgorithm()
        {
            return null;
        }

        public String getFormat()
        {
            return null;
        }

        public byte[] getEncoded()
        {
            return null;
        }

    };

    public String getName()
    {
        return "CertTest";
    }

    public void checkCertificate(
        int id,
        byte[] bytes)
    {
        ByteArrayInputStream bIn;
        String dump = "";

        try
        {
            bIn = new ByteArrayInputStream(bytes);

            CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

            Certificate cert = fact.generateCertificate(bIn);

            PublicKey k = cert.getPublicKey();
//            System.out.println("****** " + id + " ******");
//            System.out.println(cert);
        }
        catch (Exception e)
        {
            fail(dump + Strings.lineSeparator() + getName() + ": " + id + " failed - exception " + e.toString(), e);
        }

    }

    public void checkCertificate(
        int id,
        byte[] bytes,
        PublicKey pubKey)
    {
        ByteArrayInputStream bIn;
        String dump = "";

        try
        {
            bIn = new ByteArrayInputStream(bytes);

            CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

            Certificate cert = fact.generateCertificate(bIn);

            PublicKey k = cert.getPublicKey();

            cert.verify(pubKey);
//            System.out.println("****** " + id + " ******");
//            System.out.println(cert);
        }
        catch (Exception e)
        {
            fail(dump + Strings.lineSeparator() + getName() + ": " + id + " failed - exception " + e.toString(), e);
        }

    }

    public void checkNameCertificate(
        int id,
        byte[] bytes)
    {
        ByteArrayInputStream bIn;
        String dump = "";

        try
        {
            bIn = new ByteArrayInputStream(bytes);

            CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

            X509Certificate cert = (X509Certificate)fact.generateCertificate(bIn);

            PublicKey k = cert.getPublicKey();
            if (!cert.getIssuerDN().toString().equals("C=DE,O=DATEV eG,0.2.262.1.10.7.20=1+CN=CA DATEV D03 1:PN"))
            {
                fail(id + " failed - name test.");
            }
            // System.out.println(cert);
        }
        catch (Exception e)
        {
            fail(dump + Strings.lineSeparator() + getName() + ": " + id + " failed - exception " + e.toString(), e);
        }

    }

    public void checkKeyUsage(
        int id,
        byte[] bytes)
    {
        ByteArrayInputStream bIn;
        String dump = "";

        try
        {
            bIn = new ByteArrayInputStream(bytes);

            CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

            X509Certificate cert = (X509Certificate)fact.generateCertificate(bIn);

            PublicKey k = cert.getPublicKey();

            boolean[] keyUsage = cert.getKeyUsage();
            if (keyUsage == null || keyUsage.length <= 7 || keyUsage[7])
            {
                fail("error generating cert - key usage wrong.");
            }

            // System.out.println(cert);
        }
        catch (Exception e)
        {
            fail(dump + Strings.lineSeparator() + getName() + ": " + id + " failed - exception " + e.toString(), e);
        }

    }


    public void checkSelfSignedCertificate(
        int id,
        byte[] bytes)
    {
        ByteArrayInputStream bIn;
        String dump = "";

        try
        {
            bIn = new ByteArrayInputStream(bytes);

            CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

            Certificate cert = fact.generateCertificate(bIn);

            PublicKey k = cert.getPublicKey();

            X509CertificateHolder certHldr = new X509CertificateHolder(bytes);
            String provider = certHldr.getSignatureAlgorithm().getAlgorithm().equals(IsaraObjectIdentifiers.id_alg_xmss) ? "BCPQC" : BC;

            isTrue(certHldr.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(provider).build(k)));
            // System.out.println(cert);
        }
        catch (Exception e)
        {
            fail(dump + Strings.lineSeparator() + getName() + ": " + id + " failed - exception " + e.toString(), e);
        }

    }

    public void checkSelfSignedCertificateAndKey(
        int id,
        byte[] certBytes,
        String sigAlgorithm,
        byte[] keyBytes)
    {
        ByteArrayInputStream bIn;
        String dump = "";

        try
        {
            bIn = new ByteArrayInputStream(certBytes);

            CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

            Certificate cert = fact.generateCertificate(bIn);

            PublicKey k = cert.getPublicKey();

            X509CertificateHolder certHldr = new X509CertificateHolder(certBytes);

            isTrue(certHldr.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(k)));
            // System.out.println(cert);

            KeyFactory keyFactory = KeyFactory.getInstance(k.getAlgorithm(), BC);

            PrivateKey privKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));

            Signature signer = Signature.getInstance(sigAlgorithm, BC);

            signer.initSign(privKey);

            signer.update(certBytes);

            byte[] sig = signer.sign();

            signer.initVerify(cert);

            signer.update(certBytes);

            isTrue(signer.verify(sig));
        }
        catch (Exception e)
        {
            fail(dump + Strings.lineSeparator() + getName() + ": " + id + " failed - exception " + e.toString(), e);
        }
    }

    /**
     * Test a generated certificate with the sun provider
     */
    private void sunProviderCheck(byte[] encoding)
        throws CertificateException
    {
        CertificateFactory certFact = CertificateFactory.getInstance("X.509");

        certFact.generateCertificate(new ByteArrayInputStream(encoding));
    }

    /*
     * we generate a self signed certificate for the sake of testing - RSA
     */
    public void checkCreation1()
        throws Exception
    {
        //
        // a sample key pair.
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
        PrivateKey privKey;
        PublicKey pubKey;

        KeyFactory fact = KeyFactory.getInstance("RSA", BC);

        privKey = fact.generatePrivate(privKeySpec);
        pubKey = fact.generatePublic(pubKeySpec);

        //
        // distinguished name table.
        //
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

        builder.addRDN(BCStyle.C, "AU");
        builder.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
        builder.addRDN(BCStyle.L, "Melbourne");
        builder.addRDN(BCStyle.ST, "Victoria");
        builder.addRDN(BCStyle.E, "feedback-crypto@bouncycastle.org");

        //
        // extensions
        //

        //
        // create the certificate - version 3 - without extensions
        //
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BC).build(privKey);
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);

        isTrue(!certGen.hasExtension(Extension.authorityKeyIdentifier));

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        cert.checkValidity(new Date());

        cert.verify(pubKey);

        cert.verify(cert.getPublicKey());

        Set dummySet = cert.getNonCriticalExtensionOIDs();
        if (dummySet != null)
        {
            fail("non-critical oid set should be null");
        }
        dummySet = cert.getCriticalExtensionOIDs();
        if (dummySet != null)
        {
            fail("critical oid set should be null");
        }

        //
        // create the certificate - version 3 - with extensions
        //
        sigGen = new JcaContentSignerBuilder("MD5WithRSAEncryption").setProvider(BC).build(privKey);
        certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1)
            , new Date(System.currentTimeMillis() - 50000)
            , new Date(System.currentTimeMillis() + 50000)
            , builder.build()
            , pubKey)
            .addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true,
                new X509KeyUsage(X509KeyUsage.encipherOnly))
            .addExtension(new ASN1ObjectIdentifier("2.5.29.37"), true,
                new DERSequence(KeyPurposeId.anyExtendedKeyUsage))
            .addExtension(new ASN1ObjectIdentifier("2.5.29.17"), true,
                new GeneralNames(new GeneralName[]
                    {
                        new GeneralName(GeneralName.rfc822Name, "test@test.test"),
                        new GeneralName(GeneralName.dNSName, "dom.test.test")
                    }));

        X509CertificateHolder certHolder = certGen.build(sigGen);

        isEquals(new Extension(new ASN1ObjectIdentifier("2.5.29.15"), true,
            new X509KeyUsage(X509KeyUsage.encipherOnly).getEncoded()), certGen.getExtension(new ASN1ObjectIdentifier("2.5.29.15")));

        certGen.replaceExtension(new Extension(new ASN1ObjectIdentifier("2.5.29.15"), true,
            new X509KeyUsage(X509KeyUsage.digitalSignature).getEncoded()));

        isEquals(new Extension(new ASN1ObjectIdentifier("2.5.29.15"), true,
            new X509KeyUsage(X509KeyUsage.digitalSignature).getEncoded()), certGen.getExtension(new ASN1ObjectIdentifier("2.5.29.15")));

        cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certHolder);

        cert.checkValidity(new Date());

        cert.verify(pubKey);
        cert.verify(cert.getPublicKey());

        ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder().setProvider(BC).build(pubKey);
        if (!certHolder.isSignatureValid(contentVerifierProvider))
        {
            fail("signature test failed");
        }

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);

        cert = (X509Certificate)certFact.generateCertificate(bIn);

        {
            boolean[] keyUsage = cert.getKeyUsage();
            if (keyUsage == null || keyUsage.length <= 7 || !keyUsage[7])
            {
                fail("error generating cert - key usage wrong.");
            }
        }

        List l = cert.getExtendedKeyUsage();
        if (!l.get(0).equals(KeyPurposeId.anyExtendedKeyUsage.getId()))
        {
            fail("failed extended key usage test");
        }

        Collection c = cert.getSubjectAlternativeNames();
        Iterator it = c.iterator();
        while (it.hasNext())
        {
            List gn = (List)it.next();
            if (!gn.get(1).equals("test@test.test") && !gn.get(1).equals("dom.test.test"))
            {
                fail("failed subject alternative names test");
            }
        }

        sunProviderCheck(certHolder.getEncoded());
        sunProviderCheck(cert.getEncoded());

        // System.out.println(cert);

        //
        // create the certificate - version 1
        //
        sigGen = new JcaContentSignerBuilder("MD5WithRSAEncryption").setProvider(BC).build(privKey);
        X509v1CertificateBuilder certGen1 = new JcaX509v1CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);

        cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen1.build(sigGen));

        cert.checkValidity(new Date());

        cert.verify(pubKey);
        cert.verify(cert.getPublicKey());

        bIn = new ByteArrayInputStream(cert.getEncoded());
        certFact = CertificateFactory.getInstance("X.509", BC);

        cert = (X509Certificate)certFact.generateCertificate(bIn);

        // System.out.println(cert);
        if (!cert.getIssuerDN().equals(cert.getSubjectDN()))
        {
            fail("name comparison fails");
        }

        sunProviderCheck(certHolder.getEncoded());
        sunProviderCheck(cert.getEncoded());
//
        // a lightweight key pair.
        //
        RSAKeyParameters lwPubKey = new RSAKeyParameters(
            false,
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16));

        RSAPrivateCrtKeyParameters lwPrivKey = new RSAPrivateCrtKeyParameters(
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16),
            new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
            new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
            new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
            new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
            new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
            new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

        //
        // distinguished name table.
        //
        builder = new X500NameBuilder(BCStyle.INSTANCE);

        builder.addRDN(BCStyle.C, "AU");
        builder.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
        builder.addRDN(BCStyle.L, "Melbourne");
        builder.addRDN(BCStyle.ST, "Victoria");
        builder.addRDN(BCStyle.E, "feedback-crypto@bouncycastle.org");

        //
        // extensions
        //

        //
        // create the certificate - version 3 - without extensions
        //
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WithRSAEncryption");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

        sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(lwPrivKey);
        SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), new RSAPublicKey(lwPubKey.getModulus(), lwPubKey.getExponent()));
        certGen = new X509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubInfo);

        certHolder = certGen.build(sigGen);

        cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certHolder);

        cert.checkValidity(new Date());

        cert.verify(pubKey);

        contentVerifierProvider = new BcRSAContentVerifierProviderBuilder(new DefaultDigestAlgorithmIdentifierFinder()).build(lwPubKey);

        if (!certHolder.isSignatureValid(contentVerifierProvider))
        {
            fail("lw sig verification failed");
        }
    }

    /*
     * we generate a self signed certificate for the sake of testing - DSA
     */
    public void checkCreation2()
        throws Exception
    {
        //
        // set up the keys
        //
        PrivateKey privKey;
        PublicKey pubKey;

        try
        {
            KeyPairGenerator g = KeyPairGenerator.getInstance("DSA", "SUN");

            g.initialize(512, new SecureRandom());

            KeyPair p = g.generateKeyPair();

            privKey = p.getPrivate();
            pubKey = p.getPublic();
        }
        catch (Exception e)
        {
            fail("error setting up keys - " + e.toString());
            return;
        }

        //
        // distinguished name table.
        //
        X500NameBuilder builder = createStdBuilder();

        //
        // extensions
        //

        //
        // create the certificate - version 3
        //

        ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withDSA").setProvider(BC).build(privKey);
        JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);


        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        cert.checkValidity(new Date());

        cert.verify(pubKey);

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

        cert = (X509Certificate)fact.generateCertificate(bIn);

        // System.out.println(cert);


        //
        // create the certificate - version 1
        //
        sigGen = new JcaContentSignerBuilder("SHA1withDSA").setProvider(BC).build(privKey);
        JcaX509v1CertificateBuilder certGen1 = new JcaX509v1CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);

        cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen1.build(sigGen));

        cert.checkValidity(new Date());

        cert.verify(pubKey);

        bIn = new ByteArrayInputStream(cert.getEncoded());
        fact = CertificateFactory.getInstance("X.509", BC);

        cert = (X509Certificate)fact.generateCertificate(bIn);

        //System.out.println(cert);

        //
        // exception test
        //
        try
        {
            certGen1 = new JcaX509v1CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), dudPublicKey);


            fail("key without encoding not detected in v1");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    /*
     * we generate a self signed certificate for the sake of testing - SM3withSM2
     */
    public void checkSm3WithSm2Creation()
        throws Exception
    {
        //
        // set up the keys
        //
        PrivateKey privKey;
        PublicKey pubKey;

        try
        {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC", BC);

            g.initialize(new ECNamedCurveGenParameterSpec("sm2p256v1"));

            KeyPair p = g.generateKeyPair();

            privKey = p.getPrivate();
            pubKey = p.getPublic();
        }
        catch (Exception e)
        {
            fail("error setting up keys - " + e.toString());
            return;
        }

        //
        // distinguished name table.
        //
        X500NameBuilder builder = createStdBuilder();

        //
        // extensions
        //

        //
        // create the certificate - version 1
        //

        ContentSigner sigGen = new JcaContentSignerBuilder("SM3withSM2").setProvider(BC).build(privKey);
        JcaX509v1CertificateBuilder certGen = new JcaX509v1CertificateBuilder(
            builder.build(),
            BigInteger.valueOf(1),
            new Date(System.currentTimeMillis() - 50000),
            new Date(System.currentTimeMillis() + 50000),
            builder.build(),
            pubKey);


        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        cert.checkValidity(new Date());

        cert.verify(pubKey);

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

        cert = (X509Certificate)fact.generateCertificate(bIn);

        cert.getEncoded();
    }

    private void checkComparison(byte[] encCert)
        throws NoSuchProviderException, CertificateException
    {
        CertificateFactory bcFact = CertificateFactory.getInstance("X.509", BC);
        CertificateFactory sunFact = CertificateFactory.getInstance("X.509", "SUN");

        X509Certificate bcCert = (X509Certificate)bcFact.generateCertificate(new ByteArrayInputStream(encCert));
        X509Certificate sunCert = (X509Certificate)sunFact.generateCertificate(new ByteArrayInputStream(encCert));

        if (!bcCert.equals(sunCert) || !sunCert.equals(bcCert))
        {
            fail("BC/Sun equals test failed");
        }

        if (bcCert.hashCode() != sunCert.hashCode())
        {
            fail("BC/Sun hashCode test failed");
        }
    }

    private X500NameBuilder createStdBuilder()
    {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

        builder.addRDN(BCStyle.C, "AU");
        builder.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
        builder.addRDN(BCStyle.L, "Melbourne");
        builder.addRDN(BCStyle.ST, "Victoria");
        builder.addRDN(BCStyle.E, "feedback-crypto@bouncycastle.org");

        return builder;
    }

    /*
     * we generate a self signed certificate for the sake of testing - ECDSA
     */
    public void checkCreation3()
    {
        X9ECParameters x9 = ECNamedCurveTable.getByName("prime239v1");
        ECCurve curve = x9.getCurve();
        ECParameterSpec spec = new ECParameterSpec(curve, x9.getG(), x9.getN(), x9.getH());

        ECPrivateKeySpec privKeySpec = new ECPrivateKeySpec(
            new BigInteger("876300101507107567501066130761671078357010671067781776716671676178726717"), // d
            spec);

        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(
            curve.decodePoint(Hex.decode("025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70")), // Q
            spec);

        //
        // set up the keys
        //
        PrivateKey privKey;
        PublicKey pubKey;

        try
        {
            KeyFactory fact = KeyFactory.getInstance("ECDSA", BC);

            privKey = fact.generatePrivate(privKeySpec);
            pubKey = fact.generatePublic(pubKeySpec);
        }
        catch (Exception e)
        {
            fail("error setting up keys - " + e.toString());
            return;
        }

        //
        // distinguished name table.
        //
        X500NameBuilder builder = createStdBuilder();


        //
        // toString test
        //
        X500Name p = builder.build();
        String s = p.toString();

        if (!s.equals("C=AU,O=The Legion of the Bouncy Castle,L=Melbourne,ST=Victoria,E=feedback-crypto@bouncycastle.org"))
        {
            fail("ordered X509Principal test failed - s = " + s + ".");
        }

//        p = new X509Principal(attrs);
//        s = p.toString();
//
//        //
//        // we need two of these as the hash code for strings changed...
//        //
//        if (!s.equals("O=The Legion of the Bouncy Castle,E=feedback-crypto@bouncycastle.org,ST=Victoria,L=Melbourne,C=AU") && !s.equals("ST=Victoria,L=Melbourne,C=AU,E=feedback-crypto@bouncycastle.org,O=The Legion of the Bouncy Castle"))
//        {
//            fail("unordered X509Principal test failed.");
//        }

        //
        // create the certificate - version 3
        //
        try
        {
            ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withECDSA").setProvider(BC).build(privKey);
            JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);

            X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

            cert.checkValidity(new Date());

            cert.verify(pubKey);

            ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
            CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

            cert = (X509Certificate)fact.generateCertificate(bIn);

            //
            // try with point compression turned off
            //
            ((ECPointEncoder)pubKey).setPointFormat("UNCOMPRESSED");

            certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);

            cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

            cert.checkValidity(new Date());

            cert.verify(pubKey);

            bIn = new ByteArrayInputStream(cert.getEncoded());
            fact = CertificateFactory.getInstance("X.509", BC);

            cert = (X509Certificate)fact.generateCertificate(bIn);
            // System.out.println(cert);
        }
        catch (Exception e)
        {
            fail("error setting generating cert - " + e.toString());
        }

        X509Principal pr = new X509Principal("O=\"The Bouncy Castle, The Legion of\",E=feedback-crypto@bouncycastle.org,ST=Victoria,L=Melbourne,C=AU");

        if (!pr.toString().equals("O=The Bouncy Castle\\, The Legion of,E=feedback-crypto@bouncycastle.org,ST=Victoria,L=Melbourne,C=AU"))
        {
            fail("string based X509Principal test failed.");
        }

        pr = new X509Principal("O=The Bouncy Castle\\, The Legion of,E=feedback-crypto@bouncycastle.org,ST=Victoria,L=Melbourne,C=AU");

        if (!pr.toString().equals("O=The Bouncy Castle\\, The Legion of,E=feedback-crypto@bouncycastle.org,ST=Victoria,L=Melbourne,C=AU"))
        {
            fail("string based X509Principal test failed.");
        }

    }

    /*
     * we generate a self signed certificate for the sake of testing - SHA224withECDSA
     */
    private void createECCert(String algorithm, ASN1ObjectIdentifier algOid)
        throws Exception
    {
        X9ECParameters x9 = ECNamedCurveTable.getByName("secp521r1");
        ECCurve curve = x9.getCurve();
        ECParameterSpec spec = new ECParameterSpec(curve, x9.getG(), x9.getN(), x9.getH());

        ECPrivateKeySpec privKeySpec = new ECPrivateKeySpec(
            new BigInteger("5769183828869504557786041598510887460263120754767955773309066354712783118202294874205844512909370791582896372147797293913785865682804434049019366394746072023"), // d
            spec);

        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(
            curve.decodePoint(Hex.decode("02006BFDD2C9278B63C92D6624F151C9D7A822CC75BD983B17D25D74C26740380022D3D8FAF304781E416175EADF4ED6E2B47142D2454A7AC7801DD803CF44A4D1F0AC")), // Q
            spec);

        //
        // set up the keys
        //
        PrivateKey privKey;
        PublicKey pubKey;

        KeyFactory fact = KeyFactory.getInstance("ECDSA", BC);

        privKey = fact.generatePrivate(privKeySpec);
        pubKey = fact.generatePublic(pubKeySpec);


        //
        // distinguished name table.
        //
        X500NameBuilder builder = createStdBuilder();

        //
        // create the certificate - version 3
        //
        ContentSigner sigGen = new JcaContentSignerBuilder(algorithm).setProvider(BC).build(privKey);
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        cert.checkValidity(new Date());

        cert.verify(pubKey);

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);

        cert = (X509Certificate)certFact.generateCertificate(bIn);

        //
        // try with point compression turned off
        //
        ((ECPointEncoder)pubKey).setPointFormat("UNCOMPRESSED");

        certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);

        cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        cert.checkValidity(new Date());

        cert.verify(pubKey);

        bIn = new ByteArrayInputStream(cert.getEncoded());
        certFact = CertificateFactory.getInstance("X.509", BC);

        cert = (X509Certificate)certFact.generateCertificate(bIn);

        if (!cert.getSigAlgOID().equals(algOid.toString()))
        {
            fail("ECDSA oid incorrect.");
        }

        if (cert.getSigAlgParams() != null)
        {
            fail("sig parameters present");
        }

        Signature sig = Signature.getInstance(algorithm, BC);

        sig.initVerify(pubKey);

        sig.update(cert.getTBSCertificate());

        if (!sig.verify(cert.getSignature()))
        {
            fail("EC certificate signature not mapped correctly.");
        }
        // System.out.println(cert);
    }

    private void checkCRL(
        int id,
        byte[] bytes)
    {
        ByteArrayInputStream bIn;
        String dump = "";

        try
        {
            bIn = new ByteArrayInputStream(bytes);

            CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

            CRL cert = fact.generateCRL(bIn);

            // System.out.println(cert);
        }
        catch (Exception e)
        {
            fail(dump + Strings.lineSeparator() + getName() + ": " + id + " failed - exception " + e.toString(), e);
        }

    }

    private void checkCreationEd448()
        throws Exception
    {
        //
        // set up the keys
        //
        PrivateKey privKey;
        PublicKey pubKey;

        try
        {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EdDSA", BC);

            g.initialize(new ECGenParameterSpec("Ed448"), new SecureRandom());

            KeyPair p = g.generateKeyPair();

            privKey = p.getPrivate();
            pubKey = p.getPublic();
        }
        catch (Exception e)
        {
            fail("error setting up keys - " + e.toString());
            return;
        }

        //
        // distinguished name table.
        //
        X500NameBuilder builder = createStdBuilder();

        //
        // extensions
        //

        //
        // create the certificate - version 3
        //

        ContentSigner sigGen = new JcaContentSignerBuilder("Ed448").setProvider(BC).build(privKey);
        JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);


        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        cert.checkValidity(new Date());

        cert.verify(pubKey);

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

        cert = (X509Certificate)fact.generateCertificate(bIn);

        // System.out.println(cert);


        //
        // create the certificate - version 1
        //
        sigGen = new JcaContentSignerBuilder("Ed448").setProvider(BC).build(privKey);
        JcaX509v1CertificateBuilder certGen1 = new JcaX509v1CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);

        cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen1.build(sigGen));

        cert.checkValidity(new Date());

        cert.verify(pubKey);

        bIn = new ByteArrayInputStream(cert.getEncoded());
        fact = CertificateFactory.getInstance("X.509", BC);

        cert = (X509Certificate)fact.generateCertificate(bIn);

        //System.out.println(cert);

        //
        // exception test
        //
        try
        {
            certGen1 = new JcaX509v1CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), dudPublicKey);


            fail("key without encoding not detected in v1");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    public void checkCRLCreation1()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", BC);
        Date now = new Date();
        KeyPair pair = kpGen.generateKeyPair();
        X509v2CRLBuilder crlGen = new X509v2CRLBuilder(new X500Name("CN=Test CA"), now);

        crlGen.setNextUpdate(new Date(now.getTime() + 100000));

        crlGen.addCRLEntry(BigInteger.ONE, now, CRLReason.privilegeWithdrawn);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(pair.getPublic()));

        isTrue(crlGen.hasExtension(Extension.authorityKeyIdentifier));

        X509CRLHolder crl = crlGen.build(new JcaContentSignerBuilder("SHA256withRSAEncryption").setProvider(BC).build(pair.getPrivate()));

        Extension authOrig = crlGen.getExtension(Extension.authorityKeyIdentifier);

        crlGen.removeExtension(Extension.authorityKeyIdentifier);

        isTrue(!crlGen.hasExtension(Extension.authorityKeyIdentifier));

        if (!crl.getIssuer().equals(new X500Name("CN=Test CA")))
        {
            fail("failed CRL issuer test");
        }

        Extension authExt = crl.getExtension(Extension.authorityKeyIdentifier);

        if (authExt == null)
        {
            fail("failed to find CRL extension");
        }

        if (!authExt.equals(authOrig))
        {
            fail("auth not matching original");
        }

        AuthorityKeyIdentifier authId = AuthorityKeyIdentifier.getInstance(authExt.getParsedValue());

        X509CRLEntryHolder entry = crl.getRevokedCertificate(BigInteger.ONE);

        if (entry == null)
        {
            fail("failed to find CRL entry");
        }

        if (!entry.getSerialNumber().equals(BigInteger.ONE))
        {
            fail("CRL cert serial number does not match");
        }

        if (!entry.hasExtensions())
        {
            fail("CRL entry extension not found");
        }

        Extension ext = entry.getExtension(Extension.reasonCode);

        if (ext != null)
        {
            ASN1Enumerated reasonCode = ASN1Enumerated.getInstance(ext.getParsedValue());

            if (reasonCode.intValueExact() != CRLReason.privilegeWithdrawn)
            {
                fail("CRL entry reasonCode wrong");
            }
        }
        else
        {
            fail("CRL entry reasonCode not found");
        }

        // build from template
        crlGen = new X509v2CRLBuilder(crl);

        crl = crlGen.build(new JcaContentSignerBuilder("SHA256withRSAEncryption").setProvider(BC).build(pair.getPrivate()));

        isTrue(crlGen.hasExtension(Extension.authorityKeyIdentifier));

        if (!crl.getIssuer().equals(new X500Name("CN=Test CA")))
        {
            fail("failed CRL issuer test");
        }

        // build from template without extensions

        crlGen = new X509v2CRLBuilder(new X500Name("CN=Test CA"), now);

        crlGen.setNextUpdate(new Date(now.getTime() + 100000));

        crlGen.addCRLEntry(BigInteger.ONE, now, CRLReason.privilegeWithdrawn);

        crl = crlGen.build(new JcaContentSignerBuilder("SHA256withRSAEncryption").setProvider(BC).build(pair.getPrivate()));

        crlGen = new X509v2CRLBuilder(crl);

        crl = crlGen.build(new JcaContentSignerBuilder("SHA256withRSAEncryption").setProvider(BC).build(pair.getPrivate()));

        isTrue(!crlGen.hasExtension(Extension.authorityKeyIdentifier));

        if (!crl.getIssuer().equals(new X500Name("CN=Test CA")))
        {
            fail("failed CRL issuer test");
        }
    }

    public void checkCRLCreation2()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", BC);

        Date now = new Date();
        KeyPair pair = kpGen.generateKeyPair();
        X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(new X500Principal("CN=Test CA"), now);

        crlGen.setNextUpdate(new Date(now.getTime() + 100000));

        Vector extOids = new Vector();
        Vector extValues = new Vector();

        CRLReason crlReason = CRLReason.lookup(CRLReason.privilegeWithdrawn);

        try
        {
            extOids.addElement(Extension.reasonCode);
            extValues.addElement(new Extension(Extension.reasonCode, false, new DEROctetString(crlReason.getEncoded())));
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("error encoding reason: " + e);
        }

        Extensions entryExtensions = generateExtensions(extOids, extValues);

        crlGen.addCRLEntry(BigInteger.ONE, now, entryExtensions);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(pair.getPublic()));

        X509CRLHolder crlHolder = crlGen.build(new JcaContentSignerBuilder("SHA256withRSAEncryption").setProvider(BC).build(pair.getPrivate()));

        X509CRL crl = new JcaX509CRLConverter().setProvider(BC).getCRL(crlHolder);

        crl.verify(pair.getPublic(), BC);

        if (!crl.getIssuerX500Principal().equals(new X500Principal("CN=Test CA")))
        {
            fail("failed CRL issuer test");
        }

        byte[] authExt = crl.getExtensionValue(Extension.authorityKeyIdentifier.getId());

        if (authExt == null)
        {
            fail("failed to find CRL extension");
        }

        AuthorityKeyIdentifier authId = AuthorityKeyIdentifier.getInstance(ASN1OctetString.getInstance(authExt).getOctets());

        X509CRLEntry entry = crl.getRevokedCertificate(BigInteger.ONE);

        if (entry == null)
        {
            fail("failed to find CRL entry");
        }

        if (!entry.getSerialNumber().equals(BigInteger.ONE))
        {
            fail("CRL cert serial number does not match");
        }

        if (!entry.hasExtensions())
        {
            fail("CRL entry extension not found");
        }

        byte[] ext = entry.getExtensionValue(Extension.reasonCode.getId());

        if (ext != null)
        {
            ASN1Enumerated reasonCode = (ASN1Enumerated)fromExtensionValue(ext);

            if (reasonCode.intValueExact() != CRLReason.privilegeWithdrawn)
            {
                fail("CRL entry reasonCode wrong");
            }
        }
        else
        {
            fail("CRL entry reasonCode not found");
        }
    }

    public void checkCRLCreation3()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", BC);
        Date now = new Date();
        KeyPair pair = kpGen.generateKeyPair();
        X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(new X500Principal("CN=Test CA"), now);

        crlGen.setNextUpdate(new Date(now.getTime() + 100000));

        Vector extOids = new Vector();
        Vector extValues = new Vector();

        CRLReason crlReason = CRLReason.lookup(CRLReason.privilegeWithdrawn);

        try
        {
            extOids.addElement(Extension.reasonCode);
            extValues.addElement(new Extension(Extension.reasonCode, false, new DEROctetString(crlReason.getEncoded())));
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("error encoding reason: " + e);
        }

        Extensions entryExtensions = generateExtensions(extOids, extValues);

        crlGen.addCRLEntry(BigInteger.ONE, now, entryExtensions);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(pair.getPublic()));

        X509CRLHolder crlHolder = crlGen.build(new JcaContentSignerBuilder("SHA256withRSAEncryption").setProvider(BC).build(pair.getPrivate()));

        X509CRL crl = new JcaX509CRLConverter().setProvider(BC).getCRL(crlHolder);

        if (!crl.getIssuerX500Principal().equals(new X500Principal("CN=Test CA")))
        {
            fail("failed CRL issuer test");
        }

        byte[] authExt = crl.getExtensionValue(Extension.authorityKeyIdentifier.getId());

        if (authExt == null)
        {
            fail("failed to find CRL extension");
        }

        AuthorityKeyIdentifier authId = AuthorityKeyIdentifier.getInstance(ASN1OctetString.getInstance(authExt).getOctets());

        X509CRLEntry entry = crl.getRevokedCertificate(BigInteger.ONE);

        if (entry == null)
        {
            fail("failed to find CRL entry");
        }

        if (!entry.getSerialNumber().equals(BigInteger.ONE))
        {
            fail("CRL cert serial number does not match");
        }

        if (!entry.hasExtensions())
        {
            fail("CRL entry extension not found");
        }

        byte[] ext = entry.getExtensionValue(Extension.reasonCode.getId());

        if (ext != null)
        {
            ASN1Enumerated reasonCode = (ASN1Enumerated)fromExtensionValue(ext);

            if (reasonCode.intValueExact() != CRLReason.privilegeWithdrawn)
            {
                fail("CRL entry reasonCode wrong");
            }
        }
        else
        {
            fail("CRL entry reasonCode not found");
        }

        //
        // check loading of existing CRL
        //
        now = new Date();
        crlGen = new X509v2CRLBuilder(new X500Name("CN=Test CA"), now);

        crlGen.setNextUpdate(new Date(now.getTime() + 100000));

        crlGen.addCRL(new JcaX509CRLHolder(crl));

        crlGen.addCRLEntry(BigInteger.valueOf(2), now, entryExtensions);

        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(pair.getPublic()));

        crlHolder = crlGen.build(new JcaContentSignerBuilder("SHA256withRSAEncryption").setProvider(BC).build(pair.getPrivate()));

        int count = 0;
        boolean oneFound = false;
        boolean twoFound = false;

        Iterator it = crlHolder.getRevokedCertificates().iterator();
        while (it.hasNext())
        {
            X509CRLEntryHolder crlEnt = (X509CRLEntryHolder)it.next();

            if (crlEnt.getSerialNumber().intValue() == 1)
            {
                oneFound = true;
                Extension extn = crlEnt.getExtension(Extension.reasonCode);

                if (extn != null)
                {
                    ASN1Enumerated reasonCode = (ASN1Enumerated)ASN1Enumerated.getInstance(extn.getParsedValue());

                    if (reasonCode.intValueExact() != CRLReason.privilegeWithdrawn)
                    {
                        fail("CRL entry reasonCode wrong");
                    }
                }
                else
                {
                    fail("CRL entry reasonCode not found");
                }
            }
            else if (crlEnt.getSerialNumber().intValue() == 2)
            {
                twoFound = true;
            }

            count++;
        }

        if (count != 2)
        {
            fail("wrong number of CRLs found");
        }

        if (!oneFound || !twoFound)
        {
            fail("wrong CRLs found in copied list");
        }

        //
        // check factory read back
        //
        CertificateFactory cFact = CertificateFactory.getInstance("X.509", BC);

        X509CRL readCrl = (X509CRL)cFact.generateCRL(new ByteArrayInputStream(crlHolder.getEncoded()));

        readCrl.verify(pair.getPublic(), BC);

        if (readCrl == null)
        {
            fail("crl not returned!");
        }

        Collection col = cFact.generateCRLs(new ByteArrayInputStream(crlHolder.getEncoded()));

        if (col.size() != 1)
        {
            fail("wrong number of CRLs found in collection");
        }
    }

    public void checkCRLCreation4()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", BC);

        Date now = new Date();
        KeyPair pair = kpGen.generateKeyPair();
        X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(new X500Principal("CN=Test CA"), now);

        crlGen.setNextUpdate(new Date(now.getTime() + 100000));

        Vector extOids = new Vector();
        Vector extValues = new Vector();

        CRLReason crlReason = CRLReason.lookup(CRLReason.privilegeWithdrawn);

        try
        {
            extOids.addElement(Extension.reasonCode);
            extValues.addElement(new Extension(Extension.reasonCode, false, new DEROctetString(crlReason.getEncoded())));
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("error encoding reason: " + e);
        }

        Extensions entryExtensions = generateExtensions(extOids, extValues);

        crlGen.addCRLEntry(BigInteger.ONE, now, entryExtensions);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(pair.getPublic()));

        X509CRLHolder crlHolder = crlGen.build(new JcaContentSignerBuilder("SHA256withRSAandMGF1").setProvider(BC).build(pair.getPrivate()));

        X509CRL crl = new JcaX509CRLConverter().setProvider(BC).getCRL(crlHolder);

        crl.verify(pair.getPublic(), BC);

        if (!crl.getIssuerX500Principal().equals(new X500Principal("CN=Test CA")))
        {
            fail("failed CRL issuer test");
        }

        byte[] authExt = crl.getExtensionValue(Extension.authorityKeyIdentifier.getId());

        if (authExt == null)
        {
            fail("failed to find CRL extension");
        }

        AuthorityKeyIdentifier authId = AuthorityKeyIdentifier.getInstance(ASN1OctetString.getInstance(authExt).getOctets());

        X509CRLEntry entry = crl.getRevokedCertificate(BigInteger.ONE);

        if (entry == null)
        {
            fail("failed to find CRL entry");
        }

        if (!entry.getSerialNumber().equals(BigInteger.ONE))
        {
            fail("CRL cert serial number does not match");
        }

        if (!entry.hasExtensions())
        {
            fail("CRL entry extension not found");
        }

        byte[] ext = entry.getExtensionValue(Extension.reasonCode.getId());

        if (ext != null)
        {
            ASN1Enumerated reasonCode = (ASN1Enumerated)fromExtensionValue(ext);

            if (reasonCode.intValueExact() != CRLReason.privilegeWithdrawn)
            {
                fail("CRL entry reasonCode wrong");
            }
        }
        else
        {
            fail("CRL entry reasonCode not found");
        }
    }

    public void checkCRLCreation5()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", BC);

        Date now = new Date();
        KeyPair pair = kpGen.generateKeyPair();
        X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(new X500Principal("CN=Test CA"), now);

        crlGen.setNextUpdate(new Date(now.getTime() + 100000));

        Vector extOids = new Vector();
        Vector extValues = new Vector();

        CRLReason crlReason = CRLReason.lookup(CRLReason.privilegeWithdrawn);

        try
        {
            extOids.addElement(Extension.reasonCode);
            extValues.addElement(new Extension(Extension.reasonCode, false, new DEROctetString(crlReason.getEncoded())));
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("error encoding reason: " + e);
        }

        Extensions entryExtensions = generateExtensions(extOids, extValues);

        crlGen.addCRLEntry(BigInteger.ONE, now, entryExtensions);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(pair.getPublic()));

        ContentSigner signer = new JcaContentSignerBuilder(
            "RSAPSS",
            new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 20, 1))
            .setProvider(BC).build(pair.getPrivate());
        X509CRLHolder crlHolder = crlGen.build(signer);

        X509CRL crl = new JcaX509CRLConverter().setProvider(BC).getCRL(crlHolder);

        crl.verify(pair.getPublic(), BC);

        if (!crl.getIssuerX500Principal().equals(new X500Principal("CN=Test CA")))
        {
            fail("failed CRL issuer test");
        }

        byte[] authExt = crl.getExtensionValue(Extension.authorityKeyIdentifier.getId());

        if (authExt == null)
        {
            fail("failed to find CRL extension");
        }

        AuthorityKeyIdentifier authId = AuthorityKeyIdentifier.getInstance(ASN1OctetString.getInstance(authExt).getOctets());

        X509CRLEntry entry = crl.getRevokedCertificate(BigInteger.ONE);

        if (entry == null)
        {
            fail("failed to find CRL entry");
        }

        if (!entry.getSerialNumber().equals(BigInteger.ONE))
        {
            fail("CRL cert serial number does not match");
        }

        if (!entry.hasExtensions())
        {
            fail("CRL entry extension not found");
        }

        byte[] ext = entry.getExtensionValue(Extension.reasonCode.getId());

        if (ext != null)
        {
            ASN1Enumerated reasonCode = (ASN1Enumerated)fromExtensionValue(ext);

            if (reasonCode.intValueExact() != CRLReason.privilegeWithdrawn)
            {
                fail("CRL entry reasonCode wrong");
            }
        }
        else
        {
            fail("CRL entry reasonCode not found");
        }
    }

    public void checkCRLCompositeCreation()
        throws Exception
    {
        //
        // set up the keys
        //
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", "BC");

        ecKpg.initialize(new ECGenParameterSpec("P-256"));

        KeyPair ecKp = ecKpg.generateKeyPair();

        PrivateKey ecPriv = ecKp.getPrivate();
        PublicKey ecPub = ecKp.getPublic();

        KeyPairGenerator lmsKpg = KeyPairGenerator.getInstance("LMS", "BCPQC");

        lmsKpg.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1));

        KeyPair lmsKp = lmsKpg.generateKeyPair();

        PrivateKey lmsPriv = lmsKp.getPrivate();
        PublicKey lmsPub = lmsKp.getPublic();

        //
        // distinguished name table.
        //
        X500NameBuilder builder = createStdBuilder();

        //
        // create the certificate - version 3
        //
        CompositeAlgorithmSpec compAlgSpec = new CompositeAlgorithmSpec.Builder()
            .add("SHA256withECDSA")
            .add("LMS")
            .build();
        CompositePublicKey compPub = new CompositePublicKey(ecPub, lmsPub);
        CompositePrivateKey compPrivKey = new CompositePrivateKey(ecPriv, lmsPriv);

        ContentSigner sigGen = new JcaContentSignerBuilder("Composite", compAlgSpec).build(compPrivKey);

        Date now = new Date();

        X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(new X500Principal("CN=Test CA"), now);

        crlGen.setNextUpdate(new Date(now.getTime() + 100000));

        Vector extOids = new Vector();
        Vector extValues = new Vector();

        CRLReason crlReason = CRLReason.lookup(CRLReason.privilegeWithdrawn);

        try
        {
            extOids.addElement(Extension.reasonCode);
            extValues.addElement(new Extension(Extension.reasonCode, false, new DEROctetString(crlReason.getEncoded())));
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("error encoding reason: " + e);
        }

        Extensions entryExtensions = generateExtensions(extOids, extValues);

        crlGen.addCRLEntry(BigInteger.ONE, now, entryExtensions);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(ecKp.getPublic()));

        X509CRLHolder crlHolder = crlGen.build(sigGen);

        X509CRL crl = new JcaX509CRLConverter().setProvider(BC).getCRL(crlHolder);

        // comp test
        crl.verify(compPub);

        // null comp test
        try
        {
            crl.verify(new CompositePublicKey(null, null));
        }
        catch (InvalidKeyException e)
        {
            isTrue(e.getMessage().equals("no matching key found"));
        }
        
        // single key test
        crl.verify(ecPub, BC);

        if (!crl.getIssuerX500Principal().equals(new X500Principal("CN=Test CA")))
        {
            fail("failed CRL issuer test");
        }

        byte[] authExt = crl.getExtensionValue(Extension.authorityKeyIdentifier.getId());

        if (authExt == null)
        {
            fail("failed to find CRL extension");
        }

        AuthorityKeyIdentifier authId = AuthorityKeyIdentifier.getInstance(ASN1OctetString.getInstance(authExt).getOctets());

        X509CRLEntry entry = crl.getRevokedCertificate(BigInteger.ONE);

        if (entry == null)
        {
            fail("failed to find CRL entry");
        }

        if (!entry.getSerialNumber().equals(BigInteger.ONE))
        {
            fail("CRL cert serial number does not match");
        }

        if (!entry.hasExtensions())
        {
            fail("CRL entry extension not found");
        }

        byte[] ext = entry.getExtensionValue(Extension.reasonCode.getId());

        if (ext != null)
        {
            ASN1Enumerated reasonCode = (ASN1Enumerated)fromExtensionValue(ext);

            if (reasonCode.intValueExact() != CRLReason.privilegeWithdrawn)
            {
                fail("CRL entry reasonCode wrong");
            }
        }
        else
        {
            fail("CRL entry reasonCode not found");
        }

        sigGen = new JcaContentSignerBuilder("SHA256withECDSA", compAlgSpec).build(compPrivKey);

        crlHolder = crlGen.build(sigGen);

        crl = new JcaX509CRLConverter().setProvider(BC).getCRL(crlHolder);

        // comp test - single key
        crl.verify(compPub);
    }

    /*
     * we generate a self signed certificate for the sake of testing - GOST3410
     */
    public void checkCreation4()
        throws Exception
    {
        //
        // set up the keys
        //
        PrivateKey privKey;
        PublicKey pubKey;

        KeyPairGenerator g = KeyPairGenerator.getInstance("GOST3410", BC);
        GOST3410ParameterSpec gost3410P = new GOST3410ParameterSpec("GostR3410-94-CryptoPro-A");

        g.initialize(gost3410P, new SecureRandom());

        KeyPair p = g.generateKeyPair();

        privKey = p.getPrivate();
        pubKey = p.getPublic();

        //
        // distinguished name table.
        //
        X500NameBuilder builder = createStdBuilder();

        //
        // extensions
        //

        //
        // create the certificate - version 3
        //
        ContentSigner sigGen = new JcaContentSignerBuilder("GOST3411withGOST3410").setProvider(BC).build(privKey);
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        cert.checkValidity(new Date());

        //
        // check verifies in general
        //
        cert.verify(pubKey);

        //
        // check verifies with contained key
        //
        cert.verify(cert.getPublicKey());

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

        cert = (X509Certificate)fact.generateCertificate(bIn);

        //System.out.println(cert);

        //check getEncoded()
        byte[] bytes = cert.getEncoded();
    }

    public void checkCreation5()
        throws Exception
    {
        //
        // a sample key pair.
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
        SecureRandom rand = new SecureRandom();
        PrivateKey privKey;
        PublicKey pubKey;

        KeyFactory fact = KeyFactory.getInstance("RSA", BC);

        privKey = fact.generatePrivate(privKeySpec);
        pubKey = fact.generatePublic(pubKeySpec);

        //
        // distinguished name table.
        //
        Vector ord = new Vector();
        Vector values = new Vector();

        X500NameBuilder builder = createStdBuilder();

        //
        // create base certificate - version 3
        //
        ContentSigner sigGen = new JcaContentSignerBuilder("MD5WithRSAEncryption").setProvider(BC).build(privKey);
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey)
            .addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true,
                new X509KeyUsage(X509KeyUsage.encipherOnly))
            .addExtension(new ASN1ObjectIdentifier("2.5.29.37"), true,
                new DERSequence(KeyPurposeId.anyExtendedKeyUsage))
            .addExtension(new ASN1ObjectIdentifier("2.5.29.17"), true,
                new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test")));

        X509Certificate baseCert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        //
        // copy certificate
        //

        certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey)
            .copyAndAddExtension(new ASN1ObjectIdentifier("2.5.29.15"), true, baseCert)
            .copyAndAddExtension(new ASN1ObjectIdentifier("2.5.29.37"), false, baseCert);

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        cert.checkValidity(new Date());

        cert.verify(pubKey);

        if (!areEqual(baseCert.getExtensionValue("2.5.29.15"), cert.getExtensionValue("2.5.29.15")))
        {
            fail("2.5.29.15 differs");
        }

        if (!areEqual(baseCert.getExtensionValue("2.5.29.37"), cert.getExtensionValue("2.5.29.37")))
        {
            fail("2.5.29.37 differs");
        }

        //
        // exception test
        //

        try
        {
            certGen.copyAndAddExtension(new ASN1ObjectIdentifier("2.5.99.99"), true, new JcaX509CertificateHolder(baseCert));

            fail("exception not thrown on dud extension copy");
        }
        catch (NullPointerException e)
        {
            // expected
        }
    }

    public void checkCreation6()
        throws Exception
    {
        if (Security.getProvider("BCPQC") == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SPHINCS256", "BCPQC");

        kpGen.initialize(new SPHINCS256KeyGenParameterSpec(), new SecureRandom());

        KeyPair kp = kpGen.generateKeyPair();

        PrivateKey privKey = kp.getPrivate();
        PublicKey pubKey = kp.getPublic();

        //
        // distinguished name table.
        //
        X500NameBuilder builder = createStdBuilder();

        //
        // create base certificate - version 3
        //
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA512withSPHINCS256").setProvider("BCPQC").build(privKey);
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey)
            .addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true,
                new X509KeyUsage(X509KeyUsage.encipherOnly))
            .addExtension(new ASN1ObjectIdentifier("2.5.29.37"), true,
                new DERSequence(KeyPurposeId.anyExtendedKeyUsage))
            .addExtension(new ASN1ObjectIdentifier("2.5.29.17"), true,
                new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test")));

        X509Certificate baseCert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        isTrue("oid wrong", BCObjectIdentifiers.sphincs256_with_SHA512.getId().equals(baseCert.getSigAlgOID()));
        isTrue("params wrong", null == baseCert.getSigAlgParams());

        //
        // copy certificate
        //

        certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey)
            .copyAndAddExtension(new ASN1ObjectIdentifier("2.5.29.15"), true, baseCert)
            .copyAndAddExtension(new ASN1ObjectIdentifier("2.5.29.37"), false, baseCert);

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        cert.checkValidity(new Date());

        cert.verify(cert.getPublicKey());

        // check encoded works
        cert.getEncoded();

        if (!areEqual(baseCert.getExtensionValue("2.5.29.15"), cert.getExtensionValue("2.5.29.15")))
        {
            fail("2.5.29.15 differs");
        }

        if (!areEqual(baseCert.getExtensionValue("2.5.29.37"), cert.getExtensionValue("2.5.29.37")))
        {
            fail("2.5.29.37 differs");
        }

        //
        // exception test
        //

        try
        {
            certGen.copyAndAddExtension(new ASN1ObjectIdentifier("2.5.99.99"), true, new JcaX509CertificateHolder(baseCert));

            fail("exception not thrown on dud extension copy");
        }
        catch (NullPointerException e)
        {
            // expected
        }

        // certificate with NewHope key
        kpGen = KeyPairGenerator.getInstance("NH", "BCPQC");

        kpGen.initialize(1024, new SecureRandom());

        KeyPair nhKp = kpGen.generateKeyPair();

        certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), nhKp.getPublic())
            .copyAndAddExtension(new ASN1ObjectIdentifier("2.5.29.15"), true, baseCert)
            .copyAndAddExtension(new ASN1ObjectIdentifier("2.5.29.37"), false, baseCert);

        cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        cert.checkValidity(new Date());

        cert.verify(pubKey);

        isTrue(nhKp.getPublic().equals(cert.getPublicKey()));

        // check encoded works
        cert.getEncoded();
    }

    /*
     * we generate a self signed certificate for the sake of testing - ECGOST3410-2012
     */
    public void checkCreation7()
        throws Exception
    {
        //
        // set up the keys
        //
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECGOST3410-2012", BC);

        g.initialize(new ECNamedCurveGenParameterSpec("Tc26-Gost-3410-12-512-paramSetA"), new SecureRandom());

        KeyPair p = g.generateKeyPair();

        PrivateKey privKey = p.getPrivate();
        PublicKey pubKey = p.getPublic();

        //
        // distinguished name table.
        //
        X500NameBuilder builder = createStdBuilder();

        //
        // create the certificate - version 3
        //
        ContentSigner sigGen = new JcaContentSignerBuilder("GOST3411-2012-512WITHECGOST3410-2012-512").setProvider(BC).build(privKey);
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        cert.checkValidity(new Date());

        //
        // check verifies in general
        //
        cert.verify(pubKey);

        //
        // check verifies with contained key
        //
        cert.verify(cert.getPublicKey());

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

        cert = (X509Certificate)fact.generateCertificate(bIn);

        //System.out.println(cert);
    }

    /*
     * we generate a self signed certificate for the sake of testing - XMSS
     */
    public void checkCreation8()
        throws Exception
    {
        //
        // set up the keys
        //
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");

        kpg.initialize(new XMSSParameterSpec(10, XMSSParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        PrivateKey privKey = kp.getPrivate();
        PublicKey pubKey = kp.getPublic();

        //
        // distinguished name table.
        //
        X500NameBuilder builder = createStdBuilder();

        //
        // create the certificate - version 3
        //
        ContentSigner sigGen = new JcaContentSignerBuilder("XMSS").setProvider("BCPQC").build(privKey);
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(((XMSSPrivateKey)privKey).getIndex()), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        cert.checkValidity(new Date());

        //
        // check verifies in general
        //
        cert.verify(pubKey);

        //
        // check verifies with contained key
        //
        cert.verify(cert.getPublicKey());

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

        cert = (X509Certificate)fact.generateCertificate(bIn);

        //System.out.println(cert);
    }

    /*
     * we generate a self signed certificate for the sake of testing - XMSS^MT
     */
    public void checkCreation9()
        throws Exception
    {
        //
        // set up the keys
        //
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(20, 4, XMSSMTParameterSpec.SHAKE256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        PrivateKey privKey = kp.getPrivate();
        PublicKey pubKey = kp.getPublic();

        //
        // distinguished name table.
        //
        X500NameBuilder builder = createStdBuilder();

        //
        // create the certificate - version 3
        //
        ContentSigner sigGen = new JcaContentSignerBuilder("XMSSMT").setProvider("BCPQC").build(privKey);
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        cert.checkValidity(new Date());

        //
        // check verifies in general
        //
        cert.verify(pubKey);

        //
        // check verifies with contained key
        //
        cert.verify(cert.getPublicKey());

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

        cert = (X509Certificate)fact.generateCertificate(bIn);

        //System.out.println(cert);
    }

    /*
     * we generate a self signed certificate for the sake of testing - LMS
     */
    public void checkCreation10()
        throws Exception
    {
        //
        // set up the keys
        //
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("LMS", "BCPQC");

        kpg.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1));

        KeyPair kp = kpg.generateKeyPair();

        PrivateKey privKey = kp.getPrivate();
        PublicKey pubKey = kp.getPublic();

        //
        // distinguished name table.
        //
        X500NameBuilder builder = createStdBuilder();

        //
        // create the certificate - version 3
        //
        ContentSigner sigGen = new JcaContentSignerBuilder("LMS").setProvider("BCPQC").build(privKey);
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        cert.checkValidity(new Date());

        //
        // check verifies in general
        //
        cert.verify(pubKey);

        //
        // check verifies with contained key
        //
        cert.verify(cert.getPublicKey());

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

        cert = (X509Certificate)fact.generateCertificate(bIn);

        //System.out.println(cert);
    }

    /*
     * we generate a self signed certificate for the sake of testing - qTESLA
     */
    public void checkCreationQTESLA()
        throws Exception
    {
        //
        // set up the keys
        //
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("qTESLA", "BCPQC");

        kpg.initialize(new QTESLAParameterSpec(QTESLAParameterSpec.PROVABLY_SECURE_I), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        PrivateKey privKey = kp.getPrivate();
        PublicKey pubKey = kp.getPublic();

        //
        // distinguished name table.
        //
        X500NameBuilder builder = createStdBuilder();

        //
        // create the certificate - version 3
        //
        ContentSigner sigGen = new JcaContentSignerBuilder(pubKey.getAlgorithm()).setProvider("BCPQC").build(privKey);
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        cert.checkValidity(new Date());

        //
        // check verifies in general
        //
        cert.verify(pubKey);

        //
        // check verifies with contained key
        //
        cert.verify(cert.getPublicKey());

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

        cert = (X509Certificate)fact.generateCertificate(bIn);

        //System.out.println(cert);
    }

    /*
     * we generate a self signed certificate across the range of DSA algorithms
     */
    public void checkCreationDSA()
        throws Exception
    {
        //
        // set up the keys
        //
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", BC);

        kpg.initialize(new DSAParameterSpec(def2048Params.getP(), def2048Params.getQ(), def2048Params.getG()), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        PrivateKey privKey = kp.getPrivate();
        PublicKey pubKey = kp.getPublic();

        String[] algs = new String[]
            {
                "SHA1WITHDSA",
                "DSAWITHSHA1",
                "SHA224WITHDSA",
                "SHA256WITHDSA",
                "SHA384WITHDSA",
                "SHA512WITHDSA",
                "SHA3-224WITHDSA",
                "SHA3-256WITHDSA",
                "SHA3-384WITHDSA",
                "SHA3-512WITHDSA"
            };

        ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[]
            {
                X9ObjectIdentifiers.id_dsa_with_sha1,
                X9ObjectIdentifiers.id_dsa_with_sha1,
                NISTObjectIdentifiers.dsa_with_sha224,
                NISTObjectIdentifiers.dsa_with_sha256,
                NISTObjectIdentifiers.dsa_with_sha384,
                NISTObjectIdentifiers.dsa_with_sha512,
                NISTObjectIdentifiers.id_dsa_with_sha3_224,
                NISTObjectIdentifiers.id_dsa_with_sha3_256,
                NISTObjectIdentifiers.id_dsa_with_sha3_384,
                NISTObjectIdentifiers.id_dsa_with_sha3_512
            };

        doGenSelfSignedCert(privKey, pubKey, algs, oids);
    }

    /*
     * we generate a self signed certificate across the range of RSA algorithms
     */
    public void checkCreationRSA()
        throws Exception
    {
        //
        // set up the keys
        //
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BC);

        kpg.initialize(2048, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        PrivateKey privKey = kp.getPrivate();
        PublicKey pubKey = kp.getPublic();

        String[] algs = new String[]
            {
                "SHA1WITHRSA",
                "SHA1WITHRSAENCRYPTION",
                "SHA224WITHRSA",
                "SHA224WITHRSAENCRYPTION",
                "SHA256WITHRSA",
                "SHA256WITHRSAENCRYPTION",
                "SHA384WITHRSA",
                "SHA384WITHRSAENCRYPTION",
                "SHA512WITHRSA",
                "SHA512WITHRSAENCRYPTION",
                "SHA3-224WITHRSA",
                "SHA3-224WITHRSAENCRYPTION",
                "SHA3-256WITHRSA",
                "SHA3-256WITHRSAENCRYPTION",
                "SHA3-384WITHRSA",
                "SHA3-384WITHRSAENCRYPTION",
                "SHA3-512WITHRSA",
                "SHA3-512WITHRSAENCRYPTION",
                "SHA1WITHRSAANDMGF1",
                "SHA224WITHRSAANDMGF1",
                "SHA256WITHRSAANDMGF1",
                "SHA384WITHRSAANDMGF1",
                "SHA512WITHRSAANDMGF1",
                "SHA3-224WITHRSAANDMGF1",
                "SHA3-256WITHRSAANDMGF1",
                "SHA3-384WITHRSAANDMGF1",
                "SHA3-512WITHRSAANDMGF1",
            };

        ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[]
            {
                PKCSObjectIdentifiers.sha1WithRSAEncryption,
                PKCSObjectIdentifiers.sha1WithRSAEncryption,
                PKCSObjectIdentifiers.sha224WithRSAEncryption,
                PKCSObjectIdentifiers.sha224WithRSAEncryption,
                PKCSObjectIdentifiers.sha256WithRSAEncryption,
                PKCSObjectIdentifiers.sha256WithRSAEncryption,
                PKCSObjectIdentifiers.sha384WithRSAEncryption,
                PKCSObjectIdentifiers.sha384WithRSAEncryption,
                PKCSObjectIdentifiers.sha512WithRSAEncryption,
                PKCSObjectIdentifiers.sha512WithRSAEncryption,
                NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224,
                NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224,
                NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256,
                NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256,
                NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384,
                NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384,
                NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512,
                NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512,
                PKCSObjectIdentifiers.id_RSASSA_PSS,
                PKCSObjectIdentifiers.id_RSASSA_PSS,
                PKCSObjectIdentifiers.id_RSASSA_PSS,
                PKCSObjectIdentifiers.id_RSASSA_PSS,
                PKCSObjectIdentifiers.id_RSASSA_PSS,
                PKCSObjectIdentifiers.id_RSASSA_PSS,
                PKCSObjectIdentifiers.id_RSASSA_PSS,
                PKCSObjectIdentifiers.id_RSASSA_PSS,
                PKCSObjectIdentifiers.id_RSASSA_PSS
            };

        doGenSelfSignedCert(privKey, pubKey, algs, oids);

        X500NameBuilder builder = createStdBuilder();

        //
        // create the certificate - version 3
        //
        ContentSigner sigGen = new JcaContentSignerBuilder("RSAPSS",
            new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 20, 1))
            .setProvider(BC).build(privKey);
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        cert.checkValidity(new Date());

        //
        // check verifies in general
        //
        cert.verify(pubKey);

        //
        // check verifies with contained key
        //
        cert.verify(cert.getPublicKey());

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

        cert = (X509Certificate)fact.generateCertificate(bIn);

        //System.out.println(cert);
    }

    public void checkCreationRSAPSS()
        throws Exception
    {
        //
        // set up the keys
        //
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSASSA-PSS", "BC");

        KeyPair kp = kpg.generateKeyPair();

        PrivateKey privKey = kp.getPrivate();
        PublicKey pubKey = kp.getPublic();

        //
        // distinguished name table.
        //
        X500NameBuilder builder = createStdBuilder();

        //
        // create the certificate - version 3
        //
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256withRSAandMGF1").setProvider("BC").build(privKey);
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        cert.checkValidity(new Date());

        //
        // check verifies in general
        //
        cert.verify(pubKey);

        //
        // check verifies with contained key
        //
        cert.verify(cert.getPublicKey());

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

        cert = (X509Certificate)fact.generateCertificate(bIn);

        org.bouncycastle.asn1.x509.Certificate crt = org.bouncycastle.asn1.x509.Certificate.getInstance(cert.getEncoded());

        isTrue(PKCSObjectIdentifiers.id_RSASSA_PSS.equals(crt.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm()));
        isTrue(null == crt.getSubjectPublicKeyInfo().getAlgorithm().getParameters());
    }

    /*
     * we generate a self signed certificate across the range of ECDSA algorithms
     */
    public void checkCreationECDSA()
        throws Exception
    {
        //
        // set up the keys
        //
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BC);

        kpg.initialize(256, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        PrivateKey privKey = kp.getPrivate();
        PublicKey pubKey = kp.getPublic();

        //
        // distinguished name table.
        //
        X500NameBuilder builder = createStdBuilder();

        String[] algs = new String[]
            {
                "SHA1WITHECDSA",
                "ECDSAWITHSHA1",
                "SHA224WITHECDSA",
                "SHA256WITHECDSA",
                "SHA384WITHECDSA",
                "SHA512WITHECDSA",
                "SHA3-224WITHECDSA",
                "SHA3-256WITHECDSA",
                "SHA3-384WITHECDSA",
                "SHA3-512WITHECDSA"
            };

        ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[]
            {
                X9ObjectIdentifiers.ecdsa_with_SHA1,
                X9ObjectIdentifiers.ecdsa_with_SHA1,
                X9ObjectIdentifiers.ecdsa_with_SHA224,
                X9ObjectIdentifiers.ecdsa_with_SHA256,
                X9ObjectIdentifiers.ecdsa_with_SHA384,
                X9ObjectIdentifiers.ecdsa_with_SHA512,
                NISTObjectIdentifiers.id_ecdsa_with_sha3_224,
                NISTObjectIdentifiers.id_ecdsa_with_sha3_256,
                NISTObjectIdentifiers.id_ecdsa_with_sha3_384,
                NISTObjectIdentifiers.id_ecdsa_with_sha3_512
            };

        doGenSelfSignedCert(privKey, pubKey, algs, oids);
    }

    public void checkCreationComposite()
        throws Exception
    {
        //
        // set up the keys
        //
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", "BC");

        ecKpg.initialize(new ECGenParameterSpec("P-256"));

        KeyPair ecKp = ecKpg.generateKeyPair();

        PrivateKey ecPriv = ecKp.getPrivate();
        PublicKey ecPub = ecKp.getPublic();

        KeyPairGenerator lmsKpg = KeyPairGenerator.getInstance("LMS", "BCPQC");

        lmsKpg.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1));

        KeyPair lmsKp = lmsKpg.generateKeyPair();

        PrivateKey lmsPriv = lmsKp.getPrivate();
        PublicKey lmsPub = lmsKp.getPublic();

        //
        // distinguished name table.
        //
        X500NameBuilder builder = createStdBuilder();

        X500Name issuer = builder.build();

        //
        // create the certificate - version 3
        //
        CompositeAlgorithmSpec compAlgSpec = new CompositeAlgorithmSpec.Builder()
            .add("SHA256withECDSA")
            .add("LMS")
            .build();
        CompositePublicKey compPub = new CompositePublicKey(ecPub, lmsPub);
        CompositePrivateKey compPrivKey = new CompositePrivateKey(ecPriv, lmsPriv);

        ContentSigner sigGen = new JcaContentSignerBuilder("Composite", compAlgSpec).build(compPrivKey);

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
            issuer,
            BigInteger.valueOf(1),
            new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), issuer,
            compPub);

        X509CertificateHolder certHldr = certGen.build(sigGen);

        ContentVerifierProvider vProv = new JcaContentVerifierProviderBuilder()
            .build(compPub);

        isTrue("multi failed", certHldr.isSignatureValid(vProv));

        vProv = new JcaContentVerifierProviderBuilder()
            .build(new CompositePublicKey(ecPub, null));

        isTrue("multi failed with null", certHldr.isSignatureValid(vProv));


        try
        {
            vProv = new JcaContentVerifierProviderBuilder()
                .build(new CompositePublicKey(null, null));

            certHldr.isSignatureValid(vProv);
        }
        catch (CertException e)
        {
            isTrue(e.getCause().getMessage().equals("no matching signature found in composite"));
        }

        vProv = new JcaContentVerifierProviderBuilder().build(ecPub);

        isTrue("ec failed", certHldr.isSignatureValid(vProv));

        vProv = new JcaContentVerifierProviderBuilder().build(lmsPub);

        isTrue("lms failed", certHldr.isSignatureValid(vProv));

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certHldr);

        cert.checkValidity(new Date());

        //
        // check verifies in general
        //
        cert.verify(compPub);

        // null comp test
        try
        {
            cert.verify(new CompositePublicKey(null, null));
        }
        catch (InvalidKeyException e)
        {
            isTrue(e.getMessage(), e.getMessage().equals("no matching key found"));
        }

        cert.verify(ecPub);      // ec key only

        cert.verify(lmsPub);     // lms key only

        cert.verify(ecPub, "BC");      // ec key only

        cert.verify(lmsPub, "BCPQC");     // lms key only

        cert.verify(ecPub, new BouncyCastleProvider());      // ec key only

        cert.verify(lmsPub, new BouncyCastlePQCProvider());     // lms key only

        //
        // check verifies with contained key
        //
        cert.verify(cert.getPublicKey());

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

        cert = (X509Certificate)fact.generateCertificate(bIn);

        org.bouncycastle.asn1.x509.Certificate crt = org.bouncycastle.asn1.x509.Certificate.getInstance(cert.getEncoded());

        isTrue(MiscObjectIdentifiers.id_alg_composite.equals(crt.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm()));
        isTrue(null == crt.getSubjectPublicKeyInfo().getAlgorithm().getParameters());

        KeyFactory kFact = KeyFactory.getInstance("Composite", "BC");

        CompositePublicKey pubKey = (CompositePublicKey)kFact.generatePublic(new X509EncodedKeySpec(compPub.getEncoded()));
        CompositePrivateKey privKey = (CompositePrivateKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(compPrivKey.getEncoded()));

        isTrue(pubKey.equals(compPub));
        isTrue(privKey.equals(compPrivKey));
    }

    private void checkCompositeCertificateVerify()
        throws Exception
    {
        //
        // set up the keys
        //
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", "BC");

        ecKpg.initialize(new ECGenParameterSpec("P-256"));

        KeyPair ecKp = ecKpg.generateKeyPair();

        PrivateKey ecPriv = ecKp.getPrivate();
        PublicKey ecPub = ecKp.getPublic();

        KeyPairGenerator lmsKpg = KeyPairGenerator.getInstance("LMS", "BCPQC");

        lmsKpg.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1));

        KeyPair lmsKp = lmsKpg.generateKeyPair();

        PrivateKey lmsPriv = lmsKp.getPrivate();
        PublicKey lmsPub = lmsKp.getPublic();

        //
        // distinguished name table.
        //
        X500NameBuilder builder = createStdBuilder();

        X500Name issuer = builder.build();

        //
        // create the certificate - version 3
        //
        CompositeAlgorithmSpec compAlgSpec = new CompositeAlgorithmSpec.Builder()
            .add("SHA256withECDSA")
            .add("LMS")
            .build();
        CompositePublicKey compPub = new CompositePublicKey(ecPub, lmsPub);
        CompositePrivateKey compPrivKey = new CompositePrivateKey(ecPriv, lmsPriv);

        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256withECDSA").build(ecPriv);

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
            issuer,
            BigInteger.valueOf(1),
            new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), issuer,
            compPub);

        X509CertificateHolder ecCertHldr = certGen.build(sigGen);

        ContentVerifierProvider vProv = new JcaContentVerifierProviderBuilder()
            .build(compPub);

        isTrue("ec multi failed", ecCertHldr.isSignatureValid(vProv));

        vProv = new JcaContentVerifierProviderBuilder().build(ecPub);

        isTrue("ec failed", ecCertHldr.isSignatureValid(vProv));

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(ecCertHldr);

        cert.checkValidity(new Date());

        //
        // check verifies in general
        //
        cert.verify(compPub);

        cert.verify(ecPub);      // ec key only

        cert.verify(ecPub, "BC");      // ec key only

        cert.verify(ecPub, new BouncyCastleProvider());      // ec key only

        //
        // check verifies with contained key
        //
        cert.verify(cert.getPublicKey());

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

        cert = (X509Certificate)fact.generateCertificate(bIn);

        org.bouncycastle.asn1.x509.Certificate crt = org.bouncycastle.asn1.x509.Certificate.getInstance(cert.getEncoded());

        isTrue(MiscObjectIdentifiers.id_alg_composite.equals(crt.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm()));
        isTrue(null == crt.getSubjectPublicKeyInfo().getAlgorithm().getParameters());

        KeyFactory kFact = KeyFactory.getInstance("Composite", "BC");

        CompositePublicKey pubKey = (CompositePublicKey)kFact.generatePublic(new X509EncodedKeySpec(compPub.getEncoded()));
        CompositePrivateKey privKey = (CompositePrivateKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(compPrivKey.getEncoded()));

        isTrue(pubKey.equals(compPub));
        isTrue(privKey.equals(compPrivKey));
    }

    private void doGenSelfSignedCert(PrivateKey privKey, PublicKey pubKey, String[] algs, ASN1ObjectIdentifier[] oids)
        throws Exception
    {
        X500NameBuilder builder = createStdBuilder();

        for (int i = 0; i != algs.length; i++)
        {
            //
            // create the certificate - version 3
            //
            ContentSigner sigGen = new JcaContentSignerBuilder(algs[i]).setProvider(BC).build(privKey);
            X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);

            isEquals("oid mismatch", sigGen.getAlgorithmIdentifier().getAlgorithm(), oids[i]);

            X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

            cert.checkValidity(new Date());

            //
            // check verifies in general
            //
            cert.verify(pubKey);

            //
            // check verifies with contained key
            //
            cert.verify(cert.getPublicKey());

            ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
            CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

            cert = (X509Certificate)fact.generateCertificate(bIn);
//            System.out.println(cert);
        }
    }

    private void testForgedSignature()
        throws Exception
    {
        String cert = "MIIBsDCCAVoCAQYwDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCQVUxEzARBgNV"
            + "BAgTClF1ZWVuc2xhbmQxGjAYBgNVBAoTEUNyeXB0U29mdCBQdHkgTHRkMSMwIQYD"
            + "VQQDExpTZXJ2ZXIgdGVzdCBjZXJ0ICg1MTIgYml0KTAeFw0wNjA5MTEyMzU4NTVa"
            + "Fw0wNjEwMTEyMzU4NTVaMGMxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpRdWVlbnNs"
            + "YW5kMRowGAYDVQQKExFDcnlwdFNvZnQgUHR5IEx0ZDEjMCEGA1UEAxMaU2VydmVy"
            + "IHRlc3QgY2VydCAoNTEyIGJpdCkwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAn7PD"
            + "hCeV/xIxUg8V70YRxK2A5jZbD92A12GN4PxyRQk0/lVmRUNMaJdq/qigpd9feP/u"
            + "12S4PwTLb/8q/v657QIDAQABMA0GCSqGSIb3DQEBBQUAA0EAbynCRIlUQgaqyNgU"
            + "DF6P14yRKUtX8akOP2TwStaSiVf/akYqfLFm3UGka5XbPj4rifrZ0/sOoZEEBvHQ"
            + "e20sRA==";

        CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);

        X509Certificate x509 = (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(Base64.decode(cert)));
        try
        {
            x509.verify(x509.getPublicKey());

            fail("forged RSA signature passed");
        }
        catch (Exception e)
        {
            // expected
        }
    }


    private void pemTest()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", BC);

        Certificate cert = readPEMCert(cf, PEMData.CERTIFICATE_1);
        if (cert == null)
        {
            fail("PEM cert not read");
        }
        cert = readPEMCert(cf, "-----BEGIN CERTIFICATE-----" + PEMData.CERTIFICATE_2);
        if (cert == null)
        {
            fail("PEM cert with extraneous header not read");
        }
        CRL crl = cf.generateCRL(new ByteArrayInputStream(PEMData.CRL_1.getBytes("US-ASCII")));
        if (crl == null)
        {
            fail("PEM crl not read");
        }
        Collection col = cf.generateCertificates(new ByteArrayInputStream(PEMData.CERTIFICATE_2.getBytes("US-ASCII")));
        if (col.size() != 1 || !col.contains(cert))
        {
            fail("PEM cert collection not right");
        }
        col = cf.generateCRLs(new ByteArrayInputStream(PEMData.CRL_2.getBytes("US-ASCII")));
        if (col.size() != 1 || !col.contains(crl))
        {
            fail("PEM crl collection not right");
        }
    }

    private static Certificate readPEMCert(CertificateFactory cf, String pemData)
        throws CertificateException, UnsupportedEncodingException
    {
        return cf.generateCertificate(new ByteArrayInputStream(pemData.getBytes("US-ASCII")));
    }

    private void pkcs7Test()
        throws Exception
    {
        /*
        ASN1EncodableVector certs = new ASN1EncodableVector();

        certs.add(new ASN1InputStream(CertPathTest.rootCertBin).readObject());
        certs.add(new DERTaggedObject(false, 2, new ASN1InputStream(AttrCertTest.attrCert).readObject()));

        ASN1EncodableVector crls = new ASN1EncodableVector();

        crls.add(new ASN1InputStream(CertPathTest.rootCrlBin).readObject());
        SignedData sigData = new SignedData(new DERSet(), new ContentInfo(CMSObjectIdentifiers.data, null), new DERSet(certs), new DERSet(crls), new DERSet());

        ContentInfo info = new ContentInfo(CMSObjectIdentifiers.signedData, sigData);

        CertificateFactory cf = CertificateFactory.getInstance("X.509", BC);

        X509Certificate cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(info.getEncoded()));
        if (cert == null || !areEqual(cert.getEncoded(), certs.get(0).getDERObject().getEncoded()))
        {
            fail("PKCS7 cert not read");
        }
        X509CRL crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(info.getEncoded()));
        if (crl == null || !areEqual(crl.getEncoded(), crls.get(0).getDERObject().getEncoded()))
        {
            fail("PKCS7 crl not read");
        }
        Collection col = cf.generateCertificates(new ByteArrayInputStream(info.getEncoded()));
        if (col.size() != 1 || !col.contains(cert))
        {
            fail("PKCS7 cert collection not right");
        }
        col = cf.generateCRLs(new ByteArrayInputStream(info.getEncoded()));
        if (col.size() != 1 || !col.contains(crl))
        {
            fail("PKCS7 crl collection not right");
        }

        // data with no certificates or CRLs

        sigData = new SignedData(new DERSet(), new ContentInfo(CMSObjectIdentifiers.data, null), new DERSet(), new DERSet(), new DERSet());

        info = new ContentInfo(CMSObjectIdentifiers.signedData, sigData);

        cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(info.getEncoded()));
        if (cert != null)
        {
            fail("PKCS7 cert present");
        }
        crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(info.getEncoded()));
        if (crl != null)
        {
            fail("PKCS7 crl present");
        }

        // data with absent certificates and CRLS

        sigData = new SignedData(new DERSet(), new ContentInfo(CMSObjectIdentifiers.data, null), null, null, new DERSet());

        info = new ContentInfo(CMSObjectIdentifiers.signedData, sigData);

        cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(info.getEncoded()));
        if (cert != null)
        {
            fail("PKCS7 cert present");
        }
        crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(info.getEncoded()));
        if (crl != null)
        {
            fail("PKCS7 crl present");
        }

        //
        // sample message
        //
        InputStream in = new ByteArrayInputStream(pkcs7CrlProblem);
        Collection certCol = cf.generateCertificates(in);
        Collection crlCol = cf.generateCRLs(in);

        if (crlCol.size() != 0)
        {
            fail("wrong number of CRLs: " + crlCol.size());
        }

        if (certCol.size() != 4)
        {
            fail("wrong number of Certs: " + certCol.size());
        }
        */
    }

    private void createPSSCert(String algorithm)
        throws Exception
    {
        KeyPair pair = generateLongFixedKeys();

        PrivateKey privKey = pair.getPrivate();
        PublicKey pubKey = pair.getPublic();

        //
        // distinguished name table.
        //

        X500NameBuilder builder = createStdBuilder();

        //
        // create base certificate - version 3
        //
        ContentSigner sigGen = new JcaContentSignerBuilder(algorithm).setProvider(BC).build(privKey);
        JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1),
            new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);

        certGen.addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true,
            new X509KeyUsage(X509KeyUsage.encipherOnly));
        certGen.addExtension(new ASN1ObjectIdentifier("2.5.29.37"), true,
            new DERSequence(KeyPurposeId.anyExtendedKeyUsage));
        certGen.addExtension(new ASN1ObjectIdentifier("2.5.29.17"), true,
            new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test")));

        X509Certificate baseCert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        baseCert.verify(pubKey);

        certGen = new JcaX509v3CertificateBuilder(baseCert);

        baseCert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        baseCert.verify(pubKey);
    }

    private KeyPair generateLongFixedKeys()
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException
    {
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
            new BigInteger("a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137", 16),
            new BigInteger("010001", 16));

        RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(
            new BigInteger("a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137", 16),
            new BigInteger("010001", 16),
            new BigInteger("33a5042a90b27d4f5451ca9bbbd0b44771a101af884340aef9885f2a4bbe92e894a724ac3c568c8f97853ad07c0266c8c6a3ca0929f1e8f11231884429fc4d9ae55fee896a10ce707c3ed7e734e44727a39574501a532683109c2abacaba283c31b4bd2f53c3ee37e352cee34f9e503bd80c0622ad79c6dcee883547c6a3b325", 16),
            new BigInteger("e7e8942720a877517273a356053ea2a1bc0c94aa72d55c6e86296b2dfc967948c0a72cbccca7eacb35706e09a1df55a1535bd9b3cc34160b3b6dcd3eda8e6443", 16),
            new BigInteger("b69dca1cf7d4d7ec81e75b90fcca874abcde123fd2700180aa90479b6e48de8d67ed24f9f19d85ba275874f542cd20dc723e6963364a1f9425452b269a6799fd", 16),
            new BigInteger("28fa13938655be1f8a159cbaca5a72ea190c30089e19cd274a556f36c4f6e19f554b34c077790427bbdd8dd3ede2448328f385d81b30e8e43b2fffa027861979", 16),
            new BigInteger("1a8b38f398fa712049898d7fb79ee0a77668791299cdfa09efc0e507acb21ed74301ef5bfd48be455eaeb6e1678255827580a8e4e8e14151d1510a82a3f2e729", 16),
            new BigInteger("27156aba4126d24a81f3a528cbfb27f56886f840a9f6e86e17a44b94fe9319584b8e22fdde1e5a2e3bd8aa5ba8d8584194eb2190acf832b847f13a3d24a79f4d", 16));

        KeyFactory fact = KeyFactory.getInstance("RSA", BC);

        return new KeyPair(fact.generatePublic(pubKeySpec), fact.generatePrivate(privKeySpec));
    }

    private void rfc4491Test()
        throws Exception
    {
        CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);

        X509Certificate x509 = (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(gostRFC4491_94));

        x509.verify(x509.getPublicKey(), BC);

        x509 = (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(gostRFC4491_2001));

        x509.verify(x509.getPublicKey(), BC);
    }

    private void testNullDerNullCert()
        throws Exception
    {
        KeyPair pair = generateLongFixedKeys();
        PublicKey pubKey = pair.getPublic();
        PrivateKey privKey = pair.getPrivate();

        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BC).build(privKey);
        JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(new X500Name("CN=Test"), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), new X500Name("CN=Test"), pubKey);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        org.bouncycastle.asn1.x509.Certificate struct = org.bouncycastle.asn1.x509.Certificate.getInstance(ASN1Primitive.fromByteArray(cert.getEncoded()));

        ASN1Encodable tbsCertificate = struct.getTBSCertificate();
        AlgorithmIdentifier sig = struct.getSignatureAlgorithm();

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(tbsCertificate);
        v.add(new AlgorithmIdentifier(sig.getAlgorithm()));
        v.add(struct.getSignature());

        // verify
        ByteArrayInputStream bIn;
        String dump = "";

        try
        {
            bIn = new ByteArrayInputStream(new DERSequence(v).getEncoded());

            CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

            cert = (X509Certificate)fact.generateCertificate(bIn);

            try
            {
                cert.verify(cert.getPublicKey());
                fail("no exception - X509Cert");
            }
            catch (CertificateException e)
            {
                isTrue(e.getMessage().equals("signature algorithm in TBS cert not same as outer cert"));
            }

            try
            {
                X509CertificateHolder x509CertHldr = new JcaX509CertificateHolder(cert);

                x509CertHldr.isSignatureValid(new JcaContentVerifierProviderBuilder()
                    .setProvider("BC").build(cert));
                fail("no exception - CertHolder");
            }
            catch (CertException e)
            {
                isTrue(e.getMessage().equals("signature invalid - algorithm identifier mismatch"));
            }

            System.setProperty("org.bouncycastle.x509.allow_absent_equiv_NULL", "true");

            cert.verify(cert.getPublicKey());

            X509CertificateHolder x509CertHldr = new JcaX509CertificateHolder(cert);

            x509CertHldr.isSignatureValid(new JcaContentVerifierProviderBuilder()
                .setProvider("BC").build(cert));
        }
        catch (Exception e)
        {
            fail(dump + Strings.lineSeparator() + getName() + ": testNullDerNull failed - exception " + e.toString(), e);
        }
        finally
        {
            System.setProperty("org.bouncycastle.x509.allow_absent_equiv_NULL", "false");
        }
    }

    private void testDirect()
        throws Exception
    {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", BC);

        ByteArrayInputStream input = new ByteArrayInputStream(testCAp12);

        keyStore.load(input, "test".toCharArray());

        X509Certificate certificate = (X509Certificate)keyStore.getCertificate("ca");
        PrivateKey privateKey = (PrivateKey)keyStore.getKey("ca", null);

        X500Name issuer = X500Name.getInstance(certificate.getIssuerX500Principal().getEncoded());

        X509v2CRLBuilder builder = new X509v2CRLBuilder(issuer, new Date());

        builder.addCRLEntry(certificate.getSerialNumber(), new Date(), CRLReason.cACompromise);

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");

        contentSignerBuilder.setProvider(BC);

        X509CRLHolder cRLHolder = builder.build(contentSignerBuilder.build(privateKey));

        if (!cRLHolder.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(certificate)))
        {
            fail("CRL signature not valid");
        }

        X509CRLEntryHolder cRLEntryHolder = cRLHolder.getRevokedCertificate(certificate.getSerialNumber());

        if (!cRLEntryHolder.getCertificateIssuer().equals(new GeneralNames(new GeneralName(cRLHolder.getIssuer()))))
        {
            fail("certificate issuer incorrect");
        }

        JcaX509CRLConverter converter = new JcaX509CRLConverter();

        converter.setProvider(BC);

        X509CRL crl = converter.getCRL(cRLHolder);

        crl.verify(certificate.getPublicKey());

        if (!crl.isRevoked(certificate))
        {
            fail("Certificate should be revoked");
        }

        // now encode the CRL and load the CRL with the JCE provider

        CertificateFactory fac = CertificateFactory.getInstance("X.509");

        X509CRL jceCRL = (X509CRL)fac.generateCRL(new ByteArrayInputStream(crl.getEncoded()));

        jceCRL.verify(certificate.getPublicKey());

        if (!jceCRL.isRevoked(certificate))
        {
            fail("This certificate should also be revoked");
        }
    }

    private void testIndirect()
        throws Exception
    {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", BC);

        ByteArrayInputStream input = new ByteArrayInputStream(testCAp12);

        keyStore.load(input, "test".toCharArray());

        X509Certificate certificate = (X509Certificate)keyStore.getCertificate("ca");
        PrivateKey privateKey = (PrivateKey)keyStore.getKey("ca", null);

        X500Name crlIssuer = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
        X500Name caName = X500Name.getInstance(certificate.getIssuerX500Principal().getEncoded());

        X509v2CRLBuilder builder = new X509v2CRLBuilder(crlIssuer, new Date());

        builder.addExtension(Extension.issuingDistributionPoint, true, new IssuingDistributionPoint(null, true, false));

        ExtensionsGenerator extGen = new ExtensionsGenerator();

        extGen.addExtension(Extension.reasonCode, false, CRLReason.lookup(CRLReason.cACompromise));
        extGen.addExtension(Extension.certificateIssuer, true, new GeneralNames(new GeneralName(caName)));

        builder.addCRLEntry(certificate.getSerialNumber(), new Date(), extGen.generate());

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");

        contentSignerBuilder.setProvider(BC);

        X509CRLHolder cRLHolder = builder.build(contentSignerBuilder.build(privateKey));

        if (!cRLHolder.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(certificate)))
        {
            fail("CRL signature not valid");
        }

        X509CRLEntryHolder cRLEntryHolder = cRLHolder.getRevokedCertificate(certificate.getSerialNumber());

        if (!cRLEntryHolder.getCertificateIssuer().equals(new GeneralNames(new GeneralName(X500Name.getInstance(certificate.getIssuerX500Principal().getEncoded())))))
        {
            fail("certificate issuer incorrect");
        }

        JcaX509CRLConverter converter = new JcaX509CRLConverter();

        converter.setProvider(BC);

        X509CRL crl = converter.getCRL(cRLHolder);

        crl.verify(certificate.getPublicKey());

        if (!crl.isRevoked(certificate))
        {
            fail("Certificate should be revoked");
        }

        // now encode the CRL and load the CRL with the JCE provider

        CertificateFactory fac = CertificateFactory.getInstance("X.509");

        X509CRL jceCRL = (X509CRL)fac.generateCRL(new ByteArrayInputStream(crl.getEncoded()));

        jceCRL.verify(certificate.getPublicKey());

        if (!jceCRL.isRevoked(certificate))
        {
            fail("This certificate should also be revoked");
        }
    }

    private void testIndirect2()
        throws Exception
    {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", BC);

        ByteArrayInputStream input = new ByteArrayInputStream(testCAp12);

        keyStore.load(input, "test".toCharArray());

        X509Certificate certificate = (X509Certificate)keyStore.getCertificate("ca");
        PrivateKey privateKey = (PrivateKey)keyStore.getKey("ca", null);

        X500Name crlIssuer = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
        X500Name caName = X500Name.getInstance(certificate.getIssuerX500Principal().getEncoded());

        X509v2CRLBuilder builder = new X509v2CRLBuilder(crlIssuer, new Date());

        builder.addExtension(Extension.issuingDistributionPoint, true, new IssuingDistributionPoint(null, true, false));

        builder.addCRLEntry(BigInteger.valueOf(100), new Date(), CRLReason.cACompromise);
        builder.addCRLEntry(BigInteger.valueOf(120), new Date(), CRLReason.cACompromise);

        ExtensionsGenerator extGen = new ExtensionsGenerator();

        extGen.addExtension(Extension.reasonCode, false, CRLReason.lookup(CRLReason.cACompromise));
        extGen.addExtension(Extension.certificateIssuer, true, new GeneralNames(new GeneralName(caName)));

        builder.addCRLEntry(certificate.getSerialNumber(), new Date(), extGen.generate());

        builder.addCRLEntry(BigInteger.valueOf(130), new Date(), CRLReason.cACompromise);

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");

        contentSignerBuilder.setProvider(BC);

        X509CRLHolder cRLHolder = builder.build(contentSignerBuilder.build(privateKey));

        if (!cRLHolder.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(certificate)))
        {
            fail("CRL signature not valid");
        }

        X509CRLEntryHolder cRLEntryHolder = cRLHolder.getRevokedCertificate(certificate.getSerialNumber());

        if (!cRLEntryHolder.getCertificateIssuer().equals(new GeneralNames(new GeneralName(caName))))
        {
            fail("certificate issuer incorrect");
        }

        cRLEntryHolder = cRLHolder.getRevokedCertificate(BigInteger.valueOf(130));

        if (!cRLEntryHolder.getCertificateIssuer().equals(new GeneralNames(new GeneralName(caName))))
        {
            fail("certificate issuer incorrect");
        }

        cRLEntryHolder = cRLHolder.getRevokedCertificate(BigInteger.valueOf(100));

        if (!cRLEntryHolder.getCertificateIssuer().equals(new GeneralNames(new GeneralName(cRLHolder.getIssuer()))))
        {
            fail("certificate issuer incorrect");
        }

        JcaX509CRLConverter converter = new JcaX509CRLConverter();

        converter.setProvider(BC);

        X509CRL crl = converter.getCRL(cRLHolder);

        crl.verify(certificate.getPublicKey());

        X509CRLEntry crlEntry = crl.getRevokedCertificate(BigInteger.valueOf(100));

        if (crlEntry.getCertificateIssuer() != null)
        {
            fail("JCA 1 certificate issuer incorrect");
        }

        crlEntry = crl.getRevokedCertificate(BigInteger.valueOf(130));
        if (!(new X500Principal(caName.getEncoded())).equals(crlEntry.getCertificateIssuer()))
        {
            fail("JCA 2 certificate issuer incorrect");
        }
    }

    // issuing distribution point must be set for an indirect CRL to be recognised
    private void testMalformedIndirect()
        throws Exception
    {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", BC);

        ByteArrayInputStream input = new ByteArrayInputStream(testCAp12);

        keyStore.load(input, "test".toCharArray());

        X509Certificate certificate = (X509Certificate)keyStore.getCertificate("ca");
        PrivateKey privateKey = (PrivateKey)keyStore.getKey("ca", null);

        X500Name crlIssuer = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
        X500Name caName = X500Name.getInstance(certificate.getIssuerX500Principal().getEncoded());

        X509v2CRLBuilder builder = new X509v2CRLBuilder(crlIssuer, new Date());

        ExtensionsGenerator extGen = new ExtensionsGenerator();

        extGen.addExtension(Extension.reasonCode, false, CRLReason.lookup(CRLReason.cACompromise));
        extGen.addExtension(Extension.certificateIssuer, true, new GeneralNames(new GeneralName(caName)));

        builder.addCRLEntry(certificate.getSerialNumber(), new Date(), extGen.generate());

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");

        contentSignerBuilder.setProvider(BC);

        X509CRLHolder cRLHolder = builder.build(contentSignerBuilder.build(privateKey));

        if (!cRLHolder.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(certificate)))
        {
            fail("CRL signature not valid");
        }

        X509CRLEntryHolder cRLEntryHolder = cRLHolder.getRevokedCertificate(certificate.getSerialNumber());

        if (!cRLEntryHolder.getCertificateIssuer().equals(new GeneralNames(new GeneralName(cRLHolder.getIssuer()))))
        {
            fail("certificate issuer incorrect");
        }

        JcaX509CRLConverter converter = new JcaX509CRLConverter();

        converter.setProvider(BC);

        X509CRL crl = converter.getCRL(cRLHolder);

        crl.verify(certificate.getPublicKey());

        if (crl.isRevoked(certificate))
        {
            throw new Exception("Certificate should not be revoked");
        }
    }

    private void zeroDataTest()
        throws Exception
    {
        try
        {
            new X509CertificateHolder(new byte[0]);
        }
        catch (IOException e)
        {
            isTrue("no content found".equals(e.getMessage()));
        }

        try
        {
            new X509AttributeCertificateHolder(new byte[0]);
        }
        catch (IOException e)
        {
            isTrue("no content found".equals(e.getMessage()));
        }

        try
        {
            new X509CRLHolder(new byte[0]);
        }
        catch (IOException e)
        {
            isTrue("no content found".equals(e.getMessage()));
        }
    }

    private void checkSerialisation()
        throws Exception
    {
        X509CertificateHolder crtHolder = new X509CertificateHolder(cert1);

        doSerialize(crtHolder);

        X509CRLHolder crlHolder = new X509CRLHolder(crl1);

        doSerialize(crlHolder);

        X509AttributeCertificateHolder attrHolder = new X509AttributeCertificateHolder(AttrCertTest.attrCert);

        doSerialize(attrHolder);
    }

    private void doSerialize(Serializable encodable)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(encodable);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        Encodable obj = (Encodable)oIn.readObject();

        isEquals(encodable, obj);
        isEquals(encodable.hashCode(), obj.hashCode());
    }

    public void performTest()
        throws Exception
    {
        if (Security.getProvider("BCPQC") == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }

        testDirect();
        testIndirect();
        testIndirect2();
        testMalformedIndirect();

        checkCertificate(1, cert1);
        checkCertificate(2, cert2);
        checkCertificate(3, cert3);
        checkCertificate(4, cert4);
        checkCertificate(5, cert5);
        checkCertificate(6, oldEcdsa);
        checkCertificate(7, cert7);

        checkComparison(cert1);
        checkComparison(cert2);

        checkKeyUsage(8, keyUsage);
        checkSelfSignedCertificate(9, uncompressedPtEC);
        checkNameCertificate(10, nameCert);

        checkSelfSignedCertificate(11, probSelfSignedCert);
        checkSelfSignedCertificate(12, gostCA1);
        checkSelfSignedCertificate(13, gostCA2);
        checkSelfSignedCertificate(14, gost341094base);
        checkSelfSignedCertificate(15, gost34102001base);
        checkSelfSignedCertificate(16, gost341094A);
        checkSelfSignedCertificate(17, gost341094B);
        checkSelfSignedCertificate(18, gost34102001A);
        checkSelfSignedCertificate(19, sha3Cert);
        checkSelfSignedCertificateAndKey(20, gost_2012_cert, "ECGOST3410-2012-256", gost_2012_privateKey);
        checkCRL(1, crl1);

        System.setProperty("org.bouncycastle.x509.allow_non-der_tbscert", "true");

        checkCertificate(9, x25519Cert,
            KeyFactory.getInstance("EdDSA").generatePublic(new X509EncodedKeySpec(Base64.decode("MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE="))));

        System.setProperty("org.bouncycastle.x509.allow_non-der_tbscert", "false");

        try
        {
            CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

            Certificate cert = fact.generateCertificate(new ByteArrayInputStream(x25519Cert));

            cert.verify(KeyFactory.getInstance("EdDSA").generatePublic(new X509EncodedKeySpec(Base64.decode("MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE="))));

            fail("no exception");
        }
        catch (SignatureException e)
        {
            isEquals("certificate does not verify with supplied key", e.getMessage());
        }

        checkSelfSignedCertificate(22, CertificateFactory.getInstance("X.509", BC).generateCertificate(this.getClass().getResourceAsStream("xmss3.pem")).getEncoded());

        checkCreation1();
        checkCreation2();
        checkCreation3();
        checkCreation4();
        checkCreation5();

        checkCreation6();
        checkCreation7();
        checkCreation8();
        checkCreation9();
        checkCreation10();

        checkCreationEd448();

        checkCreationQTESLA();
        checkCreationDSA();
        checkCreationECDSA();
        checkCreationRSA();
        checkCreationRSAPSS();

        checkSm3WithSm2Creation();

        checkCreationComposite();
        checkCompositeCertificateVerify();

        createECCert("SHA1withECDSA", X9ObjectIdentifiers.ecdsa_with_SHA1);
        createECCert("SHA224withECDSA", X9ObjectIdentifiers.ecdsa_with_SHA224);
        createECCert("SHA256withECDSA", X9ObjectIdentifiers.ecdsa_with_SHA256);
        createECCert("SHA384withECDSA", X9ObjectIdentifiers.ecdsa_with_SHA384);
        createECCert("SHA512withECDSA", X9ObjectIdentifiers.ecdsa_with_SHA512);

        createPSSCert("SHA1withRSAandMGF1");
        createPSSCert("SHA224withRSAandMGF1");
        createPSSCert("SHA256withRSAandMGF1");
        createPSSCert("SHA384withRSAandMGF1");

        checkCRLCreation1();
        checkCRLCreation2();
        checkCRLCreation3();
        checkCRLCreation4();
        checkCRLCreation5();
        checkCRLCompositeCreation();

        pemTest();
        pkcs7Test();
        rfc4491Test();

        testForgedSignature();

        testNullDerNullCert();

        checkCertificate(18, emptyDNCert);

        zeroDataTest();

        checkSerialisation();
    }

    private Extensions generateExtensions(Vector oids, Vector values)
        throws IOException
    {
        ExtensionsGenerator extGen = new ExtensionsGenerator();

        for (int i = 0; i != oids.size(); i++)
        {
            Extension ext = (Extension)values.elementAt(i);

            extGen.addExtension((ASN1ObjectIdentifier)oids.elementAt(i), ext.isCritical(), ext.getParsedValue());
        }

        return extGen.generate();
    }

    private static ASN1Primitive fromExtensionValue(
        byte[] encodedValue)
        throws IOException
    {
        ASN1OctetString octs = (ASN1OctetString)ASN1Primitive.fromByteArray(encodedValue);

        return ASN1Primitive.fromByteArray(octs.getOctets());
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new CertTest());
    }
}