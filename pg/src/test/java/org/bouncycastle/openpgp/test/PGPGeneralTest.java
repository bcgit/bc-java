package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.DSAPublicBCPGKey;
import org.bouncycastle.bcpg.DSASecretBCPGKey;
import org.bouncycastle.bcpg.ElGamalPublicBCPGKey;
import org.bouncycastle.bcpg.ElGamalSecretBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.attr.ImageAttribute;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.IntendedRecipientFingerprint;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.bcpg.sig.PolicyURI;
import org.bouncycastle.bcpg.sig.RegularExpression;
import org.bouncycastle.bcpg.sig.RevocationKey;
import org.bouncycastle.bcpg.sig.RevocationKeyTags;
import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.bcpg.sig.RevocationReasonTags;
import org.bouncycastle.bcpg.sig.SignerUserID;
import org.bouncycastle.bcpg.sig.TrustSignature;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.gpg.PGPSecretKeyParser;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.openpgp.ExtendedPGPSecretKey;
import org.bouncycastle.openpgp.OpenedPGPKeyData;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVectorGenerator;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.bc.BcPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRing;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.jcajce.JcaPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEProtectionRemoverFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;


public class PGPGeneralTest
    extends SimpleTest
{
    private static final char[] v3KeyPass = "test@key.test".toCharArray();
    private static final byte[] privv3 = Base64.decode(
        "lQOgAzroPPgAAAEIANnTx/gHfag7qRMG6cVUnYZJjLcsdF6JSaVs+PUDCZ8l2+Z2" +
            "V9tgxByp26bymIlq5qFFeoA5vCiKc8qzYiEVLJVVIIDjw/id2gq/TgmxoLAwiDQM" +
            "TUKdCFa6pmR/uaxyrnJxfUA7+Qh0R0OjoCxNlrmyO3eiKstsJGqSUFIQq7GhcHc4" +
            "nbV59zHhEWnH7DX7sDa9CgF11WxM3sjWp15iOoP1nixhmchDtQ7foUxLsCF36G/4" +
            "ijcbN2NjiCDYMFburN8fXgrQzYHAIIiVFE0J+fbXNfPRmnbhQdaC8rIdiQ3tExBb" +
            "N0qWhGPT9M4JOZd1yPdFMb9gbntd8VZkiPd6/3sABREDXB5zk3GNdSkH/+/447Kq" +
            "hR9uM+UnZz7wDkzmt+7xbNg9F2pr/tghVCM7D0PO1YjH4DBpU1ZRO+v1t/eBB/Jd" +
            "3lJYdlWYHOefJkBi44gNAafZ8ysPOJk6OGOjas/sr+JRFiX9Mgzrs2IDiejmuA98" +
            "DLuSuNtzFKbE2/DDdOBEizYUjqPLlCdn5sVEt+0WKWJiAv7YonCGguWS3RKfTaYk" +
            "9IE9SbI+qph9JsuyTD22GLv+gTMvwCkC1DVaHIVgzURpdnlyYyz4DBh3pAgg0nh6" +
            "gpUTsjnUmrvdh+r8qj3oXH7WBMhs6qKYvU1Go5iV3S1Cu4H/Z/+s6XUFgQShevVe" +
            "VCy0QtmWSFeySekEACHLJIdBDa8K4dcM2wvccz587D4PtKvMG5j71raOcgVY+r1k" +
            "e6au/fa0ACqLNvn6+vFHG+Rurn8RSKV31YmTpx7J5ixTOsB+wVcwTYbrw8uNlBWc" +
            "+IkqPwHrtdK95GIYQykfPW95PRudsOBdxwQW4Ax/WCst3fbjo0SZww0Os+3WBADJ" +
            "/Nv0mjikXRmqJIzfuI2yxxX4Wm6vqXJkPF7LGtSMB3VEJ3qPsysoai5TYboxA8C1" +
            "4rQjIoQjA+87gxZ44PUVxrxBonITCLXJ3GsvDQ2PNhS6WQ9Cf89vtYW1vLW65Nex" +
            "+7AuVRepKhx6Heqdf7S03m6UYliIglrEzgEWM1XrOwP/gLMsme4h0LjLgKfd0LBk" +
            "qSMdu21VSl60TMTjxav149AdutzuCVa/yPBM/zLQdlvQoGYg2IbN4+7gDHKURcSx" +
            "DgOAzCcEZxdMvRk2kaOI5RRf5gV9e+ErvEMzJ/xT8xWsi+aLOhaDMbwq2LLiK2L+" +
            "tXV/Z3H/Ot4u3E7H+6fHPElFYbQUdGVzdCA8dGVzdEBrZXkudGVzdD4="
    );
    private static final byte[] probExpPubKey = Base64.decode(
        "mQENBFj1Q70BCAC2ynacUueCmIUXxeYy1HIA92JAhgXrPcD5JkQiNlI779/f"
            + "72gLzFDqeNCKLsatnjD3m0tNgPB8vSsg2Um2Np1zTyHRO6hyUZsxmwsMoDrm"
            + "RCaJxBuLU6if1S7b9I8A8vIVOLrvUrw48Vh16GZO9eeTmqQ/oNRxN3kuZSVC"
            + "ccQ9jgMJqvq3TUJpNeNWp/ibLdBFN6HoOw2Zf1jm+jvYntsocVD+ZtpfHQoO"
            + "ZzA55hc7QO0LU3odtdy6sQHvTmZZGHZVYgg6joARY+HZuzm+63vn31ajI16g"
            + "ZKKnAjyubQ+giZT05ApQgHpJ7hMXVXVzjxoiE1qapNZBU+K3CwNJWqdjABEB"
            + "AAG0CXZhbGlkLWtleYkBPwQTAQgAKQUCWPVDvQIbAwUJAeEzgAcLCQgHAwIB"
            + "BhUIAgkKCwQWAgMBAh4BAheAAAoJEBmVFZBmFliQwYUIAIz+PAYEQ2tDjOiq"
            + "R6IG0V7zyQjthLcSxWbOEIF53FD3xBx3tAXScq88RlW/QY4d9en+cK3gpvrr"
            + "/5aWomi7QoziZeUcMN7HtdqPgqk8DMcogIyS/geK8z4r6eDz3HQWDxAitRTw"
            + "bbjFxahUHuetOh9nnTgsDTaimBRKVMLSUqqVYcgmPJLFaJSGRLMF7qHzN9hc"
            + "jaiGLCLM9zVg74PnyORwmlnsM81uHzJ3uKueudGDKjMvgsMKODGMUzXArUKO"
            + "PrDKKkrx82F5FHMIJ5Mn9fq57leJKzy1APnz7E8/ieqasTsBcC0L/6uJ+sS9"
            + "Eca93q4mziqGvFx8cL5ZmlYx++ewAgADuQENBFj1Q70BCADFmn2DXY/G7K5G"
            + "v5KLI8296e8q0iETX8516tXB5t0jWzxcsAHeMflsDR+TloXp4Ecznx3Pv8Q0"
            + "4dkoo2MiSBiJ5adkwr/zLs+WWqwUjVw6m4ButTaFH/GaoKF+7HWg066NSd/u"
            + "4JQaeAqsWqvTW4p3YRDm5GbXID0GsN7APtvUk9ShCeDXP9KZvNeTWFy2+iWd"
            + "aYQBoRzTGPpjoboStZPDmLxuPXDbjQIXLys7k3Z0Shx/f5GMHnSyhVDNPlGQ"
            + "+aCi2VL/PrwEVp4CCP5dQefNm1q95DCM2wdEQBeC3r3fGTTkBprZTWCwNPo6"
            + "sCVaG/BbaFtFgilDUvMFEj5MP3FPABEBAAGJASUEGAEIAA8FAlj1Q70CGwwF"
            + "CQHhM4AACgkQGZUVkGYWWJCQxwgAp/eIdOjWK9Tw9SOyFwi83nI92zWdnIxP"
            + "KUroKQcXilH1nIyIykDSL2SLHK49c2Cw819MjWTwcUn7/OdZYc+X9ryteEFR"
            + "Jge/Qw5CXvmRzhaCDtx6OU2U+/uHGMuvAOwpS1brmKaSN46LwHDHRMGn1+1D"
            + "n4uXnFyc9lMDbja5c+b5vX3loulBwXO35ColrLx0Q585QusgMoGJwkr/8tx5"
            + "jvLdI+T35e6f84gAlexGenvMDgobw32vaW8dXQQ0BKqNZKjXMy/0OGJs7G1X"
            + "VhL+80K6K2UAu84JhBYFgoZQQ6cHtPn/WrSVN7RykSAKIOzvhqt8dFnjDHdH"
            + "4xagReRrQbACAAOZAQ0EWPVHNwEIAKy/E/vob7FC+e+FX+W09pqNVMQXACxa"
            + "7SCF51aFAMmncOJVS5BlyUjevaC77nXq5YXBvzZjYSN7nS6AOO/5BBXAH2/i"
            + "bFBjrtqlLfH7sMqqly3gMWxXDOGw0FvH5DrlIiO8F4TciEXXOLHgMkC6RlBQ"
            + "rj+Ca0iB8hEz34xkDB8NccQgfySDdcmOWvVHm9DCO8xbdLRoTb9WFb8w6pkX"
            + "wioJnaQ0pa4VYC8gTHOqMgy9/Yk8GHdZ9iOALTNFKCGJZvVKYKL7vhthQV5O"
            + "XVBeBGB6eTCFutJpcqdv27V3EwsV77WBHxgTvjsWJoGK7p8jvApgZSYSV1fB"
            + "YetDiXhgezEAEQEAAbQKc2lnbi1rZXktMYkBOQQTAQgAIwUCWPVHNwIbAwcL"
            + "CQgHAwIBBhUIAgkKCwQWAgMBAh4BAheAAAoJEFdUbHpYn0hjUYwIAIovaR+B"
            + "YOYD8nYz3ylrnbRx7pAxaniNN2ZdzkhvbAx9ACvuN56R9GkaU3mwTd3LUEMG"
            + "iw4MlvbEeADCckL6sB73esOiteoJz3+0+NCDb5rhbt5YCKQicubxhSNd2qkR"
            + "eQE3IYpEd++QHXr/B7U95rwzjXzGImNyK15zuFGboC9VEQOc3ckTugoMirC0"
            + "QSpHXAQlPHdwcA/f5ljceVSqGTDPbKFjwpU4kB10ZK8Jm8VLlL1JiCfufyfL"
            + "mYTa/ysjzcMI/Z4jTuZ2y0pLR+q8gMpuMfA+MVby3IXrK6hsgQcTjm3idHRx"
            + "xxBiRzdpJbh4CJAEu/9BTCr4WQF48rmwLmqwAgADuQENBFj1RzcBCACisowf"
            + "NnQQTZBK7nYv24T3I0jDy3fENEtZ/g3pVW/e9BdeyXy0eXMSHgiWqn8LWznD"
            + "BYzPbAth4Eq4fyNv2FbkvEHeQwoF893oLonXeyM171A6siptL1LXdqBNYaai"
            + "Z62pHYFa4r8q7UzcAeVMKHQYEjbat90FTnFHrT/Mc84ZN7nVnu8PevdM73z0"
            + "pdLq2aQ6oPJ+zZDU5nnx9dBiftc3BCn+gBuNua1rQVPBjXv+urEc/nig9dG0"
            + "LDH3Gio7Va9AOgkyq6RB0X/yGF1Q4B88n9pHsbIUEH6SjA/WNX0iAqjv2Z7v"
            + "fgJaJIr7UY5Lz9hBBpMKeHhhY3p9I4k3gZTnABEBAAGJAR8EGAEIAAkFAlj1"
            + "RzcCGwwACgkQV1RselifSGN2Mgf/SmLWjy7PQa8WzwdMfM3ngTkqc6cunmVr"
            + "R8cDsevKnwCzN86I9SHgSBIFt3YcCaFOFprF6gREq6He0G+VbyY/7xnjCfrl"
            + "ZczkwFddHl3vO/3CcZrPyfFnItMmLYW1WjSOoSfz/uiijzV+R7KcmT3s8z4G"
            + "hB4u/yCa5WszRYepVaH6J3IYbfCjMn5YDuv/bxPeqbv0xkTanKeeGHT0MKN2"
            + "ff9mtlAK9gj8awU0rlvIcmHXIpcEih9pJDhmtCbapNH2ne4SyixztjfYgdEd"
            + "uVUD8gp0mN/5ckVtAwQ8j6Qa6tYoQJfNj/p6OMmR0bQFvVpqTasWoL+hO8Bw"
            + "TvUuMkI1uLACAAOZAQ0EWPVHXQEIANB18VoDCSng6SiOIeQwmk01K4Q8jak7"
            + "3J5nwKvGHTLHy105AI5d6b3QFRcdK4WzM5ai9Pm5snTyAAGgubcU25dDUAqO"
            + "EfyKwWkeBEl9Zc6iXgB2KGrTJylVSrRH6y/CsAo9JOXtyV6S9iKacQBZHVKN"
            + "xZGWOlQ72xDfPBjhYi65cUZhNhK4fn32L8WmyKWVWNFfajybHnKN/Wv0R/Uf"
            + "TxCWEDA0ieUVKs//m97gCzYC2xODGDEKal6xQsmQB6iRrcPAWpxC9LHG7cGh"
            + "oqS99Guj2b5UqdI+69KNpqrbX7vj1mnYo+QrJJCp62+7QMlXAs+1Xih2P6Qe"
            + "KMlk97j2gPsAEQEAAbQKc2lnbi1rZXktMokBOQQTAQgAIwUCWPVHXQIbAwcL"
            + "CQgHAwIBBhUIAgkKCwQWAgMBAh4BAheAAAoJEGFcNg7n5zRXZYoH/3iFmvXH"
            + "TR8lCLs/dj0JQ3FdbBNSwhJRHUh8cpPTcJxFZumAjf1nVJbqKVLhTrrcqZF/"
            + "QJdYvfaD/pziaDgNTUdzBC4VXKqtNODS0QLlq1dcZQ/rNst/HlP/e0FCfq3V"
            + "HZgsY2Xwmf2gj8sK9bnZT9U6THUU7m6miW4TnQDAhUmBJubmYzKwbrkuca2c"
            + "lW3PC53IIjycp7+jY9Hxah/D+MU+0eaelBTQ9rypZNbVOCKcm8rMIKk9HxoX"
            + "GfbZuo7L5TT/TFZVwK9DRh0qBqW4fOGSLTNsz0O9QkcrsXxdhvAvX2fiWsZu"
            + "2r7E3/c5CIL/s/5C7AzA370wtriu2b4toWSwAgADmQENBFj1XDoBCACyr8Bu"
            + "03osh26GiIKOzhfbgH0hdlnJlh8LNo8ALE/Hz4KbxzM9Zyh46NZG5aS5NADd"
            + "c7FBWTLqcxS14JobkjM2edJJXIilpCdw9ThuW/gSEYpJbPKRncq8D4K6d8Bg"
            + "kWkjadYPsmFzFlnSL0Eki9sW8JRzEACe1R3srJLUN0SsQ6OPwOimv4i2CkYw"
            + "RIvjpBhCtIs2qV1ERMpct9/rPDzLlL/YS7MF7PSXd9Jy7J2KuwPNXjcXwRFR"
            + "MOTYV3Cx7+OAnUs6+Pyb6DbrYPF8AgC6KKqJXR4Ei5sQCwWkIXQ3sjPBD4x8"
            + "hAqBuUzJMnNF00YhDXl4kMI+2r0GSwo+6ZF5ABEBAAG0GWV4cGlyZWQtZW5j"
            + "cnlwdGlvbi1zdWJrZXmJAT8EEwEIACkFAlj1XDoCGwMFCRLMAwAHCwkIBwMC"
            + "AQYVCAIJCgsEFgIDAQIeAQIXgAAKCRDDZIMAG7vFqFoXB/9exlOGLLK3tiYl"
            + "RaPZsq26uOdiU1efO98aJCK7lRaUZkTXlxF9THVQnCRUGjEHPjYIxwm1oeUy"
            + "2dvqklq5jIL6Vcmt5hrVax++tIuKBpqISF8wpJcNEmq3zwWUxAhvE3d2mgAn"
            + "9AzoabzAy8SBkCZD/o0THB1z1R8CJ3PcmbIzt+CdMwG2NVJLlw5VTNVCp0fc"
            + "m8OzxoH0C0qiaR2DPjuRNlXepjz0LC+8coIMOOiJnJnQywGnjNbgoDp79XPn"
            + "KpoN+TpXkQkAiuIwlu4GSADUDV8MiUDbhMxZTPJD5KSC47COMZV2huLgRx1x"
            + "kwQil3Pqp4PMf/fvgbWE7L9yNz+ysAIAA7kBDQRY9Vw6AQgAzvv+T0ykClWK"
            + "wyPuDd+2e0NSxzzyn7ZWrms7FClnvKszjpKnznHiRRE+kXwEJ3HIBJIs604I"
            + "09pgIkZZrfx5zkrZm2zpUp7gWndh2c/AiO6/cAe6I3vwodhPyDFn7+JXQjgz"
            + "aJWg9jNEbSjodq/mK9K7Ln5YqYNjn/mb+VX4xa0E5YBMcGnLdrkmOJcEZTd5"
            + "fedeIVKzU/BAk6YQcrDXuDAKD5yXB4djAhP1p6DUSaQ7iS35pgHTdgNuHBMC"
            + "uFxzR4vco/eqRElzaUVIIBGQYUcUE+RDRDREQKCkchrTELGh2GNFieig78D1"
            + "3HaVdZb6yJg9gYcuWH54QKgVSnzPxQARAQABiQElBBgBCAAPAhsMBQJY9V0/"
            + "BQkABpiFAAoJEMNkgwAbu8WokgoIAIE2uNH0SpHVKB4hJRqYes6hURn8q0HB"
            + "+tfvlfrSopaDp2nr55B6dDiJNS3QIMb9nZePOnbW0tVPwga1775Gh0LM3+jf"
            + "s8oVgG5EcH+CZWiW0dj4LXvZ5hO4qqJJYF5IC9cbQQOG8TUNZZEHO/Rwe1/0"
            + "5mEV+Qw9vPSvEfloMku7pdeZIn8+GLai/jxSC/7WGBeuyhjuCmookrqcufh1"
            + "SICnRZPGuIGVqAsAm5pthWHwwwcW7TYy70ml5eTSBwrR3ciVJ+gibLo+p6IK"
            + "pd+E71rpk6NwHKvFDCaBW2BUYItgzcapA4ellc6OLeXVSktd4rL9Ad/Vb9Xu"
            + "v9zqQppjemywAgADmQENBFj1Z9YBCADEsA6PsyFNS2lK1DOPenoZCLYYujDf"
            + "j3zIf7AUG3DHEya3km+mm/etpSS38ENtJRzjZ8Xb8T73iMbsRiMuvbPhLP7L"
            + "zMw0YQz2OBqXeft/TM8GhAfRdxGwTRKEhczA/GBVj1uXtt3aH9PKqa4ZBAUC"
            + "+mhwts87IY3OlchAzESJnpWYfL+9PD6y0PdgPCQXjwrLuXkwpmR4L2VKLunW"
            + "RKdYcV4pWF/MbqND4ZHuYsj11CDYaKdC7Q4LegBlU9wBOEzJR+pRzMog1HgM"
            + "UYnifpfcQqJ4xY7mr57eHDNZ/x8UeJDQN2uH3bflWmi8GmE4lrCOp1C7jNAD"
            + "vJeF76LP5o1fABEBAAG0EGV4cGlyZWQtbWFpbi1rZXmJAT4EEwEIACkCGwMH"
            + "CwkIBwMCAQYVCAIJCgsEFgIDAQIeAQIXgAUCWPVpAgUJAAaYrAAKCRBRNKkC"
            + "/D9UQS56B/j/H4nxRPjPHkUSlfPrvP1zP58hDWDN7vFF/3/r8kVTRScWfXXm"
            + "63OWpsvWP1i1rPnKsvq/TiS9hvO7bmvhpWiGViUZhWewaPTmtygNbXLgsbF+"
            + "47VDG3kHeOLXwouCNwCOa9KUUVy6SJqom3FBlVqU8NyW6SUQtw5Jwvi9nsAV"
            + "Vbo9Cg1YDwEJbiVuXO9IB5VZ09+ZEcWMWAJzDPy7yuBeVDoHXuS6uZrkMIMx"
            + "gGsH84V3o/8v0D3+a5PnQ1Ke/IRLlLJ2kGMNyqenFVQJWLTIxJK58ppWXwGM"
            + "E5jB/Wi0xzw/uSf3aZVBodp2AZdYB48qfMyLOeSObyyPkYayGOSwAgADuQEN"
            + "BFj1Z9YBCACwO+T+s2ZXiHmiKSSf5ZdHA02LiHxmO5vfPfh/z65FhYuhkRgt"
            + "9wHdKabf7drG2xDmDJwumUxQiut3OnLimN8kXX7Yh/+11S9OHJHA6HkhXAxb"
            + "323bHpfJ0Rdjt7MEscIk1qCwboG7cMHiWH1e2IsyR2w5NNQuKLRyUC1AAuMs"
            + "1qFmwYpJDSuJZsuL/dd9d2BTfHKA0KeCx5j/6xme82ULNyU8niA3EWjt/Lql"
            + "4IZaVQXbBKlBi7ZNC9q8tuYYHkxxGfwhq0g5FWKPumtpFIOV5KZVoil48U9p"
            + "c0B/I/IRHXJ2Q4w5YlZQR5cbOKOrQ0/ELYRRvzh4yurzy+sobiGfABEBAAGJ"
            + "ASUEGAEIAA8FAlj1Z9YCGwwFCRLMAwAACgkQUTSpAvw/VEHj2ggAoKv89H6V"
            + "TSRWCXNq6FZVbD8WFz4emuyn/k4e5C4ULVI8j2eSNUVG3VfPQLzxYC/GjVUU"
            + "m38p7wGG8aYYZumUc4+7vR811uBxDTgWnmthR6SRTqutpuvYShlgT5kor3E2"
            + "hkZapIrxqKBwZOAi8JK5ADbdLrpQRlDoik10a4KZH4c7FblIxcag1Ee95IOv"
            + "xrxFDRRJqdkka+TmtWFuf5eMOSTDeSS8XK4Az8kl8W3CGULICwVWJmfASeeR"
            + "TwE+Guw/gx/dhz6ukTgSsxn1EdQMu4GMrlCk5Khwq1soVLumfrch8iqt7y1k"
            + "CgNgcu7sk31BaZp2xrGpP1G/kklggTVtxrACAAOZAQ0EWPVqQQEIAMpR07Jm"
            + "F2fLdLGLEpge3FCUqxbnyp5xAvLJHyUHLmFqoW8xpPMJHnIZycBcPe5G/S+a"
            + "7uLbUMaRALHHFebmopmw4JzW2wFMk/LXST6MmRIfFTcpYqtAn+YNKLUxuqqH"
            + "1kHPDG+kjMqzWmW/Heoh4rPHuREm3D0PBXQNLrcHlOV862+g/yLW8QfPd/0E"
            + "Mi2A+1gb54J3zLsyQjCEHYguLPtGD7tMdOk7exBgrHD1nado3Ofu3H2zZ7Sc"
            + "+izarkIeNDnq4k2eaEmfmiambqDsqdCB8mSP0jKo3+hChDMU43WlL7jka2Ko"
            + "Q6zKmKHopZAHjNM1AfUzF8XZWEhQZ8yQP4sAEQEAAbQNZnVsbHktZXhwaXJl"
            + "ZIkBPwQTAQgAKQIbAwcLCQgHAwIBBhUIAgkKCwQWAgMBAh4BAheABQJY9Ws1"
            + "BQkABph0AAoJEEkvIbBfB919T2oH/1LRkMTU0U/H7gVxMsWyv1aFF5d8FZE4"
            + "CnGz9YJmOQky+wck1GH5qLdGaPikD/hC73N2s276KE2iW3wg/VRH+760k69I"
            + "+Ffjn252lafBxN5ZISxU1YM7GTjdkLo28ZEVR7dgFJMZTYpoefULh/Vac4KC"
            + "ZbAp7OMNBuc8CSYTYGtqThcZB58aM/w4TeWRSBi9CcxP4JObdx2U0aoowJf/"
            + "MNcN6/6/tEDYcAYYJoCLiLiVc4yzfS+vrrdM/knARyPyqjQnyo2s/CGyccYz"
            + "u0lENc8mquRhqBbb+zI98eez8oxAVxzxhafTmtOn5+M8/1fpsPT70sZUlK+K"
            + "z7iVCCJS0uewAgADuQENBFj1akEBCADhxBHK/Yzg5kuLiF0DsTYCslRTNr3s"
            + "wU+vv1WGrGd14ktp2XZlNnhnF5N2cpCVi9CiUf8B9Hq7N7caa4E7F56EzEpf"
            + "ccTJy3tysvtRiWwOhlBgkgNK5RxRCBMa6fXAgON2AX8EjFYBc0L7e/35CLQn"
            + "3SGAyYiZ97PhH3gD15C7qwyqSKR2J++FPYEH1BYm2FbxZ22joJ3jP86EWTiq"
            + "UYcXWwIRuDeZvP7hDdozJMMM8MGtnnSFWvBgotBf7P8ttq6lbdMLQzJTFXUS"
            + "z9qsNgdBQo8PNrE2Ig9HuOJlEY2g8EXUhqHgMtCYIimN4FjFFEMdMiIrwc+t"
            + "ygNSysmcN/EnABEBAAGJASUEGAEIAA8CGwwFAlj1a0EFCQAGmIAACgkQSS8h"
            + "sF8H3X2XPggAlxD+W9jL+AAlKpXcwuvzLOxHL4i/x4snqx+UMZkNrohP5wed"
            + "du8KuewWCjF08qVL4CzkUbu7T3xOkG3mghvwv8/2AeoEtyeNCNyNtVi+oLAL"
            + "AW3fA199rFwK/6C+c5QPUlFLrJMFK4S62LR16U+gLpWbjVg88DFRIfq7ISGP"
            + "K+VLZlMGqvtO6s/uRgFpjTZsrh50CaQ7l1gHwFsdA7W0J0uR9fq3YYWXcUS+"
            + "Dzn1bYyL47v67YfSIAe3fWkwKujMWgqeZP37Wx9S68mdZwGWM4dL7p2gm+FZ"
            + "rnv5PgyOlHqBTHHj/pnLNNAhlPGLtQkVe5MuluSPpQYwAsdJzX5aLrACAAOZ"
            + "AQ0EWPV1SgEIALxHYi0DZvv2m+M/6p8FxOye/PAaJhhrMsKOS2D7IJeEujk3"
            + "+6/75P7Rp3P50qCHq5jl7+GqquEf1pKjwBgTe8vhT7sxPimzsZ73R4PmTFhj"
            + "WzxDUnLKYE2+McuhuBTKFep0tZcxtzEMLPuA7Wd78lR1YtuAYmLI5Q24iGn5"
            + "X62RZhvecms5Iul0GVo77o3S52P+yiyEWhd0v3LuHxoglJiLAqWv4EoO3ciG"
            + "LAZTgfMloDyHmkuGI+fqnfb6wYbkmH6pEguXV6GAfcWvBH0UoaVgcp7muAkD"
            + "B7MNWMljmy7KEseUJ5/jqJd+CFPPLx6HL3PYV+L8rsrKGkVZ98PDKUUAEQEA"
            + "AbQeZG91YmxlLXNpZ25hdHVyZS1leHBpcmVkLWZpcnN0iQE/BBMBCAApAhsD"
            + "BwsJCAcDAgEGFQgCCQoLBBYCAwECHgECF4AFAlj1dzkFCQAGmW8ACgkQWv1T"
            + "qduyxA0fKgf/d4WPcxh+4TK+tPNM2JKP7X3UywiUeK7DL8Hbz1Fd4JvOrw9t"
            + "EBlrX6+RLzljjfZ1iXIvZLwMacV70zO64pndiKUi24cIFtumOgSY29WSfA6r"
            + "VEy/7Pj8KB6D8h52uEmI/l7+R01W9cDTc2/FMwHpfgMGs4tnfDPs9I5o3GaP"
            + "N7gPyeh1CWPg07Se4vYTQXQpE80i3NuSDIIdxDRF60mXhIzuKuPmZaky5VfZ"
            + "JemkuJg9xZUqIZkKN7DPd+bdLCHYT/4sO9KpXdhCqXOcrQcrZ+pK8+XF9oow"
            + "I0zHmVfzs6sx49nN9r6IkWp2ptcPVYy/xbuR4FNqu3zywBoaHCYwm7ACAAOJ"
            + "AT8EEwEIACkFAlj1dUoCGwMFCRLMAwAHCwkIBwMCAQYVCAIJCgsEFgIDAQIe"
            + "AQIXgAAKCRBa/VOp27LEDTKpB/97tH64nH+il9x/3JYXqXZ5dBoQnvUbPbU0"
            + "Zb6MJXKRfh+T+SDtUSzjeWGgNFY8tGe2EuPbWrSY6IOilwKs2mk/flXoiKxm"
            + "x45nAjPfdbaOhNC8J4d3GOqga8ysICWpWZK6JOb3SfzKa49Un4aALp5tGEIu"
            + "aJAlNyS+U5BHhCMl5qiYCn+YyuL54B6z1MChqC8s9Zsmr7vbum97bsK8X5dK"
            + "fZEL5CJqZGcVgh4dbcVhjXmBCFXfwNxHyZGeMBUegcF9TNdi03QghFjyV3qn"
            + "WtesVjx9AWN3QFxgHRPwOt4vGPMDPvLgGLIJ1ecZT3PEelKG5fuHrWdwjnaL"
            + "YmmzrjUbsAIAA7kBDQRY9XVKAQgAzr1JH5kZ+GeSDcflHZHQQ/cjoqvRw7dl"
            + "SP/Je7IGBF21QDjlgesSzSyKvR49P0pI9us9fN7weU4YyJEWk1JP87wO/hAb"
            + "qHkZvqaPFmUQq+8s/JaWcAdADqmEYaqf4O5Z4QpaWelv+DiXITLFyHGchKwY"
            + "Z7JQv8JtWRuNSARMl4Xw/rrB342cy7BVU4p502tv/0tTWdtGn/lJA2kashoN"
            + "7GS2AmSvXtHHT4acLuIYglJAMU2Xb5P3vhKalvLVbwqVEEkH2rFeX9QQIw2r"
            + "JpqZarW6sbXxMuOxj7lBWa4/hL0oz2Tyit6f8QIqJDlvzR4tus/xyDgipFhT"
            + "6Kzey6dRFQARAQABiQElBBgBCAAPBQJY9XVKAhsMBQkSzAMAAAoJEFr9U6nb"
            + "ssQNIcYH/juwAmPLNTRkssajoT2I+z6rk/SHMWyfYgxml+XneBE/sQQ8pU6f"
            + "9DrroqyZpQh8cOMzdKLNM3/ilFbHplRXDk4ehDo5XYgVk2PcQvo10eOrVHO/"
            + "9YMXzb8ZYwkbdiQGPB/1nQNl80mWcVQjw2atlyoWm7MKpqZDjil2t59s8Jxv"
            + "IXqc0o7FkpB6r8i2TKZuWkUhyzrPBr+i6yuFfJg6diV2huGYTZ2lcNO7TiMj"
            + "pRgq8KjK59Cm8iosvJxGTAd2KXZBAxCamiIYEhNHFRmBX5+PR+zpeG0p+t2k"
            + "voqMwoEHcbSh4L6h/aiH6fFpPMjdKuYKj1QOJ2Aie2HbhYqbE6ewAgADmQEN"
            + "BFj1fKQBCACZB8WV+FuMc4Ryh/Z9/AwdV2h0kRaux2A/7fsvoSVPUi4o89hN"
            + "uzULN7qfw3kcoYf63LsAXT9xYeYmrBpPhUg/jWSHqb7sX3du30hRO2YaikPJ"
            + "VD1j241zn9VjwBsKNbbUSp1pxvCjhQazwm06wFKWfJ7KbyHrZuH0F1ynLga3"
            + "6UNfPrHPxxDaBx3TlvEM0dJMu5dhPyWpUUTMAM1cEzkY13W2evwZ9mmvnJEc"
            + "kKuomoLk1rVGLsyP0OH8uR3+2Uvm2zFUnr/zRm7y6561nlJNTCr+Y3U+4j05"
            + "VwunRyA85Kw6QqEhVq7E2e49rPafSfgF5wcvcCnnyaumtY8efo9rABEBAAG0"
            + "EXRyaXBsZS1zaWduZWQta2V5iQE/BBMBCAApAhsDBwsJCAcDAgEGFQgCCQoL"
            + "BBYCAwECHgECF4AFAlj1fVEFCQBB660ACgkQifz6SyM2MzO2Qgf/SlF+9qsf"
            + "nMJyH+8sn+v4wyarKbHvXh6oXLRWp2pdtRXD/H2HfkTj9zCnSwDuos1mAtet"
            + "YDRX/dc6C4YRTUJM9VHmHXkQJN8cW1b33cleHSViUdSmKRMCDYoCYbgT7k2u"
            + "wZx+OQZLxqQ9oT7AqJFhxxSJNYKDBwOPJmV++8L84FCOFxO1bwfpwq0zRTlL"
            + "WSMRwcwICeBaZ6qwCuHSxVzHL27JEWLM1v5T2DWYYY8TCgH0sspO3FLepPaS"
            + "mMHsUoX1vo72fTqzSeucO7eFWMX919h/2YsVpk/G8c3N7YaulAa0bfc1C+1u"
            + "iRygA978Uh7dwO8fGX7ZZApk/mCoKQwB7LACAAOJAT8EEwEIACkFAlj1fKQC"
            + "GwMFCQANLwAHCwkIBwMCAQYVCAIJCgsEFgIDAQIeAQIXgAAKCRCJ/PpLIzYz"
            + "Mw9GB/4mzkmW2HeeAXDvy2KZqpoGnrzR8AO3HmkZBPKV+kXTDp4Vpt6Tr9AB"
            + "Sg3IOv07mLj9T7v0UI4HiKX+s8vFVGGE1Ad74zYJTJJNBKojSP4ZmqldJbS1"
            + "DbvqfYxZgm/oC56qtKhLI/eB/3lPJxrGWnB5Vq9HbRY5Y3Jrvky8LLM7rhfn"
            + "8MDFJGQebgC4RaR/AhQ8wstp2LnwsqptUX06sQXzfNKjv1N1JjCV5WUPDnI+"
            + "wEXt0jvlcVN7BVNGOnMVuQt3HSJcDHSwUrVkIOZMbTfNsW7n6LiTYdOZZsVS"
            + "I5KEEx23DYOKwWwBagGII4RlhYJO1cm6XediuZMqLl1qwIjwsAIAA4kBPwQT"
            + "AQgAKQIbAwcLCQgHAwIBBhUIAgkKCwQWAgMBAh4BAheABQJY9XzpBQkSzANF"
            + "AAoJEIn8+ksjNjMzih4H/RUKWx4oHSI+QfsNwWUFjxgoM8qPuya248fJVqTr"
            + "zqT2zhEctLKcyFsei7QcgfksJyZklY9AV0NeNCXkg6iUoX+5ZTxpu2Fblf6l"
            + "7ZKzQZPGV1lWBbOW+ybm8xGpmKZaNYiFHjVvXZ4QNkvQMw+GCe+D+yQxvMIm"
            + "G5/1k7VrEGpwL31BaiBsoQ2ADHXAHk7Aa+4stp8V3db2jNzln6aHbriGvjLH"
            + "FUa2CstdtfBo52hzWcQGSp4XsbEcrjP6bYskJW+spJjvLL48tFMbSFIdNJMo"
            + "l6WIXBItbCkG9GUbAK6t3reIeVvoXLqKN/vzWFPJ6B1JLmRfRU5q5GFBBzvH"
            + "TZOwAgADuQENBFj1fKQBCAC3B46wgfnaS/TgBQD284P+isKn6jcEy79oivV0"
            + "lMTrQxexQBbzXnCBt2l8p+kOYm8YTeNJecg7gpTYLckbL2EsMwhiLt3mrgiB"
            + "eFdRhNbuYH9jXekysE3zmGmM4BS/KjIcm8Jngk2zVY/o/GA6Mg3s3XgCU4Fa"
            + "HYd+ojbkORVI3p1MF/hy3Rqbe1WJKgPOCXW+n/TLMzciRr0Y8EVCcSopFCGX"
            + "6QFJVKPwYLqIKfYkJhyEmIAlBu1747ysAV42Bfr5TjkNH+jIOy4rDVYjDzCS"
            + "pwx/TF/7970QEYlwPQYKEZGW2yYVKq4Y0pMKbAwo/sCpjI2cOu9cwcLkBlFg"
            + "8/hlABEBAAGJASUEGAEIAA8CGwwFAlj1fVYFCQBB67IACgkQifz6SyM2MzMf"
            + "DAf/T/rfVynO00CLLX5oMvRJITQH6yu7aiCqOJEsDaxxpQL3tJhMJRyybCmI"
            + "kXATcEtn6GNAbGJViw6I1o1K6HmeAHECxR64uKvhsMeoC0XuPPvVZD7qAUaQ"
            + "KRi6l4j/2e7YCqp5F+Xz1zhER2nwGnqYpM7IR0M3OPbwQVgPe2FaQYYnY16J"
            + "bGHyFtdfwyJEzzR8YMcgAnrD8TI+SvErFEH+0vzV+JA1gjYd2l3/ijDj82rn"
            + "WDoIM5gfjeZgwht1vl6+7J+h20yjFrBdf7gJj9OcIGmwlpQ56qzbT4U++mw3"
            + "pW2tN2VuYtreceEoI4B6yUGMEhI9t/asLgn7wEAU2lpuE7ACAAM=");
    byte[] pub2 = Base64.decode(
        "mQGiBEBtfW8RBADfWjTxFedIbGBNVgh064D/OCf6ul7x4PGsCl+BkAyheYkr"
            + "mVUsChmBKoeXaY+Fb85wwusXzyM/6JFK58Rg+vEb3Z19pue8Ixxq7cRtCtOA"
            + "tOP1eKXLNtTRWJutvLkQmeOa19UZ6ziIq23aWuWKSq+KKMWek2GUnGycnx5M"
            + "W0pn1QCg/39r9RKhY9cdKYqRcqsr9b2B/AsD/Ru24Q15Jmrsl9zZ6EC47J49"
            + "iNW5sLQx1qf/mgfVWQTmU2j6gq4ND1OuK7+0OP/1yMOUpkjjcqxFgTnDAAoM"
            + "hHDTzCv/aZzIzmMvgLsYU3aIMfbz+ojpuASMCMh+te01cEMjiPWwDtdWWOdS"
            + "OSyX9ylzhO3PiNDks8R83onsacYpA/9WhTcg4bvkjaj66I7wGZkm3BmTxNSb"
            + "pE4b5HZDh31rRYhY9tmrryCfFnU4BS2Enjj5KQe9zFv7pUBCBW2oFo8i8Osn"
            + "O6fa1wVN4fBHC6wqWmmpnkFerNPkiC9V75KUFIfeWHmT3r2DVSO3dfdHDERA"
            + "jFIAioMLjhaX6DnODF5KQrABh7QmU2FpIFB1bGxhYmhvdGxhIDxwc2FpQG15"
            + "amF2YXdvcmxkLmNvbT6wAwP//4kAVwQQEQIAFwUCQG19bwcLCQgHAwIKAhkB"
            + "BRsDAAAAAAoJEKXQf/RT99uYmfAAoMKxV5g2owIfmy2w7vSLvOQUpvvOAJ4n"
            + "jB6xJot523rPAQW9itPoGGekirABZ7kCDQRAbX1vEAgA9kJXtwh/CBdyorrW"
            + "qULzBej5UxE5T7bxbrlLOCDaAadWoxTpj0BV89AHxstDqZSt90xkhkn4DIO9"
            + "ZekX1KHTUPj1WV/cdlJPPT2N286Z4VeSWc39uK50T8X8dryDxUcwYc58yWb/"
            + "Ffm7/ZFexwGq01uejaClcjrUGvC/RgBYK+X0iP1YTknbzSC0neSRBzZrM2w4"
            + "DUUdD3yIsxx8Wy2O9vPJI8BD8KVbGI2Ou1WMuF040zT9fBdXQ6MdGGzeMyEs"
            + "tSr/POGxKUAYEY18hKcKctaGxAMZyAcpesqVDNmWn6vQClCbAkbTCD1mpF1B"
            + "n5x8vYlLIhkmuquiXsNV6TILOwACAgf9F7/nJHDayJ3pBVTTVSq2g5WKUXMg"
            + "xxGKTvOahiVRcbO03w0pKAkH85COakVfe56sMYpWRl36adjNoKOxaciow74D"
            + "1R5snY/hv/kBXPBkzo4UMkbANIVaZ0IcnLp+rkkXcDVbRCibZf8FfCY1zXbq"
            + "d680UtEgRbv1D8wFBqfMt7kLsuf9FnIw6vK4DU06z5ZDg25RHGmswaDyY6Mw"
            + "NGCrKGbHf9I/T7MMuhGF/in8UU8hv8uREOjseOqklG3/nsI1hD/MdUC7fzXi"
            + "MRO4RvahLoeXOuaDkMYALdJk5nmNuCL1YPpbFGttI3XsK7UrP/Fhd8ND6Nro"
            + "wCqrN6keduK+uLABh4kATAQYEQIADAUCQG19bwUbDAAAAAAKCRCl0H/0U/fb"
            + "mC/0AJ4r1yvyu4qfOXlDgmVuCsvHFWo63gCfRIrCB2Jv/N1cgpmq0L8LGHM7"
            + "G/KwAWeZAQ0EQG19owEIAMnavLYqR7ffaDPbbq+lQZvLCK/3uA0QlyngNyTa"
            + "sDW0WC1/ryy2dx7ypOOCicjnPYfg3LP5TkYAGoMjxH5+xzM6xfOR+8/EwK1z"
            + "N3A5+X/PSBDlYjQ9dEVKrvvc7iMOp+1K1VMf4Ug8Yah22Ot4eLGP0HRCXiv5"
            + "vgdBNsAl/uXnBJuDYQmLrEniqq/6UxJHKHxZoS/5p13Cq7NfKB1CJCuJXaCE"
            + "TW2do+cDpN6r0ltkF/r+ES+2L7jxyoHcvQ4YorJoDMlAN6xpIZQ8dNaTYP/n"
            + "Mx/pDS3shUzbU+UYPQrreJLMF1pD+YWP5MTKaZTo+U/qPjDFGcadInhPxvh3"
            + "1ssAEQEAAbABh7QuU2FuZGh5YSBQdWxsYWJob3RsYSA8cHNhbmRoeWFAbXlq"
            + "YXZhd29ybGQuY29tPrADA///iQEtBBABAgAXBQJAbX2jBwsJCAcDAgoCGQEF"
            + "GwMAAAAACgkQx87DL9gOvoeVUwgAkQXYiF0CxhKbDnuabAssnOEwJrutgCRO"
            + "CJRQvIwTe3fe6hQaWn2Yowt8OQtNFiR8GfAY6EYxyFLKzZbAI/qtq5fHmN3e"
            + "RSyNWe6d6e17hqZZL7kf2sVkyGTChHj7Jiuo7vWkdqT2MJN6BW5tS9CRH7Me"
            + "D839STv+4mAAO9auGvSvicP6UEQikAyCy/ihoJxLQlspfbSNpi0vrUjCPT7N"
            + "tWwfP0qF64i9LYkjzLqihnu+UareqOPhXcWnyFKrjmg4ezQkweNU2pdvCLbc"
            + "W24FhT92ivHgpLyWTswXcqjhFjVlRr0+2sIz7v1k0budCsJ7PjzOoH0hJxCv"
            + "sJQMlZR/e7ABZ7kBDQRAbX2kAQgAm5j+/LO2M4pKm/VUPkYuj3eefHkzjM6n"
            + "KbvRZX1Oqyf+6CJTxQskUWKAtkzzKafPdS5Wg0CMqeXov+EFod4bPEYccszn"
            + "cKd1U8NRwacbEpCvvvB84Yl2YwdWpDpkryyyLI4PbCHkeuwx9Dc2z7t4XDB6"
            + "FyAJTMAkia7nzYa/kbeUO3c2snDb/dU7uyCsyKtTZyTyhTgtl/f9L03Bgh95"
            + "y3mOUz0PimJ0Sg4ANczF4d04BpWkjLNVJi489ifWodPlHm1hag5drYekYpWJ"
            + "+3g0uxs5AwayV9BcOkPKb1uU3EoYQw+nn0Kn314Nvx2M1tKYunuVNLEm0PhA"
            + "/+B8PTq8BQARAQABsAGHiQEiBBgBAgAMBQJAbX2kBRsMAAAAAAoJEMfOwy/Y"
            + "Dr6HkLoH/RBY8lvUv1r8IdTs5/fN8e/MnGeThLl+JrlYF/4t3tjXYIf5xUj/"
            + "c9NdjreKYgHfMtrbVM08LlxUVQlkjuF3DIk5bVH9Blq8aXmyiwiM5GrCry+z"
            + "WiqkpZze1G577C38mMJbHDwbqNCLALMzo+W2q04Avl5sniNnDNGbGz9EjhRg"
            + "o7oS16KkkD6Ls4RnHTEZ0vyZOXodDHu+sk/2kzj8K07kKaM8rvR7aDKiI7HH"
            + "1GxJz70fn1gkKuV2iAIIiU25bty+S3wr+5h030YBsUZF1qeKCdGOmpK7e9Of"
            + "yv9U7rf6Z5l8q+akjqLZvej9RnxeH2Um7W+tGg2me482J+z6WOawAWc=");

    private static byte[] secWithPersonalCertificate = Base64.decode(
        "lQOYBEjGLGsBCACp1I1dZKsK4N/I0/4g02hDVNLdQkDZfefduJgyJUyBGo/I"
            + "/ZBpc4vT1YwVIdic4ADjtGB4+7WohN4v8siGzwRSeXardSdZVIw2va0JDsQC"
            + "yeoTnwVkUgn+w/MDgpL0BBhTpr9o3QYoo28/qKMni3eA8JevloZqlAbQ/sYq"
            + "rToMAqn0EIdeVVh6n2lRQhUJaNkH/kA5qWBpI+eI8ot/Gm9kAy3i4e0Xqr3J"
            + "Ff1lkGlZuV5H5p/ItZui9BDIRn4IDaeR511NQnKlxFalM/gP9R9yDVI1aXfy"
            + "STcp3ZcsTOTGNzACtpvMvl6LZyL42DyhlOKlJQJS81wp4dg0LNrhMFOtABEB"
            + "AAEAB/0QIH5UEg0pTqAG4r/3v1uKmUbKJVJ3KhJB5xeSG3dKWIqy3AaXR5ZN"
            + "mrJfXK7EfC5ZcSAqx5br1mzVl3PHVBKQVQxvIlmG4r/LKvPVhQYZUFyJWckZ"
            + "9QMR+EA0Dcran9Ds5fa4hH84jgcwalkj64XWRAKDdVh098g17HDw+IYnQanl"
            + "7IXbYvh+1Lr2HyPo//vHX8DxXIJBv+E4skvqGoNfCIfwcMeLsrI5EKo+D2pu"
            + "kAuBYI0VBiZkrJHFXWmQLW71Mc/Bj7wTG8Q1pCpu7YQ7acFSv+/IOCsB9l9S"
            + "vdB7pNhB3lEjYFGoTgr03VfeixA7/x8uDuSXjnBdTZqmGqkZBADNwCqlzdaQ"
            + "X6CjS5jc3vzwDSPgM7ovieypEL6NU3QDEUhuP6fVvD2NYOgVnAEbJzgOleZS"
            + "W2AFXKAf5NDxfqHnBmo/jlYb5yZV5Y+8/poLLj/m8t7sAfAmcZqGXfYMbSbe"
            + "tr6TGTUXcXgbRyU5oH1e4iq691LOwZ39QjL8lNQQywQA006XYEr/PS9uJkyM"
            + "Cg+M+nmm40goW4hU/HboFh9Ru6ataHj+CLF42O9sfMAV02UcD3Agj6w4kb5L"
            + "VswuwfmY+17IryT81d+dSmDLhpo6ufKoAp4qrdP+bzdlbfIim4Rdrw5vF/Yk"
            + "rC/Nfm3CLJxTimHJhqFx4MG7yEC89lxgdmcD/iJ3m41fwS+bPN2rrCAf7j1u"
            + "JNr/V/8GAnoXR8VV9150BcOneijftIIYKKyKkV5TGwcTfjaxRKp87LTeC3MV"
            + "szFDw04MhlIKRA6nBdU0Ay8Yu+EjXHK2VSpLG/Ny+KGuNiFzhqgBxM8KJwYA"
            + "ISa1UEqWjXoLU3qu1aD7cCvANPVCOASwAYe0GlBHUCBEZXNrdG9wIDxpbmZv"
            + "QHBncC5jb20+sAMD//+JAW4EEAECAFgFAkjGLGswFIAAAAAAIAAHcHJlZmVy"
            + "cmVkLWVtYWlsLWVuY29kaW5nQHBncC5jb21wZ3BtaW1lBwsJCAcDAgoCGQEF"
            + "GwMAAAADFgECBR4BAAAABRUCCAkKAAoJEHHHqp2m1tlWsx8H/icpHl1Nw17A"
            + "D6MJN6zJm+aGja+5BOFxOsntW+IV6JI+l5WwiIVE8xTDhoXW4zdH3IZTqoyY"
            + "frtkqLGpvsPtAQmV6eiPgE3+25ahL+MmjXKsceyhbZeCPDtM2M382VCHYCZK"
            + "DZ4vrHVgK/BpyTeP/mqoWra9+F5xErhody71/cLyIdImLqXgoAny6YywjuAD"
            + "2TrFnzPEBmZrkISHVEso+V9sge/8HsuDqSI03BAVWnxcg6aipHtxm907sdVo"
            + "jzl2yFbxCCCaDIKR7XVbmdX7VZgCYDvNSxX3WEOgFq9CYl4ZlXhyik6Vr4XP"
            + "7EgqadtfwfMcf4XrYoImSQs0gPOd4QqwAWedA5gESMYsawEIALiazFREqBfi"
            + "WouTjIdLuY09Ks7PCkn0eo/i40/8lEj1R6JKFQ5RlHNnabh+TLvjvb3nOSU0"
            + "sDg+IKK/JUc8/Fo7TBdZvARX6BmltEGakqToDC3eaF9EQgHLEhyE/4xXiE4H"
            + "EeIQeCHdC7k0pggEuWUn5lt6oeeiPUWhqdlUOvzjG+jqMPJL0bk9STbImHUR"
            + "EiugCPTekC0X0Zn0yrwyqlJQMWnh7wbSl/uo4q45K7qOhxcijo+hNNrkRAMi"
            + "fdNqD4s5qDERqqHdAAgpWqydo7zV5tx0YSz5fjh59Z7FxkUXpcu1WltT6uVn"
            + "hubiMTWpXzXOQI8wZL2fb12JmRY47BEAEQEAAQAH+wZBeanj4zne+fBHrWAS"
            + "2vx8LYiRV9EKg8I/PzKBVdGUnUs0vTqtXU1dXGXsAsPtu2r1bFh0TQH06gR1"
            + "24iq2obgwkr6x54yj+sZlE6SU0SbF/mQc0NCNAXtSKV2hNXvy+7P+sVJR1bn"
            + "b5ukuvkj1tgEln/0W4r20qJ60F+M5QxXg6kGh8GAlo2tetKEv1NunAyWY6iv"
            + "FTnSaIJ/YaKQNcudNvOJjeIakkIzfzBL+trUiI5n1LTBB6+u3CF/BdZBTxOy"
            + "QwjAh6epZr+GnQqeaomFxBc3mU00sjrsB1Loso84UIs6OKfjMkPoZWkQrQQW"
            + "+xvQ78D33YwqNfXk/5zQAxkEANZxJGNKaAeDpN2GST/tFZg0R5GPC7uWYC7T"
            + "pG100mir9ugRpdeIFvfAa7IX2jujxo9AJWo/b8hq0q0koUBdNAX3xxUaWy+q"
            + "KVCRxBifpYVBfEViD3lsbMy+vLYUrXde9087YD0c0/XUrj+oowWJavblmZtS"
            + "V9OjkQW9zoCigpf5BADcYV+6bkmJtstxJopJG4kD/lr1o35vOEgLkNsMLayc"
            + "NuzES084qP+8yXPehkzSsDB83kc7rKfQCQMZ54V7KCCz+Rr4wVG7FCrFAw4e"
            + "4YghfGVU/5whvbJohl/sXXCYGtVljvY/BSQrojRdP+/iZxFbeD4IKiTjV+XL"
            + "WKSS56Fq2QQAzeoKBJFUq8nqc8/OCmc52WHSOLnB4AuHL5tNfdE9tjqfzZAE"
            + "tx3QB7YGGP57tPQxPFDFJVRJDqw0YxI2tG9Pum8iriKGjHg+oEfFhxvCmPxf"
            + "zDKaGibkLeD7I6ATpXq9If+Nqb5QjzPjFbXBIz/q2nGjamZmp4pujKt/aZxF"
            + "+YRCebABh4kCQQQYAQIBKwUCSMYsbAUbDAAAAMBdIAQZAQgABgUCSMYsawAK"
            + "CRCrkqZshpdZSNAiB/9+5nAny2O9/lp2K2z5KVXqlNAHUmd4S/dpqtsZCbAo"
            + "8Lcr/VYayrNojga1U7cyhsvFky3N9wczzPHq3r9Z+R4WnRM1gpRWl+9+xxtd"
            + "ZxGfGzMRlxX1n5rCqltKKk6IKuBAr2DtTnxThaQiISO2hEw+P1MT2HnSzMXt"
            + "zse5CZ5OiOd/bm/rdvTRD/JmLqhXmOFaIwzdVP0dR9Ld4Dug2onOlIelIntC"
            + "cywY6AmnL0DThaTy5J8MiMSPamSmATl4Bicm8YRbHHz58gCYxI5UMLwtwR1+"
            + "rSEmrB6GwVHZt0/BzOpuGpvFZI5ZmC5yO/waR1hV+VYj025cIz+SNuDPyjy4"
            + "AAoJEHHHqp2m1tlW/w0H/3w38SkB5n9D9JL3chp+8fex03t7CQowVMdsBYNY"
            + "qI4QoVQkakkxzCz5eF7rijXt5eC3NE/quWhlMigT8LARiwBROBWgDRFW4WuX"
            + "6MwYtjKKUkZSkBKxP3lmaqZrJpF6jfhPEN76zr/NxWPC/nHRNldUdqkzSu/r"
            + "PeJyePMofJevzMkUzw7EVtbtWhZavCz+EZXRTZXub9M4mDMj64BG6JHMbVZI"
            + "1iDF2yka5RmhXz9tOhYgq80m7UQUb1ttNn86v1zVbe5lmB8NG4Ndv+JaaSuq"
            + "SBZOYQ0ZxtMAB3vVVLZCWxma1P5HdXloegh+hosqeu/bl0Wh90z5Bspt6eI4"
            + "imqwAWeVAdgESMYtmwEEAM9ZeMFxor7oSoXnhQAXD9lXLLfBky6IcIWISY4F"
            + "JWc8sK8+XiVzpOrefKro0QvmEGSYcDFQMHdScBLOTsiVJiqenA7fg1bkBr/M"
            + "bnD7vTKMJe0DARlU27tE5hsWCDYTluxIFjGcAcecY2UqHkqpctYKY0WY9EIm"
            + "dBA5TYaw3c0PABEBAAEAA/0Zg6318nC57cWLIp5dZiO/dRhTPZD0hI+BWZrg"
            + "zJtPT8rXVY+qK3Jwquig8z29/r+nppEE+xQWVWDlv4M28BDJAbGE+qWKAZqT"
            + "67lyKgc0c50W/lfbGvvs+F7ldCcNpFvlk79GODKxcEeTGDQKb9R6FnHFee/K"
            + "cZum71O3Ku3vUQIA3B3PNM+tKocIUNDHnInuLyqLORwQBNGfjU/pLMM0MkpP"
            + "lWeIfgUmn2zL/e0JrRoO0LQqX1LN/TlfcurDM0SEtwIA8Sba9OpDq99Yz360"
            + "FiePJiGNNlbj9EZsuGJyMVXL1mTLA6WHnz5XZOfYqJXHlmKvaKDbARW4+0U7"
            + "0/vPdYWSaQIAwYeo2Ce+b7M5ifbGMDWYBisEvGISg5xfvbe6qApmHS4QVQzE"
            + "Ym81rdJJ8OfvgSbHcgn37S3OBXIQvNdejF4BWqM9sAGHtCBIeW5lay1JbnRy"
            + "YW5ldCA8aHluZWtAYWxzb2Z0LmN6PrADA///iQDrBBABAgBVBQJIxi2bBQkB"
            + "mgKAMBSAAAAAACAAB3ByZWZlcnJlZC1lbWFpbC1lbmNvZGluZ0BwZ3AuY29t"
            + "cGdwbWltZQULBwgJAgIZAQUbAQAAAAUeAQAAAAIVAgAKCRDlTa3BE84gWVKW"
            + "BACcoCFKvph9r9QiHT1Z3N4wZH36Uxqu/059EFALnBkEdVudX/p6S9mynGRk"
            + "EfhmWFC1O6dMpnt+ZBEed/4XyFWVSLPwirML+6dxfXogdUsdFF1NCRHc3QGc"
            + "txnNUT/zcZ9IRIQjUhp6RkIvJPHcyfTXKSbLviI+PxzHU2Padq8pV7ABZ7kA"
            + "jQRIfg8tAQQAutJR/aRnfZYwlVv+KlUDYjG8YQUfHpTxpnmVu7W6N0tNg/Xr"
            + "5dg50wq3I4HOamRxUwHpdPkXyNF1szpDSRZmlM+VmiIvJDBnyH5YVlxT6+zO"
            + "8LUJ2VTbfPxoLFp539SQ0oJOm7IGMAGO7c0n/QV0N3hKUfWgCyJ+sENDa0Ft"
            + "JycAEQEAAbABj4kEzQQYAQIENwUCSMYtnAUJAeEzgMLFFAAAAAAAFwNleDUw"
            + "OWNlcnRpZmljYXRlQHBncC5jb20wggNhMIICyqADAgECAgkA1AoCoRKJCgsw"
            + "DQYJKoZIhvcNAQEFBQAwgakxCzAJBgNVBAYTAkNaMRcwFQYDVQQIEw5DemVj"
            + "aCBSZXB1YmxpYzESMBAGA1UEChQJQSYmTCBzb2Z0MSAwHgYDVQQLExdJbnRl"
            + "cm5hbCBEZXZlbG9wbWVudCBDQTEqMCgGA1UEAxQhQSYmTCBzb2Z0IEludGVy"
            + "bmFsIERldmVsb3BtZW50IENBMR8wHQYJKoZIhvcNAQkBFhBrYWRsZWNAYWxz"
            + "b2Z0LmN6MB4XDTA4MDcxNjE1MDkzM1oXDTA5MDcxNjE1MDkzM1owaTELMAkG"
            + "A1UEBhMCQ1oxFzAVBgNVBAgTDkN6ZWNoIFJlcHVibGljMRIwEAYDVQQKFAlB"
            + "JiZMIHNvZnQxFDASBgNVBAsTC0RldmVsb3BtZW50MRcwFQYDVQQDEw5IeW5l"
            + "ay1JbnRyYW5ldDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAutJR/aRn"
            + "fZYwlVv+KlUDYjG8YQUfHpTxpnmVu7W6N0tNg/Xr5dg50wq3I4HOamRxUwHp"
            + "dPkXyNF1szpDSRZmlM+VmiIvJDBnyH5YVlxT6+zO8LUJ2VTbfPxoLFp539SQ"
            + "0oJOm7IGMAGO7c0n/QV0N3hKUfWgCyJ+sENDa0FtJycCAwEAAaOBzzCBzDAJ"
            + "BgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBD"
            + "ZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUNaw7A6r10PtYZzAvr9CrSKeRYJgwHwYD"
            + "VR0jBBgwFoAUmqSRM8rN3+T1+tkGiqef8S5suYgwGgYDVR0RBBMwEYEPaHlu"
            + "ZWtAYWxzb2Z0LmN6MCgGA1UdHwQhMB8wHaAboBmGF2h0dHA6Ly9wZXRyazIv"
            + "Y2EvY2EuY3JsMAsGA1UdDwQEAwIF4DANBgkqhkiG9w0BAQUFAAOBgQCUdOWd"
            + "7mBLWj1/GSiYgfwgdTrgk/VZOJvMKBiiFyy1iFEzldz6Xx+mAexnFJKfZXZb"
            + "EMEGWHfWPmgJzAtuTT0Jz6tUwDmeLH3MP4m8uOZtmyUJ2aq41kciV3rGxF0G"
            + "BVlZ/bWTaOzHdm6cjylt6xxLt6MJzpPBA/9ZfybSBh1DaAUbDgAAAJ0gBBkB"
            + "AgAGBQJIxi2bAAoJEAdYkEWLb2R2fJED/RK+JErZ98uGo3Z81cHkdP3rk8is"
            + "DUL/PR3odBPFH2SIA5wrzklteLK/ZXmBUzcvxqHEgI1F7goXbsBgeTuGgZdx"
            + "pINErxkNpcMl9FTldWKGiapKrhkZ+G8knDizF/Y7Lg6uGd2nKVxzutLXdHJZ"
            + "pU89Q5nzq6aJFAZo5TBIcchQAAoJEOVNrcETziBZXvQD/1mvFqBfWqwXxoj3"
            + "8fHUuFrE2pcp32y3ciO2i+uNVEkNDoaVVNw5eHQaXXWpllI/Pe6LnBl4vkyc"
            + "n3pjONa4PKrePkEsCUhRbIySqXIHuNwZumDOlKzZHDpCUw72LaC6S6zwuoEf"
            + "ucOcxTeGIUViANWXyTIKkHfo7HfigixJIL8nsAFn");

    //
    // PGP8 with SHA1 checksum.
    //
    public byte[] rewrapKey = Base64.decode(
        "lQOWBEUPOQgBCADdjPTtl8oOwqJFA5WU8p7oDK5KRWfmXeXUZr+ZJipemY5RSvAM"
            + "rxqsM47LKYbmXOJznXCQ8+PPa+VxXAsI1CXFHIFqrXSwvB/DUmb4Ec9EuvNd18Zl"
            + "hJAybzmV2KMkaUp9oG/DUvxZJqkpUddNfwqZu0KKKZWF5gwW5Oy05VCpaJxQVXFS"
            + "whdbRfwEENJiNx4RB3OlWhIjY2p+TgZfgQjiGB9i15R+37sV7TqzBUZF4WWcnIRQ"
            + "DnpUfxHgxQ0wO/h/aooyRHSpIx5i4oNpMYq9FNIyakEx/Bomdbs5hW9dFxhrE8Es"
            + "UViAYITgTsyROxmgGatGG09dcmVDJVYF4i7JAAYpAAf/VnVyUDs8HrxYTOIt4rYY"
            + "jIHToBsV0IiLpA8fEA7k078L1MwSwERVVe6oHVTjeR4A9OxE52Vroh2eOLnF3ftf"
            + "6QThVVZr+gr5qeG3yvQ36N7PXNEVOlkyBzGmFQNe4oCA+NR2iqnAIspnekVmwJV6"
            + "xVvPCjWw/A7ZArDARpfthspwNcJAp4SWfoa2eKzvUTznTyqFu2PSS5fwQZUgOB0P"
            + "Y2FNaKeqV8vEZu4SUWwLOqXBQIZXiaLvdKNgwFvUe3kSHdCNsrVzW7SYxFwaEog2"
            + "o6YLKPVPqjlGX1cMOponGp+7n9nDYkQjtEsGSSMQkQRDAcBdSVJmLO07kFOQSOhL"
            + "WQQA49BcgTZyhyH6TnDBMBHsGCYj43FnBigypGT9FrQHoWybfX47yZaZFROAaaMa"
            + "U6man50YcYZPwzDzXHrK2MoGALY+DzB3mGeXVB45D/KYtlMHPLgntV9T5b14Scbc"
            + "w1ES2OUtsSIUs0zelkoXqjLuKnSIYK3mMb67Au7AEp6LXM8EAPj2NypvC86VEnn+"
            + "FH0QHvUwBpmDw0EZe25xQs0brvAG00uIbiZnTH66qsIfRhXV/gbKK9J5DTGIqQ15"
            + "DuPpz7lcxg/n2+SmjQLNfXCnG8hmtBjhTe+udXAUrmIcfafXyu68SAtebgm1ga56"
            + "zUfqsgN3FFuMUffLl3myjyGsg5DnA/oCFWL4WCNClOgL6A5VkNIUait8QtSdCACT"
            + "Y7jdSOguSNXfln0QT5lTv+q1AjU7zjRl/LsFNmIJ5g2qdDyK937FOXM44FEEjZty"
            + "/4P2dzYpThUI4QUohIj8Qi9f2pZQueC5ztH6rpqANv9geZKcciAeAbZ8Md0K2TEU"
            + "RD3Lh+RSBzILtBtUZXN0IEtleSA8dGVzdEBleGFtcGxlLmNvbT6JATYEEwECACAF"
            + "AkUPOQgCGwMGCwkIBwMCBBUCCAMEFgIDAQIeAQIXgAAKCRDYpknHeQaskD9NB/9W"
            + "EbFuLaqZAl3yjLU5+vb75BdvcfL1lUs44LZVwobNp3/0XbZdY76xVPNZURtU4u3L"
            + "sJfGlaF+EqZDE0Mqc+vs5SIb0OnCzNJ00KaUFraUtkByRV32T5ECHK0gMBjCs5RT"
            + "I0vVv+Qmzl4+X1Y2bJ2mlpBejHIrOzrBD5NTJimTAzyfnNfipmbqL8p/cxXKKzS+"
            + "OM++ZFNACj6lRM1W9GioXnivBRC88gFSQ4/GXc8yjcrMlKA27JxV+SZ9kRWwKH2f"
            + "6o6mojUQxnHr+ZFKUpo6ocvTgBDlC57d8IpwJeZ2TvqD6EdA8rZ0YriVjxGMDrX1"
            + "8esfw+iLchfEwXtBIRwS");

    char[] rewrapPass = "voltage123".toCharArray();

    byte[] secretKeyByteArray = Base64.decode(
        "lQOWBEQh2+wBCAD26kte0hO6flr7Y2aetpPYutHY4qsmDPy+GwmmqVeCDkX+"
            + "r1g7DuFbMhVeu0NkKDnVl7GsJ9VarYsFYyqu0NzLa9XS2qlTIkmJV+2/xKa1"
            + "tzjn18fT/cnAWL88ZLCOWUr241aPVhLuIc6vpHnySpEMkCh4rvMaimnTrKwO"
            + "42kgeDGd5cXfs4J4ovRcTbc4hmU2BRVsRjiYMZWWx0kkyL2zDVyaJSs4yVX7"
            + "Jm4/LSR1uC/wDT0IJJuZT/gQPCMJNMEsVCziRgYkAxQK3OWojPSuv4rXpyd4"
            + "Gvo6IbvyTgIskfpSkCnQtORNLIudQSuK7pW+LkL62N+ohuKdMvdxauOnAAYp"
            + "AAf+JCJJeAXEcrTVHotsrRR5idzmg6RK/1MSQUijwPmP7ZGy1BmpAmYUfbxn"
            + "B56GvXyFV3Pbj9PgyJZGS7cY+l0BF4ZqN9USiQtC9OEpCVT5LVMCFXC/lahC"
            + "/O3EkjQy0CYK+GwyIXa+Flxcr460L/Hvw2ZEXJZ6/aPdiR+DU1l5h99Zw8V1"
            + "Y625MpfwN6ufJfqE0HLoqIjlqCfi1iwcKAK2oVx2SwnT1W0NwUUXjagGhD2s"
            + "VzJVpLqhlwmS0A+RE9Niqrf80/zwE7QNDF2DtHxmMHJ3RY/pfu5u1rrFg9YE"
            + "lmS60mzOe31CaD8Li0k5YCJBPnmvM9mN3/DWWprSZZKtmQQA96C2/VJF5EWm"
            + "+/Yxi5J06dG6Bkz311Ui4p2zHm9/4GvTPCIKNpGx9Zn47YFD3tIg3fIBVPOE"
            + "ktG38pEPx++dSSFF9Ep5UgmYFNOKNUVq3yGpatBtCQBXb1LQLAMBJCJ5TQmk"
            + "68hMOEaqjMHSOa18cS63INgA6okb/ueAKIHxYQcEAP9DaXu5n9dZQw7pshbN"
            + "Nu/T5IP0/D/wqM+W5r+j4P1N7PgiAnfKA4JjKrUgl8PGnI2qM/Qu+g3qK++c"
            + "F1ESHasnJPjvNvY+cfti06xnJVtCB/EBOA2UZkAr//Tqa76xEwYAWRBnO2Y+"
            + "KIVOT+nMiBFkjPTrNAD6fSr1O4aOueBhBAC6aA35IfjC2h5MYk8+Z+S4io2o"
            + "mRxUZ/dUuS+kITvWph2e4DT28Xpycpl2n1Pa5dCDO1lRqe/5JnaDYDKqxfmF"
            + "5tTG8GR4d4nVawwLlifXH5Ll7t5NcukGNMCsGuQAHMy0QHuAaOvMdLs5kGHn"
            + "8VxfKEVKhVrXsvJSwyXXSBtMtUcRtBNnZ2dnZ2dnZyA8Z2dnQGdnZ2c+iQE2"
            + "BBMBAgAgBQJEIdvsAhsDBgsJCAcDAgQVAggDBBYCAwECHgECF4AACgkQ4M/I"
            + "er3f9xagdAf/fbKWBjLQM8xR7JkRP4ri8YKOQPhK+VrddGUD59/wzVnvaGyl"
            + "9MZE7TXFUeniQq5iXKnm22EQbYchv2Jcxyt2H9yptpzyh4tP6tEHl1C887p2"
            + "J4qe7F2ATua9CzVGwXQSUbKtj2fgUZP5SsNp25guhPiZdtkf2sHMeiotmykF"
            + "ErzqGMrvOAUThrO63GiYsRk4hF6rcQ01d+EUVpY/sBcCxgNyOiB7a84sDtrx"
            + "nX5BTEZDTEj8LvuEyEV3TMUuAjx17Eyd+9JtKzwV4v3hlTaWOvGro9nPS7Ya"
            + "PuG+RtufzXCUJPbPfTjTvtGOqvEzoztls8tuWA0OGHba9XfX9rfgorACAAA=");

    private static final byte[] curve25519Pub = Base64.decode(
        "mDMEXEzydhYJKwYBBAHaRw8BAQdAwHPDYhq7hIsCT0jHNxGh4Mbao9kDkcHZilME" +
            "jfgnnG60N1Rlc3QgS2V5IChEbyBub3QgdXNlIGZvciByZWFsLikgPHRlc3RAd29v" +
            "ZHMtZ2VibGVyLmNvbT6IlgQTFggAPhYhBIuq+f4gKmIa9ZKEqJdUhr00IJstBQJc" +
            "TPJ2AhsDBQkB4TOABQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEJdUhr00IJst" +
            "dHAA/RDOjus5OZL2m9Q9dxOVnWNguT7Cr5cWdJxUeKAWE2c6AQCcQZWA4SmV1dkJ" +
            "U0XKmLeu3xWDpqrydT4+vQXb/Qm9B7g4BFxM8nYSCisGAQQBl1UBBQEBB0AY3XTS" +
            "6S1pwFNc1QhNpEKTStG+LAJpiHPK9QyXBbW9dQMBCAeIfgQYFggAJhYhBIuq+f4g" +
            "KmIa9ZKEqJdUhr00IJstBQJcTPJ2AhsMBQkB4TOAAAoJEJdUhr00IJstmAsBAMRJ" +
            "pvh8iegwrJDMoQc53ZqDRsbieElV6ofB80a+jkzZAQCgpAaY4hZc8GUan2JIqkg0" +
            "gs23h4au7H79KqXYG4a+Bg==");

    byte[] pub1 = Base64.decode(
        "mQGiBEA83v0RBADzKVLVCnpWQxX0LCsevw/3OLs0H7MOcLBQ4wMO9sYmzGYn"
            + "xpVj+4e4PiCP7QBayWyy4lugL6Lnw7tESvq3A4v3fefcxaCTkJrryiKn4+Cg"
            + "y5rIBbrSKNtCEhVi7xjtdnDjP5kFKgHYjVOeIKn4Cz/yzPG3qz75kDknldLf"
            + "yHxp2wCgwW1vAE5EnZU4/UmY7l8kTNkMltMEAJP4/uY4zcRwLI9Q2raPqAOJ"
            + "TYLd7h+3k/BxI0gIw96niQ3KmUZDlobbWBI+VHM6H99vcttKU3BgevNf8M9G"
            + "x/AbtW3SS4De64wNSU3189XDG8vXf0vuyW/K6Pcrb8exJWY0E1zZQ1WXT0gZ"
            + "W0kH3g5ro//Tusuil9q2lVLF2ovJA/0W+57bPzi318dWeNs0tTq6Njbc/GTG"
            + "FUAVJ8Ss5v2u6h7gyJ1DB334ExF/UdqZGldp0ugkEXaSwBa2R7d3HBgaYcoP"
            + "Ck1TrovZzEY8gm7JNVy7GW6mdOZuDOHTxyADEEP2JPxh6eRcZbzhGuJuYIif"
            + "IIeLOTI5Dc4XKeV32a+bWrQidGVzdCAoVGVzdCBrZXkpIDx0ZXN0QHViaWNh"
            + "bGwuY29tPohkBBMRAgAkBQJAPN79AhsDBQkB4TOABgsJCAcDAgMVAgMDFgIB"
            + "Ah4BAheAAAoJEJh8Njfhe8KmGDcAoJWr8xgPr75y/Cp1kKn12oCCOb8zAJ4p"
            + "xSvk4K6tB2jYbdeSrmoWBZLdMLACAAC5AQ0EQDzfARAEAJeUAPvUzJJbKcc5"
            + "5Iyb13+Gfb8xBWE3HinQzhGr1v6A1aIZbRj47UPAD/tQxwz8VAwJySx82ggN"
            + "LxCk4jW9YtTL3uZqfczsJngV25GoIN10f4/j2BVqZAaX3q79a3eMiql1T0oE"
            + "AGmD7tO1LkTvWfm3VvA0+t8/6ZeRLEiIqAOHAAQNBACD0mVMlAUgd7REYy/1"
            + "mL99Zlu9XU0uKyUex99sJNrcx1aj8rIiZtWaHz6CN1XptdwpDeSYEOFZ0PSu"
            + "qH9ByM3OfjU/ya0//xdvhwYXupn6P1Kep85efMBA9jUv/DeBOzRWMFG6sC6y"
            + "k8NGG7Swea7EHKeQI40G3jgO/+xANtMyTIhPBBgRAgAPBQJAPN8BAhsMBQkB"
            + "4TOAAAoJEJh8Njfhe8KmG7kAn00mTPGJCWqmskmzgdzeky5fWd7rAKCNCp3u"
            + "ZJhfg0htdgAfIy8ppm05vLACAAA=");

    byte[] testPrivKey = Base64.decode(
        "lQH8BD89pyQBBADk1aljL6mBOvd6k4Myr/0yaSI94SPC5WDwuptXZNM92wy8FVZP"
            + "RRQAfglkvEXRTlrfxRt7RL9p83KDXUb47/VgC8iBjWsLWnuDJeqAE9Ov+ddclM1x"
            + "zpPvcSt8JFzeY3c1IX+HANqBqS0lf6WZaHLCAy/owlELbplD8BaHZkh4cwAGKf4D"
            + "AwKbLeIOVYTEdWD5v/YgW8ERs0pDsSIfBTvsJp2qA798KeFuED6jGsHUzdi1M990"
            + "6PRtplQgnoYmYQrzEc6DXAiAtBR4Kuxi4XHx0ZR2wpVlVxm2Ypgz7pbBNWcWqzvw"
            + "33inl7tR4IDsRdJOY8cFlN+1tSCf16sDidtKXUVjRjZNYJytH18VfSPlGXMeYgtw"
            + "3cSGNTERwKaq5E/SozT2MKTiORO0g0Mtyz+9MEB6XVXFavMun/mXURqbZN/k9BFb"
            + "z+TadpkihrLD1xw3Hp+tpe4CwPQ2GdWKI9KNo5gEnbkJgLrSMGgWalPhknlNHRyY"
            + "bSq6lbIMJEE3LoOwvYWwweR1+GrV9farJESdunl1mDr5/d6rKru+FFDwZM3na1IF"
            + "4Ei4FpqhivZ4zG6pN5XqLy+AK85EiW4XH0yAKX1O4YlbmDU4BjxhiwTdwuVMCjLO"
            + "5++jkz5BBQWdFX8CCMA4FJl36G70IbGzuFfOj07ly7QvRXJpYyBFY2hpZG5hICh0"
            + "ZXN0IGtleSkgPGVyaWNAYm91bmN5Y2FzdGxlLm9yZz6IuAQTAQIAIgUCPz2nJAIb"
            + "AwUJAIPWAAQLBwMCAxUCAwMWAgECHgECF4AACgkQNVhhRv3z83PFjAP/QW47gfBO"
            + "PEAJcaIlX/VPEnzXpa8/zjSQP2zL1q/yZzhgPTz5hQ+VHPpFf6voveHRDI7AuQkN"
            + "ZqFB1kj9sZUIWzswT9vqD18N89nwbPVyYJ0x+kFjAALy7N7oPaaNJaDRy6G0/w/1"
            + "3V73K298L8Lz09habWaq7aJx/znc0/SXX6w=");

    byte[] testPubKey = Base64.decode(
        "mIsEPz2nJAEEAOTVqWMvqYE693qTgzKv/TJpIj3hI8LlYPC6m1dk0z3bDLwVVk9F"
            + "FAB+CWS8RdFOWt/FG3tEv2nzcoNdRvjv9WALyIGNawtae4Ml6oAT06/511yUzXHO"
            + "k+9xK3wkXN5jdzUhf4cA2oGpLSV/pZlocsIDL+jCUQtumUPwFodmSHhzAAYptC9F"
            + "cmljIEVjaGlkbmEgKHRlc3Qga2V5KSA8ZXJpY0Bib3VuY3ljYXN0bGUub3JnPoi4"
            + "BBMBAgAiBQI/PackAhsDBQkAg9YABAsHAwIDFQIDAxYCAQIeAQIXgAAKCRA1WGFG"
            + "/fPzc8WMA/9BbjuB8E48QAlxoiVf9U8SfNelrz/ONJA/bMvWr/JnOGA9PPmFD5Uc"
            + "+kV/q+i94dEMjsC5CQ1moUHWSP2xlQhbOzBP2+oPXw3z2fBs9XJgnTH6QWMAAvLs"
            + "3ug9po0loNHLobT/D/XdXvcrb3wvwvPT2FptZqrtonH/OdzT9JdfrA==");

    byte[] jpegImage = Base64.decode(
        "/9j/4AAQSkZJRgABAQEASABIAAD/4QAWRXhpZgAATU0AKgAAAAgAAAAAAAD/2wBDAAUDBAQEAwUE"
            + "BAQFBQUGBwwIBwcHBw8LCwkMEQ8SEhEPERETFhwXExQaFRERGCEYGh0dHx8fExciJCIeJBweHx7/"
            + "wAALCAA6AFABASIA/8QAHAAAAgMAAwEAAAAAAAAAAAAABQcABAYBAggD/8QAMRAAAgEDBAEDAwME"
            + "AQUAAAAAAQIDBAURAAYSITEHIkETFFEjYXEVMkKRCCUzQ4Gh/9oACAEBAAA/APX1TdKCmlaOoqoo"
            + "WXzzbiP9nWaS71lXuA2tqrgopBOxpyGyWLAEEd4GAf3+fOjLPXoVaOcNzYAhl8HskADwAPz37f3z"
            + "opSvI9Mjypwcr7l/B1XuFwSmoTVooljB9xDYAH51Vor191F9dKGb6Py3yo4huwcHwf8AYP7ZLIyu"
            + "gZSGBGQQejrnU1NKn1EqVi3sZJOBCwxxIp9xzksfb5PR+Mdga+ljqIKje1TNBBNToYYgU4477HwQ"
            + "Bn9z8/nW6mqxLR0NzpJkMLx8lJUkOGAIx4I/0f41lJ93UkkrRxVKvNKVjZfpSe6RyqhCp7wCSD89"
            + "EEDRWppEkgqKdYohGcoZAjAlSMMcZ+PHH/3odsG6VLW2qaoqV+nTyFZpHOFQL0Sc9ADGTnHWtZap"
            + "EpoamJm/TgYkfgJ5H/zGuKieVJIGkqCgmfCJFFy64s3Z+Oh58fHyNfGavipIJ2BrZcKXA+mzEd9Y"
            + "OCcHI/gDV62SzvBGKhQHaNWzj8jvP750oN/xM3qkshLPEstOhj7IVyvkY+f7Nd7hf9vbc9QbVb7n"
            + "dadLldqc00FMCwlmZnCrgL2v/cAySPBPwSD+/wC+3HbWx3rLbaqW81CVHOWnetMZjRm9h7VvClcj"
            + "oDB7PymPTvem+a6roxvC10sd3ScmlucdEyUtRADxdice9wY3PQGRgj4OnHU3u5RW+op6imo4q+KA"
            + "1UKGQ/bzrnt0biWxkgFOJK9ZyCCVX6f3T1Rh9RawbltdQNv18CGe2wxBDQyvGrowIJd15HEnHvP+"
            + "OBjXoGzS0tNTpQipFTIw48Xn5SSBVUMw5e5wMgZ/j86yVNvvZ9TeDR1c9XSV0bl443dmYZXiCSCR"
            + "jvxkjR1L1b46iWpStpIRLOWkCqyniP8AJjxPIniBjr+etFdu11DVu321WZiFHRjZcA/gsO+seNYf"
            + "fVpq6n1Eo5KNATIYmb5Bx7csP4z/AKz8aX1N6Q7W3FuWWrS1TRzi+tXSutUESQhCGiVAvJVRgfcc"
            + "HkeidM6tSmTbps9RHIH4KoqC8j/VC8R0+CSScZLdknPZGgNfYpUUUzfewxxcWpopWbhL715KgBIQ"
            + "MCQc4A84+dD963X7ywQ0NIVW60qqzkzIfoszAMGUNyUHORkDrHxo3sSaOhtX2hnp3uNRF9b7hqtO"
            + "DxM3Rcj3dMCPHXLGfOkLuPddp9R/ViOa62KppqK3Vctvsz0UylKtWfgXy3+L8WIZFBGRhs407rTT"
            + "bcuFDRWmtsNGIZ1MMEU9GPqRorKPcJEzhich8Anz350Wk2zs2OsT7D7RZJpChMEk0MoypJZWVwM9"
            + "ZzjWw2lbKaioFjQy/U9shLyu7Esi5JLEnsgnQlaSqhqayWSRZ5JaiSSNPoBCiq54jPuJyA2W+QfA"
            + "+FrSXq4bdulZHRpWRzpArPK0SSNUExh14qB4c5X9ipz41Zud0juVouVooHN6rrZKVaoek/VhYgqE"
            + "4v7cZPTfPHwT7tZX0e2NVUV5rK2ku9TeY6aFZJ6GuLALKzNnizE4CsqHIyBxJCk4AYFNt2wSUExm"
            + "pP1lqgq1zkfXUtIgkiOFHQCsCM/kfOtZU7GsNZU1FFc1lrqCSNSlFOQ8SJk8kC4/tJx1rMwbWt0V"
            + "CW21VW+krVoFTCRrPC0bf+NF8ocqMcT/AIg6EVF5/p9U6zPXLVFGpoKlSpMiEkniSCcqVY+eQIPW"
            + "NULf/UNxJNS0dhklu8SK9Lco6pUcEr0JOu1HQ7z+R5OndaI5leWV0VQ54kA5KlWIx/Gqd2t6vcqe"
            + "FIXNJMs71SoCMsQuG5jsN8AAjyTnrGlt6mVlqswtS0SG71NTXpSiCQFpogckll6Y4wvyD/OToVd7"
            + "3tLedda4Nr3iRK2mqJhW1K0qxSSGJf1OTOAwwVADLkA9fPV2W77msVfPTClNRUyJCla0SqS5dR5J"
            + "b2kluKlQc5BbHnWu2xTS0G4qmjvSq6RwrPHJUMHkkYDhzJHXIhmBAHnxpaL6j3il3D6g1VLuSz1k"
            + "1ht//S6SZQ4KoTI6MyMOb9hR85HedM/0wqn3RsC0bhgq/pQV9J9WELEFaNWGARg+04xkd95xjQTe"
            + "df6c7U+ysl3mtMFJe5JYGkkmAVKgKZCZGzlVbBySemA/OgvpZUQxvaqitgoqSsiX6XKh5RwVCBP0"
            + "8KCTIoU8VJyDjIA8Bs2e5CprDTR8VXi8pRgyyZMh8qQMDHz850ZOlVv30RsW5blcL5S3a626+1cq"
            + "TirFQ0qJIgAQCNjgIMeFKn9wQCMA3o2vprca/ctp29Jv6/3aoZ4IRRx08dC5D8nWQv7FJYHByeuv"
            + "zo5SWn1Z2ttahutFZqbcG6JK5ZLu1TNEzzUq5ASNyVw6pxUMc5Oc5znR6KyXffldUVW4rBcbAqos"
            + "EUq1qrUzUkwy8bFB+m4ZI2IBbAJAbOdau0+nmybJYqe027atvNHTRlYomhVz+Tln8knyScn50j/+"
            + "SOyd3VO2oDtmPcNPYqJgDt23xKtOIiTy6gYO/Z5YOcAHGsJ/x39NgbzuDc+0bNt6/wAySmltbXGv"
            + "flaT8ST07xBjIR30RjsL+dex9uwT/wBKo6i5UtPFdHp4/u/pgECTiOQDYBIByB+w0RVEVmZUUM39"
            + "xA7P867ampqampqaq09BQwV9RWwUVNFU1AUTTJEoeQLnHJgMnGTjP51a1Nf/2Q==");

    char[] pass = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};

    byte[] encMessage =
        Base64.decode("hH4DrQCblwYU61MSAgMEVXjgPW2hvIhUMQ2qlAQlAliZKbyujaYfLnwZTeGvu+pt\n" +
            "gJXt+JJ8zWoENxLAp+Nb3PxJW4CjvkXQ2dEmmvkhBzAhDer86XJBrQLBQUL+6EmE\n" +
            "l+/3Yzt+cPEyEn32BSpkt31F2yGncoefCUDgj9tKiFXSRwGhjRno0qzB3CfRWzDu\n" +
            "eelwwtRcxnvXNc44TuHRf4PgZ3d4dDU69bWQswdQ5UTP/Bjjo92yMLtJ3HtBuym+\n" +
            "NazbQUh4M+SP");

    byte[] sExprKeySub =
        Base64.decode(
            "KDIxOnByb3RlY3RlZC1wcml2YXRlLWtleSgzOmVjYyg1OmN1cnZlMTA6TklT"
                + "VCBQLTI1NikoMTpxNjU6BJlWEj5qR12xbmp5dkjEkV+PRSfk37NKnw8axSJk"
                + "yDTsFNZLIugMLX/zTn3rrOamvHUdXNbLy1s8PeyrztMcOnwpKDk6cHJvdGVj"
                + "dGVkMjU6b3BlbnBncC1zMmszLXNoYTEtYWVzLWNiYygoNDpzaGExODpu2e7w"
                + "pW4L5jg6MTI5MDU0NzIpMTY6ohIkbi1P1O7QX1zgPd7Ejik5NjrCoM9qBxzy"
                + "LVJJMVRGlsjltF9/CeLnRPN1sjeiQrP1vAlZMPiOpYTmGDVRcZhdkCRO06MY"
                + "UTLDZK1wsxELVD0s9irpbskcOnXwqtXbIqhoK4B+9pnkR0h5gi0xPIGSTtYp"
                + "KDEyOnByb3RlY3RlZC1hdDE1OjIwMTQwNjA4VDE1MjgxMCkpKQ==");

    byte[] sExprKeyMaster =
        Base64.decode(
            "KDIxOnByb3RlY3RlZC1wcml2YXRlLWtleSgzOmVjYyg1OmN1cnZlMTA6TklT"
                + "VCBQLTI1NikoMTpxNjU6BGqcUsIHwQRmQAQs2rOeTzJBq79/U8AJRNT9B72O"
                + "XJtzbZs7nkF29l0WhrdGY1AeFH3zT8p5XAJDdw+l7o5AkUApKDk6cHJvdGVj"
                + "dGVkMjU6b3BlbnBncC1zMmszLXNoYTEtYWVzLWNiYygoNDpzaGExODr4PqHT"
                + "9W4lpTg6MTI5MDU0NzIpMTY6VsooQy9aGsuMpiObZk4y1ik5NjoCArOSmSsJ"
                + "IYUzxkRwy/HyDYPqjAqrNrh3m8lQco6k64Pf4SDda/0gKjkum7zYDEzBEvXI"
                + "+ZodAST6z3IDkPHL7LUy5qp2LdG73xLRFjfsqOsZgP+nwoOSUiC7N4AWJPAp"
                + "KDEyOnByb3RlY3RlZC1hdDE1OjIwMTQwNjA4VDE1MjcwOSkpKQ==");

    byte[] testPubKey2 =
        Base64.decode(
            "mFIEU5SAxhMIKoZIzj0DAQcCAwRqnFLCB8EEZkAELNqznk8yQau/f1PACUTU/Qe9\n" +
                "jlybc22bO55BdvZdFoa3RmNQHhR980/KeVwCQ3cPpe6OQJFAtD9OSVNUIFAtMjU2\n" +
                "IChHZW5lcmF0ZWQgYnkgR1BHIDIuMSBiZXRhKSA8bmlzdC1wLTI1NkBleGFtcGxl\n" +
                "LmNvbT6IeQQTEwgAIQUCU5SAxgIbAwYLCQgHAwIGFQgCCQoLAxYCAQIeAQIXgAAK\n" +
                "CRA2iYNe+deDntxvAP90U2BUL2YcxrJYnsK783VIPM5U5/2IhH7azbRfaHiLZgEA\n" +
                "1/BVNxRG/Q07gPSdEGagRZcrzPxMQPLjBL4T7Nq5eSG4VgRTlIDqEggqhkjOPQMB\n" +
                "BwIDBJlWEj5qR12xbmp5dkjEkV+PRSfk37NKnw8axSJkyDTsFNZLIugMLX/zTn3r\n" +
                "rOamvHUdXNbLy1s8PeyrztMcOnwDAQgHiGEEGBMIAAkFAlOUgOoCGwwACgkQNomD\n" +
                "XvnXg556SQD+MCXRkYgLPd0NWWbCKl5wYk4NwWRvOCDFGk7eYoRTKaYBAIkt3J86\n" +
                "Bn0zCzsphjrIUlGPXhLSX/2aJQDuuK3zzLmn");

    byte[] dsaKeyRing = Base64.decode(
        "lQHhBD9HBzURBACzkxRCVGJg5+Ld9DU4Xpnd4LCKgMq7YOY7Gi0EgK92gbaa6+zQ"
            + "oQFqz1tt3QUmpz3YVkm/zLESBBtC1ACIXGggUdFMUr5I87+1Cb6vzefAtGt8N5VV"
            + "1F/MXv1gJz4Bu6HyxL/ncfe71jsNhav0i4yAjf2etWFj53zK6R+Ojg5H6wCgpL9/"
            + "tXVfGP8SqFvyrN/437MlFSUEAIN3V6j/MUllyrZglrtr2+RWIwRrG/ACmrF6hTug"
            + "Ol4cQxaDYNcntXbhlTlJs9MxjTH3xxzylyirCyq7HzGJxZzSt6FTeh1DFYzhJ7Qu"
            + "YR1xrSdA6Y0mUv0ixD5A4nPHjupQ5QCqHGeRfFD/oHzD4zqBnJp/BJ3LvQ66bERJ"
            + "mKl5A/4uj3HoVxpb0vvyENfRqKMmGBISycY4MoH5uWfb23FffsT9r9KL6nJ4syLz"
            + "aRR0gvcbcjkc9Z3epI7gr3jTrb4d8WPxsDbT/W1tv9bG/EHawomLcihtuUU68Uej"
            + "6/wZot1XJqu2nQlku57+M/V2X1y26VKsipolPfja4uyBOOyvbP4DAwIDIBTxWjkC"
            + "GGAWQO2jy9CTvLHJEoTO7moHrp1FxOVpQ8iJHyRqZzLllO26OzgohbiPYz8u9qCu"
            + "lZ9Xn7QzRXJpYyBFY2hpZG5hIChEU0EgVGVzdCBLZXkpIDxlcmljQGJvdW5jeWNh"
            + "c3RsZS5vcmc+iFkEExECABkFAj9HBzUECwcDAgMVAgMDFgIBAh4BAheAAAoJEM0j"
            + "9enEyjRDAlwAnjTjjt57NKIgyym7OTCwzIU3xgFpAJ0VO5m5PfQKmGJRhaewLSZD"
            + "4nXkHg==");

    private static final String TEST_USER_ID = "test user id";

    byte[] rsaKeyRing = Base64.decode(
        "lQIEBEBXUNMBBADScQczBibewnbCzCswc/9ut8R0fwlltBRxMW0NMdKJY2LF"
            + "7k2COeLOCIU95loJGV6ulbpDCXEO2Jyq8/qGw1qD3SCZNXxKs3GS8Iyh9Uwd"
            + "VL07nMMYl5NiQRsFB7wOb86+94tYWgvikVA5BRP5y3+O3GItnXnpWSJyREUy"
            + "6WI2QQAGKf4JAwIVmnRs4jtTX2DD05zy2mepEQ8bsqVAKIx7lEwvMVNcvg4Y"
            + "8vFLh9Mf/uNciwL4Se/ehfKQ/AT0JmBZduYMqRU2zhiBmxj4cXUQ0s36ysj7"
            + "fyDngGocDnM3cwPxaTF1ZRBQHSLewP7dqE7M73usFSz8vwD/0xNOHFRLKbsO"
            + "RqDlLA1Cg2Yd0wWPS0o7+qqk9ndqrjjSwMM8ftnzFGjShAdg4Ca7fFkcNePP"
            + "/rrwIH472FuRb7RbWzwXA4+4ZBdl8D4An0dwtfvAO+jCZSrLjmSpxEOveJxY"
            + "GduyR4IA4lemvAG51YHTHd4NXheuEqsIkn1yarwaaj47lFPnxNOElOREMdZb"
            + "nkWQb1jfgqO24imEZgrLMkK9bJfoDnlF4k6r6hZOp5FSFvc5kJB4cVo1QJl4"
            + "pwCSdoU6luwCggrlZhDnkGCSuQUUW45NE7Br22NGqn4/gHs0KCsWbAezApGj"
            + "qYUCfX1bcpPzUMzUlBaD5rz2vPeO58CDtBJ0ZXN0ZXIgPHRlc3RAdGVzdD6I"
            + "sgQTAQIAHAUCQFdQ0wIbAwQLBwMCAxUCAwMWAgECHgECF4AACgkQs8JyyQfH"
            + "97I1QgP8Cd+35maM2cbWV9iVRO+c5456KDi3oIUSNdPf1NQrCAtJqEUhmMSt"
            + "QbdiaFEkPrORISI/2htXruYn0aIpkCfbUheHOu0sef7s6pHmI2kOQPzR+C/j"
            + "8D9QvWsPOOso81KU2axUY8zIer64Uzqc4szMIlLw06c8vea27RfgjBpSCryw"
            + "AgAA");

    byte[] p384Protected = ("Created: 20211021T023233\n" +
        "Key: (protected-private-key (ecc (curve \"NIST P-384\")(q\n" +
        "  #04CE6089B366EFB0E4238CC43CBC6631708F122AEFF3408B9C14C14E9A2918D0BD18\n" +
        " D800FD90D6FB4142387913E14F78CA232B91A6C87BFE2841778A99D96EB292E6311E81\n" +
        " FEA3D40CE62F4B9641A481846C119AFDE08AE91DC7B7F705280FF077#)(protected\n" +
        "  openpgp-s2k3-ocb-aes ((sha1 #E570C25E5DE65DD7#\n" +
        "  \"43860992\")#83D43BA89B7E7EA2EF758E52#)#CD30B49842A95DD0D18C2D8550CC59\n" +
        " 8187FE6DE7386418A319F7311197FE4344EE29ACC0B77D2EDF19E268DBB2130F82353B\n" +
        " 319D39306CDA53C6D9F883141738B522E35F6F9CD346B4B187578C#)(protected-at\n" +
        "  \"20211021T023240\")))\n").getBytes();

    byte[] p384Open = ("Created: 20211021T235533\n" +
        "Key: (private-key (ecc (curve \"NIST P-384\")(q\n" +
        "  #041F93DB4628A4CC6F5DB1C3CFE952E4EF58C91511BCCDBA2A354975B827EE0D8B38\n" +
        " E4396A28A6FE69F8685B12663C20D055580B5024CC4B15EECAA5BBF82F4170B382F903\n" +
        " C7456DAB72DCC939CDC7B9382B884D61717F8CC51BAB86AE79FEEA51#)(d\n" +
        "  #5356E5F3BAAF9E38AF2A52CBFAEC8E33456E6D60249403A1FA657954DAE088AA9AA7\n" +
        " 9C2AA85CEEA28FE48491CE223F84#)))\n").getBytes();

    byte[] p256Protected = ("Created: 20211022T000103\n" +
        "Key: (protected-private-key (ecc (curve \"NIST P-256\")(q\n" +
        "  #048B510552811D0BE5B6324D7D3FF4CA9CC4B779A875CB7289AE2EDA601E212E3F78\n" +
        " 9A8F58A7BD6D7554BCEBA9D5F59CC2FD99C7865FF47AA951878128837A6299#)(prote\n" +
        " cted openpgp-s2k3-ocb-aes ((sha1 #43AA7C9708083061#\n" +
        "  \"43860992\")#C246761F0A03FE624368BDBC#)#2C1D62FA0C79319653A4053C5ACAA1\n" +
        " B1EB657029F2A94F35D09CD1514A099203B46CDF1AEECA99AE6898B5489DE85DDA55A7\n" +
        " 9D8FD94539ECCCB95D23A6#)(protected-at \"20211022T000110\")))\n").getBytes();

    //https://github.com/bcgit/bc-java/issues/1590
    byte[] curveed25519 = (   /* OpenSSH 6.7p1 generated key:  */
        "(protected-private-key" +
            "(ecc" +
            "(curve Ed25519)" +
            "(flags eddsa)" +
            "(q #40A3577AA7830C50EBC15B538E9505DB2F0D2FFCD57EA477DD83dcaea530f3c277#)" +
            "(protected openpgp-s2k3-sha1-aes-cbc" +
            "(\n" +
            "(sha1 #FA8123F1A37CBC1F# \"3812352\")" +
            "#7671C7387E2DD931CC62C35CBBE08A28#)" +
            "#75e928f4698172b61dffe9ef2ada1d3473f690f3879c5386e2717e5b2fa46884" +
            "b189ee409827aab0ff37f62996e040b5fa7e75fc4d8152c8734e2e648dff90c9" +
            "e8c3e39ea7485618d05c34b1b74ff59676e9a3d932245cc101b5904777a09f86#)" +
            "(protected-at \"20150928T050210\")" +
            ")" +
            "(comment \"eddsa w/o comment\")" +
            ")" + /* Passphrase="abc" */
            "MD5:f1:fa:c8:a6:40:bb:b9:a1:65:d7:62:65:ac:26:78:0e" +
            "SHA256:yhwBfYnTOnSXcWf1EOPo+oIIpNJ6w/bG36udZ96MmsQ" +
            "0" /* The fingerprint works in FIPS mode because ECC algorithm is enabled */
    ).getBytes();
    char[] dsaPass = "hello world".toCharArray();

    byte[] dsaElgamalOpen = ("Created: 20211020T050343\n" +
        "Key: (private-key (elg (p #0082AEA32A1F3A30E08B19F7019E53D7DBC9351C4736\n" +
        " 25ED916439DB0E1DA9EC8CA9FA481F7B8AAC0968AE87FEDB93F9D957B8B62FFDAF15AD\n" +
        " 1375791ED4AE1A201B6E81F2800E1A0A5F600774C940C1C7687E2BDA5F603357BD25D8\n" +
        " BEAFEDEEA547EB4DEF313BBD07385F8532C21FEA4656843207B3A50C375B5ABF9E9886\n" +
        " 0243#)(g #05#)(y #7CF2AF5A729AE8C79A151377B8D8CF6A5DC5CB6450E4C42F2A82\n" +
        " 256CAA9375A0437AA1E1A0B56987FF8C801918664CF77356E8CB7A37764F3CC2EBD7BB\n" +
        " 56FFBF0E8DA3B25C9D697E7F0F609E10F1F35A62002BF5DFC930675C1339272267EBDE\n" +
        " 6588E985D0F1AC44F8C59AC50213D3D618F25C8FDF6EB6DFAC7FBA598EEB7CEA#)(x\n" +
        "  #02222A119771B79D3FA0BF2276769DB90D21F88A836064AFA890212504E12CEA#)))\n").getBytes();

    byte[] theKey = ("Created: 20211022T050720\n" +
        "Key: (private-key (elg (p #009015DEBF6AA2B801EB39EEABC20914FDBD26D8A40B\n" +
        " 6343D99F3328CEF0B76748DDC23840C0D404BE9AFF61590816D630513C5D7D73359DBE\n" +
        " E6FD0E79D5204C518113941AFACA4D8FD608AD659C4EC9DC5ABDF884C0DA7067CB7084\n" +
        " 161D9CDB06D6057DC6FE21C8213FC18F070CD2F53249E22F00B99EE315CB1191848C92\n" +
        " 43C05A453BF2CC3D20A0EA0AE097B9034A7FCA79C279D67EB82CFFD50E54630E73D020\n" +
        " C7248B1EEF6225FA82067CF3DCB40F0614F87949E917E3208CA354A22EC10B65DC1065\n" +
        " 59BEE3DE9B4C03CC65DA8C00F0DA8D19F08CB070BE65D9BF1986A680CAA3CC9A109756\n" +
        " C7F36F48D9902A4D51EE05577C309797F68A3917B28506554E32324226EA3CDF372CD5\n" +
        " 0BD86BA12AACB00EE962D93A621826A225B7C35C65A036DCB7820CAD7C904D1DD6F976\n" +
        " 2ADE5E7B528AC162C5DC0C3A833A6BE3465E97D835CA862BD7ECDF8A6AE2645D607BD8\n" +
        " 067C110C437C9FCC83A7A113DBB12CAD522FCA8E068054D0AF84B0EA45DCA11D3FE875\n" +
        " 1A5A25A84CCE04132FEAB7B993#)(g #06#)(y #5F298179167DF1A10F0260CC2C1916\n" +
        " B0F72AFE7FC173049B28AFEDA196D730FC8667D3E4F11EB51EF9965ADE15D0218C72B0\n" +
        " 64E6501E20BD9013CF2B6EC4350D7666F3E7ABBFE7C982664FDE1B70FDE24C9BDE80AA\n" +
        " 974D46F4723F111B0F6402848694D45FADBD38A5FAF3A17CDF1C8BEC35C6E83841A37A\n" +
        " 68D1B18CE2D5A30DBEDBC660D2074A3C4F4BA8DD724CF3FDB3C0CF21B5BF26AD24D5AE\n" +
        " CFED47001EBAA9231D756AC75A18BB2DF2F86ABD52BABBAD9E9A53890126B990773595\n" +
        " BBE9E9CB8E7505260C07725C3036339C5C1A40B0AF62C534F1E049FC130C78856FD070\n" +
        " 69CFFD1316FD853CABEF72C8DAF268EC0C3F7404085C0336A86C3BB5AC5B4414AA42AE\n" +
        " 26B24A0D87B1AE494766E3D4A14FFCB287E59260AE5EB952F31ADC01DF4F947EFFAF0E\n" +
        " 1F999A3C3F8E8ABAD24B3B56DC140970F22384C8821481E128F6B18D779F27D9492B88\n" +
        " A0EBB72CCB13AB07038448ADDF4A3D00F62E3EC2724730CC052C0C9385469CA364C9FD\n" +
        " 5BAAE4CCBF8635DD034B3FBEBBC2E656DB77A6#)(x\n" +
        "  #0CE0A6B334E053051076D64AFB091C1B585758BC03B1D66A3BEE0C0487707DBE8CBF\n" +
        " B4FD7A5640C3536243CC298017781127B9#)))\n").getBytes();

    byte[] dsaProtected = ("Created: 20211022T053140\n" +
        "Key: (protected-private-key (dsa (p #00CD7275234699FE0D25FDBEE69DA2AA80\n" +
        " AAAB15906FACFC8F4EB5A9BAE23D22E5649199C119FB72951BD0FA717F51CFD7B904FD\n" +
        " BB1F0D0660938199976DA4447F54E91E2CC4B21F4BB162644EA43A3F27F7CAFF7D6355\n" +
        " 16E8640558E222EF20B55E8AF2AFD33D571092CE5C090E57DA3452484BC04398E24613\n" +
        " D593113F1F5CE7CA3229F5DFAFC1EFC47B725505E46A0EB9CC45FACFBEA6ECC6CA694E\n" +
        " D3781E011C48C66BBB6C1BA35DD810EF24CF7B92D9E9BCB0B0E19053CFA073AD2D9957\n" +
        " 270B3C55D60824F93EECBF8AF393F07C05BEA38636DFC6B6152424FAF5C0287435C145\n" +
        " B021E235AA30E2B063695EE01D6C696EAA381517E50A440D8AA00164B423#)(q\n" +
        "  #00A4F8D3DC79F1F8388B9FF3F3A484568A76337BF968F05C207F5AF8E84F4B83C1#)\n" +
        " (g #32EC716A63D63CB69E17A678B9BC70686EA24AF4F96F46683E09ACF7EDE9839ADB\n" +
        " 914E61A38D151B28B65533362100B1D9D2948FD8617136FF82C8B61DF5A400B3D2A3E3\n" +
        " 2CEAF2B7DAEBF30D24CA3E681AC551F01EC366EECCDF1481B092E3534728D73211D962\n" +
        " 09069E8FA34395C94828D77F0FEF8E6DEFEA3687ED6267EB028007B84840E383E8B14C\n" +
        " AB93109FA414458E56F5BDAF7AB37ECB3E3FA8EDAED60B7323D3329FB3EA4E460FFA63\n" +
        " B9EC9836530B16710A0EA3A750BF646A48DA65E4144A9A7964513BF998755612791DC5\n" +
        " F840FAE54D34C44A62C1BE884774870BC6D0505FE5EE3F4B222194740E4CC639785E56\n" +
        " B93E17DCACBFE63703DE201DB3#)(y #1B1DAAA76ACF531DBC172304E6523C16B3E701\n" +
        " 2B8B3F0D37AFD9B2C8F63A2155F2CAAE34ADF7A8B068AB266AEE5A5598DD9BE116FA96\n" +
        " F855AA7AD74F780407F74255DC035339C28E1833E93D872EE73DE350E3E0B8AB1E9709\n" +
        " B835E58E6A5491383612A52EB4A3616C29418C0BE108739CC3D59BCF3B0299B283FEA6\n" +
        " 7E21A1909C2E02CD1BFE200F0B6EEE0BB8E4252B8F78711AD05C7056CE673ED81BE265\n" +
        " 60C0768AEC8121D5EB21EE6A8338CC35E306931D1B3516767E345B9C25DF7454C36C61\n" +
        " 739B193BC4998A47A4E5A4956FF525F322DA67B9DC6CFA468ADEBC82EBEEB7F35C4982\n" +
        " A2D347ED4ECB8605387161F03175A9D73659A34D97910B26F8027F#)(protected\n" +
        "  openpgp-s2k3-ocb-aes ((sha1 #4F333DA86C1E7E55#\n" +
        "  \"43860992\")#D8BD10519B004263EC2E35D4#)#57553ACF88CB775B65AAE3FAEB2480\n" +
        " F40BA80AFEA74DD1B9E59847B440733B3A83B062EAD3FDBF67996BA240B8504800C276\n" +
        " AAF1DE797066443807DDCE#)(protected-at \"20211022T053148\")))\n").getBytes();

    byte[] dsaElgamalProtected = ("Created: 20211020T032227\n" +
        "Key: (protected-private-key (dsa (p #00A68CA640389B919C51552D9303E8F822\n" +
        " 8F3C3083DA2D1F366349F2B3D67C9ED2B764448D4EF0579B466CEAF08C9B8477763470\n" +
        " D3BED70784B015F40067F17352B3A4EAF74CBC709000ACD58D64A79332CD828505A1D8\n" +
        " C11A083DE64318093F41AC2004CBDB941B14881183D64467C5C24FFE30A979EF5678D9\n" +
        " 2995D7AC07F3AB#)(q #00DEBBC5AB44F5652BF5FF4FF69FB08199D9652299#)(g\n" +
        "  #4A55C07638DAF38D0A50E4BC53DABDA0B858E94AF923F6B827FCA17B074C598E284E\n" +
        " 1702E1037CCD0608653E8466150AD74071DB6882A6989EC470160F795F45B5BDB93A42\n" +
        " EECC70239615B06CC2B9DD8CDA6097F8A62FF5EB352E913489D579CC6FE01B8EB6E4CE\n" +
        " EF841B3A88021B2D401025BD6C4374812435B67DBD8D3CDD#)(y\n" +
        "  #01AEF2EFC956D068EB0C37EC6185BCB37FA1ADE2585EBBF9D9AC5133FAA864BAA12C\n" +
        " A6CDBB90205BE0952EE9A98A1FD05304DBA4EE82CD748EA3E555A263FD6B7D9AA88E03\n" +
        " EED6D7FF74C432F32469470F07776B52A2B78B58F86F42BE5783A46D6266FC61CFFDC3\n" +
        " D7E59749C69E96ABD393DF4B903101F4CDD6E79547F951B9#)(protected\n" +
        "  openpgp-s2k3-ocb-aes ((sha1 #CB4E8FD129B52F0C#\n" +
        "  \"43860992\")#431AC92BE18B28ED57E69D7B#)#9EDA98358105572FBE507A49A19AAF\n" +
        " A897DFE1E3251E5E1716D77E63930FE223E66F7258B9F080B9B2302075E60E0CBD#)(p\n" +
        " rotected-at \"20211020T032236\")))\n").getBytes();

    private final byte[] protectedRSA = Strings.toUTF8ByteArray("Created: 20211017T225532\n" +
        "Key: (protected-private-key (rsa (n #00BDA748AF09EC7503A3F201E4F59ECAA4\n" +
        " C52E84FEA5E4D7B99069C3751F19C5D0180193CA2E4516B5A9ED263989E007040C1C1D\n" +
        " 53F2D8B7844AEFF77FE28C920ACE0C0F5A77A95536871DD03878BA1997FAE6368E133B\n" +
        " 5CCCB13B4500F99FD211CB6EF42FAF548BB9BEDAA399A0085F85F9CE3268A03276C31E\n" +
        " 33313F1826A9DB#)(e #010001#)(protected openpgp-s2k3-ocb-aes ((sha1\n" +
        "  #0D1568A73CF5F7C6# \"43860992\")#E5DF4BA755F1AC410C4F32FA#)#CFF9000F22E\n" +
        " 0948B2D3BB1E78EEDB42D2361C3A444C94D02E17CDBC928B0AA21275B391820944B684\n" +
        " 757088F76D6CB262768FBB1B06067FECB04E02C5A1A6C2CF18896A30166D6231CB3179\n" +
        " FD0567D03C207C04EAE6523F77302ABDBF8294D90D197B875BCEBB564CCD0DE264D8BA\n" +
        " C921DA23A21C4F7D2DD12A2E4EF20ECFEB2DABD273A2270B2AC386ECF2DCDE90D5FDDB\n" +
        " 00261814082A710A0347C57F7326E18FBE5E4D0F67B6912A903A58984E244D8A487921\n" +
        " 2712200205123AE58E7CB2457518611678C086F319CF7BED4A675E79CA8BC9DB810025\n" +
        " C5EEA8BD0D980787003992A72C005DAEC32604767ADF91AF180DB58260B21A1996240F\n" +
        " E6225B066EA9A8979E590B1BC85F44796903A2738B7871F52F4F27032AC86B25F38E07\n" +
        " 4E12CEB9ECBCD6995D03DA57710EC54A6E60B79283389BD2869FF7B7C65623C59E0B40\n" +
        " 621802DEDA97B167C806B45E0CB3A2CE4C60CD7D7FCE763F7B57EDC226AF7F05B07234\n" +
        " 32C910DD00AD4FD29FE159AEB19E084E9AC76CE#)(protected-at\n" +
        "  \"20211017T225546\")))\n");

    private final byte[] openRsa = Strings.toUTF8ByteArray("Created: 20211014T044624\n" +
        "Key: (private-key (rsa (n #00ED5B77E0107AFC1D066B4010E9B951451974E9B49E\n" +
        " 6741E0CF742427EB14587D1250DC52F7F820E9587B3714681702C5BC4BFDBE06DCE886\n" +
        " F87DF730857A045FF9A72195E04B23E742136CBFE3FA363AF5788BAE55E3BD02A54E2B\n" +
        " 3A52FB2B32B48FECD8780D07E2298983031AB97ED6C0A47A73778C5B2AF3BF93C7CFEF\n" +
        " 1325974A850096F3A73559A5B3DBF63A3246D94D4B6696D08CBFDC8678A8969E00EB17\n" +
        " 2EBC47AF31C61BC412D843F1DDE2BA95404734982687463296DC033901A030A1D5B3BC\n" +
        " 2CF00F3B1F825903E8FD47E390B82A4236EF2DA3502DE0EF6E56D00512578FA3E7C746\n" +
        " 89FAB557B4E47CD736BC1B0756775B06CBB19CFF429843923E6D05447E5ADEA30DED61\n" +
        " 24D1FD9C5FC8DEA2706624CFEB2B63DB0713CDCC3FA071B7256BBC497A3EA50D9E0B4E\n" +
        " AD15F982291D032B4999AC10D22F5C1B2BCACDCE8F4F66497087A11430A5167D8ABAE0\n" +
        " C76919356BD5B460026080502BF1279807398FCB64E03E42772B823C78A8B67DBA9EAF\n" +
        " B6C4F0CFBD09BD7068A7D47873#)(e #010001#)(d\n" +
        "  #197102750BE482D2D6F5F6AA0418B9B35465345FB3283CE6CC95C057B45A3BEF3C0A\n" +
        " B01DB1E29B747CE81D769C7EF5971DA06F9447715FA332A373341F8FD2998EF84675FA\n" +
        " D2A85DDE0BEDA38130E2A5DDDB36985085D6A3F54AB456236ADF587CAE28A43DF4A247\n" +
        " 05A36DB2E42719DCB44D6CFFFA17C5F5E151443FD89E8C48D7E1EEF0FF3D22A114A384\n" +
        " 41D6D9FF659A092F99D1748D2C4B864661F10857EF85A3F173D03D8A39E901B418A450\n" +
        " DF95419B8ADBAD00AEE34157964194D7586F692FC73FCF70B3B56A934ACCCDE0D74F02\n" +
        " FF01760AFC84CCCAD66C1A1BFFEA4C63747D1612B5EB25198F62C5F7BEA7A52674482D\n" +
        " 1B77A5CC1F9963D969C3B266798D166B652769CFFCACA28886E03F1BF7ECAE04B7D1B0\n" +
        " 7FC907D1FC156DE2E4898CFE9F08876D9E24E744CE01DBAB1170F3F59E41AC2383AAC0\n" +
        " 41A10DD394C08D1F44F987F386BE32A4AB805B1EDBA85CDDADA542DDEE2FC1FCBDFB1C\n" +
        " 0809046CB4C7B24B2EBC3EA51F015AB0A39499820F06E6B7D32EE870E8651C30A282B1\n" +
        " #)(p #00F2E626FF576CCB9684AE2698FD7ACA63543D8D28B2E75D6B7BB48C6F2A3C3A\n" +
        " 7BF484F5E0DEAEBA6C59B1114C696C26C5FFE318E213EAB8CD3AB252B0DBB69A5FD642\n" +
        " 17A55AFE5B899CE16E21E1CE7D655B7248C672BB2D1A4FF23B1E807C9361DDFAB82090\n" +
        " 6E82B634EE9E607BDAD32039E1E19C3B15FC4FC1EFC356814A3992D476B0F6E8E98A6F\n" +
        " 9CB77FEDAA7F6F56B134FAB3EB0FD8D7D2FF22E2FFE890338AF666401BD0732BA236E6\n" +
        " 69C20F5F9C2F31487647CF8589D483DFDFC98FF3BD#)(q\n" +
        "  #00FA28CC48F1C61B80B5D1CA48C8DA6B9FFAA9891D6F6E90EDF607B71278C03E4174\n" +
        " 48380CC1477786572A5BA43A772A37397B4DC362B4E495B999D0A494599A154DC556AA\n" +
        " A8D852E8AF5FB26B0EF8EFABA1C6CFF0883AC70092F6CD6B5FD9834A964DDA41D93BFF\n" +
        " 464344DC89CE6951F1BF39CCD9B60630101BB8A4F89307EECFAB43AAACCF7E824B0C39\n" +
        " EC647898CFB5CC9C8BD33087D144334C471ABCCAC525EF5AA425D8388EB6AB72900D0B\n" +
        " F04BBD076F819F242A026BC630615B2758C7EF#)(u\n" +
        "  #613BFCE8D7910CE3C4B9CFBADE79563290A834B67C68C616C8177F6937FC522E4204\n" +
        " 5C80769FDF35DBA3BE23CC623EFFEEA4B74B72F6A46EC2A876EC37D9CB65FEDEDB05AF\n" +
        " 62F69A62A911D60DB3C8E7D2B9C6122F9ACF4E39FABF1E7F83EF119A70ED9B02F5FAA9\n" +
        " 6ACFEA7E735E008F77E7F829FC6B669C72665D7E2E21DE85C66840E76FA200F832980B\n" +
        " 587BCE3AE6F748A85EF2E2BDFDCAAFF52E27752159A80E00B5B241AB45839820520F2F\n" +
        " A8B62E956F307061CB26915408CF2F014824#)))\n");

    static
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args)
        throws Exception
    {
        runTest(new PGPGeneralTest());
    }

    @Override
    public String getName()
    {
        return "PGPGeneralTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        //testEd25519();
        // Tests for OpenedPGPKeyData
        testOpenedPGPKeyData();
        testECNistCurves();
        testDSAElgamalOpen();
        testDSA();
        testProtectedRSA();

        // Tests for PGPSignatureSubpacketVector
        sigsubpacketTest();
        testParsingFromSignature();
        testPGPSignatureSubpacketVector();

        // Tests for PGPSecretKey
        testParseSecretKeyFromSExpr();

        // Tests for PGPPublicKey
        testPGPPublicKey();
        testAddRemoveCertification();
        embeddedJpegTest();

        // Tests for PGPPublicKeyRing
        testPGPPublicKeyRing();

        // Tests for PGPPublicKeyRingCollection
        testPublicKeyRingOperations();

        // Tests for PGPSecretKeyRingCollection
        testSecretKeyRingOperations();
        testRemoveSecretKeyRing();

        // Tests for PGPSecretKeyRing
        testPGPSecretKeyRingConstructor();
        testGetKeysWithSignaturesBy();
        rewrapTest();
        rewrapTestV3();
        testextraPubKeys();
        testPublicKeyOperations();
        testGetPublicKey_byteArray2();
        testPGPSecretKeyRing();

        // Tests for PGPPublicKeyRingCollection
        testGetPublicKey_byteArray();
    }

    public void testPGPPublicKey()
        throws PGPException, IOException
    {
        BcPGPPublicKeyRingCollection pubRings = new BcPGPPublicKeyRingCollection(pub2);
        final long id1 = -4049084404703773049L, id2 = -1413891222336124627L;
        final byte[] fingerprint3 = new byte[]{90, -118, 121, -77, 70, 60, -62, -39, 90, 116, 30, 117, -91, -48, 127, -12, 83, -9, -37, -104};
        final byte[] fingerprint4 = new byte[]{28, -123, 104, -64, -124, -77, 74, 91, -14, -70, -17, -13, 0, -47, -69, -50, 116, 122, 95, 64};
        PGPPublicKey publicKey1 = pubRings.getPublicKey(id1);
        PGPPublicKey publicKey2 = pubRings.getPublicKey(id2);
        PGPPublicKey publicKey3 = pubRings.getPublicKey(fingerprint3);
        PGPPublicKey publicKey4 = pubRings.getPublicKey(fingerprint4);

        final byte[] levelAndTrustAmount = new byte[]{-121};
        // Test for getTrustData

        isTrue(areEqual(publicKey1.getTrustData(), levelAndTrustAmount));
        isTrue(areEqual(publicKey2.getTrustData(), levelAndTrustAmount));
        isTrue(areEqual(publicKey3.getTrustData(), levelAndTrustAmount));
        isTrue(areEqual(publicKey4.getTrustData(), levelAndTrustAmount));
        // Test for getKeySignatures
        Iterator<PGPSignature> it;
        it = publicKey1.getKeySignatures();
        isTrue(it.hasNext() == false);
        it = publicKey2.getKeySignatures();
        isTrue(((PGPSignature)it.next()).getKeyID() == -4049084404703773049L);
        it = publicKey3.getKeySignatures();
        isTrue(it.hasNext() == false);
        it = publicKey4.getKeySignatures();
        isTrue(((PGPSignature)it.next()).getKeyID() == -6498553574938125416L);

        // Test for getEncoded(boolean)
        isTrue(areEqual(publicKey1.getEncoded(), publicKey1.getEncoded(false)));

        // Test for isRovked and hasRevocation
        isTrue(!publicKey1.isRevoked());
        isTrue(!publicKey2.hasRevocation());
        isTrue(!publicKey3.hasRevocation());
        isTrue(!publicKey4.hasRevocation());

        // Tests for join
        // TODO: cover more missing branches of PGPPublicKey.join
        try
        {
            PGPPublicKey.join(publicKey1, publicKey2, true, true);
            fail("Key-ID mismatch.");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("Key-ID mismatch.", messageIs(e.getMessage(), "Key-ID mismatch."));
        }

        PGPPublicKey publicKey7 = PGPPublicKey.join(publicKey2, publicKey2, true, true);
        isTrue(publicKey7.getKeyID() == publicKey2.getKeyID());
        isTrue(areEqual(publicKey7.getFingerprint(), publicKey2.getFingerprint()));
        isTrue(publicKey7.hasFingerprint(publicKey2.getFingerprint()));
        isTrue(publicKey2.hasFingerprint(publicKey7.getFingerprint()));

        PGPPublicKeyRingCollection pgpRingCollection = new JcaPGPPublicKeyRingCollection(probExpPubKey);
        final long id5 = 6556488621521814541L;
        PGPPublicKeyRing pubKeys = pgpRingCollection.getPublicKeyRing(id5);
        PGPPublicKey publicKey5 = pubKeys.getPublicKey(id5);

        isTrue(publicKey5.getTrustData() == null);

        PGPPublicKey publicKey6 = PGPPublicKey.join(publicKey5, publicKey5, true, true);
        isTrue(publicKey6.getKeyID() == publicKey5.getKeyID());
        isTrue(areEqual(publicKey6.getFingerprint(), publicKey5.getFingerprint()));
        isTrue(publicKey6.hasFingerprint(publicKey5.getFingerprint()));
        isTrue(publicKey5.hasFingerprint(publicKey6.getFingerprint()));
    }

    private boolean messageIs(String message, String s)
    {
        return message.indexOf(s) >= 0;
    }

    public void testAddRemoveCertification()
        throws Exception
    {
//        //
//        // key pair generation - CAST5 encryption
//        //
        char[] passPhrase = "hello".toCharArray();
        RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();
        kpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x11), new SecureRandom(), 1024, 25));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        PGPSecretKey secretKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, new BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL,
            kp, new Date()), "fred", null, null, new BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL,
            HashAlgorithmTags.SHA1), new BcPBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.CAST5).setSecureRandom(CryptoServicesRegistrar.getSecureRandom()).build(passPhrase));

        PGPPublicKey key = secretKey.getPublicKey();
        Iterator it = key.getUserIDs();
        String uid = (String)it.next();

        byte[] id = Strings.toUTF8ByteArray(uid);
        it = key.getSignaturesForID(id);
        PGPSignature sig = (PGPSignature)it.next();
        sig.init(new BcPGPContentVerifierBuilderProvider(), key);

        PGPPublicKey key1 = PGPPublicKey.removeCertification(key, id, sig);
        if (key1 == null)
        {
            fail("failed certification removal");
        }
        key1 = PGPPublicKey.addCertification(key1, id, sig);
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1));
        sGen.init(PGPSignature.KEY_REVOCATION, secretKey.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(passPhrase)));
        sig = sGen.generateCertification(key1);
        key1 = PGPPublicKey.addCertification(key1, sig);
        byte[] keyEnc = key1.getEncoded();
        PGPPublicKeyRing tmpRing = new PGPPublicKeyRing(keyEnc, new BcKeyFingerprintCalculator());
        key1 = tmpRing.getPublicKey();
        Iterator sgIt = key1.getSignaturesOfType(PGPSignature.KEY_REVOCATION);
        sig = (PGPSignature)sgIt.next();
        sig.init(new BcPGPContentVerifierBuilderProvider(), key1);
        if (!sig.verifyCertification(key1))
        {
            fail("failed to verify revocation certification");
        }

        PGPPublicKey key2 = PGPPublicKey.removeCertification(key, id);
        if (key2 == null)
        {
            fail("failed certification removal");
        }
        key2 = PGPPublicKey.addCertification(key2, id, sig);
        sGen = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1));
        sGen.init(PGPSignature.KEY_REVOCATION, secretKey.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(passPhrase)));
        sig = sGen.generateCertification(key2);
        key2 = PGPPublicKey.addCertification(key2, sig);
        keyEnc = key2.getEncoded();
        tmpRing = new PGPPublicKeyRing(keyEnc, new BcKeyFingerprintCalculator());
        key2 = tmpRing.getPublicKey();
        sgIt = key2.getSignaturesOfType(PGPSignature.KEY_REVOCATION);
        sig = (PGPSignature)sgIt.next();
        sig.init(new BcPGPContentVerifierBuilderProvider(), key2);
        if (!sig.verifyCertification(key2))
        {
            fail("failed to verify revocation certification");
        }

        PGPPublicKey key3 = PGPPublicKey.removeCertification(key, uid);
        if (key3 == null)
        {
            fail("failed certification removal");
        }
        key3 = PGPPublicKey.addCertification(key3, id, sig);
        sGen = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1));
        sGen.init(PGPSignature.KEY_REVOCATION, secretKey.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(passPhrase)));
        sig = sGen.generateCertification(key3);
        key3 = PGPPublicKey.addCertification(key3, sig);
        keyEnc = key3.getEncoded();
        tmpRing = new PGPPublicKeyRing(keyEnc, new BcKeyFingerprintCalculator());
        key3 = tmpRing.getPublicKey();
        sgIt = key3.getSignaturesOfType(PGPSignature.KEY_REVOCATION);
        sig = (PGPSignature)sgIt.next();
        sig.init(new BcPGPContentVerifierBuilderProvider(), key3);
        if (!sig.verifyCertification(key3))
        {
            fail("failed to verify revocation certification");
        }
    }

    /**
     * Test cover:
     * PGPSecretKey.replacePublicKey
     * PGPSecretKey.getUserAttributes
     * PGPPublicKey.removeCertification
     */
    private void embeddedJpegTest()
        throws Exception
    {
        PGPPublicKeyRing pgpPub = new PGPPublicKeyRing(testPubKey, new BcKeyFingerprintCalculator());
        PGPSecretKeyRing pgpSec = new PGPSecretKeyRing(testPrivKey, new BcKeyFingerprintCalculator());
        PGPPublicKey pubKey = pgpPub.getPublicKey();
        PGPUserAttributeSubpacketVectorGenerator vGen = new PGPUserAttributeSubpacketVectorGenerator();
        vGen.setImageAttribute(ImageAttribute.JPEG, jpegImage);
        PGPUserAttributeSubpacketVector uVec = vGen.generate();
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1));
        sGen.init(PGPSignature.POSITIVE_CERTIFICATION, pgpSec.getSecretKey().extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(pass)));
        PGPSignature sig = sGen.generateCertification(uVec, pubKey);
        PGPPublicKey nKey = PGPPublicKey.addCertification(pubKey, uVec, sig);
        PGPSecretKey secretKey = pgpSec.getSecretKey();
        secretKey = PGPSecretKey.replacePublicKey(secretKey, nKey);
        Iterator it = secretKey.getUserAttributes();
        int count = 0;
        while (it.hasNext())
        {
            PGPUserAttributeSubpacketVector attributes = (PGPUserAttributeSubpacketVector)it.next();
            Iterator sigs = nKey.getSignaturesForUserAttribute(attributes);
            int sigCount = 0;
            while (sigs.hasNext())
            {
                PGPSignature s = (PGPSignature)sigs.next();
                s.init(new BcPGPContentVerifierBuilderProvider(), pubKey);
                if (!s.verifyCertification(attributes, pubKey))
                {
                    fail("added signature failed verification");
                }
                sigCount++;
            }
            if (sigCount != 1)
            {
                fail("Failed added user attributes signature check");
            }
            count++;
        }
        if (count != 1)
        {
            fail("didn't find added user attributes");
        }
        nKey = PGPPublicKey.removeCertification(nKey, uVec, sig);
        count = 0;
        for (it = nKey.getSignaturesForUserAttribute(uVec); it.hasNext(); it.next())
        {
            count++;
        }
        if (count != 0)
        {
            fail("found attributes where none expected");
        }
    }

    /**
     * Test Cover:
     * PGPPublicKeyRingCollection.getPublicKey(byte[])
     * PGPPublicKeyRing.getPublicKey(byte[])
     */
    public void testGetPublicKey_byteArray()
        throws Exception
    {
        PGPPublicKeyRingCollection pgpRingCollection = new JcaPGPPublicKeyRingCollection(probExpPubKey);
        byte[] fingerprint = new byte[]{-31, -21, 70, -81, 62, 43, 9, 126, 23, -13, 81, 20, 90, -3, 83, -87, -37, -78, -60, 13};
        PGPPublicKey pubKey = pgpRingCollection.getPublicKey(fingerprint);
        isTrue("fail to get the correct public key", pubKey.getKeyID() == 0x5afd53a9dbb2c40dL);
        fingerprint[0] = 0;
        pubKey = pgpRingCollection.getPublicKey(fingerprint);
        isTrue("the public key should not exist", pubKey == null);
    }

    /**
     * Test Cover: PGPSecretKeyRing.getSecretKeyRing(byte[])
     */
    public void testGetPublicKey_byteArray2()
        throws Exception
    {
        // TODO: extraPubKeys
        JcaPGPSecretKeyRingCollection privRings = new JcaPGPSecretKeyRingCollection(
            new ByteArrayInputStream(privv3));
        byte[] fingerprint = new byte[]{-85, -29, 45, 3, -118, -2, 111, 49, -37, -83, 127, -27, 85, 18, 17, -90};
        PGPSecretKeyRing pgpPriv = privRings.getSecretKeyRing(-1056546523141439621L);
        PGPPublicKey pubKey = pgpPriv.getPublicKey(fingerprint);
        isTrue("fail to get the correct public key", pubKey.getKeyID() == -1056546523141439621L);
        fingerprint[0] = 0;
        pubKey = pgpPriv.getPublicKey(fingerprint);
        isTrue("fail to get the correct public key", pubKey == null);
    }

    /**
     * Test Cover:
     * PGPSecretKeyRing.insertOrReplacePublicKey(PGPSecretKeyRing, PGPPublicKey)
     * PGPSecretKeyRing.replacePublicKeys(PGPSecretKeyRing, PGPPublicKeyRing)
     */
    public void testPublicKeyOperations()
        throws Exception
    {
        PGPDigestCalculator digestCalculator = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
        KeyPairGenerator generator;
        KeyPair pair;

        // Generate master key

        generator = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(new ECNamedCurveGenParameterSpec("P-256"));

        pair = generator.generateKeyPair();
        PGPKeyPair pgpMasterKey = new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDSA, pair, new Date());

        PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
        hashed.setNotationData(false, true, "test@bouncycastle.org", "hashedNotation");
        PGPSignatureSubpacketGenerator unhashed = new PGPSignatureSubpacketGenerator();

        PGPContentSignerBuilder signerBuilder = new BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.ECDSA, HashAlgorithmTags.SHA512);
        PGPKeyRingGenerator keyRingGenerator = new PGPKeyRingGenerator(
            pgpMasterKey, digestCalculator, hashed.generate(), unhashed.generate(), signerBuilder, null);
        PGPSecretKeyRing secretKeys = keyRingGenerator.generateSecretKeyRing();

        PGPSecretKey secretKey = secretKeys.getSecretKey();
        PGPPublicKey publicKey = secretKey.getPublicKey();
        secretKeys = PGPSecretKeyRing.insertOrReplacePublicKey(secretKeys, publicKey);

        Iterator<PGPSignature> signatures = secretKeys.getPublicKey().getSignaturesOfType(PGPSignature.DIRECT_KEY);
        isTrue(signatures.hasNext());

        PGPSignature signature = (PGPSignature)signatures.next();
        isTrue(!signatures.hasNext());

        NotationData[] hashedNotations = signature.getHashedSubPackets().getNotationDataOccurences();
        isEquals(1, hashedNotations.length);
        isEquals("test@bouncycastle.org", hashedNotations[0].getNotationName());
        isEquals("hashedNotation", hashedNotations[0].getNotationValue());
        isEquals(1, signature.getHashedSubPackets().getNotationDataOccurrences("test@bouncycastle.org").length);

        signature.init(new BcPGPContentVerifierBuilderProvider(), secretKeys.getPublicKey());
        isTrue(signature.verifyCertification(secretKeys.getPublicKey()));

        PGPPublicKeyRing publicKeys = keyRingGenerator.generatePublicKeyRing();
        secretKeys = PGPSecretKeyRing.replacePublicKeys(secretKeys, publicKeys);

        signatures = secretKeys.getPublicKey().getSignaturesOfType(PGPSignature.DIRECT_KEY);
        isTrue(signatures.hasNext());

        signature = (PGPSignature)signatures.next();
        isTrue(!signatures.hasNext());

        hashedNotations = signature.getHashedSubPackets().getNotationDataOccurrences();
        isEquals(1, hashedNotations.length);
        isEquals("test@bouncycastle.org", hashedNotations[0].getNotationName());
        isEquals("hashedNotation", hashedNotations[0].getNotationValue());

        signature.init(new BcPGPContentVerifierBuilderProvider(), secretKeys.getPublicKey());
        isTrue(signature.verifyCertification(secretKeys.getPublicKey()));
    }

    /**
     * Test cover:
     * PGPSecretKeyRing.getPublicKey
     * PGPSecretKeyRing.insertOrReplacePublicKey
     * PGPSecretKey.replacePublicKey
     * PGPSecretKey.getEncoded
     * PGPSecretKey.getS2K
     */
    private void testextraPubKeys()
        throws Exception
    {
        BcPGPSecretKeyRingCollection secCol = new BcPGPSecretKeyRingCollection(secWithPersonalCertificate);
        byte[] fingerprint = new byte[]{90, -92, -3, 36, -60, -80, 103, 13, -40, -42, -26, 95, 7, 88, -112, 69, -117, 111, 100, 118};
        PGPSecretKeyRing secretKeys = secCol.getSecretKeyRing(-1923690421044764583L);
        PGPPublicKey publicKey = secretKeys.getPublicKey(fingerprint);
        isTrue("", publicKey.getKeyID() == 529331584582509686L);

        publicKey = secretKeys.getPublicKey(1L);
        isTrue("", publicKey == null);

        publicKey = secretKeys.getPublicKey(529331584582509686L);
        isTrue("", publicKey != null);

        secretKeys = PGPSecretKeyRing.insertOrReplacePublicKey(secretKeys, publicKey);
        publicKey = secretKeys.getPublicKey(fingerprint);
        isTrue("", publicKey.getKeyID() == 529331584582509686L);

        PGPSecretKey secretKey = secretKeys.getSecretKey();
        try
        {
            PGPSecretKey.replacePublicKey(secretKey, publicKey);
            fail("keyIDs do not match");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("keyIDs do not match", messageIs(e.getMessage(), "keyIDs do not match"));
        }

        byte[] bOut = secretKey.getEncoded();
        PGPSecretKeyRing secretKeys2 = new PGPSecretKeyRing(bOut, new BcKeyFingerprintCalculator());
        PGPSecretKey secretKey2 = secretKeys2.getSecretKey();
        isTrue(secretKey2.getKeyID() == secretKey.getKeyID());
        isTrue(secretKey2.getS2K() == null);
    }

    private void rewrapTest()
        throws Exception
    {
        SecureRandom rand = new SecureRandom();

        // Read the secret key rings
        BcPGPSecretKeyRingCollection privRings = new BcPGPSecretKeyRingCollection(
            new ByteArrayInputStream(rewrapKey));

        Iterator rIt = privRings.getKeyRings();

        if (rIt.hasNext())
        {
            PGPSecretKeyRing pgpPriv = (PGPSecretKeyRing)rIt.next();
            pgpPriv = PGPSecretKeyRing.copyWithNewPassword(pgpPriv, new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(rewrapPass),
                null);
            Iterator it = pgpPriv.getSecretKeys();
            while (it.hasNext())
            {
                PGPSecretKey pgpKey = (PGPSecretKey)it.next();
                // this should succeed
                PGPPrivateKey privTmp = pgpKey.extractPrivateKey(null);
            }
        }
    }

    /**
     * Test cover: PGPSecretKeyRing.copyWithNewPassword
     * Reference:
     */
    private void rewrapTestV3()
        throws Exception
    {
        // Read the secret key rings
        JcaPGPSecretKeyRingCollection privRings = new JcaPGPSecretKeyRingCollection(
            new ByteArrayInputStream(privv3));
        char[] newPass = "fred".toCharArray();

        Iterator rIt = privRings.getKeyRings();

        if (rIt.hasNext())
        {
            PGPSecretKeyRing pgpPriv = (PGPSecretKeyRing)rIt.next();

            Iterator it = pgpPriv.getSecretKeys();
            PGPSecretKeyRing pgpPriv2 = PGPSecretKeyRing.copyWithNewPassword(pgpPriv, new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(v3KeyPass),
                null);
            while (it.hasNext())
            {
                PGPSecretKey pgpKey = (PGPSecretKey)it.next();
                long oldKeyID = pgpKey.getKeyID();
                PGPSecretKey newPgpKey = pgpPriv2.getSecretKey(oldKeyID);

                // this should succeed
                PGPPrivateKey privTmp = newPgpKey.extractPrivateKey(null);

                if (newPgpKey.getKeyID() != oldKeyID)
                {
                    fail("key ID mismatch");
                }
            }

            it = pgpPriv2.getSecretKeys();
            PGPSecretKeyRing pgpPriv3 = PGPSecretKeyRing.copyWithNewPassword(pgpPriv2, null,
                new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.CAST5, new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build().get(HashAlgorithmTags.MD5)).setProvider("BC").build(newPass));
            while (it.hasNext())
            {
                PGPSecretKey pgpKey = (PGPSecretKey)it.next();
                long oldKeyID = pgpKey.getKeyID();
                PGPSecretKey newPgpKey = pgpPriv3.getSecretKey(oldKeyID);

                // this should succeed
                PGPPrivateKey privTmp = newPgpKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider(new BouncyCastleProvider()).build(newPass));

                if (newPgpKey.getKeyID() != oldKeyID)
                {
                    fail("key ID mismatch");
                }
            }
        }
    }


    /**
     * Test cover:
     * PGPSecretKeyRing.getKeysWithSignaturesBy
     * PGPPublicKeyRingCollection.getKeysWithSignaturesBy
     * PGPPublicKey.getKeySigatures()
     */
    public void testGetKeysWithSignaturesBy()
        throws Exception
    {
        char[] passPhrase = "hello".toCharArray();
        KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");

        dsaKpg.initialize(512);

        //
        // this takes a while as the key generator has to generate some DSA params
        // before it generates the key.
        //
        KeyPair dsaKp = dsaKpg.generateKeyPair();

        KeyPairGenerator elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
        BigInteger g = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
        BigInteger p = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

        ElGamalParameterSpec elParams = new ElGamalParameterSpec(p, g);

        elgKpg.initialize(elParams);

        //
        // this is quicker because we are using pregenerated parameters.
        //
        KeyPair elgKp = elgKpg.generateKeyPair();
        PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date());
        PGPKeyPair elgKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKp, new Date());
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair,
            "test", sha1Calc, null, null, new JcaPGPContentSignerBuilder(PGPPublicKey.DSA, HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256).setProvider("BC").build(passPhrase));


        keyRingGen.addSubKey(elgKeyPair, null);

        PGPSecretKeyRing keyRing = keyRingGen.generateSecretKeyRing();

        keyRing.getSecretKey().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passPhrase));

        PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();

        PGPPublicKey vKey = null;
        PGPPublicKey sKey = null;

        Iterator it = pubRing.getPublicKeys();
        while (it.hasNext())
        {
            PGPPublicKey pk = (PGPPublicKey)it.next();
            if (pk.isMasterKey())
            {
                vKey = pk;
            }
            else
            {
                sKey = pk;
            }
        }

        Iterator skrIt = keyRing.getKeysWithSignaturesBy(vKey.getKeyID());
        if (skrIt.hasNext())
        {
            while (skrIt.hasNext())
            {
                PGPPublicKey pub = (PGPPublicKey)skrIt.next();

                if (pub.isMasterKey())
                {
                    Iterator sigIt = pub.getSignaturesForKeyID(vKey.getKeyID());

                    PGPSignature sig = (PGPSignature)sigIt.next();

                    if (sig.getSignatureType() != PGPSignature.POSITIVE_CERTIFICATION || sigIt.hasNext())
                    {
                        fail("master sig check failed");
                    }
                }
                else
                {
                    Iterator sigIt = pub.getSignaturesForKeyID(vKey.getKeyID());

                    PGPSignature sig = (PGPSignature)sigIt.next();

                    if (sig.getSignatureType() != PGPSignature.SUBKEY_BINDING || sigIt.hasNext())
                    {
                        fail("sub sig check failed");
                    }
                }
            }
        }
        else
        {
            fail("no keys found in iterator");
        }

        List<PGPPublicKeyRing> collection = new ArrayList<PGPPublicKeyRing>();
        collection.add(pubRing);
        PGPPublicKeyRingCollection pubRings = new PGPPublicKeyRingCollection(collection);
        it = pubRings.getKeysWithSignaturesBy(vKey.getKeyID());
        while (it.hasNext())
        {
            PGPPublicKey pub = (PGPPublicKey)it.next();
            if (pub.isMasterKey())
            {
                Iterator sigIt = pub.getSignaturesForKeyID(vKey.getKeyID());

                PGPSignature sig = (PGPSignature)sigIt.next();

                if (sig.getSignatureType() != PGPSignature.POSITIVE_CERTIFICATION || sigIt.hasNext())
                {
                    fail("master sig check failed");
                }
            }
            else
            {
                Iterator sigIt = pub.getSignaturesForKeyID(vKey.getKeyID());

                PGPSignature sig = (PGPSignature)sigIt.next();

                if (sig.getSignatureType() != PGPSignature.SUBKEY_BINDING || sigIt.hasNext())
                {
                    fail("sub sig check failed");
                }
            }
        }
    }

    public void testPGPSecretKeyRing()
        throws Exception
    {
        BcPGPSecretKeyRingCollection secCol = new BcPGPSecretKeyRingCollection(secWithPersonalCertificate);
        PGPSecretKeyRing secretKeys = secCol.getSecretKeyRing(8198709240736962902L);
        PGPSecretKey secretKey1 = secretKeys.getSecretKey(8198709240736962902L);
        PGPSecretKey secretKey2 = secretKeys.getSecretKey(-6083617161579374264L);
        try
        {
            List<PGPSecretKey> skList = new ArrayList<PGPSecretKey>();
            skList.add(secretKey2);
            skList.add(secretKey1);
            PGPSecretKeyRing secretKeys1 = new PGPSecretKeyRing(skList);
            fail("key 0 must be a master key");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("key 0 must be a master key", messageIs(e.getMessage(), "key 0 must be a master key"));
        }

        try
        {
            List<PGPSecretKey> skList = new ArrayList<PGPSecretKey>();
            skList.add(secretKey1);
            skList.add(secretKey1);
            PGPSecretKeyRing secretKeys1 = new PGPSecretKeyRing(skList);
            fail("key 0 can be only master key");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("key 0 can be only master key", messageIs(e.getMessage(), "key 0 can be only master key"));
        }

        PGPSecretKeyRing secretKeys2 = new PGPSecretKeyRing(new ArrayList<PGPSecretKey>());
        secretKeys2 = PGPSecretKeyRing.insertSecretKey(secretKeys2, secretKey1);
        secretKeys2 = PGPSecretKeyRing.insertSecretKey(secretKeys2, secretKey1);
        secretKeys2 = PGPSecretKeyRing.insertSecretKey(secretKeys2, secretKey2);
        isTrue("The secret key should be in the ring", secretKeys2.getSecretKey(secretKey1.getFingerprint()) != null);
        isTrue("The secret key should be in the ring", secretKeys2.getSecretKey(secretKey2.getFingerprint()) != null);

        secretKeys2 = PGPSecretKeyRing.removeSecretKey(secretKeys2, secretKey2);
        secretKeys2 = PGPSecretKeyRing.removeSecretKey(secretKeys2, secretKey2);
        isTrue("The secret key should be null", secretKeys2 == null);
    }

    public void testPGPSecretKeyRingConstructor()
        throws Exception
    {
        try
        {
            new PGPSecretKeyRing(new ByteArrayInputStream(curve25519Pub), new JcaKeyFingerprintCalculator());
            fail("the constructor for this initialisation should fail as the input is a stream of a public key ");
        }
        catch (IOException e)
        {
            isTrue("secret key ring doesn't start with secret key tag: tag 0x",
                messageIs(e.getMessage(), "secret key ring doesn't start with secret key tag: tag 0x"));
        }
    }

    public void testRemoveSecretKeyRing()
        throws Exception
    {
        final long keyID = -2247357259537451242L;
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(new ByteArrayInputStream(secretKeyByteArray), new JcaKeyFingerprintCalculator());
        PGPSecretKeyRing secretKeyRing = pgpSec.getSecretKeyRing(keyID);
        isTrue("The secret key should be in the secret key ring collection", secretKeyRing != null);
        PGPSecretKeyRingCollection pgpSec2 = PGPSecretKeyRingCollection.removeSecretKeyRing(pgpSec, secretKeyRing);
        pgpSec2.contains(keyID);
        secretKeyRing = pgpSec2.getSecretKeyRing(keyID);
        isTrue("The secret key should be in the secret key ring collection", secretKeyRing == null);
    }

    public void testSecretKeyRingOperations()
        throws Exception
    {
        final long id1 = -1923690421044764583L, id2 = -6083617161579374264L, id3 = 8198709240736962902L;
        PGPSecretKeyRingCollection secCol = new BcPGPSecretKeyRingCollection(secWithPersonalCertificate);
        PGPSecretKeyRing secretKeys = secCol.getSecretKeyRing(id1);
        isTrue("secret key should not be null", secretKeys != null);
        secretKeys = secCol.getSecretKeyRing(id2);
        isTrue("secret key should not be null", secretKeys != null);

        try
        {
            PGPSecretKeyRingCollection.addSecretKeyRing(secCol, secretKeys);
            fail("Collection already contains a key with a keyID for the passed in ring.");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("Collection already contains a key with a keyID for the passed in ring.",
                messageIs(e.getMessage(), "Collection already contains a key with a keyID for the passed in ring."));
        }

        secCol = PGPSecretKeyRingCollection.removeSecretKeyRing(secCol, secretKeys);
        isTrue("secret key has been removed", !secCol.contains(id2));

        try
        {
            secCol = PGPSecretKeyRingCollection.removeSecretKeyRing(secCol, secretKeys);
            fail("Collection does not contain a key with a keyID for the passed in ring.");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("Collection does not contain a key with a keyID for the passed in ring.",
                messageIs(e.getMessage(), "Collection does not contain a key with a keyID for the passed in ring."));
        }

        secCol = PGPSecretKeyRingCollection.addSecretKeyRing(secCol, secretKeys);
        isTrue("secret key has been added", secCol.contains(id2));

        secCol = new PGPSecretKeyRingCollection(secWithPersonalCertificate, new BcKeyFingerprintCalculator());
        isTrue(secCol.contains(id1) && secCol.contains(id2) && secCol.contains(id3) && secCol.size() == 2);

        Iterator it = secCol.iterator();
        List<PGPSecretKeyRing> collection = new ArrayList<PGPSecretKeyRing>();
        while (it.hasNext())
        {
            collection.add((PGPSecretKeyRing)it.next());
        }
        PGPSecretKeyRingCollection secCol2 = new BcPGPSecretKeyRingCollection(collection);
        isTrue(secCol2.contains(id1) && secCol2.contains(id2) && secCol2.contains(id3) && secCol2.size() == 2);

        try
        {
            BcPGPSecretKeyRingCollection secCol3 = new BcPGPSecretKeyRingCollection(pub1);
            fail("found where PGPSecretKeyRing expected");
        }
        catch (PGPException e)
        {
            isTrue("found where PGPSecretKeyRing expected", messageIs(e.getMessage(), "found where PGPSecretKeyRing expected"));
        }
    }

    public void testPublicKeyRingOperations()
        throws Exception
    {
        final long id1 = -7459027269198298458L, id2 = -4437440411852492852L;
        PGPPublicKeyRingCollection pubRings = new BcPGPPublicKeyRingCollection(pub1);
        byte[] fingerprint1 = pubRings.getPublicKey(id1).getFingerprint();
        isTrue("the public key ring should be in the collection", pubRings.getPublicKeyRing(id1) != null);
        isTrue("the public key ring should be in the collection", pubRings.contains(id2));

        isTrue("The public key should not be found", pubRings.getPublicKey(1L) == null);
        isTrue("The public key ring should not be found", pubRings.getPublicKeyRing(1L) == null);
        isTrue("The public key ring should not be found", pubRings.getPublicKeyRing(new byte[fingerprint1.length]) == null);

        PGPPublicKeyRing pubRing = pubRings.getPublicKeyRing(id2);

        try
        {
            PGPPublicKeyRingCollection pubRings1 = PGPPublicKeyRingCollection.addPublicKeyRing(pubRings, pubRing);
            fail("Collection already contains a key with a keyID for the passed in ring.");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("Collection already contains a key with a keyID for the passed in ring.",
                messageIs(e.getMessage(), "Collection already contains a key with a keyID for the passed in ring."));
        }

        pubRings = PGPPublicKeyRingCollection.removePublicKeyRing(pubRings, pubRing);
        try
        {
            PGPPublicKeyRingCollection pubRings1 = PGPPublicKeyRingCollection.removePublicKeyRing(pubRings, pubRing);
            fail("Collection does not contain a key with a keyID for the passed in ring.");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("Collection does not contain a key with a keyID for the passed in ring.",
                messageIs(e.getMessage(), "Collection does not contain a key with a keyID for the passed in ring."));
        }
        pubRings = PGPPublicKeyRingCollection.addPublicKeyRing(pubRings, pubRing);

        pubRings = new PGPPublicKeyRingCollection(pub1, new BcKeyFingerprintCalculator());
        isTrue(pubRings.getPublicKeyRing(fingerprint1) != null && pubRings.contains(id2) && pubRings.size() == 1);

        Iterator it = pubRings.iterator();
        List<PGPPublicKeyRing> collection = new ArrayList<PGPPublicKeyRing>();
        while (it.hasNext())
        {
            collection.add((PGPPublicKeyRing)it.next());
        }
        PGPPublicKeyRingCollection pubRings2 = new BcPGPPublicKeyRingCollection(collection);
        isTrue(pubRings2.contains(fingerprint1) && pubRings2.contains(id2) && pubRings2.size() == 1);

        try
        {
            PGPPublicKeyRingCollection pubRings3 = new BcPGPPublicKeyRingCollection(secWithPersonalCertificate);
            fail("found where PGPPublicKeyRing expected");
        }
        catch (PGPException e)
        {
            isTrue("found where PGPPublicKeyRing expected", messageIs(e.getMessage(), "found where PGPPublicKeyRing expected"));
        }
    }

    public void testPGPPublicKeyRing()
        throws PGPException, IOException
    {
        PGPPublicKeyRingCollection pgpRingCollection = new JcaPGPPublicKeyRingCollection(probExpPubKey);
        final long id1 = 6556488621521814541L, id2 = 3905109942809550596L;
        PGPPublicKeyRing pubKeys = pgpRingCollection.getPublicKeyRing(id1);
        PGPPublicKey publicKey1 = pubKeys.getPublicKey(id1);
        PGPPublicKey publicKey2 = pubKeys.getPublicKey(id2);
        try
        {
            List<PGPPublicKey> pubkeys = new ArrayList<PGPPublicKey>();
            pubkeys.add(publicKey2);
            pubkeys.add(publicKey1);
            PGPPublicKeyRing publickeys = new PGPPublicKeyRing(pubkeys);
            fail("key 0 must be a master key");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("key 0 must be a master key", messageIs(e.getMessage(), "key 0 must be a master key"));
        }
        try
        {
            List<PGPPublicKey> pubkeys = new ArrayList<PGPPublicKey>();
            pubkeys.add(publicKey1);
            pubkeys.add(publicKey1);
            PGPPublicKeyRing publickeys = new PGPPublicKeyRing(pubkeys);
            fail("key 0 can be only master key");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("key 0 can be only master key", messageIs(e.getMessage(), "key 0 can be only master key"));
        }

        try
        {
            PGPPublicKeyRing publicKeys = new PGPPublicKeyRing(secWithPersonalCertificate, new BcKeyFingerprintCalculator());
            fail("public key ring doesn't start with public key tag");
        }
        catch (IOException e)
        {
            isTrue("public key ring doesn't start with public key tag: ", messageIs(e.getMessage(), "public key ring doesn't start with public key tag: "));
        }

        PGPPublicKeyRing pubKeys2 = new PGPPublicKeyRing(new ArrayList<PGPPublicKey>());
        pubKeys2 = PGPPublicKeyRing.insertPublicKey(pubKeys2, publicKey1);
        pubKeys2 = PGPPublicKeyRing.insertPublicKey(pubKeys2, publicKey1);
        pubKeys2 = PGPPublicKeyRing.insertPublicKey(pubKeys2, publicKey2);
        isTrue("The public key should be in the ring", pubKeys2.getPublicKey(publicKey1.getFingerprint()) != null);
        isTrue("The public key should be in the ring", pubKeys2.getPublicKey(publicKey2.getFingerprint()) != null);

        PGPPublicKeyRing pubKeys3 = PGPPublicKeyRing.removePublicKey(pubKeys2, publicKey2);
        pubKeys3 = PGPPublicKeyRing.removePublicKey(pubKeys3, publicKey2);
        isTrue("removePublicKey should return null", pubKeys3 == null);
    }

    public void testParseSecretKeyFromSExpr()
        throws Exception
    {
        PGPObjectFactory pgpFact = new JcaPGPObjectFactory(encMessage);
        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpFact.nextObject();
        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);
        PGPPublicKey publicKey = new JcaPGPPublicKeyRing(testPubKey2).getPublicKey(encP.getKeyID());
        JcaPGPDigestCalculatorProviderBuilder digBuild = new JcaPGPDigestCalculatorProviderBuilder();
        PGPSecretKey secretKey = PGPSecretKey.parseSecretKeyFromSExpr(new ByteArrayInputStream(sExprKeySub), new JcePBEProtectionRemoverFactory("test".toCharArray(), digBuild.build()).setProvider("BC"), publicKey);
        InputStream clear = encP.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").setContentProvider("BC").build(secretKey.extractPrivateKey(null)));
        PGPObjectFactory plainFact = new PGPObjectFactory(clear, new BcKeyFingerprintCalculator());
        PGPCompressedData cData = (PGPCompressedData)plainFact.nextObject();
        PGPObjectFactory compFact = new PGPObjectFactory(cData.getDataStream(), new BcKeyFingerprintCalculator());
        PGPLiteralData lData = (PGPLiteralData)compFact.nextObject();
        if (!"test.txt".equals(lData.getFileName()))
        {
            fail("wrong file name detected");
        }

        PGPSecretKey key = PGPSecretKey.parseSecretKeyFromSExpr(new ByteArrayInputStream(sExprKeyMaster), new JcePBEProtectionRemoverFactory("test".toCharArray(), digBuild.build()).setProvider(new BouncyCastleProvider()), new JcaKeyFingerprintCalculator());
        PGPSignatureGenerator signGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(PGPPublicKey.ECDSA, HashAlgorithmTags.SHA256).setProvider("BC"));
        signGen.init(PGPSignature.BINARY_DOCUMENT, key.extractPrivateKey(null));
        signGen.update("hello world!".getBytes());
        PGPSignature sig = signGen.generate();
        publicKey = new JcaPGPPublicKeyRing(testPubKey2).getPublicKey();
        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);
        sig.update("hello world!".getBytes());
        if (!sig.verify())
        {
            fail("signature failed to verify!");
        }
    }

    private void sigsubpacketTest()
        throws Exception
    {
        char[] passPhrase = "test".toCharArray();
        String identity = "TEST <test@test.org>";
        Date date = new Date();

        RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();
        kpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x11), new SecureRandom(), 2048, 25));
        AsymmetricCipherKeyPair kpSgn = kpg.generateKeyPair();
        AsymmetricCipherKeyPair kpEnc = kpg.generateKeyPair();

        PGPKeyPair sgnKeyPair = new BcPGPKeyPair(PGPPublicKey.RSA_SIGN, kpSgn, date);
        PGPKeyPair encKeyPair = new BcPGPKeyPair(PGPPublicKey.RSA_GENERAL, kpEnc, date);

        PGPSignatureSubpacketGenerator svg = new PGPSignatureSubpacketGenerator();

        int[] aeadAlgs = new int[]{AEADAlgorithmTags.EAX,
            AEADAlgorithmTags.OCB, AEADAlgorithmTags.GCM, AEADAlgorithmTags.GCM};
        svg.setPreferredAEADAlgorithms(true, aeadAlgs);
        svg.setFeature(true, Features.FEATURE_MODIFICATION_DETECTION);
        svg.setKeyFlags(true, KeyFlags.CERTIFY_OTHER + KeyFlags.SIGN_DATA);
        PGPSignatureSubpacketVector hashedPcks = svg.generate();

        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION,
            sgnKeyPair, identity, new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
            hashedPcks, null, new BcPGPContentSignerBuilder(PGPPublicKey.RSA_GENERAL, HashAlgorithmTags.SHA1), new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256).build(passPhrase));

        svg = new PGPSignatureSubpacketGenerator();
        svg.setKeyExpirationTime(true, 2L);
        svg.setKeyFlags(true, KeyFlags.ENCRYPT_COMMS + KeyFlags.ENCRYPT_STORAGE);
        svg.setPrimaryUserID(true, false);
        svg.setFeature(true, Features.FEATURE_MODIFICATION_DETECTION);
        hashedPcks = svg.generate();

        keyRingGen.addSubKey(encKeyPair, hashedPcks, null);

        byte[] encodedKeyRing = keyRingGen.generatePublicKeyRing().getEncoded();

        PGPPublicKeyRing keyRing = new PGPPublicKeyRing(encodedKeyRing, new BcKeyFingerprintCalculator());

        for (Iterator it = keyRing.getPublicKeys(); it.hasNext(); )
        {
            PGPPublicKey pKey = (PGPPublicKey)it.next();

            if (!pKey.isEncryptionKey())
            {
                for (Iterator sit = pKey.getSignatures(); sit.hasNext(); )
                {
                    PGPSignature sig = (PGPSignature)sit.next();
                    PGPSignatureSubpacketVector v = sig.getHashedSubPackets();
                    if (!Arrays.areEqual(v.getPreferredAEADAlgorithms(), aeadAlgs))
                    {
                        fail("preferred aead algs don't match");
                    }
                }
            }
        }
    }


    public void testParsingFromSignature()
        throws IOException
    {
        String signatureWithPolicyUri = "-----BEGIN PGP SIGNATURE-----\n" +
            "\n" +
            "iKQEHxYKAFYFAmIRIAgJEDXXpSQjWzWvFiEEVSc3S9X9kRTsyfjqNdelJCNbNa8u\n" +
            "Gmh0dHBzOi8vZXhhbXBsZS5vcmcvfmFsaWNlL3NpZ25pbmctcG9saWN5LnR4dAAA\n" +
            "NnwBAImA2KdiS/7kLWoQpwc+A6N2PtAvLxG0gkZmGzYgRWvGAP9g4GLAA/GQ0plr\n" +
            "Xn7uLnOG49S1fFA9P+R1Dd8Qoa4+Dg==\n" +
            "=OPUu\n" +
            "-----END PGP SIGNATURE-----\n";

        ByteArrayInputStream byteIn = new ByteArrayInputStream(Strings.toByteArray(signatureWithPolicyUri));
        ArmoredInputStream armorIn = new ArmoredInputStream(byteIn);
        PGPObjectFactory objectFactory = new BcPGPObjectFactory(armorIn);

        PGPSignatureList signatures = (PGPSignatureList)objectFactory.nextObject();
        PGPSignature signature = signatures.get(0);

        PolicyURI[] policyURI = signature.getHashedSubPackets().getPolicyURIs();
        isEquals("https://example.org/~alice/signing-policy.txt", policyURI[0].getURI());

        PolicyURI other = new PolicyURI(false, "https://example.org/~alice/signing-policy.txt");

        ByteArrayOutputStream first = new ByteArrayOutputStream();
        policyURI[0].encode(first);

        ByteArrayOutputStream second = new ByteArrayOutputStream();
        other.encode(second);

        areEqual(first.toByteArray(), second.toByteArray());
    }

    /**
     * Test cover:
     * PGPSignatureSubpacketVector
     * PGPSignatureSubpacketGenerator
     */
    public void testPGPSignatureSubpacketVector()
        throws Exception
    {
        PGPSecretKeyRing pgpDSAPriv = new PGPSecretKeyRing(dsaKeyRing, new JcaKeyFingerprintCalculator());
        PGPSecretKeyRing pgpPriv = new PGPSecretKeyRing(rsaKeyRing, new JcaKeyFingerprintCalculator());
        PGPSecretKey secretKey = pgpPriv.getSecretKey();
        PGPPublicKey publicKey = pgpPriv.getPublicKey();
        PGPSecretKey secretDSAKey = pgpDSAPriv.getSecretKey();
        PGPPrivateKey pgpPrivDSAKey = secretDSAKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(dsaPass));
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1).setProvider("BC"));
        sGen.init(PGPSignature.DEFAULT_CERTIFICATION, pgpPrivDSAKey);
        PGPSignatureSubpacketGenerator hashedGen = new PGPSignatureSubpacketGenerator();
        hashedGen.addIntendedRecipientFingerprint(false, secretKey.getPublicKey());
        sGen.setHashedSubpackets(hashedGen.generate());
        //sGen.setUnhashedSubpackets(null);
        PGPSignature sig = sGen.generateCertification(TEST_USER_ID, secretKey.getPublicKey());
        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), secretDSAKey.getPublicKey());
        if (!sig.verifyCertification(TEST_USER_ID, secretKey.getPublicKey()))
        {
            fail("user-id verification failed.");
        }
        PGPSignatureSubpacketVector hashedPcks = sig.getHashedSubPackets();

        IntendedRecipientFingerprint[] intFig = hashedPcks.getIntendedRecipientFingerprints();
        isTrue("mismatch on intended rec. fingerprint", secretKey.getPublicKey().hasFingerprint(intFig[0].getFingerprint()));

        // Tests for null value
        isTrue("issuer key id should be 0", hashedPcks.getIssuerKeyID() == 0);
        // getSignatureCreationTime cannot return null via PGPSignatureGenerator.generate()
        isTrue("SignatureCreationTime cannot be null", hashedPcks.getSignatureCreationTime() != null);
        isTrue("PreferredAEADAlgorithms should be null", hashedPcks.getPreferredAEADAlgorithms() == null);
        isTrue("KeyFlags should be 0", hashedPcks.getKeyFlags() == 0);
        isTrue("isPrimaryUserID should be false", !hashedPcks.isPrimaryUserID());
        isTrue("SignatureTarget should be null", hashedPcks.getSignatureTarget() == null);
        isTrue("Features should be null", hashedPcks.getFeatures() == null);
        isTrue("IssuerFingerprint should be null", hashedPcks.getIssuerFingerprint() == null);
        isTrue("PolicyURI should be null", hashedPcks.getPolicyURI() == null);
        isTrue("PolicyURIs should be empty", hashedPcks.getPolicyURIs().length == 0);
        isTrue("RegularExpression should be null", hashedPcks.getRegularExpression() == null);
        isTrue("RegularExpressions should be empty", hashedPcks.getRegularExpressions().length == 0);
        isTrue("Revocable should be null", hashedPcks.getRevocable() == null);
        isTrue("Revocable should be true", hashedPcks.isRevocable());
        isTrue("RevocationKeys should be empty", hashedPcks.getRevocationKeys().length == 0);
        isTrue("RevocationReason should be null", hashedPcks.getRevocationReason() == null);
        isTrue("Trust should be null", hashedPcks.getTrust() == null);
        isTrue(hashedPcks.getIntendedRecipientFingerprint().getKeyVersion() == publicKey.getVersion());

        String regexString = "example.org";
        RegularExpression regex = new RegularExpression(false, regexString);
        hashedGen.addCustomSubpacket(regex);
        hashedGen.addRegularExpression(false, regexString);
        hashedGen.removePacket(hashedPcks.getIntendedRecipientFingerprint());
        hashedGen.setRevocable(false, false);
        hashedGen.setRevocationKey(false, PublicKeyAlgorithmTags.DSA, publicKey.getFingerprint());
        hashedGen.setIssuerKeyID(false, publicKey.getKeyID());
        hashedGen.setIssuerFingerprint(false, publicKey);
        final String description = "Test for Revocation";
        hashedGen.setRevocationReason(false, RevocationReasonTags.KEY_SUPERSEDED, description);
        hashedGen.setExportable(false, false);
        hashedGen.setPrimaryUserID(false, true);

        final int depth = 1;
        final int trustAmount = 255;
        hashedGen.setTrust(false, depth, trustAmount);
        sGen.setHashedSubpackets(hashedGen.generate());
        sig = sGen.generateCertification(TEST_USER_ID, secretKey.getPublicKey());
        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), secretDSAKey.getPublicKey());
        hashedPcks = sig.getHashedSubPackets();
        hashedPcks = PGPSignatureSubpacketVector.fromSubpackets(hashedPcks.toArray());

        isTrue("IntendedRecipientFingerprint should not be null", hashedPcks.getIntendedRecipientFingerprint() == null);
        isTrue("RegularExpression should not be null", hashedPcks.getRegularExpression() != null);
        isTrue("RegularExpressions should be empty", hashedPcks.getRegularExpressions().length == 2);
        isTrue("Revocable should not be null", hashedPcks.getRevocable() != null);
        isTrue("Revocable should be false", !hashedPcks.isRevocable());
        isTrue("RevocationKeys should not be empty", hashedPcks.getRevocationKeys().length == 1);
        RevocationKey revocationKey = hashedPcks.getRevocationKeys()[0];
        isTrue(publicKey.hasFingerprint(revocationKey.getFingerprint()));
        isTrue(revocationKey.getAlgorithm() == PublicKeyAlgorithmTags.DSA);
        // TODO: addRevocationKey has no parameter for setting signatureClass
        isTrue(revocationKey.getSignatureClass() == RevocationKeyTags.CLASS_DEFAULT);
        isTrue("IssuerKeyID should not be 0", hashedPcks.getIssuerKeyID() != 0L);
        RevocationReason revocationReason = hashedPcks.getRevocationReason();
        isTrue("RevocationReason should not be null", revocationReason != null);
        isTrue(revocationReason.getRevocationReason() == RevocationReasonTags.KEY_SUPERSEDED);
        isTrue(revocationReason.getRevocationDescription().equals(description));
        TrustSignature trustSignature = hashedPcks.getTrust();
        isTrue("Trust should be null", trustSignature != null);
        isTrue("Trust level depth should be " + depth, trustSignature.getDepth() == depth);
        isTrue("Trust amount should be " + trustAmount, trustSignature.getTrustAmount() == trustAmount);
        isTrue("Exporable should be false", !hashedPcks.isExportable());
        isTrue(hashedPcks.getIssuerFingerprint().getKeyVersion() == publicKey.getVersion());
        isTrue("isPrimaryUserID should be true", hashedPcks.isPrimaryUserID());


        PGPSignatureSubpacketVector hashedPcks2 = PGPSignatureSubpacketVector.fromSubpackets(null);
        isTrue("Empty PGPSignatureSubpacketVector", hashedPcks2.size() == 0);

        hashedGen = new PGPSignatureSubpacketGenerator();
        hashedGen.setExportable(false, true);
        try
        {
            hashedGen.setExportable(false, false);
            fail("Duplicated settings for Exportable");
        }
        catch (IllegalStateException e)
        {
            isTrue("Exportable Certification exists in the Signature Subpacket Generator",
                messageIs(e.getMessage(), "Exportable Certification exists in the Signature Subpacket Generator"));
        }
        hashedGen.setRevocable(false, true);
        try
        {
            hashedGen.setRevocable(false, false);
            fail("Duplicated settings for Revocable");
        }
        catch (IllegalStateException e)
        {
            isTrue("Revocable exists in the Signature Subpacket Generator",
                messageIs(e.getMessage(), "Revocable exists in the Signature Subpacket Generator"));
        }

        try
        {
            hashedGen.addSignerUserID(false, (String)null);
            fail("attempt to set null SignerUserID");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("attempt to set null SignerUserID", messageIs(e.getMessage(), "attempt to set null SignerUserID"));
        }
        try
        {
            hashedGen.setSignerUserID(false, (byte[])null);
            fail("attempt to set null SignerUserID");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("attempt to set null SignerUserID", messageIs(e.getMessage(), "attempt to set null SignerUserID"));
        }

        final byte[] signerUserId = new byte[0];
        hashedGen.setSignerUserID(false, signerUserId);
        SignerUserID signerUserID = (SignerUserID)hashedGen.getSubpackets(SignatureSubpacketTags.SIGNER_USER_ID)[0];
        isTrue(areEqual(signerUserID.getRawID(), signerUserId));
        isTrue("Test for null exist Subpacket", !hashedGen.hasSubpacket(SignatureSubpacketTags.KEY_SERVER_PREFS));

        final String url = "https://bouncycastle.org/policy/alice.txt";
        try
        {
            hashedGen.addRegularExpression(false, null);
            fail("attempt to set null regular expression");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("attempt to set null regular expression", messageIs(e.getMessage(), "attempt to set null regular expression"));
        }
        hashedGen.setRevocationReason(false, RevocationReasonTags.USER_NO_LONGER_VALID, "");
        hashedGen.addPolicyURI(false, url);
        hashedGen.setFeature(false, Features.FEATURE_SEIPD_V2);
        sGen.setHashedSubpackets(hashedGen.generate());
        sig = sGen.generateCertification(TEST_USER_ID, secretKey.getPublicKey());
        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), secretDSAKey.getPublicKey());
        hashedPcks = sig.getHashedSubPackets();
        isTrue("URL should be " + url, hashedPcks.getPolicyURI().getURI().equals(url));
        isTrue(areEqual(hashedPcks.getPolicyURI().getRawURI(), Strings.toUTF8ByteArray(url)));
        isTrue("Exporable should be true", hashedPcks.isExportable());
        isTrue("Test Singner User ID", hashedPcks.getSignerUserID().equals(""));
        isTrue("Test for empty description", hashedPcks.getRevocationReason().getRevocationDescription().equals(""));
        Features features = hashedPcks.getFeatures();
        isTrue(features.supportsSEIPDv2());
        isTrue(features.getFeatures() == Features.FEATURE_SEIPD_V2);
        isTrue(hashedPcks.getRevocable().isRevocable());
    }

    public void testECNistCurves()
        throws Exception
    {
        byte[][] examples = {p384Protected, p384Open};//, p384Open, p256Protected, p256Open, p512Protected, p512Open};
        byte[] data = ("Created: 20211021T235533\n" +
            "Key: (private-key (ecc (curve \"NIST P-384\")(q\n" +
            "  #041F93DB4628A4CC6F5DB1C3CFE952E4EF58C91511BCCDBA2A354975B827EE0D8B38\n" +
            " E4396A28A6FE69F8685B12663C20D055580B5024CC4B15EECAA5BBF82F4170B382F903\n" +
            " C7456DAB72DCC939CDC7B9382B884D61717F8CC51BAB86AE79FEEA51#)(d\n" +
            "  #5356E5F3BAAF9E38AF2A52CBFAEC8E33456E6D60249403A1FA657954DAE088AA9AA7\n" +
            " 9C2AA85CEEA28FE48491CE223F84#)))\n").getBytes();
        ByteArrayInputStream bin = new ByteArrayInputStream(data);
        JcaPGPDigestCalculatorProviderBuilder digBuild = new JcaPGPDigestCalculatorProviderBuilder();

        OpenedPGPKeyData openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);

        ExtendedPGPSecretKey secretKey = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
            null,
            digBuild.build(),
            new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()).setProvider("BC"),
            new JcaKeyFingerprintCalculator(), 10);

        PGPPublicKey publicKey = secretKey.getPublicKey();

        ExtendedPGPSecretKey secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
            publicKey,
            digBuild.build(),
            new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
            new JcaKeyFingerprintCalculator(), 10);

        try
        {
            bin = new ByteArrayInputStream(p256Protected);

            openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
            secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
                publicKey,
                digBuild.build(),
                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
                new JcaKeyFingerprintCalculator(), 10);
            fail("passed in public key does not match secret key");
        }
        catch (PGPException e)
        {
            isTrue("passed in public key does not match secret key",
                messageIs(e.getMessage(), "passed in public key does not match secret key"));
        }


        data = ("Created: 20211021T235533\n" +
            "Key: (shadowed-private-key (ecc (curve \"NIST P-384\")(q\n" +
            "  #041F93DB4628A4CC6F5DB1C3CFE952E4EF58C91511BCCDBA2A354975B827EE0D8B38\n" +
            " E4396A28A6FE69F8685B12663C20D055580B5024CC4B15EECAA5BBF82F4170B382F903\n" +
            " C7456DAB72DCC939CDC7B9382B884D61717F8CC51BAB86AE79FEEA51#)(d\n" +
            "  #5356E5F3BAAF9E38AF2A52CBFAEC8E33456E6D60249403A1FA657954DAE088AA9AA7\n" +
            " 9C2AA85CEEA28FE48491CE223F84#)))\n").getBytes();
        bin = new ByteArrayInputStream(data);

        openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
        secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
            null,
            digBuild.build(),
            new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
            new JcaKeyFingerprintCalculator(), 10);
        PGPKeyPair keyPair = secretKey.extractKeyPair(null);
        BcPGPKeyConverter keyConverter = new BcPGPKeyConverter();
        ECPrivateKeyParameters priv = (ECPrivateKeyParameters)keyConverter.getPrivateKey(keyPair.getPrivateKey());
        ECPublicKeyParameters pub = (ECPublicKeyParameters)keyConverter.getPublicKey(secretKey2.getPublicKey());
        if (!(priv.getParameters().getCurve().equals(pub.getParameters().getCurve())
            || !priv.getParameters().getG().equals(pub.getParameters().getG())
            || !priv.getParameters().getN().equals(pub.getParameters().getN())
            || priv.getParameters().getH().equals(pub.getParameters().getH())))
        {
            throw new IllegalArgumentException("EC keys do not have the same domain parameters");
        }

        ECDomainParameters spec = priv.getParameters();

        if (!spec.getG().multiply(priv.getD()).normalize().equals(pub.getQ()))
        {
            throw new IllegalArgumentException("EC public key not consistent with EC private key");
        }
        try
        {
            data = ("Created: 20211021T023233\n" +
                "Key: (protected-private-key (ecc (curve \"NIST P-384\")(q\n" +
                "  #04CE6089B366EFB0E4238CC43CBC6631708F122AEFF3408B9C14C14E9A2918D0BD18\n" +
                " D800FD90D6FB4142387913E14F78CA232B91A6C87BFE2841778A99D96EB292E6311E81\n" +
                " FEA3D40CE62F4B9641A481846C119AFDE08AE91DC7B7F705280FF077#)(protected\n" +
                "  openpgp-s2k3-ocb ((sha1 #E570C25E5DE65DD7#\n" +
                "  \"43860992\")#83D43BA89B7E7EA2EF758E52#)#CD30B49842A95DD0D18C2D8550CC59\n" +
                " 8187FE6DE7386418A319F7311197FE4344EE29ACC0B77D2EDF19E268DBB2130F82353B\n" +
                " 319D39306CDA53C6D9F883141738B522E35F6F9CD346B4B187578C#)(protected-at\n" +
                "  \"20211021T023240\")))\n").getBytes();
            bin = new ByteArrayInputStream(data);

            openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
            secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
                null,
                digBuild.build(),
                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
                new JcaKeyFingerprintCalculator(), 10);
            fail("unsupported protection type");
        }
        catch (PGPException e)
        {
            isTrue("unsupported protection type", messageIs(e.getMessage(), "unsupported protection type"));
        }

        try
        {
            data = ("Created: 20211021T023233\n" +
                "Key: (protected-private-key (ecc (curve \"NIST P-384\")(q\n" +
                "  #04CE6089B366EFB0E4238CC43CBC6631708F122AEFF3408B9C14C14E9A2918D0BD18\n" +
                " D800FD90D6FB4142387913E14F78CA232B91A6C87BFE2841778A99D96EB292E6311E81\n" +
                " FEA3D40CE62F4B9641A481846C119AFDE08AE91DC7B7F705280FF077#)(protected-at\n" +
                "  \"20211021T023240\")))\n").getBytes();
            bin = new ByteArrayInputStream(data);

            openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
            secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
                null,
                digBuild.build(),
                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
                new JcaKeyFingerprintCalculator(), 10);
            fail("does not have protected block");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("does not have protected block", messageIs(e.getMessage(), "does not have protected block"));
        }


        try
        {
            data = ("Created: 20211021T235533\n" +
                "Key: (private-key (ecc (q\n" +
                "  #041F93DB4628A4CC6F5DB1C3CFE952E4EF58C91511BCCDBA2A354975B827EE0D8B38\n" +
                " E4396A28A6FE69F8685B12663C20D055580B5024CC4B15EECAA5BBF82F4170B382F903\n" +
                " C7456DAB72DCC939CDC7B9382B884D61717F8CC51BAB86AE79FEEA51#)(d\n" +
                "  #5356E5F3BAAF9E38AF2A52CBFAEC8E33456E6D60249403A1FA657954DAE088AA9AA7\n" +
                " 9C2AA85CEEA28FE48491CE223F84#)))\n").getBytes();
            bin = new ByteArrayInputStream(data);

            openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
            secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
                null,
                digBuild.build(),
                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
                new JcaKeyFingerprintCalculator(), 10);
            fail("no curve expression");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("no curve expression", messageIs(e.getMessage(), "no curve expression"));
        }

        try
        {
            data = ("Created: 20211021T023233\n" +
                "Key: (protected-private-key (ecc (q\n" +
                "  #04CE6089B366EFB0E4238CC43CBC6631708F122AEFF3408B9C14C14E9A2918D0BD18\n" +
                " D800FD90D6FB4142387913E14F78CA232B91A6C87BFE2841778A99D96EB292E6311E81\n" +
                " FEA3D40CE62F4B9641A481846C119AFDE08AE91DC7B7F705280FF077#)(protected\n" +
                "  openpgp-s2k3-ocb-aes ((sha1 #E570C25E5DE65DD7#\n" +
                "  \"43860992\")#83D43BA89B7E7EA2EF758E52#)#CD30B49842A95DD0D18C2D8550CC59\n" +
                " 8187FE6DE7386418A319F7311197FE4344EE29ACC0B77D2EDF19E268DBB2130F82353B\n" +
                " 319D39306CDA53C6D9F883141738B522E35F6F9CD346B4B187578C#)(protected-at\n" +
                "  \"20211021T023240\")))\n").getBytes();
            bin = new ByteArrayInputStream(data);

            openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
            secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
                null,
                digBuild.build(),
                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
                new JcaKeyFingerprintCalculator(), 10);
            fail("no curve expression");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("no curve expression", messageIs(e.getMessage(), "no curve expression"));
        }

//        try
//        {
//            data = ("Created: 20211021T023233\n" +
//                "Key: (protected-private-key (ecc (curve \"NIST P-384\")(q\n" +
//                "  #04CE6089B366EFB0E4238CC43CBC6631708F122AEFF3408B9C14C14E9A2918D0BD18\n" +
//                " D800FD90D6FB4142387913E14F78CA232B91A6C87BFE2841778A99D96EB292E6311E81\n" +
//                " FEA3D40CE62F4B9641A481846C119AFDE08AE91DC7B7F705280FF077#)(protected\n" +
//                "  openpgp-s2k3-sha1-aes-cbc ((sha1 #E570C25E5DE65DD7#\n" +
//                "  \"43860992\")#83D43BA89B7E7EA2EF758E52#)#CD30B49842A95DD0D18C2D8550CC59\n" +
//                " 8187FE6DE7386418A319F7311197FE4344EE29ACC0B77D2EDF19E268DBB2130F82353B\n" +
//                " 319D39306CDA53C6D9F883141738B522E35F6F9CD346B4B187578C#)(protected-at\n" +
//                "  \"20211021T023240\")))\n").getBytes();
//            bin = new ByteArrayInputStream(data);
//
//            openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
//            secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
//                null,
//                digBuild.build(),
//                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
//                new JcaKeyFingerprintCalculator(), 10);
//            fail("openpgp-s2k3-sha1-aes-cbc not supported on newer key type");
//        }
//        catch (IllegalArgumentException e)
//        {
//            isTrue("openpgp-s2k3-sha1-aes-cbc not supported on newer key type", e.getMessage().contains("openpgp-s2k3-sha1-aes-cbc not supported on newer key type"));
//        }

        try
        {
            data = ("Created: 20211021T023233\n" +
                "Key: (protected-private-key (ecc (curve \"NIST P-384\")(q\n" +
                "  #04CE6089B366EFB0E4238CC43CBC6631708F122AEFF3408B9C14C14E9A2918D0BD18\n" +
                " D800FD90D6FB4142387913E14F78CA232B91A6C87BFE2841778A99D96EB292E6311E81\n" +
                " FEA3D40CE62F4B9641A481846C119AFDE08AE91DC7B7F705280FF077#)(protected\n" +
                "  openpgp-s2k3-sha1-aes ((sha1 #E570C25E5DE65DD7#\n" +
                "  \"43860992\")#83D43BA89B7E7EA2EF758E52#)#CD30B49842A95DD0D18C2D8550CC59\n" +
                " 8187FE6DE7386418A319F7311197FE4344EE29ACC0B77D2EDF19E268DBB2130F82353B\n" +
                " 319D39306CDA53C6D9F883141738B522E35F6F9CD346B4B187578C#)(protected-at\n" +
                "  \"20211021T023240\")))\n").getBytes();
            bin = new ByteArrayInputStream(data);

            openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
            secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
                null,
                digBuild.build(),
                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
                new JcaKeyFingerprintCalculator(), 10);
            fail("unsupported protection type ");
        }
        catch (PGPException e)
        {
            isTrue("unsupported protection type ", messageIs(e.getMessage(), "unsupported protection type "));
        }

        //TODO: getKeyData: branch in line 157 cannot be reached
    }


    public void testDSAElgamalOpen()
        throws Exception
    {
        byte[] key = dsaElgamalOpen;
        ByteArrayInputStream bin = new ByteArrayInputStream(key);
        isTrue(PGPSecretKeyParser.isExtendedSExpression(bin));
        JcaPGPDigestCalculatorProviderBuilder digBuild = new JcaPGPDigestCalculatorProviderBuilder();
        OpenedPGPKeyData openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
        ExtendedPGPSecretKey secretKey = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
            null,
            digBuild.build(),
            new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()).setProvider(new BouncyCastleProvider()),
            new JcaKeyFingerprintCalculator(), 10);

        bin = new ByteArrayInputStream(key);

        openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
        ExtendedPGPSecretKey secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
            secretKey.getPublicKey(),
            digBuild.build(),
            new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
            new JcaKeyFingerprintCalculator(), 10);
        PGPKeyPair pair = secretKey2.extractKeyPair(null);
        validateDSAKey(pair);

        key = ("Created: 20211020T050343\n" +
            "Key: (shadowed-private-key (elg (p #0082AEA32A1F3A30E08B19F7019E53D7DBC9351C4736\n" +
            " 25ED916439DB0E1DA9EC8CA9FA481F7B8AAC0968AE87FEDB93F9D957B8B62FFDAF15AD\n" +
            " 1375791ED4AE1A201B6E81F2800E1A0A5F600774C940C1C7687E2BDA5F603357BD25D8\n" +
            " BEAFEDEEA547EB4DEF313BBD07385F8532C21FEA4656843207B3A50C375B5ABF9E9886\n" +
            " 0243#)(g #05#)(y #7CF2AF5A729AE8C79A151377B8D8CF6A5DC5CB6450E4C42F2A82\n" +
            " 256CAA9375A0437AA1E1A0B56987FF8C801918664CF77356E8CB7A37764F3CC2EBD7BB\n" +
            " 56FFBF0E8DA3B25C9D697E7F0F609E10F1F35A62002BF5DFC930675C1339272267EBDE\n" +
            " 6588E985D0F1AC44F8C59AC50213D3D618F25C8FDF6EB6DFAC7FBA598EEB7CEA#)(x\n" +
            "  #02222A119771B79D3FA0BF2276769DB90D21F88A836064AFA890212504E12CEA#)))\n").getBytes();

        bin = new ByteArrayInputStream(key);

        openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
        secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
            secretKey.getPublicKey(),
            digBuild.build(),
            new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
            new JcaKeyFingerprintCalculator(), 10);

        ElGamalSecretBCPGKey priv = (ElGamalSecretBCPGKey)pair.getPrivateKey().getPrivateKeyDataPacket();
        BCPGInputStream inputStream = new BCPGInputStream(new ByteArrayInputStream(secretKey2.getPublicKey().getPublicKeyPacket().getKey().getEncoded()));
        isTrue(inputStream.markSupported());
        ElGamalPublicBCPGKey pub = new ElGamalPublicBCPGKey(inputStream);
        isTrue(pub.getFormat().equals("PGP"));
        isTrue(priv.getFormat().equals("PGP"));
        if (!pub.getG().modPow(priv.getX(), pub.getP()).equals(pub.getY()))
        {
            throw new IllegalArgumentException("DSA public key not consistent with DSA private key");
        }

        try
        {
            key = theKey;
            bin = new ByteArrayInputStream(key);

            openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
            secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
                secretKey.getPublicKey(),
                digBuild.build(),
                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
                new JcaKeyFingerprintCalculator(), 10);
            fail("passed in public key does not match secret key");
        }
        catch (PGPException e)
        {
            isTrue("passed in public key does not match secret key", messageIs(e.getMessage(), "passed in public key does not match secret key"));
        }

        try
        {
            key = ("Created: 20211020T050343\n" +
                "Key: (protected-private-key (elg (p #0082AEA32A1F3A30E08B19F7019E53D7DBC9351C4736\n" +
                " 25ED916439DB0E1DA9EC8CA9FA481F7B8AAC0968AE87FEDB93F9D957B8B62FFDAF15AD\n" +
                " 1375791ED4AE1A201B6E81F2800E1A0A5F600774C940C1C7687E2BDA5F603357BD25D8\n" +
                " BEAFEDEEA547EB4DEF313BBD07385F8532C21FEA4656843207B3A50C375B5ABF9E9886\n" +
                " 0243#)(g #05#)(y #7CF2AF5A729AE8C79A151377B8D8CF6A5DC5CB6450E4C42F2A82\n" +
                " 256CAA9375A0437AA1E1A0B56987FF8C801918664CF77356E8CB7A37764F3CC2EBD7BB\n" +
                " 56FFBF0E8DA3B25C9D697E7F0F609E10F1F35A62002BF5DFC930675C1339272267EBDE\n" +
                " 6588E985D0F1AC44F8C59AC50213D3D618F25C8FDF6EB6DFAC7FBA598EEB7CEA#)(x\n" +
                "  #02222A119771B79D3FA0BF2276769DB90D21F88A836064AFA890212504E12CEA#)))\n").getBytes();

            bin = new ByteArrayInputStream(key);

            openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
            secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
                secretKey.getPublicKey(),
                digBuild.build(),
                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
                new JcaKeyFingerprintCalculator(), 10);
            fail("does not have protected block");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("does not have protected block", messageIs(e.getMessage(), "does not have protected block"));
        }

        try
        {
            key = ("Created: 20211022T053140\n" +
                "Key: (protected-private-key (elg (p #00CD7275234699FE0D25FDBEE69DA2AA80\n" +
                " AAAB15906FACFC8F4EB5A9BAE23D22E5649199C119FB72951BD0FA717F51CFD7B904FD\n" +
                " BB1F0D0660938199976DA4447F54E91E2CC4B21F4BB162644EA43A3F27F7CAFF7D6355\n" +
                " 16E8640558E222EF20B55E8AF2AFD33D571092CE5C090E57DA3452484BC04398E24613\n" +
                " D593113F1F5CE7CA3229F5DFAFC1EFC47B725505E46A0EB9CC45FACFBEA6ECC6CA694E\n" +
                " D3781E011C48C66BBB6C1BA35DD810EF24CF7B92D9E9BCB0B0E19053CFA073AD2D9957\n" +
                " 270B3C55D60824F93EECBF8AF393F07C05BEA38636DFC6B6152424FAF5C0287435C145\n" +
                " B021E235AA30E2B063695EE01D6C696EAA381517E50A440D8AA00164B423#)(q\n" +
                "  #00A4F8D3DC79F1F8388B9FF3F3A484568A76337BF968F05C207F5AF8E84F4B83C1#)\n" +
                " (g #32EC716A63D63CB69E17A678B9BC70686EA24AF4F96F46683E09ACF7EDE9839ADB\n" +
                " 914E61A38D151B28B65533362100B1D9D2948FD8617136FF82C8B61DF5A400B3D2A3E3\n" +
                " 2CEAF2B7DAEBF30D24CA3E681AC551F01EC366EECCDF1481B092E3534728D73211D962\n" +
                " 09069E8FA34395C94828D77F0FEF8E6DEFEA3687ED6267EB028007B84840E383E8B14C\n" +
                " AB93109FA414458E56F5BDAF7AB37ECB3E3FA8EDAED60B7323D3329FB3EA4E460FFA63\n" +
                " B9EC9836530B16710A0EA3A750BF646A48DA65E4144A9A7964513BF998755612791DC5\n" +
                " F840FAE54D34C44A62C1BE884774870BC6D0505FE5EE3F4B222194740E4CC639785E56\n" +
                " B93E17DCACBFE63703DE201DB3#)(y #1B1DAAA76ACF531DBC172304E6523C16B3E701\n" +
                " 2B8B3F0D37AFD9B2C8F63A2155F2CAAE34ADF7A8B068AB266AEE5A5598DD9BE116FA96\n" +
                " F855AA7AD74F780407F74255DC035339C28E1833E93D872EE73DE350E3E0B8AB1E9709\n" +
                " B835E58E6A5491383612A52EB4A3616C29418C0BE108739CC3D59BCF3B0299B283FEA6\n" +
                " 7E21A1909C2E02CD1BFE200F0B6EEE0BB8E4252B8F78711AD05C7056CE673ED81BE265\n" +
                " 60C0768AEC8121D5EB21EE6A8338CC35E306931D1B3516767E345B9C25DF7454C36C61\n" +
                " 739B193BC4998A47A4E5A4956FF525F322DA67B9DC6CFA468ADEBC82EBEEB7F35C4982\n" +
                " A2D347ED4ECB8605387161F03175A9D73659A34D97910B26F8027F#)(protected\n" +
                "  openpgp-s2k3-ocb ((sha1 #4F333DA86C1E7E55#\n" +
                "  \"43860992\")#D8BD10519B004263EC2E35D4#)#57553ACF88CB775B65AAE3FAEB2480\n" +
                " F40BA80AFEA74DD1B9E59847B440733B3A83B062EAD3FDBF67996BA240B8504800C276\n" +
                " AAF1DE797066443807DDCE#)(protected-at \"20211022T053148\")))\n").getBytes();
            bin = new ByteArrayInputStream(key);

            openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
            secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
                null,
                digBuild.build(),
                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
                new JcaKeyFingerprintCalculator(), 10);
            fail("unsupported protection type");
        }
        catch (PGPException e)
        {
            isTrue("unsupported protection type", messageIs(e.getMessage(), "unsupported protection type"));
        }
    }

    public void testDSA()
        throws Exception
    {
        byte[] key = dsaProtected;
        ByteArrayInputStream bin = new ByteArrayInputStream(key);
        isTrue(PGPSecretKeyParser.isExtendedSExpression(bin));

        JcaPGPDigestCalculatorProviderBuilder digBuild = new JcaPGPDigestCalculatorProviderBuilder();

        OpenedPGPKeyData openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);

        ExtendedPGPSecretKey secretKey = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
            null,
            digBuild.build(),
            new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
            new JcaKeyFingerprintCalculator(), 10);
        PGPKeyPair pair = secretKey.extractKeyPair(null);
        ExtendedPGPSecretKey secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
            pair.getPublicKey(),
            digBuild.build(),
            new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
            new JcaKeyFingerprintCalculator(), 10);
        PGPKeyPair pair2 = secretKey2.extractKeyPair(null);
        validateDSAKey(pair2);

        try
        {
            key = ("Created: 20211022T053140\n" +
                "Key: (protected-private-key (dsa (p #00CD7275234699FE0D25FDBEE69DA2AA80\n" +
                " AAAB15906FACFC8F4EB5A9BAE23D22E5649199C119FB72951BD0FA717F51CFD7B904FD\n" +
                " BB1F0D0660938199976DA4447F54E91E2CC4B21F4BB162644EA43A3F27F7CAFF7D6355\n" +
                " 16E8640558E222EF20B55E8AF2AFD33D571092CE5C090E57DA3452484BC04398E24613\n" +
                " D593113F1F5CE7CA3229F5DFAFC1EFC47B725505E46A0EB9CC45FACFBEA6ECC6CA694E\n" +
                " D3781E011C48C66BBB6C1BA35DD810EF24CF7B92D9E9BCB0B0E19053CFA073AD2D9957\n" +
                " 270B3C55D60824F93EECBF8AF393F07C05BEA38636DFC6B6152424FAF5C0287435C145\n" +
                " B021E235AA30E2B063695EE01D6C696EAA381517E50A440D8AA00164B423#)(q\n" +
                "  #00A4F8D3DC79F1F8388B9FF3F3A484568A76337BF968F05C207F5AF8E84F4B83C1#)\n" +
                " (g #32EC716A63D63CB69E17A678B9BC70686EA24AF4F96F46683E09ACF7EDE9839ADB\n" +
                " 914E61A38D151B28B65533362100B1D9D2948FD8617136FF82C8B61DF5A400B3D2A3E3\n" +
                " 2CEAF2B7DAEBF30D24CA3E681AC551F01EC366EECCDF1481B092E3534728D73211D962\n" +
                " 09069E8FA34395C94828D77F0FEF8E6DEFEA3687ED6267EB028007B84840E383E8B14C\n" +
                " AB93109FA414458E56F5BDAF7AB37ECB3E3FA8EDAED60B7323D3329FB3EA4E460FFA63\n" +
                " B9EC9836530B16710A0EA3A750BF646A48DA65E4144A9A7964513BF998755612791DC5\n" +
                " F840FAE54D34C44A62C1BE884774870BC6D0505FE5EE3F4B222194740E4CC639785E56\n" +
                " B93E17DCACBFE63703DE201DB3#)(y #1B1DAAA76ACF531DBC172304E6523C16B3E701\n" +
                " 2B8B3F0D37AFD9B2C8F63A2155F2CAAE34ADF7A8B068AB266AEE5A5598DD9BE116FA96\n" +
                " F855AA7AD74F780407F74255DC035339C28E1833E93D872EE73DE350E3E0B8AB1E9709\n" +
                " B835E58E6A5491383612A52EB4A3616C29418C0BE108739CC3D59BCF3B0299B283FEA6\n" +
                " 7E21A1909C2E02CD1BFE200F0B6EEE0BB8E4252B8F78711AD05C7056CE673ED81BE265\n" +
                " 60C0768AEC8121D5EB21EE6A8338CC35E306931D1B3516767E345B9C25DF7454C36C61\n" +
                " 739B193BC4998A47A4E5A4956FF525F322DA67B9DC6CFA468ADEBC82EBEEB7F35C4982\n" +
                " A2D347ED4ECB8605387161F03175A9D73659A34D97910B26F8027D#)(protected\n" +
                "  openpgp-s2k3-ocb-aes ((sha1 #4F333DA86C1E7E55#\n" +
                "  \"43860992\")#D8BD10519B004263EC2E35D4#)#57553ACF88CB775B65AAE3FAEB2480\n" +
                " F40BA80AFEA74DD1B9E59847B440733B3A83B062EAD3FDBF67996BA240B8504800C276\n" +
                " AAF1DE797066443807DDCE#)(protected-at \"20211022T053148\")))\n").getBytes();
            bin = new ByteArrayInputStream(key);

            openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
            secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
                secretKey.getPublicKey(),
                digBuild.build(),
                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
                new JcaKeyFingerprintCalculator(), 10);
            fail("passed in public key does not match secret key");
        }
        catch (PGPException e)
        {
            isTrue("passed in public key does not match secret key", messageIs(e.getMessage(), "passed in public key does not match secret key"));
        }

        key = ("Created: 20211022T053140\n" +
            "Key: (shadowed-private-key (dsa (p #00CD7275234699FE0D25FDBEE69DA2AA80\n" +
            " AAAB15906FACFC8F4EB5A9BAE23D22E5649199C119FB72951BD0FA717F51CFD7B904FD\n" +
            " BB1F0D0660938199976DA4447F54E91E2CC4B21F4BB162644EA43A3F27F7CAFF7D6355\n" +
            " 16E8640558E222EF20B55E8AF2AFD33D571092CE5C090E57DA3452484BC04398E24613\n" +
            " D593113F1F5CE7CA3229F5DFAFC1EFC47B725505E46A0EB9CC45FACFBEA6ECC6CA694E\n" +
            " D3781E011C48C66BBB6C1BA35DD810EF24CF7B92D9E9BCB0B0E19053CFA073AD2D9957\n" +
            " 270B3C55D60824F93EECBF8AF393F07C05BEA38636DFC6B6152424FAF5C0287435C145\n" +
            " B021E235AA30E2B063695EE01D6C696EAA381517E50A440D8AA00164B423#)(q\n" +
            "  #00A4F8D3DC79F1F8388B9FF3F3A484568A76337BF968F05C207F5AF8E84F4B83C1#)\n" +
            " (g #32EC716A63D63CB69E17A678B9BC70686EA24AF4F96F46683E09ACF7EDE9839ADB\n" +
            " 914E61A38D151B28B65533362100B1D9D2948FD8617136FF82C8B61DF5A400B3D2A3E3\n" +
            " 2CEAF2B7DAEBF30D24CA3E681AC551F01EC366EECCDF1481B092E3534728D73211D962\n" +
            " 09069E8FA34395C94828D77F0FEF8E6DEFEA3687ED6267EB028007B84840E383E8B14C\n" +
            " AB93109FA414458E56F5BDAF7AB37ECB3E3FA8EDAED60B7323D3329FB3EA4E460FFA63\n" +
            " B9EC9836530B16710A0EA3A750BF646A48DA65E4144A9A7964513BF998755612791DC5\n" +
            " F840FAE54D34C44A62C1BE884774870BC6D0505FE5EE3F4B222194740E4CC639785E56\n" +
            " B93E17DCACBFE63703DE201DB3#)(y #1B1DAAA76ACF531DBC172304E6523C16B3E701\n" +
            " 2B8B3F0D37AFD9B2C8F63A2155F2CAAE34ADF7A8B068AB266AEE5A5598DD9BE116FA96\n" +
            " F855AA7AD74F780407F74255DC035339C28E1833E93D872EE73DE350E3E0B8AB1E9709\n" +
            " B835E58E6A5491383612A52EB4A3616C29418C0BE108739CC3D59BCF3B0299B283FEA6\n" +
            " 7E21A1909C2E02CD1BFE200F0B6EEE0BB8E4252B8F78711AD05C7056CE673ED81BE265\n" +
            " 60C0768AEC8121D5EB21EE6A8338CC35E306931D1B3516767E345B9C25DF7454C36C61\n" +
            " 739B193BC4998A47A4E5A4956FF525F322DA67B9DC6CFA468ADEBC82EBEEB7F35C4982\n" +
            " A2D347ED4ECB8605387161F03175A9D73659A34D97910B26F8027F#)(protected-at \"20211022T053148\")))\n").getBytes();
        bin = new ByteArrayInputStream(key);

        openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
        secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
            null,
            digBuild.build(),
            new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
            new JcaKeyFingerprintCalculator(), 10);

        DSASecretBCPGKey priv = (DSASecretBCPGKey)pair.getPrivateKey().getPrivateKeyDataPacket();
        DSAPublicBCPGKey pub = (DSAPublicBCPGKey)secretKey2.getPublicKey().getPublicKeyPacket().getKey();
        isTrue(priv.getFormat().equals("PGP"));
        isTrue(pub.getFormat().equals("PGP"));
        pub = new DSAPublicBCPGKey(new BCPGInputStream(new ByteArrayInputStream(pub.getEncoded())));

        if (!pub.getG().modPow(priv.getX(), pub.getP()).equals(pub.getY()))
        {
            throw new IllegalArgumentException("DSA public key not consistent with DSA private key");
        }

        try
        {
            key = ("Created: 20211022T053140\n" +
                "Key: (protected-private-key (dsa (p #00CD7275234699FE0D25FDBEE69DA2AA80\n" +
                " AAAB15906FACFC8F4EB5A9BAE23D22E5649199C119FB72951BD0FA717F51CFD7B904FD\n" +
                " BB1F0D0660938199976DA4447F54E91E2CC4B21F4BB162644EA43A3F27F7CAFF7D6355\n" +
                " 16E8640558E222EF20B55E8AF2AFD33D571092CE5C090E57DA3452484BC04398E24613\n" +
                " D593113F1F5CE7CA3229F5DFAFC1EFC47B725505E46A0EB9CC45FACFBEA6ECC6CA694E\n" +
                " D3781E011C48C66BBB6C1BA35DD810EF24CF7B92D9E9BCB0B0E19053CFA073AD2D9957\n" +
                " 270B3C55D60824F93EECBF8AF393F07C05BEA38636DFC6B6152424FAF5C0287435C145\n" +
                " B021E235AA30E2B063695EE01D6C696EAA381517E50A440D8AA00164B423#)(q\n" +
                "  #00A4F8D3DC79F1F8388B9FF3F3A484568A76337BF968F05C207F5AF8E84F4B83C1#)\n" +
                " (g #32EC716A63D63CB69E17A678B9BC70686EA24AF4F96F46683E09ACF7EDE9839ADB\n" +
                " 914E61A38D151B28B65533362100B1D9D2948FD8617136FF82C8B61DF5A400B3D2A3E3\n" +
                " 2CEAF2B7DAEBF30D24CA3E681AC551F01EC366EECCDF1481B092E3534728D73211D962\n" +
                " 09069E8FA34395C94828D77F0FEF8E6DEFEA3687ED6267EB028007B84840E383E8B14C\n" +
                " AB93109FA414458E56F5BDAF7AB37ECB3E3FA8EDAED60B7323D3329FB3EA4E460FFA63\n" +
                " B9EC9836530B16710A0EA3A750BF646A48DA65E4144A9A7964513BF998755612791DC5\n" +
                " F840FAE54D34C44A62C1BE884774870BC6D0505FE5EE3F4B222194740E4CC639785E56\n" +
                " B93E17DCACBFE63703DE201DB3#)(y #1B1DAAA76ACF531DBC172304E6523C16B3E701\n" +
                " 2B8B3F0D37AFD9B2C8F63A2155F2CAAE34ADF7A8B068AB266AEE5A5598DD9BE116FA96\n" +
                " F855AA7AD74F780407F74255DC035339C28E1833E93D872EE73DE350E3E0B8AB1E9709\n" +
                " B835E58E6A5491383612A52EB4A3616C29418C0BE108739CC3D59BCF3B0299B283FEA6\n" +
                " 7E21A1909C2E02CD1BFE200F0B6EEE0BB8E4252B8F78711AD05C7056CE673ED81BE265\n" +
                " 60C0768AEC8121D5EB21EE6A8338CC35E306931D1B3516767E345B9C25DF7454C36C61\n" +
                " 739B193BC4998A47A4E5A4956FF525F322DA67B9DC6CFA468ADEBC82EBEEB7F35C4982\n" +
                " A2D347ED4ECB8605387161F03175A9D73659A34D97910B26F8027F#)(protected-at \"20211022T053148\")))\n").getBytes();
            bin = new ByteArrayInputStream(key);

            openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
            secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
                null,
                digBuild.build(),
                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
                new JcaKeyFingerprintCalculator(), 10);
            fail("does not have protected block");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("does not have protected block", messageIs(e.getMessage(), "does not have protected block"));
        }

        try
        {
            key = ("Created: 20211022T053140\n" +
                "Key: (protected-private-key (dsa (p #00CD7275234699FE0D25FDBEE69DA2AA80\n" +
                " AAAB15906FACFC8F4EB5A9BAE23D22E5649199C119FB72951BD0FA717F51CFD7B904FD\n" +
                " BB1F0D0660938199976DA4447F54E91E2CC4B21F4BB162644EA43A3F27F7CAFF7D6355\n" +
                " 16E8640558E222EF20B55E8AF2AFD33D571092CE5C090E57DA3452484BC04398E24613\n" +
                " D593113F1F5CE7CA3229F5DFAFC1EFC47B725505E46A0EB9CC45FACFBEA6ECC6CA694E\n" +
                " D3781E011C48C66BBB6C1BA35DD810EF24CF7B92D9E9BCB0B0E19053CFA073AD2D9957\n" +
                " 270B3C55D60824F93EECBF8AF393F07C05BEA38636DFC6B6152424FAF5C0287435C145\n" +
                " B021E235AA30E2B063695EE01D6C696EAA381517E50A440D8AA00164B423#)(q\n" +
                "  #00A4F8D3DC79F1F8388B9FF3F3A484568A76337BF968F05C207F5AF8E84F4B83C1#)\n" +
                " (g #32EC716A63D63CB69E17A678B9BC70686EA24AF4F96F46683E09ACF7EDE9839ADB\n" +
                " 914E61A38D151B28B65533362100B1D9D2948FD8617136FF82C8B61DF5A400B3D2A3E3\n" +
                " 2CEAF2B7DAEBF30D24CA3E681AC551F01EC366EECCDF1481B092E3534728D73211D962\n" +
                " 09069E8FA34395C94828D77F0FEF8E6DEFEA3687ED6267EB028007B84840E383E8B14C\n" +
                " AB93109FA414458E56F5BDAF7AB37ECB3E3FA8EDAED60B7323D3329FB3EA4E460FFA63\n" +
                " B9EC9836530B16710A0EA3A750BF646A48DA65E4144A9A7964513BF998755612791DC5\n" +
                " F840FAE54D34C44A62C1BE884774870BC6D0505FE5EE3F4B222194740E4CC639785E56\n" +
                " B93E17DCACBFE63703DE201DB3#)(y #1B1DAAA76ACF531DBC172304E6523C16B3E701\n" +
                " 2B8B3F0D37AFD9B2C8F63A2155F2CAAE34ADF7A8B068AB266AEE5A5598DD9BE116FA96\n" +
                " F855AA7AD74F780407F74255DC035339C28E1833E93D872EE73DE350E3E0B8AB1E9709\n" +
                " B835E58E6A5491383612A52EB4A3616C29418C0BE108739CC3D59BCF3B0299B283FEA6\n" +
                " 7E21A1909C2E02CD1BFE200F0B6EEE0BB8E4252B8F78711AD05C7056CE673ED81BE265\n" +
                " 60C0768AEC8121D5EB21EE6A8338CC35E306931D1B3516767E345B9C25DF7454C36C61\n" +
                " 739B193BC4998A47A4E5A4956FF525F322DA67B9DC6CFA468ADEBC82EBEEB7F35C4982\n" +
                " A2D347ED4ECB8605387161F03175A9D73659A34D97910B26F8027F#)(protected\n" +
                "  openpgp-s2k3-ocb ((sha1 #4F333DA86C1E7E55#\n" +
                "  \"43860992\")#D8BD10519B004263EC2E35D4#)#57553ACF88CB775B65AAE3FAEB2480\n" +
                " F40BA80AFEA74DD1B9E59847B440733B3A83B062EAD3FDBF67996BA240B8504800C276\n" +
                " AAF1DE797066443807DDCE#)(protected-at \"20211022T053148\")))\n").getBytes();
            bin = new ByteArrayInputStream(key);

            openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
            secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
                null,
                digBuild.build(),
                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
                new JcaKeyFingerprintCalculator(), 10);
            fail("unsupported protection type");
        }
        catch (PGPException e)
        {
            isTrue("unsupported protection type", messageIs(e.getMessage(), "unsupported protection type"));
        }

//        try
//        {
//            key = ("Created: 20211022T053140\n" +
//                "Key: (protected-private-key (dsa (p #00CD7275234699FE0D25FDBEE69DA2AA80\n" +
//                " AAAB15906FACFC8F4EB5A9BAE23D22E5649199C119FB72951BD0FA717F51CFD7B904FD\n" +
//                " BB1F0D0660938199976DA4447F54E91E2CC4B21F4BB162644EA43A3F27F7CAFF7D6355\n" +
//                " 16E8640558E222EF20B55E8AF2AFD33D571092CE5C090E57DA3452484BC04398E24613\n" +
//                " D593113F1F5CE7CA3229F5DFAFC1EFC47B725505E46A0EB9CC45FACFBEA6ECC6CA694E\n" +
//                " D3781E011C48C66BBB6C1BA35DD810EF24CF7B92D9E9BCB0B0E19053CFA073AD2D9957\n" +
//                " 270B3C55D60824F93EECBF8AF393F07C05BEA38636DFC6B6152424FAF5C0287435C145\n" +
//                " B021E235AA30E2B063695EE01D6C696EAA381517E50A440D8AA00164B423#)(q\n" +
//                "  #00A4F8D3DC79F1F8388B9FF3F3A484568A76337BF968F05C207F5AF8E84F4B83C1#)\n" +
//                " (g #32EC716A63D63CB69E17A678B9BC70686EA24AF4F96F46683E09ACF7EDE9839ADB\n" +
//                " 914E61A38D151B28B65533362100B1D9D2948FD8617136FF82C8B61DF5A400B3D2A3E3\n" +
//                " 2CEAF2B7DAEBF30D24CA3E681AC551F01EC366EECCDF1481B092E3534728D73211D962\n" +
//                " 09069E8FA34395C94828D77F0FEF8E6DEFEA3687ED6267EB028007B84840E383E8B14C\n" +
//                " AB93109FA414458E56F5BDAF7AB37ECB3E3FA8EDAED60B7323D3329FB3EA4E460FFA63\n" +
//                " B9EC9836530B16710A0EA3A750BF646A48DA65E4144A9A7964513BF998755612791DC5\n" +
//                " F840FAE54D34C44A62C1BE884774870BC6D0505FE5EE3F4B222194740E4CC639785E56\n" +
//                " B93E17DCACBFE63703DE201DB3#)(y #1B1DAAA76ACF531DBC172304E6523C16B3E701\n" +
//                " 2B8B3F0D37AFD9B2C8F63A2155F2CAAE34ADF7A8B068AB266AEE5A5598DD9BE116FA96\n" +
//                " F855AA7AD74F780407F74255DC035339C28E1833E93D872EE73DE350E3E0B8AB1E9709\n" +
//                " B835E58E6A5491383612A52EB4A3616C29418C0BE108739CC3D59BCF3B0299B283FEA6\n" +
//                " 7E21A1909C2E02CD1BFE200F0B6EEE0BB8E4252B8F78711AD05C7056CE673ED81BE265\n" +
//                " 60C0768AEC8121D5EB21EE6A8338CC35E306931D1B3516767E345B9C25DF7454C36C61\n" +
//                " 739B193BC4998A47A4E5A4956FF525F322DA67B9DC6CFA468ADEBC82EBEEB7F35C4982\n" +
//                " A2D347ED4ECB8605387161F03175A9D73659A34D97910B26F8027F#)(protected\n" +
//                "  openpgp-s2k3-sha1-aes-cbc ((sha1 #4F333DA86C1E7E55#\n" +
//                "  \"43860992\")#D8BD10519B004263EC2E35D4#)#57553ACF88CB775B65AAE3FAEB2480\n" +
//                " F40BA80AFEA74DD1B9E59847B440733B3A83B062EAD3FDBF67996BA240B8504800C276\n" +
//                " AAF1DE797066443807DDCE#)(protected-at \"20211022T053148\")))\n").getBytes();
//            bin = new ByteArrayInputStream(key);
//
//            openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
//            secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
//                null,
//                digBuild.build(),
//                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
//                new JcaKeyFingerprintCalculator(), 10);
//            fail("openpgp-s2k3-sha1-aes-cbc not supported on newer key type");
//        }
//        catch (IllegalArgumentException e)
//        {
//            isTrue("openpgp-s2k3-sha1-aes-cbc not supported on newer key type",
//                e.getMessage().contains("openpgp-s2k3-sha1-aes-cbc not supported on newer key type"));
//        }

//        try
//        {
//            key = ("Created: 20211022T053140\n" +
//                "Key: (protected-private-key (dsa (p #00CD7275234699FE0D25FDBEE69DA2AA80\n" +
//                " AAAB15906FACFC8F4EB5A9BAE23D22E5649199C119FB72951BD0FA717F51CFD7B904FD\n" +
//                " BB1F0D0660938199976DA4447F54E91E2CC4B21F4BB162644EA43A3F27F7CAFF7D6355\n" +
//                " 16E8640558E222EF20B55E8AF2AFD33D571092CE5C090E57DA3452484BC04398E24613\n" +
//                " D593113F1F5CE7CA3229F5DFAFC1EFC47B725505E46A0EB9CC45FACFBEA6ECC6CA694E\n" +
//                " D3781E011C48C66BBB6C1BA35DD810EF24CF7B92D9E9BCB0B0E19053CFA073AD2D9957\n" +
//                " 270B3C55D60824F93EECBF8AF393F07C05BEA38636DFC6B6152424FAF5C0287435C145\n" +
//                " B021E235AA30E2B063695EE01D6C696EAA381517E50A440D8AA00164B423#)(q\n" +
//                "  #00A4F8D3DC79F1F8388B9FF3F3A484568A76337BF968F05C207F5AF8E84F4B83C1#)\n" +
//                " (g #32EC716A63D63CB69E17A678B9BC70686EA24AF4F96F46683E09ACF7EDE9839ADB\n" +
//                " 914E61A38D151B28B65533362100B1D9D2948FD8617136FF82C8B61DF5A400B3D2A3E3\n" +
//                " 2CEAF2B7DAEBF30D24CA3E681AC551F01EC366EECCDF1481B092E3534728D73211D962\n" +
//                " 09069E8FA34395C94828D77F0FEF8E6DEFEA3687ED6267EB028007B84840E383E8B14C\n" +
//                " AB93109FA414458E56F5BDAF7AB37ECB3E3FA8EDAED60B7323D3329FB3EA4E460FFA63\n" +
//                " B9EC9836530B16710A0EA3A750BF646A48DA65E4144A9A7964513BF998755612791DC5\n" +
//                " F840FAE54D34C44A62C1BE884774870BC6D0505FE5EE3F4B222194740E4CC639785E56\n" +
//                " B93E17DCACBFE63703DE201DB3#)(y #1B1DAAA76ACF531DBC172304E6523C16B3E701\n" +
//                " 2B8B3F0D37AFD9B2C8F63A2155F2CAAE34ADF7A8B068AB266AEE5A5598DD9BE116FA96\n" +
//                " F855AA7AD74F780407F74255DC035339C28E1833E93D872EE73DE350E3E0B8AB1E9709\n" +
//                " B835E58E6A5491383612A52EB4A3616C29418C0BE108739CC3D59BCF3B0299B283FEA6\n" +
//                " 7E21A1909C2E02CD1BFE200F0B6EEE0BB8E4252B8F78711AD05C7056CE673ED81BE265\n" +
//                " 60C0768AEC8121D5EB21EE6A8338CC35E306931D1B3516767E345B9C25DF7454C36C61\n" +
//                " 739B193BC4998A47A4E5A4956FF525F322DA67B9DC6CFA468ADEBC82EBEEB7F35C4982\n" +
//                " A2D347ED4ECB8605387161F03175A9D73659A34D97910B26F8027F#)(protected\n" +
//                "  openpgp-s2k3-aes ((sha1 #4F333DA86C1E7E55#\n" +
//                "  \"43860992\")#D8BD10519B004263EC2E35D4#)#57553ACF88CB775B65AAE3FAEB2480\n" +
//                " F40BA80AFEA74DD1B9E59847B440733B3A83B062EAD3FDBF67996BA240B8504800C276\n" +
//                " AAF1DE797066443807DDCE#)(protected-at \"20211022T053148\")))\n").getBytes();
//            bin = new ByteArrayInputStream(key);
//
//            openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
//            secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
//                null,
//                digBuild.build(),
//                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
//                new JcaKeyFingerprintCalculator(), 10);
//            fail("unhandled protection type");
//        }
//        catch (PGPException e)
//        {
//            isTrue("unhandled protection type", e.getMessage().contains("unhandled protection type"));
//        }
    }

    private void validateDSAKey(PGPKeyPair keyPair)
    {

        if (keyPair.getPrivateKey().getPrivateKeyDataPacket() instanceof ElGamalSecretBCPGKey)
        {
            ElGamalSecretBCPGKey priv = (ElGamalSecretBCPGKey)keyPair.getPrivateKey().getPrivateKeyDataPacket();
            ElGamalPublicBCPGKey pub = (ElGamalPublicBCPGKey)keyPair.getPublicKey().getPublicKeyPacket().getKey();

            if (!pub.getG().modPow(priv.getX(), pub.getP()).equals(pub.getY()))
            {
                throw new IllegalArgumentException("DSA public key not consistent with DSA private key");
            }
        }
        else
        {
            DSASecretBCPGKey priv = (DSASecretBCPGKey)keyPair.getPrivateKey().getPrivateKeyDataPacket();
            DSAPublicBCPGKey pub = (DSAPublicBCPGKey)keyPair.getPublicKey().getPublicKeyPacket().getKey();

            if (!pub.getG().modPow(priv.getX(), pub.getP()).equals(pub.getY()))
            {
                throw new IllegalArgumentException("DSA public key not consistent with DSA private key");
            }
        }
    }

    public void testProtectedRSA()
        throws Exception
    {
        byte[] data = protectedRSA;
        ByteArrayInputStream bin = new ByteArrayInputStream(data);
        JcaPGPDigestCalculatorProviderBuilder digBuild = new JcaPGPDigestCalculatorProviderBuilder();
        digBuild.setProvider("BC");
        OpenedPGPKeyData openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);

        ExtendedPGPSecretKey secretKey = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
            null,
            null,
            new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
            new JcaKeyFingerprintCalculator(), 10);

        bin = new ByteArrayInputStream(data);
        openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
        ExtendedPGPSecretKey secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
            secretKey.getPublicKey(),
            null,
            new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
            new JcaKeyFingerprintCalculator(), 10);

        PGPKeyPair pair = secretKey2.extractKeyPair(null);
        validateRSAKey(pair);

        Strings.toUTF8ByteArray("Created: 20211017T225532\n" +
            "Key: (protected-private-key (rsa (n #00BDA748AF09EC7503A3F201E4F59ECAA4\n" +
            " C52E84FEA5E4D7B99069C3751F19C5D0180193CA2E4516B5A9ED263989E007040C1C1D\n" +
            " 53F2D8B7844AEFF77FE28C920ACE0C0F5A77A95536871DD03878BA1997FAE6368E133B\n" +
            " 5CCCB13B4500F99FD211CB6EF42FAF548BB9BEDAA399A0085F85F9CE3268A03276C31E\n" +
            " 33313F1826A9DB#)(e #010001#)(protected openpgp-s2k3-ocb-aes ((sha1\n" +
            "  #0D1568A73CF5F7C6# \"43860992\")#E5DF4BA755F1AC410C4F32FA#)#CFF9000F22E\n" +
            " 0948B2D3BB1E78EEDB42D2361C3A444C94D02E17CDBC928B0AA21275B391820944B684\n" +
            " 757088F76D6CB262768FBB1B06067FECB04E02C5A1A6C2CF18896A30166D6231CB3179\n" +
            " FD0567D03C207C04EAE6523F77302ABDBF8294D90D197B875BCEBB564CCD0DE264D8BA\n" +
            " C921DA23A21C4F7D2DD12A2E4EF20ECFEB2DABD273A2270B2AC386ECF2DCDE90D5FDDB\n" +
            " 00261814082A710A0347C57F7326E18FBE5E4D0F67B6912A903A58984E244D8A487921\n" +
            " 2712200205123AE58E7CB2457518611678C086F319CF7BED4A675E79CA8BC9DB810025\n" +
            " C5EEA8BD0D980787003992A72C005DAEC32604767ADF91AF180DB58260B21A1996240F\n" +
            " E6225B066EA9A8979E590B1BC85F44796903A2738B7871F52F4F27032AC86B25F38E07\n" +
            " 4E12CEB9ECBCD6995D03DA57710EC54A6E60B79283389BD2869FF7B7C65623C59E0B40\n" +
            " 621802DEDA97B167C806B45E0CB3A2CE4C60CD7D7FCE763F7B57EDC226AF7F05B07234\n" +
            " 32C910DD00AD4FD29FE159AEB19E084E9AC76CE#)(protected-at\n" +
            "  \"20211017T225546\")))\n");
        try
        {
            data = openRsa;
            bin = new ByteArrayInputStream(data);
            openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
            secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
                secretKey.getPublicKey(),
                null,
                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
                new JcaKeyFingerprintCalculator(), 10);
            fail("passed in public key does not match secret key");
        }
        catch (PGPException e)
        {
            isTrue("passed in public key does not match secret key",
                messageIs(e.getMessage(), "passed in public key does not match secret key"));
        }

        try
        {
            data = Strings.toUTF8ByteArray("Created: 20211017T225532\n" +
                "Key: (protected-private-key (rsa (n #00BDA748AF09EC7503A3F201E4F59ECAA4\n" +
                " C52E84FEA5E4D7B99069C3751F19C5D0180193CA2E4516B5A9ED263989E007040C1C1D\n" +
                " 53F2D8B7844AEFF77FE28C920ACE0C0F5A77A95536871DD03878BA1997FAE6368E133B\n" +
                " 5CCCB13B4500F99FD211CB6EF42FAF548BB9BEDAA399A0085F85F9CE3268A03276C31E\n" +
                " 33313F1826A9DB#)(e #010001#)(protected-at\n" +
                "  \"20211017T225546\")))\n");
            bin = new ByteArrayInputStream(data);
            openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
            secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
                secretKey.getPublicKey(),
                null,
                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
                new JcaKeyFingerprintCalculator(), 10);
            fail(" does not have protected block");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(" does not have protected block",
                messageIs(e.getMessage(), " does not have protected block"));
        }

        try
        {
            data = Strings.toUTF8ByteArray("Created: 20211017T225532\n" +
                "Key: (protected-private-key (rsa (n #00BDA748AF09EC7503A3F201E4F59ECAA4\n" +
                " C52E84FEA5E4D7B99069C3751F19C5D0180193CA2E4516B5A9ED263989E007040C1C1D\n" +
                " 53F2D8B7844AEFF77FE28C920ACE0C0F5A77A95536871DD03878BA1997FAE6368E133B\n" +
                " 5CCCB13B4500F99FD211CB6EF42FAF548BB9BEDAA399A0085F85F9CE3268A03276C31E\n" +
                " 33313F1826A9DB#)(protected openpgp-s2k3-ocb-aes ((sha1\n" +
                "  #0D1568A73CF5F7C6# \"43860992\")#E5DF4BA755F1AC410C4F32FA#)#CFF9000F22E\n" +
                " 0948B2D3BB1E78EEDB42D2361C3A444C94D02E17CDBC928B0AA21275B391820944B684\n" +
                " 757088F76D6CB262768FBB1B06067FECB04E02C5A1A6C2CF18896A30166D6231CB3179\n" +
                " FD0567D03C207C04EAE6523F77302ABDBF8294D90D197B875BCEBB564CCD0DE264D8BA\n" +
                " C921DA23A21C4F7D2DD12A2E4EF20ECFEB2DABD273A2270B2AC386ECF2DCDE90D5FDDB\n" +
                " 00261814082A710A0347C57F7326E18FBE5E4D0F67B6912A903A58984E244D8A487921\n" +
                " 2712200205123AE58E7CB2457518611678C086F319CF7BED4A675E79CA8BC9DB810025\n" +
                " C5EEA8BD0D980787003992A72C005DAEC32604767ADF91AF180DB58260B21A1996240F\n" +
                " E6225B066EA9A8979E590B1BC85F44796903A2738B7871F52F4F27032AC86B25F38E07\n" +
                " 4E12CEB9ECBCD6995D03DA57710EC54A6E60B79283389BD2869FF7B7C65623C59E0B40\n" +
                " 621802DEDA97B167C806B45E0CB3A2CE4C60CD7D7FCE763F7B57EDC226AF7F05B07234\n" +
                " 32C910DD00AD4FD29FE159AEB19E084E9AC76CE#)(protected-at\n" +
                "  \"20211017T225546\")))\n");
            bin = new ByteArrayInputStream(data);
            openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
            secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
                secretKey.getPublicKey(),
                null,
                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
                new JcaKeyFingerprintCalculator(), 10);
            fail("The public key should not be null");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("The public key should not be null",
                messageIs(e.getMessage(), "The public key should not be null"));
        }

        try
        {
            data = Strings.toUTF8ByteArray("Created: 20211017T225532\n" +
                "Key: (protected-private-key (rsa (n #00BDA748AF09EC7503A3F201E4F59ECAA4\n" +
                " C52E84FEA5E4D7B99069C3751F19C5D0180193CA2E4516B5A9ED263989E007040C1C1D\n" +
                " 53F2D8B7844AEFF77FE28C920ACE0C0F5A77A95536871DD03878BA1997FAE6368E133B\n" +
                " 5CCCB13B4500F99FD211CB6EF42FAF548BB9BEDAA399A0085F85F9CE3268A03276C31E\n" +
                " 33313F1826A9DB#)(e #010001#)(protected openpgp-s2k3-ocb ((sha1\n" +
                "  #0D1568A73CF5F7C6# \"43860992\")#E5DF4BA755F1AC410C4F32FA#)#CFF9000F22E\n" +
                " 0948B2D3BB1E78EEDB42D2361C3A444C94D02E17CDBC928B0AA21275B391820944B684\n" +
                " 757088F76D6CB262768FBB1B06067FECB04E02C5A1A6C2CF18896A30166D6231CB3179\n" +
                " FD0567D03C207C04EAE6523F77302ABDBF8294D90D197B875BCEBB564CCD0DE264D8BA\n" +
                " C921DA23A21C4F7D2DD12A2E4EF20ECFEB2DABD273A2270B2AC386ECF2DCDE90D5FDDB\n" +
                " 00261814082A710A0347C57F7326E18FBE5E4D0F67B6912A903A58984E244D8A487921\n" +
                " 2712200205123AE58E7CB2457518611678C086F319CF7BED4A675E79CA8BC9DB810025\n" +
                " C5EEA8BD0D980787003992A72C005DAEC32604767ADF91AF180DB58260B21A1996240F\n" +
                " E6225B066EA9A8979E590B1BC85F44796903A2738B7871F52F4F27032AC86B25F38E07\n" +
                " 4E12CEB9ECBCD6995D03DA57710EC54A6E60B79283389BD2869FF7B7C65623C59E0B40\n" +
                " 621802DEDA97B167C806B45E0CB3A2CE4C60CD7D7FCE763F7B57EDC226AF7F05B07234\n" +
                " 32C910DD00AD4FD29FE159AEB19E084E9AC76CE#)(protected-at\n" +
                "  \"20211017T225546\")))\n");
            bin = new ByteArrayInputStream(data);
            openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
            secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
                secretKey.getPublicKey(),
                null,
                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
                new JcaKeyFingerprintCalculator(), 10);
            fail("unsupported protection type");
        }
        catch (PGPException e)
        {
            isTrue("unsupported protection type",
                messageIs(e.getMessage(), "unsupported protection type"));
        }

//        try
//        {
//            data = Strings.toUTF8ByteArray("Created: 20211017T225532\n" +
//                "Key: (protected-private-key (rsa (n #00BDA748AF09EC7503A3F201E4F59ECAA4\n" +
//                " C52E84FEA5E4D7B99069C3751F19C5D0180193CA2E4516B5A9ED263989E007040C1C1D\n" +
//                " 53F2D8B7844AEFF77FE28C920ACE0C0F5A77A95536871DD03878BA1997FAE6368E133B\n" +
//                " 5CCCB13B4500F99FD211CB6EF42FAF548BB9BEDAA399A0085F85F9CE3268A03276C31E\n" +
//                " 33313F1826A9DB#)(e #010001#)(protected openpgp-s2k3-sha1-aes-cbc ((sha1\n" +
//                "  #0D1568A73CF5F7C6# \"43860992\")#E5DF4BA755F1AC410C4F32FA#)#CFF9000F22E\n" +
//                " 0948B2D3BB1E78EEDB42D2361C3A444C94D02E17CDBC928B0AA21275B391820944B684\n" +
//                " 757088F76D6CB262768FBB1B06067FECB04E02C5A1A6C2CF18896A30166D6231CB3179\n" +
//                " FD0567D03C207C04EAE6523F77302ABDBF8294D90D197B875BCEBB564CCD0DE264D8BA\n" +
//                " C921DA23A21C4F7D2DD12A2E4EF20ECFEB2DABD273A2270B2AC386ECF2DCDE90D5FDDB\n" +
//                " 00261814082A710A0347C57F7326E18FBE5E4D0F67B6912A903A58984E244D8A487921\n" +
//                " 2712200205123AE58E7CB2457518611678C086F319CF7BED4A675E79CA8BC9DB810025\n" +
//                " C5EEA8BD0D980787003992A72C005DAEC32604767ADF91AF180DB58260B21A1996240F\n" +
//                " E6225B066EA9A8979E590B1BC85F44796903A2738B7871F52F4F27032AC86B25F38E07\n" +
//                " 4E12CEB9ECBCD6995D03DA57710EC54A6E60B79283389BD2869FF7B7C65623C59E0B40\n" +
//                " 621802DEDA97B167C806B45E0CB3A2CE4C60CD7D7FCE763F7B57EDC226AF7F05B07234\n" +
//                " 32C910DD00AD4FD29FE159AEB19E084E9AC76CE#)(protected-at\n" +
//                "  \"20211017T225546\")))\n");
//            bin = new ByteArrayInputStream(data);
//            openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
//            secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
//                secretKey.getPublicKey(),
//                null,
//                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
//                new JcaKeyFingerprintCalculator(), 10);
//            fail("openpgp-s2k3-sha1-aes-cbc not supported on newer key type");
//        }
//        catch (IllegalArgumentException e)
//        {
//            isTrue("openpgp-s2k3-sha1-aes-cbc not supported on newer key type",
//                e.getMessage().contains("openpgp-s2k3-sha1-aes-cbc not supported on newer key type"));
//        }

//        try
//        {
//            data = Strings.toUTF8ByteArray("Created: 20211017T225532\n" +
//                "Key: (protected-private-key (rsa (n #00BDA748AF09EC7503A3F201E4F59ECAA4\n" +
//                " C52E84FEA5E4D7B99069C3751F19C5D0180193CA2E4516B5A9ED263989E007040C1C1D\n" +
//                " 53F2D8B7844AEFF77FE28C920ACE0C0F5A77A95536871DD03878BA1997FAE6368E133B\n" +
//                " 5CCCB13B4500F99FD211CB6EF42FAF548BB9BEDAA399A0085F85F9CE3268A03276C31E\n" +
//                " 33313F1826A9DB#)(e #010001#)(protected openpgp-s2k3-aes ((sha1\n" +
//                "  #0D1568A73CF5F7C6# \"43860992\")#E5DF4BA755F1AC410C4F32FA#)#CFF9000F22E\n" +
//                " 0948B2D3BB1E78EEDB42D2361C3A444C94D02E17CDBC928B0AA21275B391820944B684\n" +
//                " 757088F76D6CB262768FBB1B06067FECB04E02C5A1A6C2CF18896A30166D6231CB3179\n" +
//                " FD0567D03C207C04EAE6523F77302ABDBF8294D90D197B875BCEBB564CCD0DE264D8BA\n" +
//                " C921DA23A21C4F7D2DD12A2E4EF20ECFEB2DABD273A2270B2AC386ECF2DCDE90D5FDDB\n" +
//                " 00261814082A710A0347C57F7326E18FBE5E4D0F67B6912A903A58984E244D8A487921\n" +
//                " 2712200205123AE58E7CB2457518611678C086F319CF7BED4A675E79CA8BC9DB810025\n" +
//                " C5EEA8BD0D980787003992A72C005DAEC32604767ADF91AF180DB58260B21A1996240F\n" +
//                " E6225B066EA9A8979E590B1BC85F44796903A2738B7871F52F4F27032AC86B25F38E07\n" +
//                " 4E12CEB9ECBCD6995D03DA57710EC54A6E60B79283389BD2869FF7B7C65623C59E0B40\n" +
//                " 621802DEDA97B167C806B45E0CB3A2CE4C60CD7D7FCE763F7B57EDC226AF7F05B07234\n" +
//                " 32C910DD00AD4FD29FE159AEB19E084E9AC76CE#)(protected-at\n" +
//                "  \"20211017T225546\")))\n");
//            bin = new ByteArrayInputStream(data);
//            openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
//            secretKey2 = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
//                secretKey.getPublicKey(),
//                null,
//                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
//                new JcaKeyFingerprintCalculator(), 10);
//            fail("unhandled protection type");
//        }
//        catch (PGPException e)
//        {
//            isTrue("unhandled protection type",
//                e.getMessage().contains("unhandled protection type"));
//        }
    }

    public void validateRSAKey(PGPKeyPair keyPair)
    {
        RSASecretBCPGKey priv = (RSASecretBCPGKey)keyPair.getPrivateKey().getPrivateKeyDataPacket();
        RSAPublicBCPGKey pub = (RSAPublicBCPGKey)keyPair.getPublicKey().getPublicKeyPacket().getKey();
        isTrue(pub.getFormat().equals("PGP"));
        isTrue(priv.getFormat().equals("PGP"));

        if (!priv.getModulus().equals(pub.getModulus()))
        {
            throw new IllegalArgumentException("RSA keys do not have the same modulus");
        }
        BigInteger val = BigInteger.valueOf(2);
        if (!val.modPow(priv.getPrivateExponent(), priv.getModulus()).modPow(pub.getPublicExponent(), priv.getModulus()).equals(val))
        {
            throw new IllegalArgumentException("RSA public key not consistent with RSA private key");
        }
    }

    public void testOpenedPGPKeyData()
        throws Exception
    {
        byte[] key = dsaElgamalOpen;
        ByteArrayInputStream bin = new ByteArrayInputStream(key);
        isTrue(PGPSecretKeyParser.isExtendedSExpression(bin));
        JcaPGPDigestCalculatorProviderBuilder digBuild = new JcaPGPDigestCalculatorProviderBuilder();
        OpenedPGPKeyData openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
        isTrue(openedPGPKeyData.getKeyType() == null);
        isTrue(openedPGPKeyData.getHeaderList().size() == 1);


        try
        {
            byte[] data = ("Created: 20211029T004805\n" +
                "Key: (private-key (ecc (curve sect113r12)(flags eddsa)(q\n" +
                "  #4019C37A2D6179A29B7D48D0DC16498615BF5906FB610312FDE72CCB9C05DDE892#)\n" +
                " (d #56399E28956FAA43AEDDE4C7778EA6EEDEC0EA0A166C4C108162472043483A8F#)\n" +
                " ))\n").getBytes();
            bin = new ByteArrayInputStream(data);
            isTrue(PGPSecretKeyParser.isExtendedSExpression(bin));
            digBuild = new JcaPGPDigestCalculatorProviderBuilder();
            openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
            ExtendedPGPSecretKey secretKey = openedPGPKeyData.getKeyData(
                null,
                digBuild.build(),
                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
                new JcaKeyFingerprintCalculator(), 10);
            fail("unable to resolve parameters for ");
        }
        catch (IllegalStateException e)
        {
            isTrue("unable to resolve parameters for ", messageIs(e.getMessage(), "unable to resolve parameters for "));
        }
    }

    public void testEd25519()
        throws Exception
    {
        //TODO: Invalid key?
        byte[] data = curveed25519;
        ByteArrayInputStream bin = new ByteArrayInputStream(data);
//        isTrue(PGPSecretKeyParser.isExtendedSExpression(bin));
        JcaPGPDigestCalculatorProviderBuilder digBuild = new JcaPGPDigestCalculatorProviderBuilder();
        OpenedPGPKeyData openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);
        ExtendedPGPSecretKey secretKey = openedPGPKeyData.getKeyData(
            null,
            digBuild.build(),
            new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
            new JcaKeyFingerprintCalculator(), 10);
        PGPKeyPair pair = secretKey.extractKeyPair(null);
    }
}
