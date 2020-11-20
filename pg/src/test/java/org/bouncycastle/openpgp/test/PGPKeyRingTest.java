package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import javax.crypto.Cipher;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.TrustPacket;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRing;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.jcajce.JcaPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPPrivateKey;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

public class PGPKeyRingTest
    extends SimpleTest
{
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

    byte[] sec1 = Base64.decode(
        "lQHhBEA83v0RBADzKVLVCnpWQxX0LCsevw/3OLs0H7MOcLBQ4wMO9sYmzGYn"
      + "xpVj+4e4PiCP7QBayWyy4lugL6Lnw7tESvq3A4v3fefcxaCTkJrryiKn4+Cg"
      + "y5rIBbrSKNtCEhVi7xjtdnDjP5kFKgHYjVOeIKn4Cz/yzPG3qz75kDknldLf"
      + "yHxp2wCgwW1vAE5EnZU4/UmY7l8kTNkMltMEAJP4/uY4zcRwLI9Q2raPqAOJ"
      + "TYLd7h+3k/BxI0gIw96niQ3KmUZDlobbWBI+VHM6H99vcttKU3BgevNf8M9G"
      + "x/AbtW3SS4De64wNSU3189XDG8vXf0vuyW/K6Pcrb8exJWY0E1zZQ1WXT0gZ"
      + "W0kH3g5ro//Tusuil9q2lVLF2ovJA/0W+57bPzi318dWeNs0tTq6Njbc/GTG"
      + "FUAVJ8Ss5v2u6h7gyJ1DB334ExF/UdqZGldp0ugkEXaSwBa2R7d3HBgaYcoP"
      + "Ck1TrovZzEY8gm7JNVy7GW6mdOZuDOHTxyADEEP2JPxh6eRcZbzhGuJuYIif"
      + "IIeLOTI5Dc4XKeV32a+bWv4CAwJ5KgazImo+sGBfMhDiBcBTqyDGhKHNgHic"
      + "0Pky9FeRvfXTc2AO+jGmFPjcs8BnTWuDD0/jkQnRZpp1TrQidGVzdCAoVGVz"
      + "dCBrZXkpIDx0ZXN0QHViaWNhbGwuY29tPohkBBMRAgAkBQJAPN79AhsDBQkB"
      + "4TOABgsJCAcDAgMVAgMDFgIBAh4BAheAAAoJEJh8Njfhe8KmGDcAn3XeXDMg"
      + "BZgrZzFWU2IKtA/5LG2TAJ0Vf/jjyq0jZNZfGfoqGTvD2MAl0rACAACdAVgE"
      + "QDzfARAEAJeUAPvUzJJbKcc55Iyb13+Gfb8xBWE3HinQzhGr1v6A1aIZbRj4"
      + "7UPAD/tQxwz8VAwJySx82ggNLxCk4jW9YtTL3uZqfczsJngV25GoIN10f4/j"
      + "2BVqZAaX3q79a3eMiql1T0oEAGmD7tO1LkTvWfm3VvA0+t8/6ZeRLEiIqAOH"
      + "AAQNBACD0mVMlAUgd7REYy/1mL99Zlu9XU0uKyUex99sJNrcx1aj8rIiZtWa"
      + "Hz6CN1XptdwpDeSYEOFZ0PSuqH9ByM3OfjU/ya0//xdvhwYXupn6P1Kep85e"
      + "fMBA9jUv/DeBOzRWMFG6sC6yk8NGG7Swea7EHKeQI40G3jgO/+xANtMyTP4C"
      + "AwJ5KgazImo+sGBl2C7CFuI+5KM4ZhbtVie7l+OiTpr5JW2z5VgnV3EX9p04"
      + "LcGKfQvD65+ELwli6yh8B2zGcipqTaYk3QoYNIhPBBgRAgAPBQJAPN8BAhsM"
      + "BQkB4TOAAAoJEJh8Njfhe8KmG7kAniuRkaFFv1pdCBN8JJXpcorHmyouAJ9L"
      + "xxmusffR6OI7WgD3XZ0AL8zUC7ACAAA=");

    char[]    pass1 = "qwertzuiop".toCharArray();

    byte[] pub2 = Base64.decode(
         "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");

    byte[] sec2 = Base64.decode(
        "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"
      + "Nifs+ljmsAFn");


    char[]  sec2pass1 = "sandhya".toCharArray();
    char[]    sec2pass2 = "psai".toCharArray();

    byte[] pub3 = Base64.decode(
        "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"
      + "n3FaE6UZE9GMDmCIAjhI+0X9aH6CsAIAAw==");

    byte[] sec3 = Base64.decode(
        "lQHhBEB9BH0RBACtYQtE7tna6hgGyGLpq+ds3r2cLC0ISn5dNw7tm9vwiNVF"
      + "JA2N37RRrifw4PvgelRSvLaX3M3ZBqC9s1Metg3v4FSlIRtSLWCNpHSvNw7i"
      + "X8C2Xy9Hdlbh6Y/50o+iscojLRE14upfR1bIkcCZQGSyvGV52V2wBImUUZjV"
      + "s2ZngwCg7mu852vK7+euz4WaL7ERVYtq9CMEAJ5swrljerDpz/RQ4Lhp6KER"
      + "KyuI0PUttO57xINGshEINgYlZdGaZHRueHe7uKfI19mb0T4N3NJWaZ0wF+Cn"
      + "rixsq0VrTUfiwfZeGluNG73aTCeY45fVXMGTTSYXzS8T0LW100Xn/0g9HRyA"
      + "xUpuWo8IazxkMqHJis2uwriYKpAfA/9anvj5BS9p5pfPjp9dGM7GTMIYl5f2"
      + "fcP57f+AW1TVR6IZiMJAvAdeWuLtwLnJiFpGlnFz273pfl+sAuqm1yNceImR"
      + "2SDDP4+vtyycWy8nZhgEuhZx3W3cWMQz5WyNJSY1JJHh9TCQkCoN8E7XpVP4"
      + "zEPboB2GzD93mfD8JLHP+/4DAwIvYrn+YqRaaGAu19XUj895g/GROyP8WEaU"
      + "Bd/JNqWc4kE/0guetGnPzq7G3bLVwiKfFd4X7BrgHAo3mrQtVGVzdCBLZXkg"
      + "KG5vIGNvbW1lbnQpIDx0ZXN0QGJvdW5jeWNhc3RsZS5vcmc+iFkEExECABkF"
      + "AkB9BH0ECwcDAgMVAgMDFgIBAh4BAheAAAoJEKnMV8vjZQOpSRQAoKZy6YS1"
      + "irF5/Q3JlWiwbkN6dEuLAJ9lldRLOlXsuQ5JW1+SLEc6K9ho4rACAADRwXPB"
      + "cQEQAAEBAAAAAAAAAAAAAAAA/9j/4AAQSkZJRgABAQEASABIAAD//gAXQ3Jl"
      + "YXRlZCB3aXRoIFRoZSBHSU1Q/9sAQwAIBgYHBgUIBwcHCQkICgwUDQwLCwwZ"
      + "EhMPFB0aHx4dGhwcICQuJyAiLCMcHCg3KSwwMTQ0NB8nOT04MjwuMzQy/9sA"
      + "QwEJCQkMCwwYDQ0YMiEcITIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIy"
      + "MjIyMjIyMjIyMjIyMjIyMjIyMjIy/8AAEQgAFAAUAwEiAAIRAQMRAf/EABoA"
      + "AQACAwEAAAAAAAAAAAAAAAAEBQIDBgf/xAAoEAABAgUDBAEFAAAAAAAAAAAB"
      + "AgMABBEhMQUSQQYTIiNhFFGBkcH/xAAXAQEAAwAAAAAAAAAAAAAAAAAEAgMF"
      + "/8QAJBEAAQQAAwkAAAAAAAAAAAAAAQACERIEIfATMTJBUZGx0fH/2gAMAwEA"
      + "AhEDEQA/APMuotJlJVxstqaPo22NlAUp+YsNO0qSUtBcMu6n6EtOHcfPAHHF"
      + "I16++oajQtTA3DapK02HFR8UpE9pTbQWtKm2WG2rlxVyQTcfGbn7Qm0OIjL7"
      + "7Wrs2NNm9lzTmmSxQ0PX4opSprk5tmESF6syggzGwOLG6gXgHFbZhBixk8Xl"
      + "IDcOQLRKt+rX+3qC5ZLTQblpQlvwvxn9CMpZturVGkJHapQJphRH8hCLXbzr"
      + "qpYsCx1zC5rtpJNuYQhASc0UAQv/2YhcBBMRAgAcBQJAfQV+AhsDBAsHAwID"
      + "FQIDAxYCAQIeAQIXgAAKCRCpzFfL42UDqfa2AJ9hjtEeDTbTEAuuSbzhYFxN"
      + "/qc0FACgsmzysdbBpuN65yK01tbEaeIMtqCwAgAAnQEUBEB9BH4QAwCqRuWO"
      + "rxm5v/8WWBtPEUZnYuu3WYxefRKn6ON5ka5Ymp4AfKpKqKqn982tjlG13GVE"
      + "P2ow11L4yQKGNm+VyVEapm7SpMD0SHg9vsJygAWrfMJnBYWSgE19W6o3ckUR"
      + "sWsAAwYDAKDCSiSxC3Z5/POaCehw5iHs/vmVk5Wn831LSZEEwkSohNDbIEry"
      + "ia/9tFXSt11AP4stJtZ0MH87/6JBbiIRD4JXcx+zfzchL7Teczr/06QMphSn"
      + "sAENupbhLupfpR+BbP4DAwIvYrn+YqRaaGBjvFK1fbxCt7ZM4I2W/3BC0lCX"
      + "m/NypKNspGflec8u96uUlA0fNCnxm6f9nbB0jpvoKi0g4iqAf+P2iEYEGBEC"
      + "AAYFAkB9BH4ACgkQqcxXy+NlA6mtMgCgvccZA/Sg7BXVpxli47SYhxSHoM4A"
      + "oNCOMplSnYTuh5ikKeBWtz36gC1psAIAAA==");

    char[]  sec3pass1 = "123456".toCharArray();
    
    //
    // GPG comment packets.
    //
    byte[] sec4 = Base64.decode(
           "lQG7BD0PbK8RBAC0cW4Y2MZXmAmqYp5Txyw0kSQsFvwZKHNMFRv996IsN57URVF5"
        + "BGMVPRBi9dNucWbjiSYpiYN13wE9IuLZsvVaQojV4XWGRDc+Rxz9ElsXnsYQ3mZU"
        + "7H1bNQEofstChk4z+dlvPBN4GFahrIzn/CeVUn6Ut7dVdYbiTqviANqNXwCglfVA"
        + "2OEePvqFnGxs1jhJyPSOnTED/RwRvsLH/k43mk6UEvOyN1RIpBXN+Ieqs7h1gFrQ"
        + "kB+WMgeP5ZUsotTffVDSUS9UMxRQggVUW1Xml0geGwQsNfkr/ztWMs/T4xp1v5j+"
        + "QyJx6OqNlkGdqOsoqkzJx0SQ1zBxdinFyyC4H95SDAb/RQOu5LQmxFG7quexztMs"
        + "infEA/9cVc9+qCo92yRAaXRqKNVVQIQuPxeUsGMyVeJQvJBD4An8KTMCdjpF10Cp"
        + "qA3t+n1S0zKr5WRUtvS6y60MOONO+EJWVWBNkx8HJDaIMNkfoqQoz3Krn7w6FE/v"
        + "/5uwMd6jY3N3yJZn5nDZT9Yzv9Nx3j+BrY+henRlSU0c6xDc9QAAnjJYg0Z83VJG"
        + "6HrBcgc4+4K6lHulCqH9JiM6RFNBX2ZhY3RvcjoAAK9hV206agp99GI6x5qE9+pU"
        + "vs6O+Ich/SYjOkRTQV9mYWN0b3I6AACvYAfGn2FGrpBYbjnpTuFOHJMS/T5xg/0m"
        + "IzpEU0FfZmFjdG9yOgAAr0dAQz6XxMwxWIn8xIZR/v2iN2L9C6O0EkZvbyBCYXIg"
        + "PGJhekBxdXV4PohXBBMRAgAXBQI9D2yvBQsHCgMEAxUDAgMWAgECF4AACgkQUGLI"
        + "YCIktfoGogCfZiXMJUKrScqozv5tMwzTTk2AaT8AniM5iRr0Du/Y08SL/NMhtF6H"
        + "hJ89nO4EPQ9ssRADAI6Ggxj6ZBfoavuXd/ye99osW8HsNlbqhXObu5mCMNySX2wa"
        + "HoWyRUEaUkI9eQw+MlHzIwzA32E7y2mU3OQBKdgLcBg4jxtcWVEg8ESKF9MpFXxl"
        + "pExxWrr4DFBfCRcsTwAFEQL9G3OvwJuEZXgx2JSS41D3pG4/qiHYICVa0u3p/14i"
        + "cq0kXajIk5ZJ6frCIAHIzuQ3n7jjzr05yR8s/qCrNbBA+nlkVNa/samk+jCzxxxa"
        + "cR/Dbh2wkvTFuDFFETwQYLuZAADcDck4YGQAmHivVT2NNDCf/aTz0+CJWl+xRc2l"
        + "Qw7D/SQjOkVMR19mYWN0b3I6AACbBnv9m5/bb/pjYAm2PtDp0CysQ9X9JCM6RUxH"
        + "X2ZhY3RvcjoAAJsFyHnSmaWguTFf6lJ/j39LtUNtmf0kIzpFTEdfZmFjdG9yOgAA"
        + "mwfwMD3LxmWtuCWBE9BptWMNH07Z/SQjOkVMR19mYWN0b3I6AACbBdhBrbSiM4UN"
        + "y7khDW2Sk0e4v9mIRgQYEQIABgUCPQ9ssQAKCRBQYshgIiS1+jCMAJ9txwHnb1Kl"
        + "6i/fSoDs8SkdM7w48wCdFvPEV0sSxE73073YhBgPZtMWbBo=");

    //
    // PGP freeware version 7
    //
    byte[] pub5 = Base64.decode(
        "mQENBEBrBE4BCACjXVcNIFDQSofaIyZnALb2CRg+WY9uUqgHEEAOlPe03Cs5STM5"
      + "HDlNmrh4TdFceJ46rxk1mQOjULES1YfHay8lCIzrD7FX4oj0r4DC14Fs1vXaSar2"
      + "1szIpttOw3obL4A1e0p6N4jjsoG7N/pA0fEL0lSw92SoBrMbAheXRg4qNTZvdjOR"
      + "grcuOuwgJRvPLtRXlhyLBoyhkd5mmrIDGv8QHJ/UjpeIcRXY9kn9oGXnEYcRbMaU"
      + "VwXB4pLzWqz3ZejFI3lOxRWjm760puPOnGYlzSVBxlt2LgzUgSj1Mn+lIpWmAzsa"
      + "xEiU4xUwEomQns72yYRZ6D3euNCibcte4SeXABEBAAG0KXBhbGFzaCBrYXNvZGhh"
      + "biA8cGthc29kaGFuQHRpYWEtY3JlZi5vcmc+iQEuBBABAgAYBQJAawROCAsBAwkI"
      + "BwIKAhkBBRsDAAAAAAoJEOfelumuiOrYqPEH+wYrdP5Tq5j+E5yN1pyCg1rwbSOt"
      + "Dka0y0p7Oq/VIGLk692IWPItLEunnBXQtGBcWqklrvogvlhxtf16FgoyScfLJx1e"
      + "1cJa+QQnVuH+VOESN6iS9Gp9lUfVOHv74mEMXw0l2Djfy/lnrkAMBatggyGnF9xF"
      + "VXOLk1J2WVFm9KUE23o6qdB7RGkf31pN2eA7SWmkdJSkUH7o/QSFBI+UTRZ/IY5P"
      + "ZIJpsdiIOqd9YMG/4RoSZuPqNRR6x7BSs8nQVR9bYs4PPlp4GfdRnOcRonoTeJCZ"
      + "83RnsraWJnJTg34gRLBcqumhTuFKc8nuCNK98D6zkQESdcHLLTquCOaF5L+5AQ0E"
      + "QGsETwEIAOVwNCTaDZvW4dowPbET1bI5UeYY8rAGLYsWSUfgaFv2srMiApyBVltf"
      + "i6OLcPjcUCHDBjCv4pwx/C4qcHWb8av4xQIpqQXOpO9NxYE1eZnel/QB7DtH12ZO"
      + "nrDNmHtaXlulcKNGe1i1utlFhgzfFx6rWkRL0ENmkTkaQmPY4gTGymJTUhBbsSRq"
      + "2ivWqQA1TPwBuda73UgslIAHRd/SUaxjXoLpMbGOTeqzcKGjr5XMPTs7/YgBpWPP"
      + "UxMlEQIiU3ia1bxpEhx05k97ceK6TSH2oCPQA7gumjxOSjKT+jEm+8jACVzymEmc"
      + "XRy4D5Ztqkw/Z16pvNcu1DI5m6xHwr8AEQEAAYkBIgQYAQIADAUCQGsETwUbDAAA"
      + "AAAKCRDn3pbprojq2EynB/4/cEOtKbI5UisUd3vkTzvWOcqWUqGqi5wjjioNtIM5"
      + "pur2nFvhQE7SZ+PbAa87HRJU/4WcWMcoLkHD48JrQwHCHOLHSV5muYowb78X4Yh9"
      + "epYtSJ0uUahcn4Gp48p4BkhgsPYXkxEImSYzAOWStv21/7WEMqItMYl89BV6Upm8"
      + "HyTJx5MPTDbMR7X51hRg3OeQs6po3WTCWRzFIMyGm1rd/VK1L5ZDFPqO3S6YUJ0z"
      + "cxecYruvfK0Wp7q834wE8Zkl/PQ3NhfEPL1ZiLr/L00Ty+77/FZqt8SHRCICzOfP"
      + "OawcVGI+xHVXW6lijMpB5VaVIH8i2KdBMHXHtduIkPr9");
      
    byte[] sec5 = Base64.decode(
        "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");

    char[]  sec5pass1 = "12345678".toCharArray();

        //
        // Werner Koch "odd keys"
        //
    byte[] pub6 = Base64.decode(
        "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"
      + "L4Kb7TWkd/OHQScVBO8sTUz0+2g=");

    byte[] pub6check = Base64.decode("62O9");

    //
    // revoked master key
    //
    byte[] pub7 = Base64.decode(
        "mQGiBFKQDEMRBACtcEzu15gGDrZKLuO2zgDJ9qFkweOxKyeO45LKIfUGBful"
      + "lheoFHbsJIeNGjWbSOfWWtphTaSu9//BJt4xxg2pqVLYqzR+hEPpDy9kXxnZ"
      + "LwwxjAP2TcOvuZKWe+JzoYQxDunOH4Zu9CPJhZhF3RNPw+tbv0jHfTV/chtb"
      + "23Dj5wCg7eoM8bL9NYXacsAfkS//m+AB1MkD/jEZJqJSQHW8WVP7wKRrAZse"
      + "N4l9b8+yY4RwLIodhD8wGsMYjkCF4yb/SQ5QlmLlvrHDLBofRzG+8oxldX4o"
      + "GLZWvqPmW+BlS4QNSr+ZBu+OwnpClXG2pR+ExumXNoeArREyylrmOgD+0cUa"
      + "8K2UbOxbJ8EioyOKxa7wjUVxmHmhBACAGQGLT/lpHA5zcU0g8AlSk8fsd+bB"
      + "nwa/+9xdLqVsCTZdOWULtPOw9hbAdjjAy0L4M/MDAJYYtCEl9rB7aOc9PVdT"
      + "h7CT9Ma6ltiSMKDlqWbDmogNEGx9Gz3GjiSGxAy/SN6JR1On4c60TAiTv6eE"
      + "uEHszE6CH4qceK5W8HLLB4hJBCARAgAJBQJSkA0OAh0CAAoJEBCIvJhXZzdI"
      + "X8wAn0qUP/jqAuPEX9g2XCr5jN3RKvKjAKDpx4NP7P1/yLN2ycFIgxKZ1plK"
      + "CLACAAO0J3Jldm9rZSAoUmV2b2tlIFRlc3QpIDxyZXZva2VAdGVzdC50ZXN0"
      + "PohiBBMRAgAiBQJSkAxDAhsDBgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAK"
      + "CRAQiLyYV2c3SKw0AJ9kufxvnorVOv6a+WM+I/bNP+mjLQCgtPKuwTyeZU2k"
      + "Sec1fJZUssDL1hGwAgADuQENBFKQDEMQBACruJ54GuhUaXgqGzu/HsCrgGQA"
      + "n86PZW1qPCX28E9sayEmVOgzSDA/OT5c05P0PVLhMNEguSnUGC249MpZfPK/"
      + "9LVKMXATZLzEB6lFX1YJdfrrb9KrQ5kdDhOcFXm1GIGBwLzjUmXYRVPH+TsT"
      + "4QFvDpfIANQZfKK4UV5BJzJV5wADBQP/ew75dy1x58KWpPqfeH1OVln/Ui6e"
      + "EDyyISic147+FIfVDuLtWoxMFE0ZPg47+rEQrhWC96izaSKPW97y5bkWz5PG"
      + "CMChnLcg+3M91x/QCGzNhzVMiVpY5VhBDFP+7iiOaKYRiN/x7oasf2482Ny8"
      + "1oiykOZUm8FCUQnRmJzIlbiISQQYEQIACQUCUpAMQwIbDAAKCRAQiLyYV2c3"
      + "SL04AJ9VceD1DtcEDaWPDzFPgpe3ZfiXiQCfe5azYl26JpHSJvNKZRLi0I8H"
      + "shCwAgAD");

    byte[] pub7sub = Base64.decode(
        "mQGiBFKQFFURBAD7CTE4RYPD7O+ki7pl/vXSZsSR0kQhCD9BR4lwE/Iffzmr"
      + "vK8tmr2yLKWoXyoc3VF0Gdg/VATDcawBnKSjuCIsFZ58Edacb7uVRl4+ACiu"
      + "OsvCKl9JuZ54SQ/tbD+NFS+HWNyVlWn7vDv8l+37DWNxuQRIYtQR+drAnIwQ"
      + "g0O4owCg5a9cGAaN0zNVssUo6GFEoAI8nE0EAJMxQMcHTlLQQN1c549Ub0+E"
      + "LV4dRIxjO7O6yi6Bg5udwS9Un1XeHF4GM7fj95WHi7o9sgErr2evhuGWl337"
      + "ySytE1npk2F/jqevhAJazQTuilEuyjMbCShV39qJlEKtU9uHQYxN8oqGT9Ot"
      + "lOoXXtrgfHbsrouCVwm4Jk14kzCaA/4okwrQwGkPlXRpVFyLn4GwrGivG7eh"
      + "enRbAd2SQBiNVKmMsKLxHT1avZ11qcx6OU3ixdw5wYmq7TNR+5FXiz/e2MIq"
      + "m7VhKONN21F7WC7siHxXfqqI/uz2tTPrFoLbnr/j/RZZRUMh6qUQrWpv58ci"
      + "Bh+xkWCRantLCL9khuvRSrQncmV2b2tlIChSZXZva2UgVGVzdCkgPHJldm9r"
      + "ZUB0ZXN0LnRlc3Q+iGIEExECACIFAlKQFFUCGwMGCwkIBwMCBhUIAgkKCwQW"
      + "AgMBAh4BAheAAAoJEDKzvtpHqpp2DN4AoNS9M634KdvZT25DclGpb2bCFjv0"
      + "AKDYXl5fIRGi583vFJ9C/q8hNGyNc7ACAAO5AQ0EUpAUVRAEALusV5UIL4gB"
      + "6qQk++h+czV9KS0yxwgZyR+dJza+duEG88aNv28Wmjpfr3ZkvIiUaOcxFoct"
      + "LgVGtPJM1HhWJtoA94CRBFTGzLfUIfXHcyXSdAw8Qh96svRl2w2KM+/pJl1r"
      + "A3CWIy48jQei0mLwElRELLG7HJKYJxjCbg4+ihYTAAMGA/42PgHTV5VpF7YC"
      + "XodlLOyGDVOoRjsvu0Gu/P88QnVP2jN57MJcla224aN3pGprtcbTwyjt+dtf"
      + "5IJlB+3RZLczyqvT5hw7j9h81mr3RDbg3cn57xdYwQNP+6b6Wf9QRmaE813s"
      + "g3kF0IJ0oFvwZdHnjndQ0JCrKaPflGSO6msjIYhTBCgRAgATBQJSkBXdDB0B"
      + "U3VwZXJzZWRlZAAKCRAys77aR6qadmZPAJ0eJzmgBLTWK9RIbVtRUFzm736I"
      + "hACgsPGHdZmLUFhV80fvYnUtB7TYGeKwAgADiEkEGBECAAkFAlKQFFUCGwwA"
      + "CgkQMrO+2keqmnZGIACfRTkdqi6b7fjqkWxx7DysKBedgS8An1TJrhhkeJVd"
      + "smkOCYLILgjrBHq4sAIAAw==");

    byte[] pub8 = Base64.decode(
              "mQGiBEEcraYRBADFYj+uFOhHz5SdECvJ3Z03P47gzmWLQ5HH8fPYC9rrv7AgqFFX"
            + "aWlJJVMLua9e6xoCiDWJs/n4BbZ/weL/11ELg6XqUnzFhYyz0H2KFsPgQ/b9lWLY"
            + "MtcPMFy5jE33hv/ixHgYLFqoNaAIbg0lzYEW/otQ9IhRl16fO1Q/CQZZrQCg/9M2"
            + "V2BTmm9RYog86CXJtjawRBcD/RIqU0zulxZ2Zt4javKVxrGIwW3iBU935ebmJEIK"
            + "Y5EVkGKBOCvsApZ+RGzpYeR2uMsTnQi8RJgiAnjaoVPCdsVJE7uQ0h8XuJ5n5mJ2"
            + "kLCFlF2hj5ViicZzse+crC12CGtgRe8z23ubLRcd6IUGhVutK8/b5knZ22vE14JD"
            + "ykKdA/96ObzJQdiuuPsEWN799nUUCaYWPAoLAmiXuICSP4GEnxLbYHWo8zhMrVMT"
            + "9Q5x3h8cszUz7Acu2BXjP1m96msUNoxPOZtt88NlaFz1Q/JSbQTsVOMd9b/IRN6S"
            + "A/uU0BiKEMHXuT8HUHVPK49oCKhZrGFP3RT8HZxDKLmR/qrgZ7ABh7QhSmlhIFlp"
            + "eXUgPHl5amlhQG5vd21lZGlhdGVjaC5jb20+sAMD//+JAF0EEBECAB0FAkEcraYH"
            + "CwkIBwMCCgIZAQUbAwAAAAUeAQAAAAAKCRD0/lb4K/9iFJlhAKCRMifQewiX5o8F"
            + "U099FG3QnLVUZgCfWpMOsHulGHfNrxdBSkE5Urqh1ymwAWe5Ag0EQRytphAIAPZC"
            + "V7cIfwgXcqK61qlC8wXo+VMROU+28W65Szgg2gGnVqMU6Y9AVfPQB8bLQ6mUrfdM"
            + "ZIZJ+AyDvWXpF9Sh01D49Vlf3HZSTz09jdvOmeFXklnN/biudE/F/Ha8g8VHMGHO"
            + "fMlm/xX5u/2RXscBqtNbno2gpXI61Brwv0YAWCvl9Ij9WE5J280gtJ3kkQc2azNs"
            + "OA1FHQ98iLMcfFstjvbzySPAQ/ClWxiNjrtVjLhdONM0/XwXV0OjHRhs3jMhLLUq"
            + "/zzhsSlAGBGNfISnCnLWhsQDGcgHKXrKlQzZlp+r0ApQmwJG0wg9ZqRdQZ+cfL2J"
            + "SyIZJrqrol7DVekyCzsAAgIH/3K2wKRSzkIpDfZR25+tnQ8brv3TYoDZo3/wN3F/"
            + "r6PGjx0150Q8g8EAC0bqm4rXWzOqdSxYxvIPOAGm5P4y+884yS6j3vKcXitT7vj+"
            + "ODc2pVwGDLDjrMRrosSK89ycPCK6R/5pD7Rv4l9DWi2fgLvXqJHS2/ujUf2uda9q"
            + "i9xNMnBXIietR82Sih4undFUOwh6Mws/o3eed9DIdaqv2Y2Aw43z/rJ6cjSGV3C7"
            + "Rkf9x85AajYA3LwpS8d99tgFig2u6V/A16oi6/M51oT0aR/ZAk50qUc4WBk9uRUX"
            + "L3Y+P6v6FCBE/06fgVltwcQHO1oKYKhH532tDL+9mW5/dYGwAYeJAEwEGBECAAwF"
            + "AkEcraYFGwwAAAAACgkQ9P5W+Cv/YhShrgCg+JW8m5nF3R/oZGuG87bXQBszkjMA"
            + "oLhGPncuGKowJXMRVc70/8qwXQJLsAFnmQGiBD2K5rYRBADD6kznWZA9nH/pMlk0"
            + "bsG4nI3ELgyI7KpgRSS+Dr17+CCNExxCetT+fRFpiEvUcSxeW4pOe55h0bQWSqLo"
            + "MNErXVJEXrm1VPkC08W8D/gZuPIsdtKJu4nowvdoA+WrI473pbeONGjaEDbuIJak"
            + "yeKM1VMSGhsImdKtxqhndq2/6QCg/xARUIzPRvKr2TJ52K393895X1kEAMCdjSs+"
            + "vABnhaeNNR5+NNkkIOCCjCS8qZRZ4ZnIayvn9ueG3KrhZeBIHoajUHrlTXBVj7XO"
            + "wXVfGpW17jCDiqhU8Pu6VwEwX1iFbuUwqBffiRLXKg0zfcN+MyFKToi+VsJi4jiZ"
            + "zcwUFMb8jE8tvR/muXti7zKPRPCbNBExoCt4A/0TgkzAosG/W4dUkkbc6XoHrjob"
            + "iYuy6Xbs/JYlV0vf2CyuKCZC6UoznO5x2GkvOyVtAgyG4HSh1WybdrutZ8k0ysks"
            + "mOthE7n7iczdj9Uwg2h+TfgDUnxcCAwxnOsX5UaBqGdkX1PjCWs+O3ZhUDg6UsZc"
            + "7O5a3kstf16lHpf4q7ABAIkAYQQfEQIAIQUCPYrmtgIHABcMgBHRi/xlIgI+Q6LT"
            + "kNJ7zKvTd87NHAAKCRDJM3gHb/sRj7bxAJ9f6mdlXQH7gMaYiY5tBe/FRtPr1gCf"
            + "UhDJQG0ARvORFWHjwhhBMLxW7j2wAWC0KkRlc21vbmQgS2VlIDxkZXNtb25kLmtl"
            + "ZUBub3dtZWRpYXRlY2guY29tPrADAQD9iQBYBBARAgAYBQI9iua2CAsDCQgHAgEK"
            + "AhkBBRsDAAAAAAoJEMkzeAdv+xGP7v4An19iqadBCCgDIe2DTpspOMidwQYPAJ4/"
            + "5QXbcn4ClhOKTO3ZEZefQvvL27ABYLkCDQQ9iua2EAgA9kJXtwh/CBdyorrWqULz"
            + "Bej5UxE5T7bxbrlLOCDaAadWoxTpj0BV89AHxstDqZSt90xkhkn4DIO9ZekX1KHT"
            + "UPj1WV/cdlJPPT2N286Z4VeSWc39uK50T8X8dryDxUcwYc58yWb/Ffm7/ZFexwGq"
            + "01uejaClcjrUGvC/RgBYK+X0iP1YTknbzSC0neSRBzZrM2w4DUUdD3yIsxx8Wy2O"
            + "9vPJI8BD8KVbGI2Ou1WMuF040zT9fBdXQ6MdGGzeMyEstSr/POGxKUAYEY18hKcK"
            + "ctaGxAMZyAcpesqVDNmWn6vQClCbAkbTCD1mpF1Bn5x8vYlLIhkmuquiXsNV6TIL"
            + "OwACAgf/SO+bbg+owbFKVN5HgOjOElQZVnCsegwCLqTeQzPPzsWmkGX2qZJPDIRN"
            + "RZfJzti6+oLJwaRA/3krjviUty4VKhZ3lKg8fd9U0jEdnw+ePA7yJ6gZmBHL15U5"
            + "OKH4Zo+OVgDhO0c+oetFpend+eKcvtoUcRoQoi8VqzYUNG0b/nmZGDlxQe1/ZNbP"
            + "HpNf1BAtJXivCEKMD6PVzsLPg2L4tFIvD9faeeuKYQ4jcWtTkBLuIaZba3i3a4wG"
            + "xTN20j9HpISVuLW/EfZAK1ef4DNjLmHEU9dMzDqfi+hPmMbGlFqcKr+VjcYIDuje"
            + "o+92xm/EWAmlti88r2hZ3MySamHDrLABAIkATAQYEQIADAUCPYrmtgUbDAAAAAAK"
            + "CRDJM3gHb/sRjzVTAKDVS+OJLMeS9VLAmT8atVCB42MwIQCgoh1j3ccWnhc/h6B7"
            + "9Uqz3fUvGoewAWA=");

    byte[] sec8 = Base64.decode(
              "lQHpBEEcraYRBADFYj+uFOhHz5SdECvJ3Z03P47gzmWLQ5HH8fPYC9rrv7AgqFFX"
            + "aWlJJVMLua9e6xoCiDWJs/n4BbZ/weL/11ELg6XqUnzFhYyz0H2KFsPgQ/b9lWLY"
            + "MtcPMFy5jE33hv/ixHgYLFqoNaAIbg0lzYEW/otQ9IhRl16fO1Q/CQZZrQCg/9M2"
            + "V2BTmm9RYog86CXJtjawRBcD/RIqU0zulxZ2Zt4javKVxrGIwW3iBU935ebmJEIK"
            + "Y5EVkGKBOCvsApZ+RGzpYeR2uMsTnQi8RJgiAnjaoVPCdsVJE7uQ0h8XuJ5n5mJ2"
            + "kLCFlF2hj5ViicZzse+crC12CGtgRe8z23ubLRcd6IUGhVutK8/b5knZ22vE14JD"
            + "ykKdA/96ObzJQdiuuPsEWN799nUUCaYWPAoLAmiXuICSP4GEnxLbYHWo8zhMrVMT"
            + "9Q5x3h8cszUz7Acu2BXjP1m96msUNoxPOZtt88NlaFz1Q/JSbQTsVOMd9b/IRN6S"
            + "A/uU0BiKEMHXuT8HUHVPK49oCKhZrGFP3RT8HZxDKLmR/qrgZ/4JAwLXyWhb4pf4"
            + "nmCmD0lDwoYvatLiR7UQVM2MamxClIiT0lCPN9C2AYIFgRWAJNS215Tjx7P/dh7e"
            + "8sYfh5XEHErT3dMbsAGHtCFKaWEgWWl5dSA8eXlqaWFAbm93bWVkaWF0ZWNoLmNv"
            + "bT6wAwP//4kAXQQQEQIAHQUCQRytpgcLCQgHAwIKAhkBBRsDAAAABR4BAAAAAAoJ"
            + "EPT+Vvgr/2IUmWEAoJEyJ9B7CJfmjwVTT30UbdCctVRmAJ9akw6we6UYd82vF0FK"
            + "QTlSuqHXKbABZ50CawRBHK2mEAgA9kJXtwh/CBdyorrWqULzBej5UxE5T7bxbrlL"
            + "OCDaAadWoxTpj0BV89AHxstDqZSt90xkhkn4DIO9ZekX1KHTUPj1WV/cdlJPPT2N"
            + "286Z4VeSWc39uK50T8X8dryDxUcwYc58yWb/Ffm7/ZFexwGq01uejaClcjrUGvC/"
            + "RgBYK+X0iP1YTknbzSC0neSRBzZrM2w4DUUdD3yIsxx8Wy2O9vPJI8BD8KVbGI2O"
            + "u1WMuF040zT9fBdXQ6MdGGzeMyEstSr/POGxKUAYEY18hKcKctaGxAMZyAcpesqV"
            + "DNmWn6vQClCbAkbTCD1mpF1Bn5x8vYlLIhkmuquiXsNV6TILOwACAgf/crbApFLO"
            + "QikN9lHbn62dDxuu/dNigNmjf/A3cX+vo8aPHTXnRDyDwQALRuqbitdbM6p1LFjG"
            + "8g84Aabk/jL7zzjJLqPe8pxeK1Pu+P44NzalXAYMsOOsxGuixIrz3Jw8IrpH/mkP"
            + "tG/iX0NaLZ+Au9eokdLb+6NR/a51r2qL3E0ycFciJ61HzZKKHi6d0VQ7CHozCz+j"
            + "d5530Mh1qq/ZjYDDjfP+snpyNIZXcLtGR/3HzkBqNgDcvClLx3322AWKDa7pX8DX"
            + "qiLr8znWhPRpH9kCTnSpRzhYGT25FRcvdj4/q/oUIET/Tp+BWW3BxAc7WgpgqEfn"
            + "fa0Mv72Zbn91gf4JAwITijME9IlFBGAwH6YmBtWIlnDiRbsq/Pxozuhbnes831il"
            + "KmdpUKXkiIfHY0MqrEWl3Dfn6PMJGTnhgqXMrDxx3uHrq0Jl2swRnAWIIO8gID7j"
            + "uPetUqEviPiwAYeJAEwEGBECAAwFAkEcraYFGwwAAAAACgkQ9P5W+Cv/YhShrgCg"
            + "+JW8m5nF3R/oZGuG87bXQBszkjMAoLhGPncuGKowJXMRVc70/8qwXQJLsAFn");
    
    char[]  sec8pass = "qwertyui".toCharArray();
    
    byte[] sec9 = Base64.decode(
              "lQGqBEHCokERBAC9rh5SzC1sX1y1zoFuBB/v0SGhoKMEvLYf8Qv/j4deAMrc"
            + "w5dxasYoD9oxivIUfTbZKo8cqr+dKLgu8tycigTM5b/T2ms69SUAxSBtj2uR"
            + "LZrh4vjC/93kF+vzYJ4fNaBs9DGfCnsTouKjXqmfN3SlPMKNcGutO7FaUC3d"
            + "zcpYfwCg7qyONHvXPhS0Iw4QL3mJ/6wMl0UD/0PaonqW0lfGeSjJSM9Jx5Bt"
            + "fTSlwl6GmvYmI8HKvOBXAUSTZSbEkMsMVcIgf577iupzgWCgNF6WsNqQpKaq"
            + "QIq1Kjdd0Y00xU1AKflOkhl6eufTigjviM+RdDlRYsOO5rzgwDTRTu9giErs"
            + "XIyJAIZIdu2iaBHX1zHTfJ1r7nlAA/9H4T8JIhppUk/fLGsoPNZzypzVip8O"
            + "mFb9PgvLn5GmuIC2maiocT7ibbPa7XuXTO6+k+323v7PoOUaKD3uD93zHViY"
            + "Ma4Q5pL5Ajc7isnLXJgJb/hvvB1oo+wSDo9vJX8OCSq1eUPUERs4jm90/oqy"
            + "3UG2QVqs5gcKKR4o48jTiv4DZQJHTlUBtB1mb28ga2V5IDxmb28ua2V5QGlu"
            + "dmFsaWQuY29tPoheBBMRAgAeBQJBwqJCAhsDBgsJCAcDAgMVAgMDFgIBAh4B"
            + "AheAAAoJEOKcXvehtw4ajJMAoK9nLfsrRY6peq56l/KzmjzuaLacAKCXnmiU"
            + "waI7+uITZ0dihJ3puJgUz50BWARBwqJDEAQA0DPcNIn1BQ4CDEzIiQkegNPY"
            + "mkYyYWDQjb6QFUXkuk1WEB73TzMoemsA0UKXwNuwrUgVhdpkB1+K0OR/e5ik"
            + "GhlFdrDCqyT+mw6dRWbJ2i4AmFXZaRKO8AozZeWojsfP1/AMxQoIiBEteMFv"
            + "iuXnZ3pGxSfZYm2+33IuPAV8KKMAAwUD/0C2xZQXgVWTiVz70HUviOmeTQ+f"
            + "b1Hj0U9NMXWB383oQRBZCvQDM12cqGsvPZuZZ0fkGehGAIoyXtIjJ9lejzZN"
            + "1TE9fnXZ9okXI4yCl7XLSE26OAbNsis4EtKTNScNaU9Dk3CS5XD/pkRjrkPN"
            + "2hdUFtshuGmYkqhb9BIlrwE7/gMDAglbVSwecr9mYJcDYCH62U9TScWDTzsQ"
            + "NFEfhMez3hGnNHNfHe+7yN3+Q9/LIhbba3IJEN5LsE5BFvudLbArp56EusIn"
            + "JCxgiEkEGBECAAkFAkHCokMCGwwACgkQ4pxe96G3Dho2UQCeN3VPwx3dROZ+"
            + "4Od8Qj+cLrBndGEAn0vaQdy6eIGeDw2I9u3Quwy6JnROnQHhBEHCozMRBADH"
            + "ZBlB6xsAnqFYtYQOHr4pX6Q8TrqXCiHHc/q56G2iGbI9IlbfykQzaPHgWqZw"
            + "9P0QGgF/QZh8TitiED+imLlGDqj3nhzpazqDh5S6sg6LYkQPqhwG/wT5sZQQ"
            + "fzdeupxupjI5YN8RdIqkWF+ILOjk0+awZ4z0TSY/f6OSWpOXlwCgjIquR3KR"
            + "tlCLk+fBlPnOXaOjX+kEAJw7umykNIHNaoY/2sxNhQhjqHVxKyN44y6FCSv9"
            + "jRyW8Q/Qc8YhqBIHdmlcXoNWkDtlvErjdYMvOKFqKB1e2bGpjvhtIhNVQWdk"
            + "oHap9ZuM1nV0+fD/7g/NM6D9rOOVCahBG2fEEeIwxa2CQ7zHZYfg9Umn3vbh"
            + "TYi68R3AmgLOA/wKIVkfFKioI7iX4crQviQHJK3/A90SkrjdMQwLoiUjdgtk"
            + "s7hJsTP1OPb2RggS1wCsh4sv9nOyDULj0T0ySGv7cpyv5Nq0FY8gw2oogHs5"
            + "fjUnG4VeYW0zcIzI8KCaJT4UhR9An0A1jF6COrYCcjuzkflFbQLtQb9uNj8a"
            + "hCpU4/4DAwIUxXlRMYE8uWCranzPo83FnBPRnGJ2aC9SqZWJYVUKIn4Vf2nu"
            + "pVvCGFja0usl1WfV72hqlNKEONq7lohJBBgRAgAJBQJBwqMzAhsCAAoJEOKc"
            + "Xvehtw4afisAoME/t8xz/rj/N7QRN9p8Ji8VPGSqAJ9K8eFJ+V0mxR+octJr"
            + "6neEEX/i1Q==");

    public char[] sec9pass = "foo".toCharArray();

    // version 4 keys with expiry dates
    byte[] pub10 = Base64.decode(
          "mQGiBEKqia0RBACc3hkufmscRSC4UvPZqMDsHm4+d/GXIr+3iNMSSEySJu8yk+k0"
        + "Xs11C/K+n+v1rnn2jGGknv+1lDY6w75TIcTE6o6HGKeIDxsAm8P3MhoGU1GNPamA"
        + "eTDeNybtrN/g6C65fCY9uI11hsUboYgQZ8ND22PB0VtvdOgq9D85qNUzxwCg1BbJ"
        + "ycAKd4VqEvQ2Zglp3dCSrFMD/Ambq1kZqYa69sp3b9BPKuAgUgUPoytOArEej3Bk"
        + "easAgAxNhWJy4GxigES3vk50rVi7w8XBuqbD1mQCzldF0HX0/A7PxLBv6od5uqqF"
        + "HFxIyxg/KBZLd9ZOrsSaoUWH58jZq98X/sFtJtRi5VuJagMxCIJD4mLgtMv7Unlb"
        + "/GrsA/9DEnObA/fNTgK70T+ZmPIS5tSt+bio30Aw4YGpPCGqpnm1u73b5kqX3U3B"
        + "P+vGDvFuqZYpqQA8byAueH0MbaDHI4CFugvShXvgysJxN7ov7/8qsZZUMfK1t2Nr"
        + "SAsPuKRbcY4gNKXIElKeXbyaET7vX7uAEKuxEwdYGFp/lNTkHLQgdGVzdCBrZXkg"
        + "KHRlc3QpIDx0ZXN0QHRlc3QudGVzdD6IZAQTEQIAJAUCQqqJrQIbAwUJACTqAAYL"
        + "CQgHAwIDFQIDAxYCAQIeAQIXgAAKCRDjDROQZRqIzDzLAJ42AeCRIBBjv8r8qw9y"
        + "laNj2GZ1sACgiWYHVXMA6B1H9I1kS3YsCd3Oq7qwAgAAuM0EQqqJrhADAKWkix8l"
        + "pJN7MMTXob4xFF1TvGll0UD1bDGOMMbes6aeXSbT9QXee/fH3GnijLY7wB+qTPv9"
        + "ohubrSpnv3yen3CEBW6Q2YK+NlCskma42Py8YMV2idmYjtJi1ckvHFWt5wADBQL/"
        + "fkB5Q5xSGgspMaTZmtmX3zG7ZDeZ0avP8e8mRL8UszCTpqs6vMZrXwyQLZPbtMYv"
        + "PQpuRGEeKj0ysimwYRA5rrLQjnRER3nyuuEUUgc4j+aeRxPf9WVsJ/a1FCHtaAP1"
        + "iE8EGBECAA8FAkKqia4CGwwFCQAk6gAACgkQ4w0TkGUaiMzdqgCfd66H7DL7kFGd"
        + "IoS+NIp8JO+noxAAn25si4QAF7og8+4T5YQUuhIhx/NesAIAAA==");

    byte[] sec10 = Base64.decode(
         "lQHhBEKqia0RBACc3hkufmscRSC4UvPZqMDsHm4+d/GXIr+3iNMSSEySJu8yk+k0"
       + "Xs11C/K+n+v1rnn2jGGknv+1lDY6w75TIcTE6o6HGKeIDxsAm8P3MhoGU1GNPamA"
       + "eTDeNybtrN/g6C65fCY9uI11hsUboYgQZ8ND22PB0VtvdOgq9D85qNUzxwCg1BbJ"
       + "ycAKd4VqEvQ2Zglp3dCSrFMD/Ambq1kZqYa69sp3b9BPKuAgUgUPoytOArEej3Bk"
       + "easAgAxNhWJy4GxigES3vk50rVi7w8XBuqbD1mQCzldF0HX0/A7PxLBv6od5uqqF"
       + "HFxIyxg/KBZLd9ZOrsSaoUWH58jZq98X/sFtJtRi5VuJagMxCIJD4mLgtMv7Unlb"
       + "/GrsA/9DEnObA/fNTgK70T+ZmPIS5tSt+bio30Aw4YGpPCGqpnm1u73b5kqX3U3B"
       + "P+vGDvFuqZYpqQA8byAueH0MbaDHI4CFugvShXvgysJxN7ov7/8qsZZUMfK1t2Nr"
       + "SAsPuKRbcY4gNKXIElKeXbyaET7vX7uAEKuxEwdYGFp/lNTkHP4DAwLssmOjVC+d"
       + "mWB783Lpzjb9evKzsxisTdx8/jHpUSS+r//6/Guyx3aA/zUw5bbftItW57mhuNNb"
       + "JTu7WrQgdGVzdCBrZXkgKHRlc3QpIDx0ZXN0QHRlc3QudGVzdD6IZAQTEQIAJAUC"
       + "QqqJrQIbAwUJACTqAAYLCQgHAwIDFQIDAxYCAQIeAQIXgAAKCRDjDROQZRqIzDzL"
       + "AJ0cYPwKeoSReY14LqJtAjnkX7URHACgsRZWfpbalrSyDnq3TtZeGPUqGX+wAgAA"
       + "nQEUBEKqia4QAwClpIsfJaSTezDE16G+MRRdU7xpZdFA9WwxjjDG3rOmnl0m0/UF"
       + "3nv3x9xp4oy2O8Afqkz7/aIbm60qZ798np9whAVukNmCvjZQrJJmuNj8vGDFdonZ"
       + "mI7SYtXJLxxVrecAAwUC/35AeUOcUhoLKTGk2ZrZl98xu2Q3mdGrz/HvJkS/FLMw"
       + "k6arOrzGa18MkC2T27TGLz0KbkRhHio9MrIpsGEQOa6y0I50REd58rrhFFIHOI/m"
       + "nkcT3/VlbCf2tRQh7WgD9f4DAwLssmOjVC+dmWDXVLRopzxbBGOvodp/LZoSDb56"
       + "gNJjDMJ1aXqWW9qTAg1CFjBq73J3oFpVzInXZ8+Q8inxv7bnWiHbiE8EGBECAA8F"
       + "AkKqia4CGwwFCQAk6gAACgkQ4w0TkGUaiMzdqgCgl2jw5hfk/JsyjulQqe1Nps1q"
       + "Lx0AoMdnFMZmTMLHn8scUW2j9XO312tmsAIAAA==");

    public char[] sec10pass = "test".toCharArray();
   
    public byte[] subKeyBindingKey = Base64.decode(
            "mQGiBDWagYwRBAD7UcH4TAIp7tmUoHBNxVxCVz2ZrNo79M6fV63riOiH2uDxfIpr"
          + "IrL0cM4ehEKoqlhngjDhX60eJrOw1nC5BpYZRnDnyDYT4wTWRguxObzGq9pqA1dM"
          + "oPTJhkFZVIBgFY99/ULRqaUYIhFGgBtnwS70J8/L/PGVc3DmWRLMkTDjSQCg/5Nh"
          + "MCjMK++MdYMcMl/ziaKRT6EEAOtw6PnU9afdohbpx9CK4UvCCEagfbnUtkSCQKSk"
          + "6cUp6VsqyzY0pai/BwJ3h4apFMMMpVrtBAtchVgqo4xTr0Sve2j0k+ase6FSImiB"
          + "g+AR7hvTUTcBjwtIExBc8TuCTqmn4GG8F7UMdl5Z0AZYj/FfAQYaRVZYP/pRVFNx"
          + "Lw65BAC/Fi3qgiGCJFvXnHIckTfcAmZnKSEXWY9NJ4YQb4+/nH7Vsw0wR/ZObUHR"
          + "bWgTc9Vw1uZIMe0XVj6Yk1dhGRehUnrm3mE7UJxu7pgkBCbFECFSlSSqP4MEJwZV"
          + "09YP/msu50kjoxyoTpt+16uX/8B4at24GF1aTHBxwDLd8X0QWrQsTWVycmlsbCBM"
          + "eW5jaCBDTEVBUiBzeXN0ZW0gREggPGNsZWFyQG1sLmNvbT6JAEsEEBECAAsFAjWa"
          + "gYwECwMBAgAKCRDyAGjiP47/XanfAKCs6BPURWVQlGh635VgL+pdkUVNUwCdFcNa"
          + "1isw+eAcopXPMj6ACOapepu5Ag0ENZqBlBAIAPZCV7cIfwgXcqK61qlC8wXo+VMR"
          + "OU+28W65Szgg2gGnVqMU6Y9AVfPQB8bLQ6mUrfdMZIZJ+AyDvWXpF9Sh01D49Vlf"
          + "3HZSTz09jdvOmeFXklnN/biudE/F/Ha8g8VHMGHOfMlm/xX5u/2RXscBqtNbno2g"
          + "pXI61Brwv0YAWCvl9Ij9WE5J280gtJ3kkQc2azNsOA1FHQ98iLMcfFstjvbzySPA"
          + "Q/ClWxiNjrtVjLhdONM0/XwXV0OjHRhs3jMhLLUq/zzhsSlAGBGNfISnCnLWhsQD"
          + "GcgHKXrKlQzZlp+r0ApQmwJG0wg9ZqRdQZ+cfL2JSyIZJrqrol7DVekyCzsAAgIH"
          + "/RYtVo+HROZ6jrNjrATEwQm1fUQrk6n5+2dniN881lF0CNkB4NkHw1Xxz4Ejnu/0"
          + "iLg8fkOAsmanOsKpOkRtqUnVpsVL5mLJpFEyCY5jbcfj+KY9/25bs0ga7kLHNZia"
          + "zbCxJdF+W179z3nudQxRaXG/0XISIH7ziZbSVni69sKc1osk1+OoOMbSuZ86z535"
          + "Pln4fXclkFE927HxfbWoO+60hkOLKh7x+8fC82b3x9vCETujEaxrscO2xS7/MYXP"
          + "8t1ffriTDmhuIuQS2q4fLgeWdqrODrMhrD8Dq7e558gzp30ZCqpiS7EmKGczL7B8"
          + "gXxbBCVSTxYMJheXt2xMXsuJAD8DBRg1moGU8gBo4j+O/10RAgWdAKCPhaFIXuC8"
          + "/cdiNMxTDw9ug3De5QCfYXmDzRSFUu/nrCi8yz/l09wsnxo=");
    
    public byte[] subKeyBindingCheckSum = Base64.decode("3HU+");
    
    //
    // PGP8 with SHA1 checksum.
    //
    public byte[] rewrapKey = Base64.decode(
            "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"
          + "8esfw+iLchfEwXtBIRwS");

    char[] rewrapPass = "voltage123".toCharArray();

    byte[] pubWithX509 = Base64.decode(
        "mQENBERabjABCACtmfyo6Nph9MQjv4nmCWjZrRYnhXbivomAdIwYkLZUj1bjqE+j"+
        "uaLzjZV8xSI59odZvrmOiqlzOc4txitQ1OX7nRgbOJ7qku0dvwjtIn46+HQ+cAFn"+
        "2mTi81RyXEpO2uiZXfsNTxUtMi+ZuFLufiMc2kdk27GZYWEuasdAPOaPJnA+wW6i"+
        "ZHlt0NfXIGNz864gRwhD07fmBIr1dMFfATWxCbgMd/rH7Z/j4rvceHD2n9yrhPze"+
        "YN7W4Nuhsr2w/Ft5Cm9xO7vXT/cpto45uxn8f7jERep6bnUwNOhH8G+6xLQgTLD0"+
        "qFBGVSIneK3lobs6+xn6VaGN8W0tH3UOaxA1ABEBAAG0D0NOPXFhLWRlZXBzaWdo"+
        "dIkFDgQQZAIFAQUCRFpuMAUDCWdU0gMF/3gCGwPELGQBAQQwggTkMIIDzKADAgEC"+
        "AhBVUMV/M6rIiE+IzmnPheQWMA0GCSqGSIb3DQEBBQUAMG4xEzARBgoJkiaJk/Is"+
        "ZAEZFgNjb20xEjAQBgoJkiaJk/IsZAEZFgJxYTEVMBMGCgmSJomT8ixkARkWBXRt"+
        "czAxMRUwEwYKCZImiZPyLGQBGRYFV2ViZmUxFTATBgNVBAMTDHFhLWRlZXBzaWdo"+
        "dDAeFw0wNjA1MDQyMTEyMTZaFw0xMTA1MDQyMTIwMDJaMG4xEzARBgoJkiaJk/Is"+
        "ZAEZFgNjb20xEjAQBgoJkiaJk/IsZAEZFgJxYTEVMBMGCgmSJomT8ixkARkWBXRt"+
        "czAxMRUwEwYKCZImiZPyLGQBGRYFV2ViZmUxFTATBgNVBAMTDHFhLWRlZXBzaWdo"+
        "dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK2Z/Kjo2mH0xCO/ieYJ"+
        "aNmtFieFduK+iYB0jBiQtlSPVuOoT6O5ovONlXzFIjn2h1m+uY6KqXM5zi3GK1DU"+
        "5fudGBs4nuqS7R2/CO0ifjr4dD5wAWfaZOLzVHJcSk7a6Jld+w1PFS0yL5m4Uu5+"+
        "IxzaR2TbsZlhYS5qx0A85o8mcD7BbqJkeW3Q19cgY3PzriBHCEPTt+YEivV0wV8B"+
        "NbEJuAx3+sftn+Piu9x4cPaf3KuE/N5g3tbg26GyvbD8W3kKb3E7u9dP9ym2jjm7"+
        "Gfx/uMRF6npudTA06Efwb7rEtCBMsPSoUEZVIid4reWhuzr7GfpVoY3xbS0fdQ5r"+
        "EDUCAwEAAaOCAXwwggF4MAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0G"+
        "A1UdDgQWBBSmFTRv5y65DHtTYae48zl0ExNWZzCCASUGA1UdHwSCARwwggEYMIIB"+
        "FKCCARCgggEMhoHFbGRhcDovLy9DTj1xYS1kZWVwc2lnaHQsQ049cWEtd3VtYW4x"+
        "LWRjLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNl"+
        "cyxDTj1Db25maWd1cmF0aW9uLERDPVdlYmZlLERDPXRtczAxLERDPXFhLERDPWNv"+
        "bT9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JM"+
        "RGlzdHJpYnV0aW9uUG9pbnSGQmh0dHA6Ly9xYS13dW1hbjEtZGMud2ViZmUudG1z"+
        "MDEucWEuY29tL0NlcnRFbnJvbGwvcWEtZGVlcHNpZ2h0LmNybDAQBgkrBgEEAYI3"+
        "FQEEAwIBADANBgkqhkiG9w0BAQUFAAOCAQEAfuZCW3XlB7Eok35zQbvYt9rhAndT"+
        "DNw3wPNI4ZzD1nXoYWnwhNNvWRpsOt4ExOSNdaHErfgDXAMyyg66Sro0TkAx8eAj"+
        "fPQsyRAh0nm0glzFmJN6TdOZbj7hqGZjc4opQ6nZo8h/ULnaEwMIUW4gcSkZt0ww"+
        "CuErl5NUrN3DpkREeCG/fVvQZ8ays3ibQ5ZCZnYBkLYq/i0r3NLW34WfYhjDY48J"+
        "oQWtvFSAxvRfz2NGmqnrCHPQZxqlfdta97kDa4VQ0zSeBaC70gZkLmD1GJMxWoXW"+
        "6tmEcgPY5SghInUf+L2u52V55MjyAFzVp7kTK2KY+p7qw35vzckrWkwu8AAAAAAA"+
        "AQE=");

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

    private static final byte[] umlautKeySig = Base64.decode(
        "mI0ETdvOgQEEALoI2a39TRk1HReEB6DP9Bu3ShZUce+/Oeg9RIL9aUFuCsNdhu02" +
        "REEHjO29Jz8daPgrnJDfFepNLD6iKKru2m9P30qnhsHMIAshO2Ozfh6wKwuHRqR3" +
        "L4gBDu7cCB6SLwPoD8AYG0yQSM+Do10Td87RlStxCgxpMK6R3TsRkxcFABEBAAG0" +
        "OlVNTEFVVFNUQVJUOsOEw6TDlsO2w5zDvMOfOlVNTEFURU5ERSA8YXNkbGFrc2Rs" +
        "QGFrc2RqLmNvbT6IuAQTAQIAIgUCTdvOgQIbAwYLCQgHAwIGFQgCCQoLBBYCAwEC" +
        "HgECF4AACgkQP8kDwm8AOFiArAP/ZXrlZJB1jFEjyBb04ckpE6F/aJuSYIXf0Yx5" +
        "T2eS+lA69vYuqKRC1qNROBrAn/WGNOQBFNEgGoy3F3gV5NgpIphnyIEZdZWGY2rv" +
        "yjunKWlioZjWc/xbSbvpvJ3Q8RyfDXBOkDEB6uF1ksimw2eJSOUTkF9AQfS5f4rT" +
        "5gs013G4jQRN286BAQQApVbjd8UhsQLB4TpeKn9+dDXAfikGgxDOb19XisjRiWxA" +
        "+bKFxu5tRt6fxXl6BGSGT7DhoVbNkcJGVQFYcbR31UGKCVYcWSL3yfz+PiVuf1UB" +
        "Rp44cXxxqxrLqKp1rk3dGvV4Ayy8lkk3ncDGPez6lIKvj3832yVtAzUOX1QOg9EA" +
        "EQEAAYifBBgBAgAJBQJN286BAhsMAAoJED/JA8JvADhYQ80D/R3TX0FBMHs/xqEh" +
        "tiS86XP/8pW6eMm2eaAYINxoDY3jmDMv2HFQ+YgrYXgqGr6eVGqDMNPj4W8VBoOt" +
        "iYW7+SWY76AAl+gmWIMm2jbN8bZXFk4jmIxpycHCrtoXX8rUk/0+se8NvbmAdMGK" +
        "POOoD7oxdRmJSU5hSspOCHrCwCa3");


    // Key from https://www.angelfire.com/pr/pgpf/pgpoddities.html
    private static final char[] v3KeyPass = "test@key.test".toCharArray();

    private static final byte[] pubv3 = Base64.decode(
        "mQENAzroPPgAAAEIANnTx/gHfag7qRMG6cVUnYZJjLcsdF6JSaVs+PUDCZ8l2+Z2" +
        "V9tgxByp26bymIlq5qFFeoA5vCiKc8qzYiEVLJVVIIDjw/id2gq/TgmxoLAwiDQM" +
        "TUKdCFa6pmR/uaxyrnJxfUA7+Qh0R0OjoCxNlrmyO3eiKstsJGqSUFIQq7GhcHc4" +
        "nbV59zHhEWnH7DX7sDa9CgF11WxM3sjWp15iOoP1nixhmchDtQ7foUxLsCF36G/4" +
        "ijcbN2NjiCDYMFburN8fXgrQzYHAIIiVFE0J+fbXNfPRmnbhQdaC8rIdiQ3tExBb" +
        "N0qWhGPT9M4JOZd1yPdFMb9gbntd8VZkiPd6/3sABRG0FHRlc3QgPHRlc3RAa2V5" +
        "LnRlc3Q+iQEVAwUQOug8+PFWZIj3ev97AQH7NQgAo3sH+KcsPtAbyp5U02J9h3Ro" +
        "aiKpAYxg3rfUVo/RH6hmCWT/AlPHLPZZC/tKiPkuIm2V3Xqyum530N0sBYxNzgNp" +
        "us8mK9QurYj2omKzf1ltN+uNHR8vjB8s7jEd/CDCARu81PqNoVq2b9JRFGpGbAde" +
        "7kQ/a0r2/IsJ8fz0iSpCH0geoHt3sBk9MyEem4uG0e2NzlH2wBz4H8l8BNHRHBq0" +
        "6tGH4h11ZhH3FiNzJWibT2AvzLCqar2qK+6pohKSvIp8zEP7Y/iQzCvkuOfHsUOH" +
        "4Utgg85k09hRDZ3pRRL/4R+Z+/1uXb+n6yKbOmpmi7U7wc9IwZxtTlGXsNIf+Q=="
    );

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

    private static final byte[] problemUserID = Base64.decode(
        "mQGiBDfzC2IRBADjnqYxAM1LPqFZCpF9ULb4G7L88E/p4sNo4k1LkzGtNOiroEHcacEAcTeP" +
        "ljhgTA06l9jpnwx/dE0MEAiEtYexvkBv3LR2qXvuF67TKKlvanB32g0AmxNijHDdN2d+79ZA" +
        "heZ4rY702W6DZh6FuKMAsTBfAFW5jLCWyJ4FwsLILwCg/3mjYePND5l0UcxaV0RKRBGnhqsE" +
        "AIb9PJyWxSa8uzYQ+/APMg16Rrbti21zEQorFoc6yrC2hWbS7ro5yEVJxJa14s7VKlR+IAhg" +
        "vR2+Q6jF6uvE1NZXzX6bvGaK3IpWMZdYcUY63EsHnutV+xON6Xd9C06xjAssvRQnxSuLXCg4" +
        "md1Cr2kiKWaBExzxniKeql5lrqXKBACPcHbwZ8Efgt1TLG4yUf8nIQZwDeAhUPqJVWXurpWx" +
        "r36ET4oQWb5HhO9GEe+2dttyJgV+stZJbZrPVmxmY1hUTZxIZ1ygGcMvrsVZZO0C9QsvMCyy" +
        "xx4RzmTqomkC6Gtl3KtrZ4X28FQFDZi7MQaSXKEu2yS/NKJu2iT2BNKnE7QjTGFzc2UgTb5y" +
        "a2VkYWhsIExhcnNlbiA8bG1sQGdyMy5kaz6ISwQQEQIACwUCN/MLYgQLAwIBAAoJEKg2SsWJ" +
        "xEiGFbcAnA/ka/KE0Mnli7ybUhSrbESR/fZlAJ9SxU2foiRHMF8pF7I8KIJ9AQKSZLkCDQQ3" +
        "8wtiEAgA9kJXtwh/CBdyorrWqULzBej5UxE5T7bxbrlLOCDaAadWoxTpj0BV89AHxstDqZSt" +
        "90xkhkn4DIO9ZekX1KHTUPj1WV/cdlJPPT2N286Z4VeSWc39uK50T8X8dryDxUcwYc58yWb/" +
        "Ffm7/ZFexwGq01uejaClcjrUGvC/RgBYK+X0iP1YTknbzSC0neSRBzZrM2w4DUUdD3yIsxx8" +
        "Wy2O9vPJI8BD8KVbGI2Ou1WMuF040zT9fBdXQ6MdGGzeMyEstSr/POGxKUAYEY18hKcKctaG" +
        "xAMZyAcpesqVDNmWn6vQClCbAkbTCD1mpF1Bn5x8vYlLIhkmuquiXsNV6TILOwACAgf/cugy" +
        "0nyWpA6GxoNqpdky1oCEbgII/lFKkGfQb/sHLgHURjmiaDXSuRJDRXC6YVC0HWqA+bfknR5m" +
        "o1cvohu4GL/oul1eD85UfU29vg5Hr6f601o6xWVCiHF14B24JvO7jhYMd1MQRl7PVzH0a1Gp" +
        "4hSoEvsUjU1HhGUhmMpUxwGJyIFt4RTkqKWK15omuJf4TLT47T58n9uClTNyxpx+oJGaiD0O" +
        "SiEn9d4w5XFewhyXFQhisr99979dLq+buvH1QueMkVDExF4D8LN5gid8JPy/RqFxnHE8AcSF" +
        "XHz9ou8m936pkyKYIMQkCwdw7/Wv7MK64ZED2zOnXnSb/JWY2YhGBBgRAgAGBQI38wtiAAoJ" +
        "EKg2SsWJxEiGJdcAoIQOLuHGGS01Gz5WUpiQZYRtRMIYAKDuYx6bfQngRMs3/gEG0zoSGohY" +
        "lQ=="
    );

    private static final byte[] probExpPubKey = Base64.decode(
        "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");

    private static final byte[] curve25519Pub =    Base64.decode(
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

    private static final byte[] curve25519Priv = Base64.decode(
    "lIYEXEzydhYJKwYBBAHaRw8BAQdAwHPDYhq7hIsCT0jHNxGh4Mbao9kDkcHZilME" +
        "jfgnnG7+BwMCgEr7OFDl3dTpT73rmw6vIwiTGqjx+Xbe8cq4l24q2AOtzO+UR97q" +
        "7ypL41jtt7BY7uoxhF+NCKzYEtRoqyaM0lfjDlOVRJP6SYRixK2UHLQ3VGVzdCBL" +
        "ZXkgKERvIG5vdCB1c2UgZm9yIHJlYWwuKSA8dGVzdEB3b29kcy1nZWJsZXIuY29t" +
        "PoiWBBMWCAA+FiEEi6r5/iAqYhr1koSol1SGvTQgmy0FAlxM8nYCGwMFCQHhM4AF" +
        "CwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQl1SGvTQgmy10cAD9EM6O6zk5kvab" +
        "1D13E5WdY2C5PsKvlxZ0nFR4oBYTZzoBAJxBlYDhKZXV2QlTRcqYt67fFYOmqvJ1" +
        "Pj69Bdv9Cb0HnIsEXEzydhIKKwYBBAGXVQEFAQEHQBjddNLpLWnAU1zVCE2kQpNK" +
        "0b4sAmmIc8r1DJcFtb11AwEIB/4HAwItKjH+kGqkMelkEdIRxSLFeCsB/A64n+os" +
        "X9nWVYsrixEWT5JcRWBniI1PKt9Cm15Yt8KQSAFDJIj5tnEm28x5RM0CzFHQ9Ej2" +
        "8Q2Lt0RoiH4EGBYIACYWIQSLqvn+ICpiGvWShKiXVIa9NCCbLQUCXEzydgIbDAUJ" +
        "AeEzgAAKCRCXVIa9NCCbLZgLAQDESab4fInoMKyQzKEHOd2ag0bG4nhJVeqHwfNG" +
        "vo5M2QEAoKQGmOIWXPBlGp9iSKpINILNt4eGrux+/Sql2BuGvgY=");

    private static final char[] curve25519Pwd = "foobar".toCharArray();

    private static final byte[] datedKey = Base64.decode(
            "xsBNBF6fiQABCACotBYSynnO2fcy65n7IIwcdDM7EM4y19FNKmKM1lBYtbXDOkRR\n" +
            "uMmIF8vQveLT/5JdCCbVRQe/xKUrYBd8Qu9ToJjPiJ70ydJCEsaCeJYqCzTNCAro\n" +
            "qhEqs6vut7IHg+iH20BZcWCk9Zs2gIKlSiuiH811A+TzfXZknxBIfqJZUmW2szXo\n" +
            "xpSQkz0sJKAeZFv91CJKKUKoJiNvse1bh0PHUW0OG6FKHPG+atjlmJ5BbMJGKs8F\n" +
            "nsYU6hLIu3EU0YiIjklXD4xNMwRFE+uwphTCgTAvRU/sL+wqWvOHChcKmcnIojDR\n" +
            "xAtQk6snka5plLrIaE0bC/uuxCPrdqH1eH+jABEBAAHCwGIEHwEIABYFCQTV8IAF\n" +
            "Al6fmtMJEFhym0NDoekEAAB7Lwf/aVmxc07XL9YhxY3uXob6eeks/CHy4wTKwXqr\n" +
            "lTHva0HtwoQetmZlWpN6/RGA1ASMY91WohVdYBafuHFZ2dGKfgXNfV262TlTUViR\n" +
            "YGgX6h/NgCGrAmkaj9uRwn1m4pdi7pWSNgWOEl++dxSbYq7D+nCKcMfVI+UVGmvJ\n" +
            "qGkmmfr7N92xaSvJevfsZdSDFi6Be6tkmLEzQHdZBiya58Pcim5cRH1BKI7UD098\n" +
            "81Uta9ytQM0ybPkTYSsRDtWX1ELE8cpxpkbNBwSlhErcN6Ke5szaKW9jPhWXeivK\n" +
            "3bPbheZl3u7UU4l/c+eBQ5Q4hwCxL+uvPkp6htO0BkhAVX0g2s0oRmlsZWFjdGl2\n" +
            "ZSBTdXBwb3J0IDxzdXBwb3J0QGFuemdjaXMuY29tPsLAXwQQAQgAEwUCXqAncwIZ\n" +
            "AQkQWHKbQ0Oh6QQAAGmPCACWn+o3V9UbrkvH5XiGoWCX4+JNNR/UANS5ch3axdVM\n" +
            "GT2jT5I/NbYCgkhwbgIuAeuv0MxAthWKz8TRCwuZ7eXG8WHTUfRTK0LrWc7uCRX4\n" +
            "obK3xs8/YafKTCAnF14s7aszBEpv/90WEuZ8Xkgoknqw23GmB00jDR6cg/zjgIb+\n" +
            "ZE2MpaCihpcIHDMJ18ZKFWM60BMA5Oqje+lu/sE3aj9q4yYceQsdwLEB414OO5Cj\n" +
            "D5IqRt7f/9WBY4hRF6ZvURvTDZez4pgSHqeNOC39hH+6ndDPBnrjOryFtBHxbT2l\n" +
            "mAKpCgOv3VtjQjW0xqV2NumiYWY8e5q9RXbJZNvDQdqa\n");

    public void test1()
        throws Exception
    {
        JcaPGPPublicKeyRingCollection    pubRings = new JcaPGPPublicKeyRingCollection(pub1);

        int                                        count = 0;

        Iterator    rIt = pubRings.getKeyRings();
        
        while (rIt.hasNext())
        {
            PGPPublicKeyRing                    pgpPub = (PGPPublicKeyRing)rIt.next();

            count++;
            
            int    keyCount = 0;
            
            byte[]    bytes = pgpPub.getEncoded();
            
            pgpPub = new PGPPublicKeyRing(bytes, new JcaKeyFingerprintCalculator());
            
            Iterator    it = pgpPub.getPublicKeys();
            while (it.hasNext())
            {
                keyCount++;

                PGPPublicKey    pubKey = (PGPPublicKey)it.next();
                
                Iterator   sIt = pubKey.getSignatures();
                while (sIt.hasNext())
                {
                    ((PGPSignature)sIt.next()).getSignatureType();
                }
            }
            
            if (keyCount != 2)
            {
                fail("wrong number of public keys");
            }
        }
        
        if (count != 1)
        {
            fail("wrong number of public keyrings");
        }
        
        //
        // exact match
        //
        rIt = pubRings.getKeyRings("test (Test key) <test@ubicall.com>");
        count = 0;
        while (rIt.hasNext())
        {
            count++;
            rIt.next();
        }
        
        if (count != 1)
        {
            fail("wrong number of public keyrings on exact match");
        }
        
        //
        // partial match 1 expected
        //
        rIt = pubRings.getKeyRings("test", true);
        count = 0;
        while (rIt.hasNext())
        {
            count++;
            rIt.next();
        }
        
        if (count != 1)
        {
            fail("wrong number of public keyrings on partial match 1");
        }
        
        //
        // partial match 0 expected
        //
        rIt = pubRings.getKeyRings("XXX", true);
        count = 0;
        while (rIt.hasNext())
        {
            count++;
            rIt.next();
        }
        
        if (count != 0)
        {
            fail("wrong number of public keyrings on partial match 0");
        }

        //
        // case-insensitive partial match
        //
        rIt = pubRings.getKeyRings("TEST@ubicall.com", true, true);
        count = 0;
        while (rIt.hasNext())
        {
            count++;
            rIt.next();
        }
        
        if (count != 1)
        {
            fail("wrong number of public keyrings on case-insensitive partial match");
        }
        
        JcaPGPSecretKeyRingCollection    secretRings = new JcaPGPSecretKeyRingCollection(sec1);

        rIt = secretRings.getKeyRings();
        count = 0;
        
        while (rIt.hasNext())
        {
            PGPSecretKeyRing                    pgpSec = (PGPSecretKeyRing)rIt.next();
    
            count++;
            
            int    keyCount = 0;
            
            byte[]    bytes = pgpSec.getEncoded();
            
            pgpSec = new PGPSecretKeyRing(bytes, new JcaKeyFingerprintCalculator());
            
            Iterator    it = pgpSec.getSecretKeys();
            while (it.hasNext())
            {
                keyCount++;

                PGPSecretKey    k = (PGPSecretKey)it.next();
                PGPPublicKey    pk = k.getPublicKey();
                
                pk.getSignatures();
                
                byte[] pkBytes = pk.getEncoded();
                
                PGPPublicKeyRing  pkR = new PGPPublicKeyRing(pkBytes, new JcaKeyFingerprintCalculator());
            }
            
            if (keyCount != 2)
            {
                fail("wrong number of secret keys");
            }
        }
        
        if (count != 1)
        {
            fail("wrong number of secret keyrings");
        }
        
        //
        // exact match
        //
        rIt = secretRings.getKeyRings("test (Test key) <test@ubicall.com>");
        count = 0;
        while (rIt.hasNext())
        {
            count++;
            rIt.next();
        }
        
        if (count != 1)
        {
            fail("wrong number of secret keyrings on exact match");
        }
        
        //
        // partial match 1 expected
        //
        rIt = secretRings.getKeyRings("test", true);
        count = 0;
        while (rIt.hasNext())
        {
            count++;
            rIt.next();
        }
        
        if (count != 1)
        {
            fail("wrong number of secret keyrings on partial match 1");
        }
        
        //
        // exact match 0 expected
        //
        rIt = secretRings.getKeyRings("test", false);
        count = 0;
        while (rIt.hasNext())
        {
            count++;
            rIt.next();
        }
        
        if (count != 0)
        {
            fail("wrong number of secret keyrings on partial match 0");
        }

        //
        // case-insensitive partial match
        //
        rIt = secretRings.getKeyRings("TEST@ubicall.com", true, true);
        count = 0;
        while (rIt.hasNext())
        {
            count++;
            rIt.next();
        }
        
        if (count != 1)
        {
            fail("wrong number of secret keyrings on case-insensitive partial match");
        }
    }
    
    public void test2()
        throws Exception
    {
        JcaPGPPublicKeyRingCollection    pubRings = new JcaPGPPublicKeyRingCollection(pub2);

        int                            count = 0;

        byte[]    encRing = pubRings.getEncoded();

        pubRings = new JcaPGPPublicKeyRingCollection(encRing);
        
        Iterator    rIt = pubRings.getKeyRings();
        
        while (rIt.hasNext())
        {
            PGPPublicKeyRing        pgpPub = (PGPPublicKeyRing)rIt.next();
            
            count++;
            
            int    keyCount = 0;
            
            byte[]    bytes = pgpPub.getEncoded();
            
            pgpPub = new PGPPublicKeyRing(bytes, new JcaKeyFingerprintCalculator());
            
            Iterator    it = pgpPub.getPublicKeys();
            while (it.hasNext())
            {
                PGPPublicKey    pk = (PGPPublicKey)it.next();
                
                byte[] pkBytes = pk.getEncoded();
                
                PGPPublicKeyRing  pkR = new PGPPublicKeyRing(pkBytes, new JcaKeyFingerprintCalculator());
                
                keyCount++;
            }
            
            if (keyCount != 2)
            {
                fail("wrong number of public keys");
            }
        }
        
        if (count != 2)
        {
            fail("wrong number of public keyrings");
        }
        
        JcaPGPSecretKeyRingCollection    secretRings = new JcaPGPSecretKeyRingCollection(sec2);

        rIt = secretRings.getKeyRings();
        count = 0;
        
        encRing = secretRings.getEncoded();
        
        secretRings = new JcaPGPSecretKeyRingCollection(encRing);
        
        while (rIt.hasNext())
        {
            PGPSecretKeyRing                    pgpSec = (PGPSecretKeyRing)rIt.next();
    
            count++;
            
            int    keyCount = 0;
            
            byte[]    bytes = pgpSec.getEncoded();
            
            pgpSec = new PGPSecretKeyRing(bytes, new JcaKeyFingerprintCalculator());
            
            Iterator    it = pgpSec.getSecretKeys();
            while (it.hasNext())
            {
                keyCount++;

                PGPSecretKey    k = (PGPSecretKey)it.next();
                PGPPublicKey    pk = k.getPublicKey();

                if (pk.getKeyID() == -1413891222336124627L)
                {
                    int         sCount = 0;
                    Iterator    sIt = pk.getSignaturesOfType(PGPSignature.SUBKEY_BINDING);
                    while (sIt.hasNext())
                    {
                        int type = ((PGPSignature)sIt.next()).getSignatureType();
                        if (type != PGPSignature.SUBKEY_BINDING)
                        {
                            fail("failed to return correct signature type");
                        }
                        sCount++;
                    }
                    
                    if (sCount != 1)
                    {
                        fail("failed to find binding signature");
                    }
                }
                
                pk.getSignatures();
                
                if (k.getKeyID() == -4049084404703773049L
                     || k.getKeyID() == -1413891222336124627L)
                {
                    k.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(sec2pass1));
                }
                else if (k.getKeyID() == -6498553574938125416L
                    || k.getKeyID() == 59034765524361024L)
                {
                    k.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(sec2pass2));
                }
            }
            
            if (keyCount != 2)
            {
                fail("wrong number of secret keys");
            }
        }
        
        if (count != 2)
        {
            fail("wrong number of secret keyrings");
        }
    }

    public void shouldStripPreserveTrustPackets()
        throws Exception
    {
        JcaPGPPublicKeyRingCollection pubRings = new JcaPGPPublicKeyRingCollection(pub2);

        for (Iterator it = pubRings.getKeyRings(); it.hasNext();)
        {
            PGPPublicKeyRing pubRing = (PGPPublicKeyRing)it.next();

            byte[] enc = pubRing.getEncoded(true);

            if (trustPackets(enc) != 0)
            {
                fail("trust packet found");
            }
        }

        byte[] ring = pubRings.getEncoded();

        isTrue("trust packets missing", trustPackets(ring) == 10);
    }

    private int trustPackets(byte[] enc)
        throws IOException
    {
        BCPGInputStream bIn = new BCPGInputStream(new ByteArrayInputStream(enc));

        Packet packet;
        int count = 0;
        while ((packet = bIn.readPacket()) != null)
        {
            if (packet instanceof TrustPacket)
            {
                count++;
            }
        }

        return count;
    }

    public void test3()
        throws Exception
    {
        JcaPGPPublicKeyRingCollection    pubRings = new JcaPGPPublicKeyRingCollection(pub3);

        int                                        count = 0;

        byte[]    encRing = pubRings.getEncoded();

        pubRings = new JcaPGPPublicKeyRingCollection(encRing);
        
        Iterator    rIt = pubRings.getKeyRings();
        
        while (rIt.hasNext())
        {
            PGPPublicKeyRing                    pgpPub = (PGPPublicKeyRing)rIt.next();
            
            count++;
            
            int    keyCount = 0;
            
            byte[]    bytes = pgpPub.getEncoded();
            
            pgpPub = new PGPPublicKeyRing(bytes, new JcaKeyFingerprintCalculator());
            
            Iterator    it = pgpPub.getPublicKeys();
            while (it.hasNext())
            {
                keyCount++;

                PGPPublicKey pubK = (PGPPublicKey)it.next();
                
                pubK.getSignatures();
            }
            
            if (keyCount != 2)
            {
                fail("wrong number of public keys");
            }
        }
        
        if (count != 1)
        {
            fail("wrong number of public keyrings");
        }
        
        JcaPGPSecretKeyRingCollection    secretRings = new JcaPGPSecretKeyRingCollection(sec3);

        rIt = secretRings.getKeyRings();
        count = 0;
        
        encRing = secretRings.getEncoded();
        
        secretRings = new JcaPGPSecretKeyRingCollection(encRing);
        
        while (rIt.hasNext())
        {
            PGPSecretKeyRing                    pgpSec = (PGPSecretKeyRing)rIt.next();
    
            count++;
            
            int    keyCount = 0;
            
            byte[]    bytes = pgpSec.getEncoded();
            
            pgpSec = new PGPSecretKeyRing(bytes, new JcaKeyFingerprintCalculator());
            
            Iterator    it = pgpSec.getSecretKeys();
            while (it.hasNext())
            {
                keyCount++;

                PGPSecretKey    k = (PGPSecretKey)it.next();

                k.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(sec3pass1));
            }
            
            if (keyCount != 2)
            {
                fail("wrong number of secret keys");
            }
        }
        
        if (count != 1)
        {
            fail("wrong number of secret keyrings");
        }
    }
    
    public void test4()
        throws Exception
    {
        JcaPGPSecretKeyRingCollection    secretRings = new JcaPGPSecretKeyRingCollection(sec4);

        Iterator    rIt = secretRings.getKeyRings();
        int            count = 0;
        
        byte[]    encRing = secretRings.getEncoded();
        
        secretRings = new JcaPGPSecretKeyRingCollection(encRing);
        
        while (rIt.hasNext())
        {
            PGPSecretKeyRing                    pgpSec = (PGPSecretKeyRing)rIt.next();
    
            count++;
            
            int    keyCount = 0;
            
            byte[]    bytes = pgpSec.getEncoded();
            
            pgpSec = new PGPSecretKeyRing(bytes, new JcaKeyFingerprintCalculator());
            
            Iterator    it = pgpSec.getSecretKeys();
            while (it.hasNext())
            {
                keyCount++;

                PGPSecretKey    k = (PGPSecretKey)it.next();

                k.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(sec3pass1));
            }

            if (keyCount != 2)
            {
                fail("test4 - wrong number of secret keys");
            }

            keyCount = 0;
            it = pgpSec.getPublicKeys();
            while (it.hasNext())
            {
                keyCount++;

                PGPPublicKey    k = (PGPPublicKey)it.next(); // make sure it's what we think it is!
            }

            if (keyCount != 2)
            {
                fail("test4 - wrong number of public keys");
            }
        }
        
        if (count != 1)
        {
            fail("wrong number of secret keyrings");
        }
    }

    public void test5()
        throws Exception
    {
        JcaPGPPublicKeyRingCollection    pubRings = new JcaPGPPublicKeyRingCollection(pub5);

        int                           count = 0;

        byte[]    encRing = pubRings.getEncoded();

        pubRings = new JcaPGPPublicKeyRingCollection(encRing);
        
        Iterator    rIt = pubRings.getKeyRings();
        
        while (rIt.hasNext())
        {
            PGPPublicKeyRing                    pgpPub = (PGPPublicKeyRing)rIt.next();
            
            count++;
            
            int    keyCount = 0;
            
            byte[]    bytes = pgpPub.getEncoded();
            
            pgpPub = new PGPPublicKeyRing(bytes, new JcaKeyFingerprintCalculator());
            
            Iterator    it = pgpPub.getPublicKeys();
            while (it.hasNext())
            {
                keyCount++;

                it.next();
            }
            
            if (keyCount != 2)
            {
                fail("wrong number of public keys");
            }
        }
        
        if (count != 1)
        {
            fail("wrong number of public keyrings");
        }

        if (noIDEA())
        {
            return;
        }

        JcaPGPSecretKeyRingCollection    secretRings = new JcaPGPSecretKeyRingCollection(sec5);

        rIt = secretRings.getKeyRings();
        count = 0;
        
        encRing = secretRings.getEncoded();
        
        secretRings = new JcaPGPSecretKeyRingCollection(encRing);
        
        while (rIt.hasNext())
        {
            PGPSecretKeyRing                    pgpSec = (PGPSecretKeyRing)rIt.next();
    
            count++;
            
            int    keyCount = 0;
            
            byte[]    bytes = pgpSec.getEncoded();
            
            pgpSec = new PGPSecretKeyRing(bytes, new JcaKeyFingerprintCalculator());
            
            Iterator    it = pgpSec.getSecretKeys();
            while (it.hasNext())
            {
                keyCount++;

                PGPSecretKey    k = (PGPSecretKey)it.next();

                k.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(sec5pass1));
            }
            
            if (keyCount != 2)
            {
                fail("wrong number of secret keys");
            }
        }
        
        if (count != 1)
        {
            fail("wrong number of secret keyrings");
        }
    }

    private boolean noIDEA()
    {
        try
        {
            Cipher.getInstance("IDEA", "BC");

            return false;
        }
        catch (Exception e)
        {
            return true;
        }
    }

    public void test6()
        throws Exception
    {
        JcaPGPPublicKeyRingCollection  pubRings = new JcaPGPPublicKeyRingCollection(pub6);
        Iterator                    rIt = pubRings.getKeyRings();

        while (rIt.hasNext())
        {
            PGPPublicKeyRing    pgpPub = (PGPPublicKeyRing)rIt.next();
            Iterator            it = pgpPub.getPublicKeys();
            while (it.hasNext())
            {
                PGPPublicKey    k = (PGPPublicKey)it.next();

                if (k.getKeyID() == 0x5ce086b5b5a18ff4L)
                {
                    int             count = 0;
                    Iterator        sIt = k.getSignaturesOfType(PGPSignature.SUBKEY_REVOCATION);
                    while (sIt.hasNext())
                    {
                        PGPSignature sig = (PGPSignature)sIt.next();
                        count++;
                    }
                    
                    if (count != 1)
                    {
                        fail("wrong number of revocations in test6.");
                    }
                }
            }
        }
        
        byte[]    encRing = pubRings.getEncoded();
    }

    public void revocationTest()
        throws Exception
    {
        PGPPublicKeyRing    pgpPub = new PGPPublicKeyRing(pub7, new JcaKeyFingerprintCalculator());
        Iterator            it = pgpPub.getPublicKeys();
        PGPPublicKey        masterKey = null;

        while (it.hasNext())
        {
            PGPPublicKey    k = (PGPPublicKey)it.next();

            if (k.isMasterKey())
            {
                masterKey = k;
                continue;
            }
        }

        int             count = 0;
        PGPSignature    sig = null;
        Iterator        sIt = masterKey.getSignaturesOfType(PGPSignature.KEY_REVOCATION);

        while (sIt.hasNext())
        {
            sig = (PGPSignature)sIt.next();
            count++;
        }

        if (count != 1)
        {
            fail("wrong number of revocations in test7.");
        }

        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), masterKey);

        if (!sig.verifyCertification(masterKey))
        {
            fail("failed to verify revocation certification");
        }

        pgpPub = new PGPPublicKeyRing(pub7sub, new JcaKeyFingerprintCalculator());
        it = pgpPub.getPublicKeys();
        masterKey = null;

        while (it.hasNext())
        {
            PGPPublicKey    k = (PGPPublicKey)it.next();

            if (k.isMasterKey())
            {
                masterKey = k;
                continue;
            }

            count = 0;
            sig = null;
            sIt = k.getSignaturesOfType(PGPSignature.SUBKEY_REVOCATION);

            while (sIt.hasNext())
            {
                sig = (PGPSignature)sIt.next();
                count++;
            }

            if (count != 1)
            {
                fail("wrong number of revocations in test7 subkey.");
            }

            if (sig.getSignatureType() != PGPSignature.SUBKEY_REVOCATION)
            {
                fail("wrong signature found");
            }

            sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), masterKey);

            if (!sig.verifyCertification(masterKey, k))
            {
                fail("failed to verify revocation certification of subkey");
            }
        }
    }

    public void test8()
        throws Exception
    {
        JcaPGPPublicKeyRingCollection    pubRings = new JcaPGPPublicKeyRingCollection(pub8);

        int                           count = 0;

        byte[]    encRing = pubRings.getEncoded();

        pubRings = new JcaPGPPublicKeyRingCollection(encRing);
        
        Iterator    rIt = pubRings.getKeyRings();
        
        while (rIt.hasNext())
        {
            PGPPublicKeyRing          pgpPub = (PGPPublicKeyRing)rIt.next();
            
            count++;
            
            int    keyCount = 0;
            
            byte[]    bytes = pgpPub.getEncoded();
            
            pgpPub = new PGPPublicKeyRing(bytes, new JcaKeyFingerprintCalculator());
            
            Iterator    it = pgpPub.getPublicKeys();
            while (it.hasNext())
            {
                keyCount++;

                it.next();
            }
            
            if (keyCount != 2)
            {
                fail("wrong number of public keys");
            }
        }
        
        if (count != 2)
        {
            fail("wrong number of public keyrings");
        }
        
        JcaPGPSecretKeyRingCollection    secretRings = new JcaPGPSecretKeyRingCollection(sec8);

        rIt = secretRings.getKeyRings();
        count = 0;
        
        encRing = secretRings.getEncoded();
        
        secretRings = new JcaPGPSecretKeyRingCollection(encRing);
        
        while (rIt.hasNext())
        {
            PGPSecretKeyRing         pgpSec = (PGPSecretKeyRing)rIt.next();
    
            count++;
            
            int    keyCount = 0;
            
            byte[]    bytes = pgpSec.getEncoded();
            
            pgpSec = new PGPSecretKeyRing(bytes, new JcaKeyFingerprintCalculator());
            
            Iterator    it = pgpSec.getSecretKeys();
            while (it.hasNext())
            {
                keyCount++;

                PGPSecretKey    k = (PGPSecretKey)it.next();

                k.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(sec8pass));
            }
            
            if (keyCount != 2)
            {
                fail("wrong number of secret keys");
            }
        }
        
        if (count != 1)
        {
            fail("wrong number of secret keyrings");
        }
    }
    
    public void test9()
        throws Exception
    { 
        JcaPGPSecretKeyRingCollection    secretRings = new JcaPGPSecretKeyRingCollection(sec9);

        Iterator    rIt = secretRings.getKeyRings();
        int         count = 0;
        
        byte[] encRing = secretRings.getEncoded();
        
        secretRings = new JcaPGPSecretKeyRingCollection(encRing);
        
        while (rIt.hasNext())
        {
            PGPSecretKeyRing         pgpSec = (PGPSecretKeyRing)rIt.next();
    
            count++;
            
            int    keyCount = 0;
            
            byte[]    bytes = pgpSec.getEncoded();
            
            pgpSec = new PGPSecretKeyRing(bytes, new JcaKeyFingerprintCalculator());
            
            Iterator    it = pgpSec.getSecretKeys();
            while (it.hasNext())
            {
                keyCount++;

                PGPSecretKey    k = (PGPSecretKey)it.next();

                PGPPrivateKey   pKey = k.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(sec9pass));
                if (keyCount == 1 && pKey != null)
                {
                    fail("primary secret key found, null expected");
                }
            }
            
            if (keyCount != 3)
            {
                fail("wrong number of secret keys");
            }
        }
        
        if (count != 1)
        {
            fail("wrong number of secret keyrings");
        }
    }
    
    public void test10()
        throws Exception
    { 
        PGPSecretKeyRing    secretRing = new PGPSecretKeyRing(sec10, new JcaKeyFingerprintCalculator());
        Iterator            secretKeys = secretRing.getSecretKeys();
        
        while (secretKeys.hasNext())
        {
            PGPPublicKey pubKey = ((PGPSecretKey)secretKeys.next()).getPublicKey();
            
            if (pubKey.getValidDays() != 28)
            {
                fail("days wrong on secret key ring");
            }
            
            if (pubKey.getValidSeconds() != 28 * 24 * 60 * 60)
            {
                fail("seconds wrong on secret key ring");
            }
        }
        
        PGPPublicKeyRing    publicRing = new PGPPublicKeyRing(pub10, new JcaKeyFingerprintCalculator());
        Iterator            publicKeys = publicRing.getPublicKeys();
        
        while (publicKeys.hasNext())
        {
            PGPPublicKey pubKey = (PGPPublicKey)publicKeys.next();

            if (pubKey.getValidDays() != 28)
            {
                fail("days wrong on public key ring");
            }
            
            if (pubKey.getValidSeconds() != 28 * 24 * 60 * 60)
            {
                fail("seconds wrong on public key ring");
            }
        }
    }

    public void generateTest()
        throws Exception
    {
        char[]              passPhrase = "hello".toCharArray();
        KeyPairGenerator    dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
    
        dsaKpg.initialize(512);
    
        //
        // this takes a while as the key generator has to generate some DSA params
        // before it generates the key.
        //
        KeyPair                    dsaKp = dsaKpg.generateKeyPair();
    
        KeyPairGenerator    elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
        BigInteger             g = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
        BigInteger             p = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);
        
        ElGamalParameterSpec         elParams = new ElGamalParameterSpec(p, g);
        
        elgKpg.initialize(elParams);
    
        //
        // this is quicker because we are using pregenerated parameters.
        //
        KeyPair                    elgKp = elgKpg.generateKeyPair();
        PGPKeyPair        dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date());
        PGPKeyPair        elgKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKp, new Date());
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator    keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair,
                "test", sha1Calc, null, null, new JcaPGPContentSignerBuilder(PGPPublicKey.DSA, HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256).setProvider("BC").build(passPhrase));

    
        keyRingGen.addSubKey(elgKeyPair);
    
        PGPSecretKeyRing       keyRing = keyRingGen.generateSecretKeyRing();
        
        keyRing.getSecretKey().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passPhrase));
        
        PGPPublicKeyRing        pubRing = keyRingGen.generatePublicKeyRing();
        
        PGPPublicKey            vKey = null;
        PGPPublicKey            sKey = null;
        
        Iterator                    it = pubRing.getPublicKeys();
        while (it.hasNext())
        {
            PGPPublicKey    pk = (PGPPublicKey)it.next();
            if (pk.isMasterKey())
            {
                vKey = pk;
            }
            else
            {
                sKey = pk;
            }
        }
        
        Iterator    sIt = sKey.getSignatures();
        while (sIt.hasNext())
        {
            PGPSignature    sig = (PGPSignature)sIt.next();
            
            if (sig.getKeyID() == vKey.getKeyID()
                && sig.getSignatureType() == PGPSignature.SUBKEY_BINDING)
            {
                sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), vKey);

                if (!sig.verifyCertification(vKey, sKey))
                {
                    fail("failed to verify sub-key signature.");
                }
            }
        }

        PGPSignature masterSig = null;
        Iterator kIt = pubRing.getKeysWithSignaturesBy(vKey.getKeyID());
        if (kIt.hasNext())
        {
            while (kIt.hasNext())
            {
                PGPPublicKey pub = (PGPPublicKey)kIt.next();

                if (pub.isMasterKey())
                {
                    Iterator sigIt = pub.getSignaturesForKeyID(vKey.getKeyID());

                    PGPSignature sig = (PGPSignature)sigIt.next();

                    if (sig.getSignatureType() != PGPSignature.POSITIVE_CERTIFICATION || sigIt.hasNext())
                    {
                        fail("master sig check failed");
                    }
                    masterSig = sig;
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

        // try remove certification by sig.
        PGPPublicKey editedKey = PGPPublicKey.removeCertification(vKey, masterSig);

        for (it = editedKey.getSignatures(); it.hasNext();)
        {
              if (masterSig.equals(it.next()))
              {
                  fail("signature found");
              }
        }
    }

    private void insertMasterTest()
        throws Exception
    {
        char[]              passPhrase = "hello".toCharArray();
        KeyPairGenerator    rsaKpg = KeyPairGenerator.getInstance("RSA", "BC");

        rsaKpg.initialize(512);

        //
        // this is quicker because we are using pregenerated parameters.
        //
        KeyPair           rsaKp = rsaKpg.generateKeyPair();
        PGPKeyPair        rsaKeyPair1 = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, rsaKp, new Date());
                          rsaKp = rsaKpg.generateKeyPair();
        PGPKeyPair        rsaKeyPair2 = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, rsaKp, new Date());
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator    keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, rsaKeyPair1,
                            "test", sha1Calc, null, null, new JcaPGPContentSignerBuilder(PGPPublicKey.RSA_SIGN, HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256).setProvider("BC").build(passPhrase));
        PGPSecretKeyRing       secRing1 = keyRingGen.generateSecretKeyRing();
        PGPPublicKeyRing       pubRing1 = keyRingGen.generatePublicKeyRing();
        keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, rsaKeyPair2,
                            "test", sha1Calc, null, null, new JcaPGPContentSignerBuilder(PGPPublicKey.RSA_SIGN, HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256).setProvider("BC").build(passPhrase));
        PGPSecretKeyRing       secRing2 = keyRingGen.generateSecretKeyRing();
        PGPPublicKeyRing       pubRing2 = keyRingGen.generatePublicKeyRing();

        try
        {
            PGPPublicKeyRing.insertPublicKey(pubRing1, pubRing2.getPublicKey());
            fail("adding second master key (public) should throw an IllegalArgumentException");
        }
        catch (IllegalArgumentException e)
        {
            if (!e.getMessage().equals("cannot add a master key to a ring that already has one"))
            {
                fail("wrong message in public test");
            }
        }

        try
        {
            PGPSecretKeyRing.insertSecretKey(secRing1, secRing2.getSecretKey());
            fail("adding second master key (secret) should throw an IllegalArgumentException");
        }
        catch (IllegalArgumentException e)
        {
            if (!e.getMessage().equals("cannot add a master key to a ring that already has one"))
            {
                fail("wrong message in secret test");
            }
        }
    }

    public void generateSha1Test()
        throws Exception
    {
        char[]              passPhrase = "hello".toCharArray();
        KeyPairGenerator    dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
    
        dsaKpg.initialize(512);
    
        //
        // this takes a while as the key generator has to generate some DSA params
        // before it generates the key.
        //
        KeyPair                    dsaKp = dsaKpg.generateKeyPair();
    
        KeyPairGenerator    elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
        BigInteger             g = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
        BigInteger             p = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);
        
        ElGamalParameterSpec         elParams = new ElGamalParameterSpec(p, g);
        
        elgKpg.initialize(elParams);
    
        //
        // this is quicker because we are using pregenerated parameters.
        //
        KeyPair                    elgKp = elgKpg.generateKeyPair();
        PGPKeyPair        dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date());
        PGPKeyPair        elgKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKp, new Date());
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator    keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair,
                   "test", sha1Calc, null, null, new JcaPGPContentSignerBuilder(PGPPublicKey.DSA, HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256).setProvider("BC").build(passPhrase));

    
        keyRingGen.addSubKey(elgKeyPair);
    
        PGPSecretKeyRing       keyRing = keyRingGen.generateSecretKeyRing();
        
        keyRing.getSecretKey().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passPhrase));

        if (!keyRing.getSecretKey().getPublicKey().equals(keyRing.getPublicKey()))
        {
            fail("secret key public key mismatch");
        }

        PGPPublicKeyRing        pubRing = keyRingGen.generatePublicKeyRing();
        
        PGPPublicKey            vKey = null;
        PGPPublicKey            sKey = null;
        
        Iterator                    it = pubRing.getPublicKeys();
        while (it.hasNext())
        {
            PGPPublicKey    pk = (PGPPublicKey)it.next();
            if (pk.isMasterKey())
            {
                vKey = pk;
            }
            else
            {
                sKey = pk;
            }
        }

        // check key id fetch
        if (keyRing.getPublicKey(vKey.getKeyID()).getKeyID() != vKey.getKeyID())
        {
            fail("secret key public key mismatch - vKey");
        }

        if (keyRing.getPublicKey(sKey.getKeyID()).getKeyID() != sKey.getKeyID())
        {
            fail("secret key public key mismatch - sKey");
        }

        Iterator    sIt = sKey.getSignatures();
        while (sIt.hasNext())
        {
            PGPSignature    sig = (PGPSignature)sIt.next();
            
            if (sig.getKeyID() == vKey.getKeyID()
                && sig.getSignatureType() == PGPSignature.SUBKEY_BINDING)
            {
                sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), vKey);
    
                if (!sig.verifyCertification(vKey, sKey))
                {
                    fail("failed to verify sub-key signature.");
                }
            }
        }
    }
    
    private void test11()
        throws Exception
    {
        PGPPublicKeyRing pubRing = new PGPPublicKeyRing(subKeyBindingKey, new JcaKeyFingerprintCalculator());
        Iterator         it = pubRing.getPublicKeys();
        
        while (it.hasNext())
        {
            PGPPublicKey key = (PGPPublicKey)it.next();
            
            if (key.getValidSeconds() != 0)
            {
                fail("expiration time non-zero");
            }
        }
    }
    
    private void rewrapTest()
        throws Exception
    {
        // Read the secret key rings
        JcaPGPSecretKeyRingCollection privRings = new JcaPGPSecretKeyRingCollection(
                                                         new ByteArrayInputStream(rewrapKey)); 
        char[] newPass = "fred".toCharArray();

        Iterator rIt = privRings.getKeyRings();

        if (rIt.hasNext())
        {
            PGPSecretKeyRing pgpPriv= (PGPSecretKeyRing)rIt.next();

            Iterator it = pgpPriv.getSecretKeys();

            while (it.hasNext())
            {
                PGPSecretKey pgpKey = (PGPSecretKey)it.next();
                long oldKeyID = pgpKey.getKeyID();

                // re-encrypt the key with an empty password
                pgpPriv = PGPSecretKeyRing.removeSecretKey(pgpPriv, pgpKey);
                pgpKey = PGPSecretKey.copyWithNewPassword(
                                    pgpKey,
                                    new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(rewrapPass),
                                    null);
                pgpPriv = PGPSecretKeyRing.insertSecretKey(pgpPriv, pgpKey);
            
                // this should succeed
                PGPPrivateKey privTmp = pgpKey.extractPrivateKey(null);

                if (pgpKey.getKeyID() != oldKeyID || pgpKey.getS2KUsage() != SecretKeyPacket.USAGE_NONE)
                {
                    fail("usage/key ID mismatch");
                }
            }

            it = pgpPriv.getSecretKeys();

            while (it.hasNext())
            {
                PGPSecretKey pgpKey = (PGPSecretKey)it.next();
                long oldKeyID = pgpKey.getKeyID();

                // re-encrypt the key with an empty password
                pgpPriv = PGPSecretKeyRing.removeSecretKey(pgpPriv, pgpKey);
                pgpKey = PGPSecretKey.copyWithNewPassword(
                                    pgpKey,
                                    null,
                                    new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.CAST5).setProvider("BC").build(newPass));
                pgpPriv = PGPSecretKeyRing.insertSecretKey(pgpPriv, pgpKey);

                // this should succeed
                PGPPrivateKey privTmp = pgpKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(newPass));

                if (pgpKey.getKeyID() != oldKeyID || pgpKey.getS2KUsage() != SecretKeyPacket.USAGE_CHECKSUM)
                {
                    fail("usage/key ID mismatch");
                }
            }
        }
    }

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

            while (it.hasNext())
            {
                PGPSecretKey pgpKey = (PGPSecretKey)it.next();
                long oldKeyID = pgpKey.getKeyID();

                // re-encrypt the key with an empty password
                pgpPriv = PGPSecretKeyRing.removeSecretKey(pgpPriv, pgpKey);

                pgpKey = PGPSecretKey.copyWithNewPassword(
                    pgpKey,
                    new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(v3KeyPass),
                    null);
                pgpPriv = PGPSecretKeyRing.insertSecretKey(pgpPriv, pgpKey);

                // this should succeed
                PGPPrivateKey privTmp = pgpKey.extractPrivateKey(null);

                if (pgpKey.getKeyID() != oldKeyID)
                {
                    fail("key ID mismatch");
                }
            }

            it = pgpPriv.getSecretKeys();

            while (it.hasNext())
            {
                PGPSecretKey pgpKey = (PGPSecretKey)it.next();
                long oldKeyID = pgpKey.getKeyID();

                // re-encrypt the key with an empty password
                pgpPriv = PGPSecretKeyRing.removeSecretKey(pgpPriv, pgpKey);
                pgpKey = PGPSecretKey.copyWithNewPassword(
                                    pgpKey,
                                    null,
                                    new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.CAST5, new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build().get(HashAlgorithmTags.MD5)).setProvider("BC").build(newPass));
                pgpPriv = PGPSecretKeyRing.insertSecretKey(pgpPriv, pgpKey);

                // this should succeed
                PGPPrivateKey privTmp = pgpKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(newPass));

                if (pgpKey.getKeyID() != oldKeyID)
                {
                    fail("key ID mismatch");
                }
            }
        }
    }

    private void rewrapTestMD5()
        throws Exception
    {
        // Read the secret key rings
        JcaPGPSecretKeyRingCollection privRings = new JcaPGPSecretKeyRingCollection(
                                                         new ByteArrayInputStream(rewrapKey));
        char[] newPass = "fred".toCharArray();

        Iterator rIt = privRings.getKeyRings();

        if (rIt.hasNext())
        {
            PGPSecretKeyRing pgpPriv= (PGPSecretKeyRing)rIt.next();

            Iterator it = pgpPriv.getSecretKeys();

            PGPDigestCalculatorProvider calcProvider = new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build();

            while (it.hasNext())
            {
                PGPSecretKey pgpKey = (PGPSecretKey)it.next();
                long oldKeyID = pgpKey.getKeyID();

                // re-encrypt the key with an empty password
                pgpPriv = PGPSecretKeyRing.removeSecretKey(pgpPriv, pgpKey);
                pgpKey = PGPSecretKey.copyWithNewPassword(
                                    pgpKey,
                                    new JcePBESecretKeyDecryptorBuilder(calcProvider).setProvider("BC").build(rewrapPass),
                                    null);
                pgpPriv = PGPSecretKeyRing.insertSecretKey(pgpPriv, pgpKey);

                // this should succeed
                PGPPrivateKey privTmp = pgpKey.extractPrivateKey(null);

                if (pgpKey.getKeyID() != oldKeyID)
                {
                    fail("key ID mismatch");
                }
            }

            it = pgpPriv.getSecretKeys();

            while (it.hasNext())
            {
                PGPSecretKey pgpKey = (PGPSecretKey)it.next();
                long oldKeyID = pgpKey.getKeyID();

                // re-encrypt the key with an empty password
                pgpPriv = PGPSecretKeyRing.removeSecretKey(pgpPriv, pgpKey);
                pgpKey = PGPSecretKey.copyWithNewPassword(
                                    pgpKey,
                                    null,
                                    new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.CAST5, calcProvider.get(HashAlgorithmTags.MD5)).setProvider("BC").build(newPass));
                pgpPriv = PGPSecretKeyRing.insertSecretKey(pgpPriv, pgpKey);

                // this should succeed
                PGPPrivateKey privTmp = pgpKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder(calcProvider).setProvider("BC").build(newPass));

                if (pgpKey.getKeyID() != oldKeyID)
                {
                    fail("key ID mismatch");
                }
            }
        }
    }

    private void testPublicKeyRingWithX509()
        throws Exception
    {
        checkPublicKeyRingWithX509(pubWithX509);

        PGPPublicKeyRing pubRing = new PGPPublicKeyRing(pubWithX509, new JcaKeyFingerprintCalculator());

        checkPublicKeyRingWithX509(pubRing.getEncoded());
    }

    private void testSecretKeyRingWithPersonalCertificate()
        throws Exception
    {
        checkSecretKeyRingWithPersonalCertificate(secWithPersonalCertificate);
        JcaPGPSecretKeyRingCollection secRing = new JcaPGPSecretKeyRingCollection(secWithPersonalCertificate);
        checkSecretKeyRingWithPersonalCertificate(secRing.getEncoded());
    }

    private void testUmlaut()
        throws Exception
    {
        PGPPublicKeyRing pubRing = new PGPPublicKeyRing(umlautKeySig, new JcaKeyFingerprintCalculator());

        PGPPublicKey pub = pubRing.getPublicKey();
        String       userID = (String)pub.getUserIDs().next();

        for (Iterator it = pub.getSignatures(); it.hasNext();)
        {
            PGPSignature sig = (PGPSignature)it.next();

            if (sig.getSignatureType() == PGPSignature.POSITIVE_CERTIFICATION)
            {
                sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pub);

                if (!sig.verifyCertification(userID, pub))
                {
                    fail("failed UTF8 userID test");
                }
            }
        }

        //
        // this is quicker because we are using pregenerated parameters.
        //
        KeyPairGenerator  rsaKpg = KeyPairGenerator.getInstance("RSA", "BC");
        KeyPair           rsaKp = rsaKpg.generateKeyPair();
        PGPKeyPair        rsaKeyPair1 = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, rsaKp, new Date());
                          rsaKp = rsaKpg.generateKeyPair();
        PGPKeyPair        rsaKeyPair2 = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, rsaKp, new Date());
        char[]            passPhrase = "passwd".toCharArray();
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, rsaKeyPair1,
                           userID, sha1Calc, null, null, new JcaPGPContentSignerBuilder(PGPPublicKey.RSA_SIGN, HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256).setProvider("BC").build(passPhrase));


        PGPPublicKeyRing       pubRing1 = keyRingGen.generatePublicKeyRing();

        pub = pubRing1.getPublicKey();

        for (Iterator it = pub.getSignatures(); it.hasNext();)
        {
            PGPSignature sig = (PGPSignature)it.next();

            if (sig.getSignatureType() == PGPSignature.POSITIVE_CERTIFICATION)
            {
                sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pub);

                if (!sig.verifyCertification(userID, pub))
                {
                    fail("failed UTF8 userID creation test");
                }
            }
        }
    }

    private void checkSecretKeyRingWithPersonalCertificate(byte[] keyRing)
        throws Exception
    {
        JcaPGPSecretKeyRingCollection secCol = new JcaPGPSecretKeyRingCollection(keyRing);


        int count = 0;

        for (Iterator rIt = secCol.getKeyRings(); rIt.hasNext();)
        {
            PGPSecretKeyRing ring = (PGPSecretKeyRing)rIt.next();

            for (Iterator it = ring.getExtraPublicKeys(); it.hasNext();)
            {
                it.next();
                count++;
            }
        }

        if (count != 1)
        {
            fail("personal certificate data subkey not found - count = " + count);
        }
    }

    private void checkPublicKeyRingWithX509(byte[] keyRing)
        throws Exception
    {
        PGPPublicKeyRing pubRing = new PGPPublicKeyRing(keyRing, new JcaKeyFingerprintCalculator());
        Iterator         it = pubRing.getPublicKeys();

        if (it.hasNext())
        {
            PGPPublicKey key = (PGPPublicKey)it.next();

            Iterator sIt = key.getSignatures();

            if (sIt.hasNext())
            {
                PGPSignature sig = (PGPSignature)sIt.next();
                if (sig.getKeyAlgorithm() != 100)
                {
                    fail("experimental signature not found");
                }
                if (!areEqual(sig.getSignature(), Hex.decode("000101")))
                {
                    fail("experimental encoding check failed");
                }
            }
            else
            {
                fail("no signature found");
            }
        }
        else
        {
            fail("no key found");
        }
    }

    // test for key ring with non-UTF8 User ID.
    private void testBadUserID()
        throws Exception
    {
        PGPPublicKeyRing pgpRing = new JcaPGPPublicKeyRing(problemUserID);

        byte[] enc = pgpRing.getEncoded();

        if (!Arrays.areEqual(problemUserID, enc))
        {
            fail("encoded key does not match original");
        }

        PGPPublicKey pubKey = pgpRing.getPublicKey();

        Iterator it = pubKey.getRawUserIDs();

        byte[] rawID = (byte[])it.next();

        it = pubKey.getSignaturesForID(rawID);

        PGPSignature sig = (PGPSignature)it.next();

        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pubKey);

        if (!sig.verifyCertification(rawID, pubKey))
        {
            fail("Certification not validated for rawID");
        }
    }

    private void testExpiryDate()
        throws Exception
    {
        PGPPublicKeyRingCollection pgpRingCollection = new JcaPGPPublicKeyRingCollection(probExpPubKey);

        for (Iterator it = pgpRingCollection.getKeyRings(); it.hasNext();)
        {
            PGPPublicKeyRing pgpRing = (PGPPublicKeyRing)it.next();

            for (Iterator rit = pgpRing.getPublicKeys(); rit.hasNext(); )
            {
                PGPPublicKey pubKey = (PGPPublicKey)rit.next();

                // this key has 2 self signatures on it - the most recent key validity is for 432495 seconds.
                if (0x5afd53a9dbb2c40dL == pubKey.getKeyID())
                {
                    isTrue("wrong validity date", pubKey.getValidSeconds() == 432495);
                }
                // this key has 3 self signatures on it - the most recent key validity is for 4320173 seconds.
                else if (0x89FCFA4B23363333L == pubKey.getKeyID())
                {
                    isTrue("wrong validity date", pubKey.getValidSeconds() == 4320173);
                }
            }
        }
    }

    public void testNoExportPrivateKey()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(1024);

        KeyPair kp = kpGen.generateKeyPair();

        JcaPGPKeyConverter converter = new JcaPGPKeyConverter();
        PGPPublicKey       pubKey = converter.getPGPPublicKey(PGPPublicKey.RSA_GENERAL, kp.getPublic(), new Date());
        PGPPrivateKey      privKey = new JcaPGPPrivateKey(pubKey, kp.getPrivate());

        doTestNoExportPrivateKey(new PGPKeyPair(pubKey, privKey));
    }

    private void doTestNoExportPrivateKey(PGPKeyPair keyPair)
        throws Exception
    {
        PGPDigestCalculator    sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator    keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, keyPair,
                       "test", sha1Calc, null, null, new JcaPGPContentSignerBuilder(PGPPublicKey.RSA_SIGN, HashAlgorithmTags.SHA1), null);

        PGPPublicKey pubKey = keyPair.getPublicKey();
        PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();
        if (pubRing.getPublicKey(pubKey.getKeyID()) == null)
        {
            fail("no public key found");
        }

        for (Iterator it = pubRing.getPublicKey().getSignatures(); it.hasNext();)
        {
            PGPSignature sig = (PGPSignature)it.next();

            sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pubKey);

            if (!sig.verifyCertification("test", pubKey))
            {
                fail("certification failed");
            }
        }

        pubRing.getEncoded();

        PGPSecretKeyRing secRing = keyRingGen.generateSecretKeyRing();

        secRing.getEncoded();
    }

    public void testNullEncryption()
        throws Exception
    {
        char[] passPhrase = "fred".toCharArray();
        KeyPairGenerator bareGenerator = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
        bareGenerator.initialize(2048);
        KeyPair rsaPair = bareGenerator.generateKeyPair();

        PGPDigestCalculator calculator = new JcaPGPDigestCalculatorProviderBuilder()
                    .setProvider(new BouncyCastleProvider())
                    .build()
                    .get(HashAlgorithmTags.SHA1);

        PGPKeyPair pgpPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, rsaPair, new Date());

        PGPSignatureSubpacketGenerator subpackets = new PGPSignatureSubpacketGenerator();

        // Key flags
        subpackets.setKeyFlags(true,
                KeyFlags.CERTIFY_OTHER
                            | KeyFlags.SIGN_DATA
                            | KeyFlags.ENCRYPT_COMMS
                            | KeyFlags.ENCRYPT_STORAGE
                            | KeyFlags.AUTHENTICATION);

       // Encryption Algorithms
       subpackets.setPreferredSymmetricAlgorithms(true, new int[]{
                    SymmetricKeyAlgorithmTags.AES_256,
           SymmetricKeyAlgorithmTags.AES_192,
           SymmetricKeyAlgorithmTags.AES_128,
           SymmetricKeyAlgorithmTags.TRIPLE_DES
        });

        // Hash Algorithms
        subpackets.setPreferredHashAlgorithms(true, new int[] {
                    HashAlgorithmTags.SHA512,
            HashAlgorithmTags.SHA384,
            HashAlgorithmTags.SHA256,
            HashAlgorithmTags.SHA224,
            HashAlgorithmTags.SHA1
        });

        // Compression Algorithms
        subpackets.setPreferredCompressionAlgorithms(true, new int[] {
                    CompressionAlgorithmTags.ZLIB,
            CompressionAlgorithmTags.BZIP2,
            CompressionAlgorithmTags.ZIP
        });

        // Modification Detection
        subpackets.setFeature(true, Features.FEATURE_MODIFICATION_DETECTION);

        PGPContentSignerBuilder signer = new JcaPGPContentSignerBuilder(
                    pgpPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256);

        PGPKeyRingGenerator ringGenerator = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, pgpPair,
                    "xmpp:juliet@capulet.lit", calculator, subpackets.generate(), null, signer, null);
        int length1 = ringGenerator.generateSecretKeyRing().getEncoded().length;
        ringGenerator = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, pgpPair,
                    "xmpp:juliet@capulet.lit", null, subpackets.generate(), null, signer, null);
        int length2 = ringGenerator.generateSecretKeyRing().getEncoded().length;

        isEquals("key ring length mismatch", length1, length2);
    }

    private void testEdDsaRing()
        throws Exception
    {
        ArmoredInputStream aIn = new ArmoredInputStream(this.getClass().getResourceAsStream("eddsa-pub-keyring.asc"));

        // make sure we can parse it without falling over.
        PGPPublicKeyRing rng = new PGPPublicKeyRing(aIn, new JcaKeyFingerprintCalculator());
    }

    private void testCurve25519Ring()
        throws Exception
    {
        // make sure we can parse it without falling over.
        PGPPublicKeyRing rng = new PGPPublicKeyRing(new ByteArrayInputStream(curve25519Pub), new JcaKeyFingerprintCalculator());

        PGPSecretKeyRing priv = new PGPSecretKeyRing(new ByteArrayInputStream(curve25519Priv), new JcaKeyFingerprintCalculator());
    }

    public void testShouldProduceSubkeys()
        throws Exception
    {
        KeyPairGenerator generator;
        KeyPair pair;

        // Generate master key

        generator = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(new ECNamedCurveGenParameterSpec("P-256"));

        pair = generator.generateKeyPair();
        PGPKeyPair pgpMasterKey = new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDSA, pair, new Date());

        PGPSignatureSubpacketGenerator subPackets = new PGPSignatureSubpacketGenerator();
        subPackets.setKeyFlags(false, KeyFlags.AUTHENTICATION & KeyFlags.CERTIFY_OTHER & KeyFlags.SIGN_DATA);
        subPackets.setPreferredSymmetricAlgorithms(false, new int[]{
            SymmetricKeyAlgorithmTags.AES_256,
            SymmetricKeyAlgorithmTags.AES_192,
            SymmetricKeyAlgorithmTags.AES_128});
        subPackets.setPreferredHashAlgorithms(false, new int[]{
            HashAlgorithmTags.SHA512,
            HashAlgorithmTags.SHA384,
            HashAlgorithmTags.SHA256,
            HashAlgorithmTags.SHA224});
        subPackets.setPreferredCompressionAlgorithms(false, new int[]{
            CompressionAlgorithmTags.ZLIB,
            CompressionAlgorithmTags.BZIP2,
            CompressionAlgorithmTags.ZIP,
            CompressionAlgorithmTags.UNCOMPRESSED});
        subPackets.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

        // Generate sub key

        generator = KeyPairGenerator.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(new ECNamedCurveGenParameterSpec("P-256"));

        pair = generator.generateKeyPair();
        PGPKeyPair pgpSubKey = new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDH, pair, new Date());

        // Assemble key

        PGPDigestCalculator calculator = new JcaPGPDigestCalculatorProviderBuilder()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build()
            .get(HashAlgorithmTags.SHA1);

        PGPContentSignerBuilder signerBuilder = new JcaPGPContentSignerBuilder(
            pgpMasterKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA512)
            .setProvider(BouncyCastleProvider.PROVIDER_NAME);

        PGPKeyRingGenerator pgpGenerator = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION,
            pgpMasterKey, "alice@wonderland.lit", calculator, subPackets.generate(), null,
            signerBuilder, null);

        // Add sub key

        subPackets.setKeyFlags(false, KeyFlags.ENCRYPT_STORAGE & KeyFlags.ENCRYPT_COMMS);

        pgpGenerator.addSubKey(pgpSubKey, subPackets.generate(), null);

        // Generate SecretKeyRing

        PGPSecretKeyRing secretKeys = pgpGenerator.generateSecretKeyRing();

        PGPPublicKeyRing publicKeys = pgpGenerator.generatePublicKeyRing();

        checkPublicKeyRing(secretKeys, publicKeys.getEncoded());
        // Extract the public keys
        ByteArrayOutputStream bOut = new ByteArrayOutputStream(2048);
        Iterator<PGPPublicKey> iterator = secretKeys.getPublicKeys();
        int count = 0;
        while (iterator.hasNext())
        {
            bOut.write(((PGPPublicKey)iterator.next()).getEncoded());
            count++;
        }

        isTrue(count == 2);

        checkPublicKeyRing(secretKeys, bOut.toByteArray());

        isTrue(Arrays.areEqual(publicKeys.getEncoded(), bOut.toByteArray()));

        // add an extra subkey
        pgpGenerator = new PGPKeyRingGenerator(secretKeys, null, calculator, signerBuilder, null);

        // Add sub key

        subPackets.setKeyFlags(false, KeyFlags.ENCRYPT_STORAGE & KeyFlags.ENCRYPT_COMMS);

        pair = generator.generateKeyPair();
        pgpSubKey = new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDH, pair, new Date());

        pgpGenerator.addSubKey(pgpSubKey, subPackets.generate(), null);

        // Generate SecretKeyRing

        secretKeys = pgpGenerator.generateSecretKeyRing();

        publicKeys = pgpGenerator.generatePublicKeyRing();
        count = 0;
        for (Iterator it = publicKeys.getPublicKeys(); it.hasNext();)
        {
            it.next();
            count++;
        }
        isTrue(count == 3);

        checkPublicKeyRing(secretKeys, publicKeys.getEncoded());
        // Extract the public keys
        bOut = new ByteArrayOutputStream(2048);
        iterator = secretKeys.getPublicKeys();
        while (iterator.hasNext())
        {
            bOut.write(((PGPPublicKey)iterator.next()).getEncoded());
        }

        checkPublicKeyRing(secretKeys, bOut.toByteArray());

        isTrue(Arrays.areEqual(publicKeys.getEncoded(), bOut.toByteArray()));
    }

    private void checkPublicKeyRing(PGPSecretKeyRing secretKeys, byte[] encRing)
        throws IOException
    {
        Iterator<PGPPublicKey> iterator;PGPPublicKeyRing publicKeys = new PGPPublicKeyRing(encRing, new BcKeyFingerprintCalculator());

        // Check, if all public keys made it to the new public key ring
        iterator = secretKeys.getPublicKeys();
        while (iterator.hasNext())
        {
            isTrue(  publicKeys.getPublicKey( ((PGPPublicKey)iterator.next()).getKeyID()) != null);
        }
    }

    private void testDirectSigDatedKey()
        throws Exception
    {
        PGPObjectFactory factory = new PGPObjectFactory(new ByteArrayInputStream(datedKey), new JcaKeyFingerprintCalculator());
        PGPPublicKeyRing pkr = (PGPPublicKeyRing)factory.nextObject();
        PGPPublicKey publicKey = pkr.getPublicKey();

        long validSeconds = publicKey.getValidSeconds();

        isEquals(81129600L, validSeconds);
    }

    private void testApacheRings()
        throws Exception
    {
        byte[] data = Streams.readAll(this.getClass().getResourceAsStream("dsa-pubring.gpg"));
        
        isTrue(PGPUtil.isKeyBox(data));
        isTrue(!PGPUtil.isKeyRing(data));

        data = Streams.readAll(this.getClass().getResourceAsStream("rsa-pubring.gpg"));
        isTrue(!PGPUtil.isKeyBox(data));
        isTrue(PGPUtil.isKeyRing(data));
    }

    public void performTest()
        throws Exception
    {
        try
        {
            testExpiryDate();
            test1();
            test2();
            test3();
            test4();
            test5();
            test6();
            revocationTest();
            test8();
            test9();
            test10();
            test11();
            generateTest();
            generateSha1Test();
            rewrapTest();
            rewrapTestV3();
            rewrapTestMD5();
            testPublicKeyRingWithX509();
            testSecretKeyRingWithPersonalCertificate();
            insertMasterTest();
            testUmlaut();
            testBadUserID();
            testNoExportPrivateKey();
            shouldStripPreserveTrustPackets();
            testNullEncryption();
            testDirectSigDatedKey();
            testEdDsaRing();
            testCurve25519Ring();
            testShouldProduceSubkeys();
            testApacheRings();
        }
        catch (PGPException e)
        {
            if (((PGPException)e).getUnderlyingException() != null)
            {
                Exception ex = ((PGPException)e).getUnderlyingException();
                fail("exception: " + ex, ex);
            }
            else
            {
                fail("exception: " + e, e);
            }
        }
    }

    public String getName()
    {
        return "PGPKeyRingTest";
    }

    public static void main(
        String[]    args)
    throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPKeyRingTest());
    }
}
