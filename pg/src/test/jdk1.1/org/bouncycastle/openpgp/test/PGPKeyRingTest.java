package org.bouncycastle.openpgp.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class PGPKeyRingTest
    implements Test
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

    private boolean notEqual(
        byte[]    b1,
        byte[]    b2)
    {
        if (b1.length != b2.length)
        {
            return true;
        }
        
        for (int i = 0; i != b2.length; i++)
        {
            if (b1[i] != b2[i])
            {
                return true;
            }
        }
        
        return false;
    }
    
    public TestResult test1()
    {
        try
        {
            PGPPublicKeyRingCollection    pubRings = new PGPPublicKeyRingCollection(pub1);

            int                                        count = 0;

            Iterator    rIt = pubRings.getKeyRings();
            
            while (rIt.hasNext())
            {
                PGPPublicKeyRing                    pgpPub = (PGPPublicKeyRing)rIt.next();
                
                count++;
                
                int    keyCount = 0;
                
                byte[]    bytes = pgpPub.getEncoded();
                
                pgpPub = new PGPPublicKeyRing(bytes);
                
                Iterator    it = pgpPub.getPublicKeys();
                while (it.hasNext())
                {
                    keyCount++;

                    it.next();
                }
                
                if (keyCount != 2)
                {
                    return new SimpleTestResult(false, getName() + ": wrong number of public keys");
                }
            }
            
            if (count != 1)
            {
                return new SimpleTestResult(false, getName() + ": wrong number of public keyrings");
            }
            
            PGPSecretKeyRingCollection    secretRings = new PGPSecretKeyRingCollection(sec1);

            rIt = secretRings.getKeyRings();
            count = 0;
            
            while (rIt.hasNext())
            {
                PGPSecretKeyRing                    pgpSec = (PGPSecretKeyRing)rIt.next();
        
                count++;
                
                int    keyCount = 0;
                
                byte[]    bytes = pgpSec.getEncoded();
                
                pgpSec = new PGPSecretKeyRing(bytes);
                
                Iterator    it = pgpSec.getSecretKeys();
                while (it.hasNext())
                {
                    keyCount++;

                    PGPSecretKey    k = (PGPSecretKey)it.next();
                    PGPPublicKey    pk = k.getPublicKey();
                    
                    byte[] pkBytes = pk.getEncoded();
                    
                    PGPPublicKeyRing  pkR = new PGPPublicKeyRing(pkBytes);
                }
                
                if (keyCount != 2)
                {
                    return new SimpleTestResult(false, getName() + ": wrong number of secret keys");
                }
            }
            
            if (count != 1)
            {
                return new SimpleTestResult(false, getName() + ": wrong number of secret keyrings");
            }
            
            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            if (e instanceof PGPException)
            {
                if (((PGPException)e).getUnderlyingException() != null)
                {
                    ((PGPException)e).getUnderlyingException().printStackTrace();
                }
            }
            else
            {
                e.printStackTrace();
            }
            return new SimpleTestResult(false, getName() + ": exception - " + e.toString());
        }
    }
    
    public TestResult test2()
    {
        try
        {
            PGPPublicKeyRingCollection    pubRings = new PGPPublicKeyRingCollection(pub2);

            int                                        count = 0;

            byte[]    encRing = pubRings.getEncoded();

            pubRings = new PGPPublicKeyRingCollection(encRing);
            
            Iterator    rIt = pubRings.getKeyRings();
            
            while (rIt.hasNext())
            {
                PGPPublicKeyRing                    pgpPub = (PGPPublicKeyRing)rIt.next();
                
                count++;
                
                int    keyCount = 0;
                
                byte[]    bytes = pgpPub.getEncoded();
                
                pgpPub = new PGPPublicKeyRing(bytes);
                
                Iterator    it = pgpPub.getPublicKeys();
                while (it.hasNext())
                {
                    PGPPublicKey    pk = (PGPPublicKey)it.next();
                    
                    byte[] pkBytes = pk.getEncoded();
                    
                    PGPPublicKeyRing  pkR = new PGPPublicKeyRing(pkBytes);
                    
                    keyCount++;
                }
                
                if (keyCount != 2)
                {
                    return new SimpleTestResult(false, getName() + ": wrong number of public keys");
                }
            }
            
            if (count != 2)
            {
                return new SimpleTestResult(false, getName() + ": wrong number of public keyrings");
            }
            
            PGPSecretKeyRingCollection    secretRings = new PGPSecretKeyRingCollection(sec2);

            rIt = secretRings.getKeyRings();
            count = 0;
            
            encRing = secretRings.getEncoded();
            
            secretRings = new PGPSecretKeyRingCollection(encRing);
            
            while (rIt.hasNext())
            {
                PGPSecretKeyRing                    pgpSec = (PGPSecretKeyRing)rIt.next();
        
                count++;
                
                int    keyCount = 0;
                
                byte[]    bytes = pgpSec.getEncoded();
                
                pgpSec = new PGPSecretKeyRing(bytes);
                
                Iterator    it = pgpSec.getSecretKeys();
                while (it.hasNext())
                {
                    keyCount++;

                    PGPSecretKey    k = (PGPSecretKey)it.next();
                    PGPPublicKey    pk = k.getPublicKey();
                    
                    byte[] pkBytes = pk.getEncoded();
                    
                    PGPPublicKeyRing  pkR = new PGPPublicKeyRing(pkBytes);
                    
                    if (k.getKeyID() == -4049084404703773049L
                         || k.getKeyID() == -1413891222336124627L)
                    {
                        k.extractPrivateKey(sec2pass1, "BC");
                    }
                    else if (k.getKeyID() == -6498553574938125416L
                        || k.getKeyID() == 59034765524361024L)
                    {
                        k.extractPrivateKey(sec2pass2, "BC");
                    }
                }
                
                if (keyCount != 2)
                {
                    return new SimpleTestResult(false, getName() + ": wrong number of secret keys");
                }
            }
            
            if (count != 2)
            {
                return new SimpleTestResult(false, getName() + ": wrong number of secret keyrings");
            }
            
            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            if (e instanceof PGPException)
            {
                if (((PGPException)e).getUnderlyingException() != null)
                {
                    ((PGPException)e).getUnderlyingException().printStackTrace();
                }
            }
            else
            {
                e.printStackTrace();
            }
            return new SimpleTestResult(false, getName() + ": exception - "+ e);
        }
    }
    
    public TestResult test3()
    {
        try
        {
            PGPPublicKeyRingCollection    pubRings = new PGPPublicKeyRingCollection(pub3);

            int                                        count = 0;

            byte[]    encRing = pubRings.getEncoded();

            pubRings = new PGPPublicKeyRingCollection(encRing);
            
            Iterator    rIt = pubRings.getKeyRings();
            
            while (rIt.hasNext())
            {
                PGPPublicKeyRing                    pgpPub = (PGPPublicKeyRing)rIt.next();
                
                count++;
                
                int    keyCount = 0;
                
                byte[]    bytes = pgpPub.getEncoded();
                
                pgpPub = new PGPPublicKeyRing(bytes);
                
                Iterator    it = pgpPub.getPublicKeys();
                while (it.hasNext())
                {
                    keyCount++;

                    it.next();
                }
                
                if (keyCount != 2)
                {
                    return new SimpleTestResult(false, getName() + ": wrong number of public keys");
                }
            }
            
            if (count != 1)
            {
                return new SimpleTestResult(false, getName() + ": wrong number of public keyrings");
            }
            
            PGPSecretKeyRingCollection    secretRings = new PGPSecretKeyRingCollection(sec3);

            rIt = secretRings.getKeyRings();
            count = 0;
            
            encRing = secretRings.getEncoded();
            
            secretRings = new PGPSecretKeyRingCollection(encRing);
            
            while (rIt.hasNext())
            {
                PGPSecretKeyRing                    pgpSec = (PGPSecretKeyRing)rIt.next();
        
                count++;
                
                int    keyCount = 0;
                
                byte[]    bytes = pgpSec.getEncoded();
                
                pgpSec = new PGPSecretKeyRing(bytes);
                
                Iterator    it = pgpSec.getSecretKeys();
                while (it.hasNext())
                {
                    keyCount++;

                    PGPSecretKey    k = (PGPSecretKey)it.next();

                    k.extractPrivateKey(sec3pass1, "BC");
                }
                
                if (keyCount != 2)
                {
                    return new SimpleTestResult(false, getName() + ": wrong number of secret keys");
                }
            }
            
            if (count != 1)
            {
                return new SimpleTestResult(false, getName() + ": wrong number of secret keyrings");
            }
            
            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            if (e instanceof PGPException)
            {
                if (((PGPException)e).getUnderlyingException() != null)
                {
                    ((PGPException)e).getUnderlyingException().printStackTrace();
                }
            }
            return new SimpleTestResult(false, getName() + ": exception - " + e.toString());
        }
    }
    
    public TestResult test4()
    {
        try
        {
            PGPSecretKeyRingCollection    secretRings = new PGPSecretKeyRingCollection(sec4);

            Iterator    rIt = secretRings.getKeyRings();
            int            count = 0;
            
            byte[]    encRing = secretRings.getEncoded();
            
            secretRings = new PGPSecretKeyRingCollection(encRing);
            
            while (rIt.hasNext())
            {
                PGPSecretKeyRing                    pgpSec = (PGPSecretKeyRing)rIt.next();
        
                count++;
                
                int    keyCount = 0;
                
                byte[]    bytes = pgpSec.getEncoded();
                
                pgpSec = new PGPSecretKeyRing(bytes);
                
                Iterator    it = pgpSec.getSecretKeys();
                while (it.hasNext())
                {
                    keyCount++;

                    PGPSecretKey    k = (PGPSecretKey)it.next();

                    k.extractPrivateKey(sec3pass1, "BC");
                }
                
                if (keyCount != 2)
                {
                    return new SimpleTestResult(false, getName() + ": wrong number of secret keys");
                }
            }
            
            if (count != 1)
            {
                return new SimpleTestResult(false, getName() + ": wrong number of secret keyrings");
            }
            
            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            if (e instanceof PGPException)
            {
                if (((PGPException)e).getUnderlyingException() != null)
                {
                    ((PGPException)e).getUnderlyingException().printStackTrace();
                }
            }
            return new SimpleTestResult(false, getName() + ": exception - " + e.toString());
        }
    }

    public TestResult test5()
    {
        try
        {
            PGPPublicKeyRingCollection    pubRings = new PGPPublicKeyRingCollection(pub5);

            int                                        count = 0;

            byte[]    encRing = pubRings.getEncoded();

            pubRings = new PGPPublicKeyRingCollection(encRing);
            
            Iterator    rIt = pubRings.getKeyRings();
            
            while (rIt.hasNext())
            {
                PGPPublicKeyRing                    pgpPub = (PGPPublicKeyRing)rIt.next();
                
                count++;
                
                int    keyCount = 0;
                
                byte[]    bytes = pgpPub.getEncoded();
                
                pgpPub = new PGPPublicKeyRing(bytes);
                
                Iterator    it = pgpPub.getPublicKeys();
                while (it.hasNext())
                {
                    keyCount++;

                    it.next();
                }
                
                if (keyCount != 2)
                {
                    return new SimpleTestResult(false, getName() + ": wrong number of public keys");
                }
            }
            
            if (count != 1)
            {
                return new SimpleTestResult(false, getName() + ": wrong number of public keyrings");
            }
            
            PGPSecretKeyRingCollection    secretRings = new PGPSecretKeyRingCollection(sec5);

            rIt = secretRings.getKeyRings();
            count = 0;
            
            encRing = secretRings.getEncoded();
            
            secretRings = new PGPSecretKeyRingCollection(encRing);
            
            while (rIt.hasNext())
            {
                PGPSecretKeyRing                    pgpSec = (PGPSecretKeyRing)rIt.next();
        
                count++;
                
                int    keyCount = 0;
                
                byte[]    bytes = pgpSec.getEncoded();
                
                pgpSec = new PGPSecretKeyRing(bytes);
                
                Iterator    it = pgpSec.getSecretKeys();
                while (it.hasNext())
                {
                    keyCount++;

                    PGPSecretKey    k = (PGPSecretKey)it.next();

                    k.extractPrivateKey(sec5pass1, "BC");
                }
                
                if (keyCount != 2)
                {
                    return new SimpleTestResult(false, getName() + ": wrong number of secret keys");
                }
            }
            
            if (count != 1)
            {
                return new SimpleTestResult(false, getName() + ": wrong number of secret keyrings");
            }
            
            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            if (e instanceof PGPException)
            {
                if (((PGPException)e).getUnderlyingException() != null)
                {
                    ((PGPException)e).getUnderlyingException().printStackTrace();
                }
            }
            return new SimpleTestResult(false, getName() + ": exception - " + e.toString());
        }
    }
    
    public TestResult perform()
    {
        TestResult    res = test1();
        if (!res.isSuccessful())
        {
            return res;
        }
 
        res = test2();
        if (!res.isSuccessful())
        {
            return res;
        }
 
        res = test3();
        if (!res.isSuccessful())
        {
            return res;
        }
        
        res = test4();
        if (!res.isSuccessful())
        {
            return res;
        }

        res = test5();
        if (!res.isSuccessful())
        {
            return res;
        }
        
         return res;
    }

    public String getName()
    {
        return "PGPKeyRingTest";
    }

    public static void main(
        String[]    args)
    {
        Test            test = new PGPKeyRingTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
