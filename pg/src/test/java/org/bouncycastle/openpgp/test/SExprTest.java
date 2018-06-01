package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.security.Security;

import org.bouncycastle.gpg.SExprParser;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEProtectionRemoverFactory;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class SExprTest
    extends SimpleTest
{
    byte[] key1 = Base64.decode(
        "KDIxOnByb3RlY3RlZC1wcml2YXRlLWtleSgzOnJzYSgxOm4yNTc6AOpclatE"
        + "WCIXSUA2y44L/jPGE1lU3d75nMN5+iJK/vXFGmQdvZWhewX2LSJ5vwpcLcQ1"
        + "u3QXRbOcY0o+jRAER2vHZMEfyHfHir6QDibVTO5IOjLettW054hew/HoFbA2"
        + "v3t0BB2HERWMFO6WLrC7wBVpgL85m85VhE/OmZGIOY7bapQtULoTQQ5Fwr0n"
        + "+zG3gujxDcmpcTouz0DPtVLvMERnHMtJ4GEccWfiFrGUnLbBnYCnnsNoV/0m"
        + "f/GseRltCnxPS2Fl+rhdkPmxC0Dkv6naV+NMiaZVk5FYdtY66xATvETv+xTa"
        + "X8xHIhJc4CrR/e4T0VPBh/94o5nHL1cT6HcpKDE6ZTM6AQABKSg5OnByb3Rl"
        + "Y3RlZDI1Om9wZW5wZ3AtczJrMy1zaGExLWFlcy1jYmMoKDQ6c2hhMTg6vqXu"
        + "vvqQtUw4OjI3OTYxMzQ0KTE2OlYbNG/073BvJLzSjbvoxQYpNzM2OkcNABDe"
        + "gU7iUAJwVxNszEG+ackC6qk7Y+dQ6NN4Avy9pkGo+Rufs0G4yjHhVQMkH0QF"
        + "Wrzf5GOvsvrJQyJGVLn2amz5KxU+onNv66UVi4D3LlCOghDcGoe/V7hY+zsh"
        + "GN7elPhnBYbk7X1Jb5D03YrCOOCTnGLTLMc7E5qy4YSyRWMzAGGj/jkcY/B+"
        + "ZEeLkTlHsnnukIMb24+1/sZrsV57AaVPRZwgzInxDGC9Tkg4j6fsHvvVw6ZD"
        + "cm+ET/YGOf1dhMKEq/7GXcd5qeEpMBFi+6p2PrPJUwUHu/PIOs1SCIYlrhGR"
        + "iifAHtOIdFGefo+E1v6kKZMO+FgLTeiGYN6T6vjkG7FMiWwnmamF6qNd1D5i"
        + "TS2E4uiS5Z3QuwyXJfGkYYDjEmV5rVSol95Kd4wpebC7mFNbOk+zA4TB5Ytb"
        + "5KN/w2lSW4btuB/pD/akfg6xJQ9BREv1vpO4CtK+d8VLCPHI7et1tKjwJNxd"
        + "obw9P4HOBIPYdzbHARpAfZRLQlLRNcYp8DbHfzmDhIEPymO6+3CCtdfRE7xY"
        + "c0SMpFFYGX17WGlmjdOYWtbqYrhDQ3ylzD3vrIQr12ZZXw00xSJkNk4aJ8Lx"
        + "SihOXTuLiHhueckfCCbkWPfdJQg1ukjRiNgHdEF+7rk/2aMDsSYULJqtjSed"
        + "CDi9tLqawmCz405E+W+Htbrp2yv7ktST2IaV56JQB4Yay8WAlnngoBtdlSyA"
        + "wFVFm5VrCeZ5ckdUfK1qSezd32uQlb27XCZYGiaco5AWkhBOrdPoiw4Z14Pf"
        + "z6xhhV+vA+X6lm9k70iG7RO9vf3V+EAbKktFos72rGJGhWOZgv5xr8DRjbIf"
        + "/dOQsgceYg4xrTzn/SjOSNmTQu++Q1Uo5jjtMozgXawJNFPKcZ28DLTxdHQl"
        + "a7jZK/FiiXXBL8J/VbN9DWZq7IOUMEhRym8KcAoyC7wQgpua2qhp8EXX7Qqd"
        + "7dU4EcdWzzz/lF8pKDEyOnByb3RlY3RlZC1hdDE1OjIwMTgwNTI4VDAyMjIw"
        + "MikpKQ==");

    byte[] key2 = Base64.decode(
        "KDIxOnByb3RlY3RlZC1wcml2YXRlLWtleSgzOnJzYSgxOm4yNTc6AOsNQU9o"
      + "sprkIIpmBTBTGHHDeXEZEL8UF4feaFUa9hsqdTIzX9aEaBAu3SJ3Zgzi8dMh"
      + "ixPsTQuAoDoUa7DxTdOD8wLgk18+X5gep3Gqs6wl5xwhr2gQ9tOJMJrHd2yl"
      + "r8VBehPXKC1lc5kNClGtufjfQ+0WI56lHSh9DW1jyLGSkq8pRBZPZnaXC51q"
      + "kS1wfrg5II9qqhmaxWTHAe7VIss/vQac2E6s/ITUSXxy7MtAJ0I3fGdqtAS0"
      + "QXPRgyJt0ooGeGjAosyiiR8PmPf2Q0lNNfffyqu0ebTXXTakLHiVomt+VAR2"
      + "0tgsiJ3t8wg6j38R/NLOWOGVGPQfpDI3p08pKDE6ZTM6AQABKSg5OnByb3Rl"
      + "Y3RlZDI1Om9wZW5wZ3AtczJrMy1zaGExLWFlcy1jYmMoKDQ6c2hhMTg6cmsV"
      + "l8pPyBQ4OjI3OTYxMzQ0KTE2OnEddL6BwQQT+ZoWsHy9GFwpNzIwOpMFSLTw"
      + "29ytDZsiyzVWHj/3gI7bhRtORyko6NEOQKdG8n1wHXfYxre1uiCjYW8jdYUO"
      + "lcZEBKWDM4lVQeHzoF6cVbQNYy9UGY+El2d0WT92c8cmucmPKDizv9TqVY89"
      + "QZTa7A/m0UmPd57b3XhkwkJvt5mOnmpyFXabtiNV1YrRUdpyeiyDwyqkHvZZ"
      + "8lNixSvE2tTSuN5/xU76oFmN3JKCxw9q0WOc/gvtG31gkR7/HfvgmyZWyFjK"
      + "O0vCIA0XANwFjt14umPFVGSDxNXBy3hyHHeiQJOCsBWmB1TyWSmYY7Fc2zYL"
      + "oiPcBwmYvcfywAL7zFwYie9IteEx10eEHl76/iVI2qX5mUmJlzkzRlcdW2B6"
      + "bjeUxP2/oPQ3XyJafW3NZ4eEvJNdJ5486Gq9uBQ4Du1yhrWzFkV9fYoI42l0"
      + "Vr8oDzX66l0GJj8mZOjI7iX0IdGL5dOQyOldwv/19x3w38RnTqG/y4/hU1s3"
      + "bSuXxZz6+8AgKfxIOkNFm9KLkP1Y7pfxujy6StzYhdsPLwNsBXDEMogCt9dW"
      + "GNERw6urHjKuU7FyzDbq6eUjnaVjyoNwpfdodb4xGnyLgEPBqFNzQko/kvfQ"
      + "JncxVXz/d008qzAvb3nYqRcJJoi4wCMg+f4LA9cIqtE9UWn5NMcMIQnT+IHI"
      + "zYZmZx3J9TKksFGzyK+MpIWbyTGRBEMJVW1NadI7hX6hz0jIjRkXCwCJUi8p"
      + "E1aCHgsAeE7O7KPsLVPyaKL1fZHgMYPkNvP5bh8qTWRxjn0AjKbfm0q3exT/"
      + "R5fBChM2FWB2fY2euUfD7f1zRbiazDpPN3REDhbzF9fE8Yn8OGrmJ3OFooES"
      + "uzIhUG83CtlE1N41lSw/TFoWQmePw57XkdIGiiSAKbuQB7rMlDJ6eHFCCBFt"
      + "aUy2CI2eyCdx2IIENDwe3fd+lNNgkDKXFBtWYP9OQ4MESZuL7HC4ZikoMTI6"
      + "cHJvdGVjdGVkLWF0MTU6MjAxODA1MjhUMDIyMjAyKSkp");

    byte[] key3 =
        Base64.decode(
            "KDIxOnByb3RlY3RlZC1wcml2YXRlLWtleSgzOmVjYyg1OmN1cnZlMTU6YnJh"
                + "aW5wb29sUDM4NHIxKSgxOnE5NzoEi29XCqkugtlRvONnpAVMQgfecL+Gk86O"
                + "t8LnUizfHG2TqRrtqlMg1DdU8Z8dJWmhJG84IUOURCyjt8nE4BeeCfRIbTU5"
                + "7CB13OqveBdNIRfK45UQnxHLO2MPVXf4GMdtKSg5OnByb3RlY3RlZDI1Om9w"
                + "ZW5wZ3AtczJrMy1zaGExLWFlcy1jYmMoKDQ6c2hhMTg6itLEzGV4Cfg4OjEy"
                + "OTA1NDcyKTE2OgxmufENKFTZUB72+X7AwkgpMTEyOvMWNLZgaGdlTN8XCxa6"
                + "8ia0Xqqb9RvHgTh+iBf0RgY5Tx5hqO9fHOi76LTBMfxs9VC4f1rTketjEUKR"
                + "f5amKb8lrJ67kKEsny4oRtP9ejkNzcvHFqRdxmHyL10ui8M8rJN9OU8ArqWf"
                + "g22dTcKu02cpKDEyOnByb3RlY3RlZC1hdDE1OjIwMTQwNjA4VDE2MDg1MCkp"
                + "KQ==");

    public String getName()
    {
        return "SExprTest";
    }

    public void performTest()
        throws Exception
    {
        SExprParser parser = new SExprParser(new JcaPGPDigestCalculatorProviderBuilder().build());

        PGPSecretKey k1 = parser.parseSecretKey(new ByteArrayInputStream(key1), new JcePBEProtectionRemoverFactory("fred".toCharArray()), new JcaKeyFingerprintCalculator());
        PGPSecretKey k2 = parser.parseSecretKey(new ByteArrayInputStream(key2), new JcePBEProtectionRemoverFactory("fred".toCharArray()), new JcaKeyFingerprintCalculator());
        PGPSecretKey k3 = parser.parseSecretKey(new ByteArrayInputStream(key3), new JcePBEProtectionRemoverFactory("test".toCharArray()), new JcaKeyFingerprintCalculator());
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new SExprTest());
    }
}
