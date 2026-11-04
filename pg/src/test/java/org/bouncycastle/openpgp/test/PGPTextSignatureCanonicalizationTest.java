package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.OpenPGPTestKeys;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPContentSigner;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.TeeOutputStream;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Canonical text form of text signatures (type 0x01), github #2553: a LF not preceded by a CR is
 * hashed as CR LF and every other byte, a bare CR included, is hashed unaltered. Releases before
 * 1.87 hashed a bare CR as CR LF; that form is still accepted on verification unless
 * {@link Properties#OPENPGP_TEXT_SIG_ALLOW_LEGACY_CR} is set to false.
 */
public class PGPTextSignatureCanonicalizationTest
    extends SimpleTest
{
    /*
     * Signatures made with the draft-bre-openpgp-samples-00 "Alice" key
     * (OpenPGPTestKeys.ALICE_KEY), taken from the OpenPGP interoperability test suite,
     * https://sequoia-pgp.gitlab.io/openpgp-interoperability-test-suite/detached_signatures.html
     * (run of 2026-11-04), tests "Detached text-mode Sign-Verify roundtrip with bare CR character"
     * (message "a\ra") and "... with trailing bare CR character" (message "a\r").
     *
     * rpgpie, GopenPGP, OpenPGP.js and GnuPG hash a bare CR unaltered; Sequoia and PGPainless
     * (BC before 1.87) hash it as CR LF.
     */
    private static final String SEQUOIA_BARE_CR =
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "wr0EARYKAG8FgmrrSb4JEPIxVQxPR+OORxQAAAAAAB4AIHNhbHRAbm90YXRpb25z\n" +
        "LnNlcXVvaWEtcGdwLm9yZ9wJPVs6Jih71UYcp7edDZkhmJ3Oia84H8p6lhK2Gpzp\n" +
        "FiEE64W7X6M6deFelE5j8jFVDE9H444AAO4dAQCTIsRZWemv1zmPbqGsl/ZERhbH\n" +
        "gfG2+wiTHuTfMxhvzgD9FNYwfnR0RgavrXeInlyyfKi9ESD4xRsUMv4cndeIEwc=\n" +
        "=+Gdc\n" +
        "-----END PGP SIGNATURE-----\n";

    private static final String RPGPIE_BARE_CR =
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "wnUEARYIAB0WIQTrhbtfozp14V6UTmPyMVUMT0fjjgWCautJwwAKCRDyMVUMT0fj\n" +
        "jmKJAP4ijSNHuHD37649qGQtFxWdvOY7I62yOlEJreeIYfeBsQEA16gGP5K+YCiX\n" +
        "GPknJ9NvOzK3kHFx9zBx7aZeiYMhxgQ=\n" +
        "=OFgK\n" +
        "-----END PGP SIGNATURE-----\n";

    private static final String GOPENPGP_BARE_CR =
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "wqsEARYIAF0FgmrrScsJEPIxVQxPR+OONRQAAAAAABwAEHNhbHRAbm90YXRpb25z\n" +
        "Lm9wZW5wZ3Bqcy5vcmdyotAnyv685c7/RXunPj8IFiEE64W7X6M6deFelE5j8jFV\n" +
        "DE9H444AAAxmAQDPid6vGBxG9GksKVQERQr85MupCcDpFA2/UlW6GLX47gD+KVGL\n" +
        "lNrUXXSgnOT+AyrLfqlVFTUJWcfRnvvcoEipUgk=\n" +
        "=bs2/\n" +
        "-----END PGP SIGNATURE-----\n";

    private static final String OPENPGPJS_BARE_CR =
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "wrsEARYKAG0FgmrrSdMJEPIxVQxPR+OORRQAAAAAABwAIHNhbHRAbm90YXRp\n" +
        "b25zLm9wZW5wZ3Bqcy5vcmcNrM+imeZC0cQUfQ1t49vbS6hyWW1zdsnY1+k0\n" +
        "z2S3+BYhBOuFu1+jOnXhXpROY/IxVQxPR+OOAAAxOgEA/yFNUDZCU8B6ip4H\n" +
        "M7NDB5ABS7tPhQPhcY72dXE967IBAPNsl3G3hEWaTGcSMnwobdE+56URsnAT\n" +
        "4FMen20Yv3kN\n" +
        "=qdzZ\n" +
        "-----END PGP SIGNATURE-----\n";

    private static final String PGPAINLESS_BARE_CR =
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "wnUEARYKACcFgmrrSdkJEPIxVQxPR+OOFqEE64W7X6M6deFelE5j8jFVDE9H444A\n" +
        "AF/NAQDv99ma8/5Gpml/xmHaLnhHGiOGFUyogkPIZ6iIPmbRmAD8DQFXYbnd/unS\n" +
        "qS7m9JTYqbRb8JiV8QVed3fUVdPWUgc=\n" +
        "=CbvI\n" +
        "-----END PGP SIGNATURE-----\n";

    private static final String GNUPG_BARE_CR =
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "iHUEARYKAB0WIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCautJ4wAKCRDyMVUMT0fj\n" +
        "jkX6APwIjuOkio8H9xCowt6s4wBrnIYqHkEqZcgWwT/Gjv5AGAD/flf5LzC3NXFi\n" +
        "x56yFfPE8Cgzwj1YMM+DMDOe8s5AVQM=\n" +
        "=3vXA\n" +
        "-----END PGP SIGNATURE-----\n";

    private static final String SEQUOIA_TRAILING_CR =
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "wr0EARYKAG8FgmrrSe0JEPIxVQxPR+OORxQAAAAAAB4AIHNhbHRAbm90YXRpb25z\n" +
        "LnNlcXVvaWEtcGdwLm9yZw+jhY/4BEUZV5s9rJgsIPCchCYY7Aj6031o+Bv1aFdM\n" +
        "FiEE64W7X6M6deFelE5j8jFVDE9H444AADhaAQCiz/I5qEs1r8yux+1A++UTBtet\n" +
        "o6ZXXwmXj0rhJFdqTQD+IhB+m28S8YBRChBkxs1PDyEMW57FV6NTQr5KUSAziwk=\n" +
        "=LyCn\n" +
        "-----END PGP SIGNATURE-----\n";

    private static final String RPGPIE_TRAILING_CR =
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "wnUEARYIAB0WIQTrhbtfozp14V6UTmPyMVUMT0fjjgWCautJ8wAKCRDyMVUMT0fj\n" +
        "jm55AP4shBQu4YShIQVMFOqdg46ELw4XdHohkZVtTmsfutk9sgD/ewiy4Th4rnVo\n" +
        "/yCCQR2V6sFhpoMtBQhVgCg2Y2L1WwE=\n" +
        "=TMAv\n" +
        "-----END PGP SIGNATURE-----\n";

    private static final String GOPENPGP_TRAILING_CR =
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "wqsEARYIAF0FgmrrSf0JEPIxVQxPR+OONRQAAAAAABwAEHNhbHRAbm90YXRpb25z\n" +
        "Lm9wZW5wZ3Bqcy5vcmex9kajnmHZZ3D/6/mG0GUuFiEE64W7X6M6deFelE5j8jFV\n" +
        "DE9H444AAIduAPwNoSJ8AMovWTxFDQxnbof8itkRMIlidVfAN/jnD2o/HgD+MTZp\n" +
        "qwYcpm88RJxL8sOlkWTb4r/+pQCxKtXK2PKgOQk=\n" +
        "=eUcb\n" +
        "-----END PGP SIGNATURE-----\n";

    private static final String OPENPGPJS_TRAILING_CR =
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "wrsEARYKAG0FgmrrSgcJEPIxVQxPR+OORRQAAAAAABwAIHNhbHRAbm90YXRp\n" +
        "b25zLm9wZW5wZ3Bqcy5vcmc2LOHGvRWyeUwfr12l5wzrZwRB48oEK7g/r19G\n" +
        "R6pScBYhBOuFu1+jOnXhXpROY/IxVQxPR+OOAAADmQEAq/ZDQmNcP0w6PqLo\n" +
        "76VgGXAtUGwl04KSXrMEIykDZrIA/1AjxnkrRNvv78UAGcH2YAuLEXOZFDpp\n" +
        "Ci3bYuTvdpUF\n" +
        "=Cnmo\n" +
        "-----END PGP SIGNATURE-----\n";

    private static final String PGPAINLESS_TRAILING_CR =
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "wnUEARYKACcFgmrrSg8JEPIxVQxPR+OOFqEE64W7X6M6deFelE5j8jFVDE9H444A\n" +
        "AECrAQDExqCSn4XiC0hpJhccUisTtbuL6K8kZHNStffldy7ryAD/VPOj/exSkNJ4\n" +
        "dLrWthUxodbR6gnSD/8QjahAixVoYw0=\n" +
        "=yrMP\n" +
        "-----END PGP SIGNATURE-----\n";

    private static final String GNUPG_TRAILING_CR =
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "iHUEARYKAB0WIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCautKGgAKCRDyMVUMT0fj\n" +
        "jocoAQCUOXeBRWssajUN0K6IFlJSZZ0Hs2qmK1tXcILtLsY6wAEA+W/9nVl0MnvP\n" +
        "O9gXfhPGFxXPLpAwmp89Can49XzPhgM=\n" +
        "=tbU2\n" +
        "-----END PGP SIGNATURE-----\n";

    /*
     * gpg (GnuPG) 2.4.4, Alice's key, "gpg --textmode --detach-sign" over GPG244_DOCS[i].
     */
    private static final String[] GPG244_DOCS = { "a\ra", "a\r", "a\r\na", "a\na", "a\r\ra\n", "\r\n\n\r", "a\r\r\na" };

    private static final String GPG244_1 =
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "iHUEARYKAB0WIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCauseQAAKCRDyMVUMT0fj\n" +
        "jvjEAPkBR6rMxTvLHTVcDYbJ82VhOtX+VG5swfcnZ8g36lOi8QEAkL25kI22vQK6\n" +
        "p6cCET4ehiGgQJXjkhTRmbVfTTyG3wA=\n" +
        "=VTrq\n" +
        "-----END PGP SIGNATURE-----\n";

    private static final String GPG244_2 =
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "iHUEARYKAB0WIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCauseQAAKCRDyMVUMT0fj\n" +
        "jgveAP4nJFmoK8m7C2YA0G49rwZKksY/y+S4ypPN+ytyHbuw/gEAwYmodZv7pBuD\n" +
        "MOfuyXgy5llYYyzK86HbqCgUXvRuMwI=\n" +
        "=5eFu\n" +
        "-----END PGP SIGNATURE-----\n";

    private static final String GPG244_3 =
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "iHUEARYKAB0WIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCauseQAAKCRDyMVUMT0fj\n" +
        "jo2TAP9lDyFpVjHFUGNvteHsRaicLETtwq9Yl6Kw+DvYea9fHAEAh1RB1zts0HGF\n" +
        "KS7rAGY4/YJiMW6/lLYF2BQpZsM6MgE=\n" +
        "=Jtec\n" +
        "-----END PGP SIGNATURE-----\n";

    private static final String GPG244_4 =
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "iHUEARYKAB0WIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCauseQAAKCRDyMVUMT0fj\n" +
        "jo2TAP9lDyFpVjHFUGNvteHsRaicLETtwq9Yl6Kw+DvYea9fHAEAh1RB1zts0HGF\n" +
        "KS7rAGY4/YJiMW6/lLYF2BQpZsM6MgE=\n" +
        "=Jtec\n" +
        "-----END PGP SIGNATURE-----\n";

    private static final String GPG244_5 =
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "iHUEARYKAB0WIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCauseQAAKCRDyMVUMT0fj\n" +
        "jnrmAQDKfoEobowhvFapWSyr77+RUmWpFfLQVE0pMduCbaPhzgEApPhsgiaC0E/a\n" +
        "3ObHT/9eR9QrPJn3x4mGN5V1jGbvswk=\n" +
        "=Wr8B\n" +
        "-----END PGP SIGNATURE-----\n";

    private static final String GPG244_6 =
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "iHUEARYKAB0WIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCauseQAAKCRDyMVUMT0fj\n" +
        "jhF1AQCTTk5hghEMYmkFxWIhaf/98luRNnnOCpQoRGLlQunb0gD8DyTgm7aAx/x5\n" +
        "inKfu8hJQvFxrDe0g83eo6ybH4mFZQ8=\n" +
        "=AsKt\n" +
        "-----END PGP SIGNATURE-----\n";

    private static final String GPG244_7 =
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "iHUEARYKAB0WIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCauseQAAKCRDyMVUMT0fj\n" +
        "jo2TAP9lDyFpVjHFUGNvteHsRaicLETtwq9Yl6Kw+DvYea9fHAEAh1RB1zts0HGF\n" +
        "KS7rAGY4/YJiMW6/lLYF2BQpZsM6MgE=\n" +
        "=Jtec\n" +
        "-----END PGP SIGNATURE-----\n";

    private static final String[] GPG244_SIGS = { GPG244_1, GPG244_2, GPG244_3, GPG244_4, GPG244_5, GPG244_6, GPG244_7 };

    /*
     * GnuPG drops any CRs immediately before a LF or the end of the data before hashing a text
     * signature ("a\r\r\na" is hashed as "a\r\na", "a\r" as "a"), which neither RFC 9580 nor
     * the other implementations in the interoperability suite do, so those of its signatures do
     * not verify here, before or after github #2553. A bare CR elsewhere it hashes unaltered.
     */
    private static final boolean[] GPG244_VERIFIES = { true, false, true, true, true, false, false };

    private static final String LEGACY = Properties.OPENPGP_TEXT_SIG_ALLOW_LEGACY_CR;

    private PGPPublicKey aliceKey;
    private PGPPrivateKey alicePriv;
    private PGPPublicKey v6Key;
    private PGPPrivateKey v6Priv;

    public String getName()
    {
        return "PGPTextSignatureCanonicalizationTest";
    }

    public void performTest()
        throws Exception
    {
        PGPSecretKey alice = OpenPGPTestKeys.readPGPSecretKeyRing(OpenPGPTestKeys.ALICE_KEY).getSecretKey();
        aliceKey = alice.getPublicKey();
        alicePriv = alice.extractPrivateKey(null);

        PGPSecretKeyRing v6Ring = OpenPGPTestKeys.readPGPSecretKeyRing(OpenPGPTestKeys.V6_KEY);
        v6Key = v6Ring.getSecretKey().getPublicKey();
        v6Priv = v6Ring.getSecretKey().extractPrivateKey(null);

        testCanonicalForm();
        testRoundTrip(aliceKey, alicePriv);
        testRoundTrip(v6Key, v6Priv);
        testOtherImplementations();
        testGnuPG244();
        testLegacyForm(aliceKey, alicePriv);
        testLegacyForm(v6Key, v6Priv);
        testLegacyOnePassSignature(aliceKey, alicePriv);
        testLegacyOnePassSignature(v6Key, v6Priv);
        testFallbackScope();
        testBinaryUnaffected();
    }

    /*
     * The bytes a text signature actually hashes, captured from the content signer, for whole,
     * split and byte-at-a-time input.
     */
    private void testCanonicalForm()
        throws Exception
    {
        checkCanonical("a\ra", "a\ra");
        checkCanonical("a\r", "a\r");
        checkCanonical("\r", "\r");
        checkCanonical("\r\r", "\r\r");
        checkCanonical("a\r\na", "a\r\na");
        checkCanonical("a\na", "a\r\na");
        checkCanonical("a\n", "a\r\n");
        checkCanonical("\n\n", "\r\n\r\n");
        checkCanonical("a\r\ra\n", "a\r\ra\r\n");
        checkCanonical("\r\n\n\r", "\r\n\r\n\r");
        checkCanonical("a\n\rb", "a\r\n\rb");
        checkCanonical("", "");

        // CR LF split across update() calls is still one line ending
        checkCanonical(new String[]{ "a\r", "\na" }, "a\r\na");
        checkCanonical(new String[]{ "a\r", "", "\na" }, "a\r\na");
        // a CR at the end of one update() and something else at the start of the next stays bare
        checkCanonical(new String[]{ "a\r", "a" }, "a\ra");
        checkCanonical(new String[]{ "a\r", "\r" }, "a\r\r");
        checkCanonical(new String[]{ "a", "\n" }, "a\r\n");
    }

    private void checkCanonical(String doc, String expected)
        throws Exception
    {
        checkCanonical(new String[]{ doc }, expected);

        // and one byte at a time through update(byte)
        byte[] data = Strings.toByteArray(doc);
        byte[][] single = new byte[data.length][];
        for (int i = 0; i != data.length; i++)
        {
            single[i] = new byte[]{ data[i] };
        }
        isTrue("byte at a time: " + escape(doc),
            areEqual(Strings.toByteArray(expected), hashedData(aliceKey, alicePriv, single, true)));
    }

    private void checkCanonical(String[] chunks, String expected)
        throws Exception
    {
        byte[][] data = new byte[chunks.length][];
        for (int i = 0; i != chunks.length; i++)
        {
            data[i] = Strings.toByteArray(chunks[i]);
        }

        byte[] hashed = hashedData(aliceKey, alicePriv, data, false);
        if (!areEqual(Strings.toByteArray(expected), hashed))
        {
            fail("canonical form of " + escape(concat(chunks)) + ": expected " + escape(expected)
                + " got " + escape(Strings.fromByteArray(hashed)));
        }
    }

    /*
     * Sign/verify round trips, v4 and v6 (salted), with the legacy fallback disabled so that only
     * the current form is in play.
     */
    private void testRoundTrip(PGPPublicKey key, PGPPrivateKey priv)
        throws Exception
    {
        String[] docs = { "a\ra", "a\r", "a\r\na", "a\na", "a\r\ra\n", "\r\n\n\r", "plain" };
        for (int i = 0; i != docs.length; i++)
        {
            byte[] doc = Strings.toByteArray(docs[i]);
            PGPSignature sig = sign(key, priv, PGPSignature.CANONICAL_TEXT_DOCUMENT, doc);

            isTrue("round trip " + escape(docs[i]), verify(sig, key, new byte[][]{ doc }, false));
            isTrue("round trip, byte at a time " + escape(docs[i]), verify(sig, key, bytewise(doc), false));
            isTrue("round trip, default " + escape(docs[i]), verify(sig, key, new byte[][]{ doc }, true));
        }

        // a bare CR is no longer a line ending: these are different documents now
        PGPSignature sig = sign(key, priv, PGPSignature.CANONICAL_TEXT_DOCUMENT, Strings.toByteArray("a\ra"));
        isTrue("a\\ra vs a\\r\\na", !verify(sig, key, docs("a\r\na"), false));
        isTrue("a\\ra vs a\\na", !verify(sig, key, docs("a\na"), false));
        isTrue("a\\ra vs a\\r\\na, default", !verify(sig, key, docs("a\r\na"), true));

        // while CR LF and LF still are the same line ending
        sig = sign(key, priv, PGPSignature.CANONICAL_TEXT_DOCUMENT, Strings.toByteArray("a\na"));
        isTrue("a\\na vs a\\r\\na", verify(sig, key, docs("a\r\na"), false));
        isTrue("a\\na vs split a\\r|\\na", verify(sig, key, docs("a\r", "\na"), false));
    }

    /*
     * Signatures over "a\ra" and "a\r" from the interoperability test suite.
     */
    private void testOtherImplementations()
        throws Exception
    {
        String[] current = { RPGPIE_BARE_CR, GOPENPGP_BARE_CR, OPENPGPJS_BARE_CR, GNUPG_BARE_CR };
        for (int i = 0; i != current.length; i++)
        {
            PGPSignature sig = readSignature(current[i]);
            isTrue("current form " + i, verify(sig, aliceKey, docs("a\ra"), false));
            isTrue("current form, default " + i, verify(sig, aliceKey, docs("a\ra"), true));
            isTrue("current form, split " + i, verify(sig, aliceKey, docs("a\r", "a"), false));
        }

        String[] currentTrailing = { RPGPIE_TRAILING_CR, GOPENPGP_TRAILING_CR, OPENPGPJS_TRAILING_CR };
        for (int i = 0; i != currentTrailing.length; i++)
        {
            PGPSignature sig = readSignature(currentTrailing[i]);
            isTrue("current form, trailing CR " + i, verify(sig, aliceKey, docs("a\r"), false));
            isTrue("current form, trailing CR, default " + i, verify(sig, aliceKey, docs("a\r"), true));
        }

        // GnuPG hashes "a" for "a\r" (see GPG244_VERIFIES)
        isTrue("GnuPG trailing CR", !verify(readSignature(GNUPG_TRAILING_CR), aliceKey, docs("a\r"), true));
        isTrue("GnuPG trailing CR is over a", verify(readSignature(GNUPG_TRAILING_CR), aliceKey, docs("a"), false));

        // Sequoia 2.4.2 and PGPainless 2.0.4 (BC before 1.87) hash a bare CR as CR LF
        String[] legacy = { SEQUOIA_BARE_CR, PGPAINLESS_BARE_CR };
        for (int i = 0; i != legacy.length; i++)
        {
            PGPSignature sig = readSignature(legacy[i]);
            isTrue("legacy form, strict " + i, !verify(sig, aliceKey, docs("a\ra"), false));
            isTrue("legacy form, default " + i, verify(sig, aliceKey, docs("a\ra"), true));
            isTrue("legacy form, default, split " + i, verify(sig, aliceKey, docs("a\r", "a"), true));
        }

        String[] legacyTrailing = { SEQUOIA_TRAILING_CR, PGPAINLESS_TRAILING_CR };
        for (int i = 0; i != legacyTrailing.length; i++)
        {
            PGPSignature sig = readSignature(legacyTrailing[i]);
            isTrue("legacy form, trailing CR, strict " + i, !verify(sig, aliceKey, docs("a\r"), false));
            isTrue("legacy form, trailing CR, default " + i, verify(sig, aliceKey, docs("a\r"), true));
        }
    }

    private void testGnuPG244()
        throws Exception
    {
        for (int i = 0; i != GPG244_SIGS.length; i++)
        {
            PGPSignature sig = readSignature(GPG244_SIGS[i]);
            byte[] doc = Strings.toByteArray(GPG244_DOCS[i]);
            isTrue("gpg 2.4.4 " + escape(GPG244_DOCS[i]), GPG244_VERIFIES[i] == verify(sig, aliceKey, new byte[][]{ doc }, false));
            isTrue("gpg 2.4.4, byte at a time " + escape(GPG244_DOCS[i]), GPG244_VERIFIES[i] == verify(sig, aliceKey, bytewise(doc), false));
        }

        // what GnuPG hashed instead, for the three it differs on
        isTrue("gpg 2.4.4 a\\r is over a", verify(readSignature(GPG244_SIGS[1]), aliceKey, docs("a"), false));
        isTrue("gpg 2.4.4 \\r\\n\\n\\r is over \\r\\n\\n", verify(readSignature(GPG244_SIGS[5]), aliceKey, docs("\r\n\n"), false));
        isTrue("gpg 2.4.4 a\\r\\r\\na is over a\\r\\na", verify(readSignature(GPG244_SIGS[6]), aliceKey, docs("a\r\na"), false));
    }

    /*
     * A signature in the pre-1.87 form, made here by signing the legacy canonical form of the
     * document (which contains no bare CR, so the current form leaves it as it is). Covers v6, so
     * the salted legacy hash.
     */
    private void testLegacyForm(PGPPublicKey key, PGPPrivateKey priv)
        throws Exception
    {
        String[][] cases = {
            { "a\ra", "a\r\na" },
            { "a\r", "a\r\n" },
            { "a\r\ra\n", "a\r\n\r\na\r\n" },
            { "\r\n\n\r", "\r\n\r\n\r\n" } };

        for (int i = 0; i != cases.length; i++)
        {
            byte[] doc = Strings.toByteArray(cases[i][0]);
            PGPSignature sig = sign(key, priv, PGPSignature.CANONICAL_TEXT_DOCUMENT, Strings.toByteArray(cases[i][1]));

            isTrue("legacy, strict " + escape(cases[i][0]), !verify(sig, key, new byte[][]{ doc }, false));
            isTrue("legacy, default " + escape(cases[i][0]), verify(sig, key, new byte[][]{ doc }, true));
            isTrue("legacy, default, byte at a time " + escape(cases[i][0]), verify(sig, key, bytewise(doc), true));

            // the property is read when the signature is initialised
            Properties.setThreadOverride(LEGACY, true);
            try
            {
                sig.init(new BcPGPContentVerifierBuilderProvider(), key);
            }
            finally
            {
                Properties.removeThreadOverride(LEGACY);
            }
            sig.update(doc);
            isTrue("legacy, set at init " + escape(cases[i][0]), sig.verify());
        }
    }

    /*
     * The one-pass signature path - what PGPObjectFactory, and so the OpenPGPMessageInputStream,
     * verify inline-signed messages through.
     */
    private void testLegacyOnePassSignature(PGPPublicKey key, PGPPrivateKey priv)
        throws Exception
    {
        byte[] doc = Strings.toByteArray("a\ra\rb\n");
        byte[] legacy = Strings.toByteArray("a\r\na\r\nb\r\n");

        byte[] current = signedMessage(key, priv, doc, doc);
        isTrue("ops current, strict", verifyOnePass(current, key, false));
        isTrue("ops current, default", verifyOnePass(current, key, true));

        byte[] old = signedMessage(key, priv, doc, legacy);
        isTrue("ops legacy, strict", !verifyOnePass(old, key, false));
        isTrue("ops legacy, default", verifyOnePass(old, key, true));
    }

    /*
     * What the fallback does and does not widen. Accepting the legacy form means a signature over
     * D verifies over every document whose legacy form is D: a signature over "a\r\na" made today
     * also verifies over "a\ra". BC releases before 1.87 accepted exactly that pairing, so the
     * fallback keeps, rather than adds, it; setting the property to false removes it. The fallback
     * never applies to data with no bare CR, and never makes a signature over a document with a
     * bare CR verify over anything but that document's legacy equivalents.
     */
    private void testFallbackScope()
        throws Exception
    {
        PGPSignature crlf = readSignature(GPG244_3);    // gpg, over "a\r\na"
        isTrue("crlf sig over a\\ra, default", verify(crlf, aliceKey, docs("a\ra"), true));
        isTrue("crlf sig over a\\ra, strict", !verify(crlf, aliceKey, docs("a\ra"), false));

        PGPSignature bareCR = readSignature(GNUPG_BARE_CR);   // over "a\ra"
        isTrue("bare CR sig over a\\r\\na", !verify(bareCR, aliceKey, docs("a\r\na"), true));
        isTrue("bare CR sig over a\\na", !verify(bareCR, aliceKey, docs("a\na"), true));

        PGPSignature legacy = readSignature(PGPAINLESS_BARE_CR);   // legacy form of "a\ra"
        String[] others = { "aa", "a\r\ra", "a\ra\r", "a", "a\r\n\ra", "a\ra\n" };
        for (int i = 0; i != others.length; i++)
        {
            isTrue("legacy sig over " + escape(others[i]), !verify(legacy, aliceKey, docs(others[i]), true));
        }
    }

    /*
     * Binary signatures hash the data as it is, and have no fallback.
     */
    private void testBinaryUnaffected()
        throws Exception
    {
        byte[] doc = Strings.toByteArray("a\ra\n");
        PGPSignature sig = sign(aliceKey, alicePriv, PGPSignature.BINARY_DOCUMENT, doc);
        isTrue("binary", verify(sig, aliceKey, new byte[][]{ doc }, true));
        isTrue("binary, legacy form", !verify(sig, aliceKey, docs("a\r\na\r\n"), true));

        sig = sign(aliceKey, alicePriv, PGPSignature.BINARY_DOCUMENT, Strings.toByteArray("a\r\na"));
        isTrue("binary, no fallback", !verify(sig, aliceKey, docs("a\ra"), true));
    }

    private byte[] hashedData(PGPPublicKey key, PGPPrivateKey priv, byte[][] chunks, boolean byteAtATime)
        throws Exception
    {
        CapturingSignerBuilder builder = new CapturingSignerBuilder(
            new BcPGPContentSignerBuilder(key.getAlgorithm(), HashAlgorithmTags.SHA512));
        PGPSignatureGenerator gen = new PGPSignatureGenerator(builder, key);
        gen.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, priv);
        for (int i = 0; i != chunks.length; i++)
        {
            if (byteAtATime && chunks[i].length == 1)
            {
                gen.update(chunks[i][0]);
            }
            else
            {
                gen.update(chunks[i]);
            }
        }
        PGPSignature sig = gen.generate();

        // v4: data || trailer
        byte[] all = builder.captured.toByteArray();
        byte[] trailer = sig.getSignatureTrailer();
        isTrue("trailer", Arrays.areEqual(trailer, Arrays.copyOfRange(all, all.length - trailer.length, all.length)));
        return Arrays.copyOfRange(all, 0, all.length - trailer.length);
    }

    private PGPSignature sign(PGPPublicKey key, PGPPrivateKey priv, int type, byte[] data)
        throws PGPException
    {
        PGPSignatureGenerator gen = new PGPSignatureGenerator(
            new BcPGPContentSignerBuilder(key.getAlgorithm(), HashAlgorithmTags.SHA512), key);
        gen.init(type, priv);
        gen.update(data);
        return gen.generate();
    }

    private boolean verify(PGPSignature sig, PGPPublicKey key, byte[][] chunks, boolean allowLegacy)
        throws PGPException
    {
        Properties.setThreadOverride(LEGACY, allowLegacy);
        try
        {
            sig.init(new BcPGPContentVerifierBuilderProvider(), key);
        }
        finally
        {
            Properties.removeThreadOverride(LEGACY);
        }

        for (int i = 0; i != chunks.length; i++)
        {
            if (chunks[i].length == 1)
            {
                sig.update(chunks[i][0]);
            }
            else
            {
                sig.update(chunks[i]);
            }
        }
        return sig.verify();
    }

    private byte[] signedMessage(PGPPublicKey key, PGPPrivateKey priv, byte[] literal, byte[] signed)
        throws Exception
    {
        PGPSignatureGenerator gen = new PGPSignatureGenerator(
            new BcPGPContentSignerBuilder(key.getAlgorithm(), HashAlgorithmTags.SHA512), key);
        gen.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, priv);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream bcOut = new BCPGOutputStream(bOut);
        gen.generateOnePassVersion(false).encode(bcOut);

        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream lOut = lGen.open(bcOut, PGPLiteralData.UTF8, "", literal.length, new Date());
        lOut.write(literal);
        lGen.close();

        gen.update(signed);
        gen.generate().encode(bcOut);
        bcOut.close();

        return bOut.toByteArray();
    }

    private boolean verifyOnePass(byte[] message, PGPPublicKey key, boolean allowLegacy)
        throws Exception
    {
        BcPGPObjectFactory fact = new BcPGPObjectFactory(message);
        PGPOnePassSignature ops = ((PGPOnePassSignatureList)fact.nextObject()).get(0);

        Properties.setThreadOverride(LEGACY, allowLegacy);
        try
        {
            ops.init(new BcPGPContentVerifierBuilderProvider(), key);
        }
        finally
        {
            Properties.removeThreadOverride(LEGACY);
        }

        PGPLiteralData lit = (PGPLiteralData)fact.nextObject();
        InputStream in = lit.getInputStream();
        int ch;
        while ((ch = in.read()) >= 0)
        {
            ops.update((byte)ch);
        }

        PGPSignature sig = ((PGPSignatureList)fact.nextObject()).get(0);
        return ops.verify(sig);
    }

    private static PGPSignature readSignature(String armored)
        throws IOException
    {
        ArmoredInputStream aIn = new ArmoredInputStream(new ByteArrayInputStream(Strings.toByteArray(armored)));
        BcPGPObjectFactory fact = new BcPGPObjectFactory(new BCPGInputStream(aIn));
        return ((PGPSignatureList)fact.nextObject()).get(0);
    }

    private static byte[][] docs(String doc)
    {
        return new byte[][]{ Strings.toByteArray(doc) };
    }

    private static byte[][] docs(String doc1, String doc2)
    {
        return new byte[][]{ Strings.toByteArray(doc1), Strings.toByteArray(doc2) };
    }

    private static byte[][] bytewise(byte[] doc)
    {
        byte[][] res = new byte[doc.length][];
        for (int i = 0; i != doc.length; i++)
        {
            res[i] = new byte[]{ doc[i] };
        }
        return res;
    }

    private static String concat(String[] chunks)
    {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i != chunks.length; i++)
        {
            sb.append(chunks[i]);
        }
        return sb.toString();
    }

    private static String escape(String s)
    {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i != s.length(); i++)
        {
            char c = s.charAt(i);
            if (c == '\r')
            {
                sb.append("\\r");
            }
            else if (c == '\n')
            {
                sb.append("\\n");
            }
            else
            {
                sb.append(c);
            }
        }
        return "\"" + sb.toString() + "\"";
    }

    private static class CapturingSignerBuilder
        implements PGPContentSignerBuilder
    {
        private final PGPContentSignerBuilder builder;
        final ByteArrayOutputStream captured = new ByteArrayOutputStream();

        CapturingSignerBuilder(PGPContentSignerBuilder builder)
        {
            this.builder = builder;
        }

        public PGPContentSigner build(int signatureType, PGPPrivateKey privateKey)
            throws PGPException
        {
            final PGPContentSigner signer = builder.build(signatureType, privateKey);
            captured.reset();

            return new PGPContentSigner()
            {
                public OutputStream getOutputStream()
                {
                    return new TeeOutputStream(signer.getOutputStream(), captured);
                }

                public byte[] getSignature()
                {
                    return signer.getSignature();
                }

                public byte[] getDigest()
                {
                    return signer.getDigest();
                }

                public int getType()
                {
                    return signer.getType();
                }

                public int getHashAlgorithm()
                {
                    return signer.getHashAlgorithm();
                }

                public int getKeyAlgorithm()
                {
                    return signer.getKeyAlgorithm();
                }

                public long getKeyID()
                {
                    return signer.getKeyID();
                }
            };
        }
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPTextSignatureCanonicalizationTest());
    }
}
