package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Security;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.OpenPGPTestKeys;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Bare CRs in cleartext signed messages, github #2553: a line ends with LF (or CR LF) and a CR
 * not followed by LF is part of the text, so a dash after one is neither dash-escaped by
 * ArmoredOutputStream nor un-escaped or taken as the signature armor by ArmoredInputStream. A
 * message whose armor lines themselves end in bare CRs (a classic Mac text file) is still read
 * with CR as its line ending, and {@link Properties#OPENPGP_CSF_BARE_CR_LINE_ENDING} reads every
 * message that way.
 */
public class PGPClearSignedBareCRTest
    extends SimpleTest
{
    /*
     * From the OpenPGP interoperability test suite, "Cleartext Signature Sign-Verify roundtrip with
     * v6 key, bare CR characters" (inline_signatures.html, run of 2026-11-04): "test\rmessage\r"
     * cleartext signed with the RFC 9580 A.3 v6 key (OpenPGPTestKeys.V6_KEY). These are the
     * producers whose output verified with rpgpie, GopenPGP and PGPy; the signed text is
     * "test\rmessage", the trailing CR being stripped as trailing white space.
     */
    private static final String GOPENPGP_3_5_2 =
        "-----BEGIN PGP SIGNED MESSAGE-----\n" +
        "\n" +
        "test\rmessage\n" +
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "wogGARsIAAAAKQWCautKfSKhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
        "2azJAAAAAHj1EJxbHd2rayGp5B7rfWdvS97O0eE4XmUUMmvtMqjRkMS+oUndil4f\n" +
        "0uwSvjhAT1kwxn4T7dF3pZeZRUsouyBhtV3mhNs21UdzVBcanY3jCgYM\n" +
        "-----END PGP SIGNATURE-----\n";

    private static final String GOPENPGP_2_8_0 =
        "-----BEGIN PGP SIGNED MESSAGE-----\r\n" +
        "Hash: SHA512\r\n" +
        "\r\n" +
        "test\rmessage\r\n" +
        "-----BEGIN PGP SIGNATURE-----\n" +
        "Version: GopenPGP 2.8.0\n" +
        "Comment: https://gopenpgp.org\n" +
        "\n" +
        "wpgGARsKAAAAKQWCautKgSKhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
        "2azJAAAAANWHIKkVN/BwbTqcmUnR8mOmHt/nTv9H8GnD4l8KcOh/Bg7dcmnJwmhV\n" +
        "EhIeHwty4itpAkekoZOQqsDwj4MBGsJwBqyvf4zol8VpzD/0stwY5bA8anfuPSq/\n" +
        "vxKWknk/SEGzAw==\n" +
        "=aLN+\n" +
        "-----END PGP SIGNATURE-----\n";

    private static final String OPENPGPJS_6_2_2 =
        "-----BEGIN PGP SIGNED MESSAGE-----\n" +
        "\n" +
        "test\rmessage\n" +
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "wpgGARsKAAAAKQWCautKiCKhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul\n" +
        "7Ce62azJAAAAAPPaIE1MmUYwqYOT1TVIw0CuLMc19iMcMKvbfQIvM0iwK/9j\n" +
        "uUuBXvC8LIBW9mRrxl4WTpHgC2/ekg4iOILftOQ6EIK1N2cgPQ6ayJJh7Q/i\n" +
        "eaWSXfq1WPVQSqh15AKDYTuYCQ==\n" +
        "-----END PGP SIGNATURE-----\n";

    /*
     * gpg (GnuPG) 2.4.4, "gpg --clearsign" with the draft-bre-openpgp-samples-00 Alice key
     * (OpenPGPTestKeys.ALICE_KEY) over "test\rmessage\r" and "a\rb\r-c\r--d\n-e\n". Note the
     * dash-escaping: only "-e", which follows a LF, is escaped.
     */
    private static final String GPG244_CR_MESSAGE =
        "-----BEGIN PGP SIGNED MESSAGE-----\n" +
        "Hash: SHA512\n" +
        "\n" +
        "test\rmessage\r\n" +
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "iHUEARYKAB0WIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCauseQAAKCRDyMVUMT0fj\n" +
        "jrQiAQCWpxtEtT9cCq0fCRsTAK70F56moq2CnB/zWEMasBQcRwD8CSL8U/s8+IJ1\n" +
        "2+ZIagERFaCmYI3Ug+sGvGVzd7M15Q0=\n" +
        "=+aHy\n" +
        "-----END PGP SIGNATURE-----\n";

    private static final String GPG244_CR_DASHES =
        "-----BEGIN PGP SIGNED MESSAGE-----\n" +
        "Hash: SHA512\n" +
        "\n" +
        "a\rb\r-c\r--d\n" +
        "- -e\n" +
        "-----BEGIN PGP SIGNATURE-----\n" +
        "\n" +
        "iHUEARYKAB0WIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCauseQAAKCRDyMVUMT0fj\n" +
        "jmTWAP0ZUBIU3W7l1ofGek4h3QMuAgr1zgRFpbUfnkujvK434QD+NzjxhLlTuNtK\n" +
        "wlbVYumUXCCh7bQxrsvyFpsYYSXCvgY=\n" +
        "=TFXu\n" +
        "-----END PGP SIGNATURE-----\n";

    private static final String LEGACY = Properties.OPENPGP_CSF_BARE_CR_LINE_ENDING;

    private PGPPublicKey aliceKey;
    private PGPPrivateKey alicePriv;
    private PGPPublicKey v6Key;
    private PGPPrivateKey v6Priv;

    public String getName()
    {
        return "PGPClearSignedBareCRTest";
    }

    public void performTest()
        throws Exception
    {
        PGPSecretKey alice = OpenPGPTestKeys.readPGPSecretKeyRing(OpenPGPTestKeys.ALICE_KEY).getSecretKey();
        aliceKey = alice.getPublicKey();
        alicePriv = alice.extractPrivateKey(null);

        PGPSecretKey v6 = OpenPGPTestKeys.readPGPSecretKeyRing(OpenPGPTestKeys.V6_KEY).getSecretKey();
        v6Key = v6.getPublicKey();
        v6Priv = v6.extractPrivateKey(null);

        testOtherImplementations();
        testWriterMatchesGnuPG();
        testRoundTrip(aliceKey, alicePriv);
        testRoundTrip(v6Key, v6Priv);
        testUnterminatedText();
        testLegacyMessages();
    }

    private void testOtherImplementations()
        throws Exception
    {
        String[] suite = { GOPENPGP_3_5_2, GOPENPGP_2_8_0, OPENPGPJS_6_2_2 };
        for (int i = 0; i != suite.length; i++)
        {
            ClearText ct = read(suite[i], false);
            isEquals("suite " + i + " text", "test\rmessage", ct.signedText);
            isTrue("suite " + i + " verifies", ct.verify(v6Key));
        }

        ClearText ct = read(GPG244_CR_MESSAGE, false);
        isEquals("gpg text", "test\rmessage\r\n", ct.text);
        isTrue("gpg verifies", ct.verify(aliceKey));

        ct = read(GPG244_CR_DASHES, false);
        isEquals("gpg dashes text", "a\rb\r-c\r--d\n-e\n", ct.text);
        isEquals("gpg dashes signed", "a\rb\r-c\r--d\r\n-e", ct.signedText);
        isTrue("gpg dashes verifies", ct.verify(aliceKey));
    }

    /*
     * The clear text section BC writes is byte for byte the one gpg 2.4.4 wrote.
     */
    private void testWriterMatchesGnuPG()
        throws Exception
    {
        checkSameBody("test\rmessage\r", GPG244_CR_MESSAGE);
        checkSameBody("a\rb\r-c\r--d\n-e\n", GPG244_CR_DASHES);
    }

    private void checkSameBody(String text, String gpgMessage)
        throws Exception
    {
        String bc = clearSign(aliceKey, alicePriv, text);
        isEquals("body of " + escape(text), body(gpgMessage), body(bc));
    }

    private void testRoundTrip(PGPPublicKey key, PGPPrivateKey priv)
        throws Exception
    {
        String[] texts = {
            "test\rmessage\r",
            "a\rb\r-c\r--d\n-e\n",
            "\r-----BEGIN PGP SIGNATURE-----\r\n",
            "x\r- y\r\n-z\r\n",
            "plain\nlines\n- dash\n",
            "crlf\r\n-dash\r\n",
            "\r\r\r\n" };

        for (int i = 0; i != texts.length; i++)
        {
            String armored = clearSign(key, priv, texts[i]);

            ClearText ct = read(armored, false);
            isTrue("round trip text " + escape(texts[i]) + " got " + escape(ct.text), ct.text.startsWith(texts[i]));
            isTrue("round trip " + escape(texts[i]), ct.verify(key));
        }

        // only a dash after a LF is escaped
        String armored = clearSign(key, priv, "a\r-b\n-c\r\n-d\n");
        isTrue("escaping", body(armored).equals("a\r-b\n- -c\r\n- -d\n"));
    }

    /*
     * The signature armor has to start a line: text not ending in a LF gets one before it.
     */
    private void testUnterminatedText()
        throws Exception
    {
        String armored = clearSign(aliceKey, alicePriv, "abc");
        isEquals("unterminated body", "abc" + Strings.lineSeparator(), body(armored));
        isTrue("unterminated verifies", read(armored, false).verify(aliceKey));

        armored = clearSign(aliceKey, alicePriv, "abc\r");
        isEquals("bare CR terminated body", "abc\r\n", body(armored));
        isTrue("bare CR terminated verifies", read(armored, false).verify(aliceKey));
    }

    /*
     * What releases before 1.87 wrote over text with bare CRs: every CR was a line ending, so a
     * dash after one was escaped and the signature armor followed a trailing CR directly, and the
     * signature was over the lines joined with CR LF.
     */
    private void testLegacyMessages()
        throws Exception
    {
        String legacy = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n"
            + "a\r- -b\r"
            + armoredSignature(aliceKey, alicePriv, "a\r\n-b");

        // by default the dash is not un-escaped and the signature armor is not found
        isTrue("legacy, default", !verifiesQuietly(legacy, aliceKey, false));

        ClearText ct = read(legacy, true);
        isEquals("legacy, property", "a\n-b\n", ct.text);
        isTrue("legacy, property verifies", ct.verify(aliceKey));

        // a CR-only file, armor included, is read with CR as its line ending whatever the property
        String crOnly = "-----BEGIN PGP SIGNED MESSAGE-----\rHash: SHA512\r\r"
            + "a\r- -b\r"
            + armoredSignature(aliceKey, alicePriv, "a\r\n-b").replace('\n', '\r');
        ct = read(crOnly, false);
        isEquals("cr only", "a\n-b\n", ct.text);
        isTrue("cr only verifies", ct.verify(aliceKey));

        // a CR inside a header value of an LF-armored message does not make it a CR-only file
        String crInHeader = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\nComment: a\rComment: b\n\n"
            + "a\r-b\n"
            + armoredSignature(aliceKey, alicePriv, "a\r-b");
        ct = read(crInHeader, false);
        isEquals("cr in header", "a\r-b\n", ct.text);
        isTrue("cr in header verifies", ct.verify(aliceKey));

        // a legacy message with a bare CR but no dash after it still verifies through the text
        // signature's legacy canonical form (Properties.OPENPGP_TEXT_SIG_ALLOW_LEGACY_CR)
        String midLine = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n"
            + "a\rb\n"
            + armoredSignature(aliceKey, alicePriv, "a\r\nb");
        ct = read(midLine, false);
        isEquals("mid line", "a\rb", ct.signedText);
        isTrue("mid line verifies", ct.verify(aliceKey));
    }

    private boolean verifiesQuietly(String armored, PGPPublicKey key, boolean legacy)
    {
        try
        {
            return read(armored, legacy).verify(key);
        }
        catch (Exception e)
        {
            return false;
        }
    }

    /*
     * Cleartext sign as the misc ClearSignedFileProcessor example does: the text is written
     * through the armor as it is, and the signature is over its lines - split on LF, trailing
     * white space (CR included) removed - joined with CR LF.
     */
    private String clearSign(PGPPublicKey key, PGPPrivateKey priv, String text)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = new ArmoredOutputStream(bOut);
        aOut.beginClearText(HashAlgorithmTags.SHA512);
        aOut.write(Strings.toByteArray(text));
        aOut.endClearText();

        PGPSignatureGenerator gen = new PGPSignatureGenerator(
            new BcPGPContentSignerBuilder(key.getAlgorithm(), HashAlgorithmTags.SHA512), key);
        gen.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, priv);
        gen.update(Strings.toByteArray(signedText(text)));

        BCPGOutputStream bcOut = new BCPGOutputStream(aOut);
        gen.generate().encode(bcOut);
        aOut.close();

        return Strings.fromByteArray(bOut.toByteArray());
    }

    private String armoredSignature(PGPPublicKey key, PGPPrivateKey priv, String signed)
        throws Exception
    {
        PGPSignatureGenerator gen = new PGPSignatureGenerator(
            new BcPGPContentSignerBuilder(key.getAlgorithm(), HashAlgorithmTags.SHA512), key);
        gen.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, priv);
        gen.update(Strings.toByteArray(signed));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = ArmoredOutputStream.builder().clearHeaders().build(bOut);
        gen.generate().encode(aOut);
        aOut.close();

        return Strings.fromByteArray(bOut.toByteArray());
    }

    private static ClearText read(String armored, boolean legacy)
        throws IOException
    {
        ArmoredInputStream aIn;
        if (legacy)
        {
            Properties.setThreadOverride(LEGACY, true);
        }
        try
        {
            aIn = new ArmoredInputStream(new ByteArrayInputStream(Strings.toByteArray(armored)));
        }
        finally
        {
            if (legacy)
            {
                Properties.removeThreadOverride(LEGACY);
            }
        }

        ByteArrayOutputStream text = new ByteArrayOutputStream();
        int ch;
        while ((ch = aIn.read()) >= 0 && aIn.isClearText())
        {
            text.write(ch);
        }

        PGPSignatureList sigs = (PGPSignatureList)new BcPGPObjectFactory(aIn).nextObject();

        return new ClearText(Strings.fromByteArray(text.toByteArray()), sigs == null ? null : sigs.get(0));
    }

    /*
     * The text a cleartext signature is over: the lines, split on LF only, with trailing spaces,
     * tabs and CRs removed, joined with CR LF; the line ending before the signature is not part
     * of it.
     */
    static String signedText(String text)
    {
        StringBuffer sb = new StringBuffer();
        int start = 0;
        while (start <= text.length())
        {
            int end = text.indexOf('\n', start);
            if (end < 0)
            {
                end = text.length();
                if (end == start && start != 0)
                {
                    break;      // the text ended with a line ending
                }
            }

            int stripped = end;
            while (stripped > start && isTrailingWhiteSpace(text.charAt(stripped - 1)))
            {
                stripped--;
            }
            if (start != 0)
            {
                sb.append("\r\n");
            }
            sb.append(text.substring(start, stripped));
            start = end + 1;
        }
        return sb.toString();
    }

    private static boolean isTrailingWhiteSpace(char c)
    {
        return c == ' ' || c == '\t' || c == '\r';
    }

    // the clear text section: from after the blank line ending the armor headers to the signature
    private static String body(String armored)
    {
        int lf = armored.indexOf("\n\n");
        int crlf = armored.indexOf("\r\n\r\n");
        int start = (crlf >= 0 && crlf < lf) ? crlf + 4 : lf + 2;
        return armored.substring(start, armored.lastIndexOf("-----BEGIN PGP SIGNATURE-----"));
    }

    private static String escape(String s)
    {
        StringBuffer sb = new StringBuffer("\"");
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
        return sb.append('"').toString();
    }

    private static class ClearText
    {
        final String text;
        final String signedText;
        final PGPSignature sig;

        ClearText(String text, PGPSignature sig)
        {
            this.text = text;
            this.signedText = signedText(text);
            this.sig = sig;
        }

        boolean verify(PGPPublicKey key)
            throws PGPException
        {
            if (sig == null)
            {
                return false;
            }
            sig.init(new BcPGPContentVerifierBuilderProvider(), key);
            sig.update(Strings.toByteArray(signedText));
            return sig.verify();
        }
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPClearSignedBareCRTest());
    }
}
