package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;

import org.bouncycastle.bcpg.ArmoredInputException;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Regression test for the cleartext signature framework (CSF) dash-escape handling of
 * {@link ArmoredInputStream}. A payload line beginning with a dash must be dash-escaped
 * as "- " per RFC 4880 7.1; the stream previously dropped the two leading characters
 * unconditionally, so a signature over "payload" also verified against a tampered
 * "-Xpayload" line. See https://github.com/bcgit/bc-java/pull/2329 .
 */
public class ArmoredInputStreamCSFRejectPrefixedDashTest
    extends SimpleTest
{
    private static final String MESSAGE_MISMATCH = "Exception message mismatch";
    private static final String REJECT_MESSAGE =
        "Prefixed dash without trailing space encountered. CSF-signed message malformed.";

    // A cleartext-signed message whose payload line "-Xpayload" begins with a dash that is
    // neither a "-----" armor header nor a "- " dash-escape: malformed per RFC 4880 7.1.
    // The signature was created over "payload".
    private static final String MALFORMED =
        "-----BEGIN PGP SIGNED MESSAGE-----\n" +
        "Hash: SHA512\n" +
        "\n" +
        "-Xpayload\n" +
        "-----BEGIN PGP SIGNATURE-----\n" +
        "Version: PGPainless\n" +
        "\n" +
        "wnUEABYKACcFgmoz+AoJEF0ybVyS+fXHFqEE/9HfXX3exPsb+/QfXTJtXJL59ccA\n" +
        "AMmDAP4yxWVmaDycXXgNWuKtyHmWegY+TAQoS2FCrg0KZO/kuQEAnvg8YxQLcL7I\n" +
        "WbRs9RZtPLc+jgUKBbz/bode8TkqyQU=\n" +
        "=PIAb\n" +
        "-----END PGP SIGNATURE-----";

    public String getName()
    {
        return "ArmoredInputStreamCSFRejectPrefixedDashTest";
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new ArmoredInputStreamCSFRejectPrefixedDashTest());
    }

    public void performTest()
        throws IOException
    {
        rejectsMalformedWhenConfigured();
        rejectsMalformedByDefault();
        surfacesMalformedBytesWhenLenient();
        lenientStreamStillDetectsArmorBoundary();
    }

    private void rejectsMalformedWhenConfigured()
        throws IOException
    {
        ArmoredInputStream aIn = ArmoredInputStream.builder()
            .setRejectPrefixedDashesInCSFMessages(true)
            .build(new ByteArrayInputStream(MALFORMED.getBytes(StandardCharsets.UTF_8)));

        try
        {
            Streams.drain(aIn);
            fail("Prefixed dash in CSF message MUST be rejected if configured to do so.");
        }
        catch (ArmoredInputException e)
        {
            isEquals(MESSAGE_MISMATCH, REJECT_MESSAGE, e.getMessage());
        }
    }

    private void rejectsMalformedByDefault()
        throws IOException
    {
        // The default builder (no explicit configuration) must reject too: rejecting the
        // malformed message is the secure default.
        ArmoredInputStream aIn = ArmoredInputStream.builder()
            .build(new ByteArrayInputStream(MALFORMED.getBytes(StandardCharsets.UTF_8)));

        try
        {
            Streams.drain(aIn);
            fail("Prefixed dash in CSF message MUST be rejected by default.");
        }
        catch (ArmoredInputException e)
        {
            isEquals(MESSAGE_MISMATCH, REJECT_MESSAGE, e.getMessage());
        }
    }

    private void surfacesMalformedBytesWhenLenient()
        throws IOException
    {
        ArmoredInputStream aIn = ArmoredInputStream.builder()
            .setRejectPrefixedDashesInCSFMessages(false)
            .build(new ByteArrayInputStream(MALFORMED.getBytes(StandardCharsets.UTF_8)));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        while (aIn.isClearText())
        {
            bOut.write(aIn.read());
        }

        // The leading dash is no longer silently dropped - the bytes are surfaced verbatim,
        // so a signature check over the recovered text fails instead of spuriously passing.
        isTrue("Malformed payload MUST be returned unaltered", bOut.toString().startsWith("-Xpayload"));
    }

    private void lenientStreamStillDetectsArmorBoundary()
        throws IOException
    {
        // A malformed lone-dash line ("-") immediately before the signature boundary used to
        // corrupt the new-line tracking in lenient mode, so the stream never left the
        // clear-text section and consumed the whole signature block. Verify the look-ahead
        // byte is run through the new-line state machine.
        String trailingDash =
            "-----BEGIN PGP SIGNED MESSAGE-----\n" +
            "Hash: SHA512\n" +
            "\n" +
            "payload\n" +
            "-\n" +
            "-----BEGIN PGP SIGNATURE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "wnUEABYKACcFgmoz+AoJEF0ybVyS+fXHFqEE/9HfXX3exPsb+/QfXTJtXJL59ccA\n" +
            "AMmDAP4yxWVmaDycXXgNWuKtyHmWegY+TAQoS2FCrg0KZO/kuQEAnvg8YxQLcL7I\n" +
            "WbRs9RZtPLc+jgUKBbz/bode8TkqyQU=\n" +
            "=PIAb\n" +
            "-----END PGP SIGNATURE-----";

        ArmoredInputStream aIn = ArmoredInputStream.builder()
            .setRejectPrefixedDashesInCSFMessages(false)
            .build(new ByteArrayInputStream(trailingDash.getBytes(StandardCharsets.UTF_8)));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        int count = 0;
        while (aIn.isClearText() && count++ < 1000)
        {
            int ch = aIn.read();
            if (ch < 0)
            {
                break;
            }
            bOut.write(ch);
        }

        isTrue("clear-text section must stop at the armor boundary, not consume the signature",
            !bOut.toString().contains("BEGIN PGP SIGNATURE"));
        isTrue("malformed lone-dash payload must be surfaced verbatim",
            bOut.toString().startsWith("payload\n-\n"));
    }
}
