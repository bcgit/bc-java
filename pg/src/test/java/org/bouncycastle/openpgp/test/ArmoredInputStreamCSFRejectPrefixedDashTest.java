package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.ArmoredInputException;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;

import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.io.Streams;

public class ArmoredInputStreamCSFRejectPrefixedDashTest
        extends SimpleTest {

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
        // signature was created over "payload", but this malformed variant as "-X" prefixed.
        String malformed = "-----BEGIN PGP SIGNED MESSAGE-----\n" +
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

        ByteArrayInputStream bIn = new ByteArrayInputStream(malformed.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = ArmoredInputStream.builder()
                .setRejectPrefixedDashesInCSFMessages(true)
                .build(bIn);

        try {
            Streams.drain(aIn);
            fail("Prefixed dash in CSF message MUST be rejected if configured to do so.");
        } catch (ArmoredInputException e) {
            isEquals("Prefixed dash without trailing space encountered. CSF-signed message malformed.", e.getMessage());
        }
    }
}
