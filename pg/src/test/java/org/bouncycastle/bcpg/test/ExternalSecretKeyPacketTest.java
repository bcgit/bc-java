package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.ContainedPacket;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.bcpg.PublicSubkeyPacket;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SecretSubkeyPacket;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class ExternalSecretKeyPacketTest
        extends AbstractPacketTest
{
    /**
     * Example transferable secret key test vector. It includes unencrypted private key material for both
     * its primary and subkey.
     *
     * @see <a href="https://www.ietf.org/archive/id/draft-dkg-openpgp-external-secrets-02.html#name-example-transferable-secret">
     *     Example Transferable Secret Key Test Vector</a>
     */
    private static final String V4_TSK = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "xVgEZgWtcxYJKwYBBAHaRw8BAQdAlLK6UPQsVHR2ETk1SwVIG3tBmpiEtikYYlCy\n" +
            "1TIiqzYAAQCwm/O5cWsztxbUcwOHycBwszHpD4Oa+fK8XJDxLWH7dRIZzR08aGFy\n" +
            "ZHdhcmUtc2VjcmV0QGV4YW1wbGUub3JnPsKNBBAWCAA1AhkBBQJmBa1zAhsDCAsJ\n" +
            "CAcKDQwLBRUKCQgLAhYCFiEEXlP8Tur0WZR+f0I33/i9Uh4OHEkACgkQ3/i9Uh4O\n" +
            "HEnryAD8CzH2ajJvASp46ApfI4pLPY57rjBX++d/2FQPRyqGHJUA/RLsNNgxiFYm\n" +
            "K5cjtQe2/DgzWQ7R6PxPC6oa3XM7xPcCx10EZgWtcxIKKwYBBAGXVQEFAQEHQE1Y\n" +
            "XOKeaklwG01Yab4xopP9wbu1E+pCrP1xQpiFZW5KAwEIBwAA/12uOubAQ5nhf1UF\n" +
            "a51SQwFLpggB/Spn29qDnSQXOTzIDvPCeAQYFggAIAUCZgWtcwIbDBYhBF5T/E7q\n" +
            "9FmUfn9CN9/4vVIeDhxJAAoJEN/4vVIeDhxJVTgA/1WaFrKdP3AgL0Ffdooc5XXb\n" +
            "jQsj0uHo6FZSHRI4pchMAQCyJnKQ3RvW/0gm41JCqImyg2fxWG4hY0N5Q7Rc6Pyz\n" +
            "DQ==\n" +
            "=lYbx\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";
    /**
     * The same TSK as {@link #V4_TSK}, but with external secret keys for both the primary and subkey.
     *
     * @see <a href="https://www.ietf.org/archive/id/draft-dkg-openpgp-external-secrets-02.html#name-as-an-external-secret-key">
     *     External Key Test Vector</a>
     */
    private static final String V4_TSK_AS_EXTERNAL_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "xTQEZgWtcxYJKwYBBAHaRw8BAQdAlLK6UPQsVHR2ETk1SwVIG3tBmpiEtikYYlCy\n" +
            "1TIiqzb8zR08aGFyZHdhcmUtc2VjcmV0QGV4YW1wbGUub3JnPsKNBBAWCAA1AhkB\n" +
            "BQJmBa1zAhsDCAsJCAcKDQwLBRUKCQgLAhYCFiEEXlP8Tur0WZR+f0I33/i9Uh4O\n" +
            "HEkACgkQ3/i9Uh4OHEnryAD8CzH2ajJvASp46ApfI4pLPY57rjBX++d/2FQPRyqG\n" +
            "HJUA/RLsNNgxiFYmK5cjtQe2/DgzWQ7R6PxPC6oa3XM7xPcCxzkEZgWtcxIKKwYB\n" +
            "BAGXVQEFAQEHQE1YXOKeaklwG01Yab4xopP9wbu1E+pCrP1xQpiFZW5KAwEIB/zC\n" +
            "eAQYFggAIAUCZgWtcwIbDBYhBF5T/E7q9FmUfn9CN9/4vVIeDhxJAAoJEN/4vVIe\n" +
            "DhxJVTgA/1WaFrKdP3AgL0Ffdooc5XXbjQsj0uHo6FZSHRI4pchMAQCyJnKQ3RvW\n" +
            "/0gm41JCqImyg2fxWG4hY0N5Q7Rc6PyzDQ==\n" +
            "=3w/O\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    /**
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-version-6-secret-key">
     *     RFC9580: Sample Version 6 Secret Key</a>
     */
    private static final String V6_TSK = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "xYIGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laP9JgkC\n" +
            "FARdb9ccngltHraRe25uHuyuAQQVtKipJ0+r5jL4dacGWSAheCWPpITYiyfyIOPS\n" +
            "3gIDyg8f7strd1OB4+LZsUhcIjOMpVHgmiY/IutJkulneoBYwrEGHxsKAAAAQgWC\n" +
            "Y4d/4wMLCQcFFQoOCAwCFgACmwMCHgkiIQbLGGxPBgmml+TVLfpscisMHx4nwYpW\n" +
            "cI9lJewnutmsyQUnCQIHAgAAAACtKCAQPi19In7A5tfORHHbNr/JcIMlNpAnFJin\n" +
            "7wV2wH+q4UWFs7kDsBJ+xP2i8CMEWi7Ha8tPlXGpZR4UruETeh1mhELIj5UeM8T/\n" +
            "0z+5oX1RHu11j8bZzFDLX9eTsgOdWATHggZjh3/jGQAAACCGkySDZ/nlAV25Ivj0\n" +
            "gJXdp4SYfy1ZhbEvutFsr15ENf0mCQIUBA5hhGgp2oaavg6mFUXcFMwBBBUuE8qf\n" +
            "9Ock+xwusd+GAglBr5LVyr/lup3xxQvHXFSjjA2haXfoN6xUGRdDEHI6+uevKjVR\n" +
            "v5oAxgu7eJpaXNjCmwYYGwoAAAAsBYJjh3/jApsMIiEGyxhsTwYJppfk1S36bHIr\n" +
            "DB8eJ8GKVnCPZSXsJ7rZrMkAAAAABAEgpukYbZ1ZNfyP5WMUzbUnSGpaUSD5t2Ki\n" +
            "Nacp8DkBClZRa2c3AMQzSDXa9jGhYzxjzVb5scHDzTkjyRZWRdTq8U6L4da+/+Kt\n" +
            "ruh8m7Xo2ehSSFyWRSuTSZe5tm/KXgYG\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    private static final String V6_TSK_AS_EXTERNAL_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "xSwGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laP8AMKx\n" +
            "Bh8bCgAAAEIFgmOHf+MDCwkHBRUKDggMAhYAApsDAh4JIiEGyxhsTwYJppfk1S36\n" +
            "bHIrDB8eJ8GKVnCPZSXsJ7rZrMkFJwkCBwIAAAAArSggED4tfSJ+wObXzkRx2za/\n" +
            "yXCDJTaQJxSYp+8FdsB/quFFhbO5A7ASfsT9ovAjBFoux2vLT5VxqWUeFK7hE3od\n" +
            "ZoRCyI+VHjPE/9M/uaF9UR7tdY/G2cxQy1/Xk7IDnVgExywGY4d/4xkAAAAghpMk\n" +
            "g2f55QFduSL49ICV3aeEmH8tWYWxL7rRbK9eRDX8AMKbBhgbCgAAACwFgmOHf+MC\n" +
            "mwwiIQbLGGxPBgmml+TVLfpscisMHx4nwYpWcI9lJewnutmsyQAAAAAEASCm6Rht\n" +
            "nVk1/I/lYxTNtSdIalpRIPm3YqI1pynwOQEKVlFrZzcAxDNINdr2MaFjPGPNVvmx\n" +
            "wcPNOSPJFlZF1OrxTovh1r7/4q2u6HybtejZ6FJIXJZFK5NJl7m2b8peBgY=\n" +
            "=1veT\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    @Override
    public String getName()
    {
        return "ExternalSecretKeyPacketTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testPacketRoundTripping();
        testV4PacketProperties();
        testV6PacketProperties();
    }

    private String toExternalKey(String asciiArmoredKey) throws IOException {
        ByteArrayInputStream bIn = new ByteArrayInputStream(asciiArmoredKey.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = ArmoredInputStream.builder().build(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = ArmoredOutputStream.builder().build(bOut);
        BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.ROUNDTRIP);

        ContainedPacket p;
        while ((p = (ContainedPacket) pIn.readPacket()) != null)
        {
            if (p instanceof SecretSubkeyPacket)
            {
                SecretSubkeyPacket s = (SecretSubkeyPacket) p;
                p = new SecretSubkeyPacket((PublicSubkeyPacket) s.getPublicKeyPacket(), new byte[0]);
            }
            else if (p instanceof SecretKeyPacket)
            {
                SecretKeyPacket s = (SecretKeyPacket) p;
                p = new SecretKeyPacket(s.getPublicKeyPacket(), new byte[0]);
            }
            p.encode(pOut);
        }

        pOut.close();
        aOut.close();

        return bOut.toString();
    }

    private void testV4PacketProperties()
            throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(V4_TSK_AS_EXTERNAL_KEY.getBytes());
        ArmoredInputStream aIn = ArmoredInputStream.builder()
                .build(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);

        SecretKeyPacket primaryKey = (SecretKeyPacket) pIn.readPacket();
        pIn.readPacket(); // skip uid
        pIn.readPacket(); // skip uid sig
        SecretSubkeyPacket subkey = (SecretSubkeyPacket) pIn.readPacket();

        isTrue(primaryKey.getS2KUsage() == SecretKeyPacket.USAGE_EXTERNAL);
        isTrue(subkey.getS2KUsage() == SecretKeyPacket.USAGE_EXTERNAL);
        isEncodingEqual(new byte[0], primaryKey.getExternalKeyLocatorHint());
        isEncodingEqual(new byte[0], subkey.getExternalKeyLocatorHint());

        // Test with locator hint
        byte[] hint = new byte[] {(byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe};
        primaryKey = new SecretKeyPacket(primaryKey.getPublicKeyPacket(), hint);
        pIn = new BCPGInputStream(new ByteArrayInputStream(primaryKey.getEncoded()));
        primaryKey = (SecretKeyPacket) pIn.readPacket();
        isTrue(primaryKey.getS2KUsage() == SecretKeyPacket.USAGE_EXTERNAL);
        isEncodingEqual(hint, primaryKey.getExternalKeyLocatorHint());

        subkey = new SecretSubkeyPacket((PublicSubkeyPacket) subkey.getPublicKeyPacket(), hint);
        pIn = new BCPGInputStream(new ByteArrayInputStream(subkey.getEncoded()));
        subkey = (SecretSubkeyPacket) pIn.readPacket();
        isTrue(subkey.getS2KUsage() == SecretKeyPacket.USAGE_EXTERNAL);
        isEncodingEqual(hint, subkey.getExternalKeyLocatorHint());
    }

    private void testV6PacketProperties()
            throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(V6_TSK_AS_EXTERNAL_KEY.getBytes());
        ArmoredInputStream aIn = ArmoredInputStream.builder()
                .build(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);

        SecretKeyPacket primaryKey = (SecretKeyPacket) pIn.readPacket();
        pIn.readPacket(); // skip dk sig
        SecretSubkeyPacket subkey = (SecretSubkeyPacket) pIn.readPacket();

        isTrue(primaryKey.getS2KUsage() == SecretKeyPacket.USAGE_EXTERNAL);
        isTrue(subkey.getS2KUsage() == SecretKeyPacket.USAGE_EXTERNAL);
        isEncodingEqual(new byte[0], primaryKey.getExternalKeyLocatorHint());
        isEncodingEqual(new byte[0], subkey.getExternalKeyLocatorHint());

        // Test with locator hint
        byte[] hint = new byte[] {(byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe};
        primaryKey = new SecretKeyPacket(primaryKey.getPublicKeyPacket(), hint);
        pIn = new BCPGInputStream(new ByteArrayInputStream(primaryKey.getEncoded()));
        primaryKey = (SecretKeyPacket) pIn.readPacket();
        isTrue(primaryKey.getS2KUsage() == SecretKeyPacket.USAGE_EXTERNAL);
        isEncodingEqual(hint, primaryKey.getExternalKeyLocatorHint());

        subkey = new SecretSubkeyPacket((PublicSubkeyPacket) subkey.getPublicKeyPacket(), hint);
        pIn = new BCPGInputStream(new ByteArrayInputStream(subkey.getEncoded()));
        subkey = (SecretSubkeyPacket) pIn.readPacket();
        isTrue(subkey.getS2KUsage() == SecretKeyPacket.USAGE_EXTERNAL);
        isEncodingEqual(hint, subkey.getExternalKeyLocatorHint());
    }

    private void testPacketRoundTripping()
            throws IOException
    {
        assertPacketsCanBeRoundTripped(V4_TSK);
        assertPacketsCanBeRoundTripped(V4_TSK_AS_EXTERNAL_KEY);
        assertPacketsCanBeRoundTripped(V6_TSK);
        assertPacketsCanBeRoundTripped(V6_TSK_AS_EXTERNAL_KEY);
    }

    private void assertPacketsCanBeRoundTripped(String asciiArmoredPackets)
            throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(asciiArmoredPackets.getBytes());
        ArmoredInputStream aIn = ArmoredInputStream.builder()
                .build(bIn);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        org.bouncycastle.util.io.Streams.pipeAll(aIn, bOut);
        byte[] before =  bOut.toByteArray();
        bIn = new ByteArrayInputStream(before);
        BCPGInputStream pIn = new BCPGInputStream(bIn);

        bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut, PacketFormat.ROUNDTRIP);

        ContainedPacket p;
        while ((p = (ContainedPacket) pIn.readPacket()) != null)
        {
            p.encode(pOut);
        }

        pOut.close();

        isEncodingEqual(before, bOut.toByteArray());
    }

    public static void main(String[] args)
    {
        runTest(new ExternalSecretKeyPacketTest());
    }

}
