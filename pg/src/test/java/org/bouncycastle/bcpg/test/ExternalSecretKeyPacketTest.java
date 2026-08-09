package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.ContainedPacket;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.PublicSubkeyPacket;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SecretSubkeyPacket;
import org.bouncycastle.util.io.Streams;

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
     * @see <a href="https://www.ietf.org/archive/id/draft-dkg-openpgp-external-secrets-03.html#name-example-transferable-secret">
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
     * @see <a href="https://www.ietf.org/archive/id/draft-dkg-openpgp-external-secrets-03.html#name-as-an-external-secret-key">
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
     * Example version 6 transferable secret key test vector, the v6 companion of {@link #V4_TSK}. It
     * includes unencrypted private key material for both its primary and subkey, and is the key
     * {@link #V6_TSK_AS_EXTERNAL_KEY} is derived from.
     * <p>
     * Added to the draft in revision 03 alongside the v6 external key.
     *
     * @see <a href="https://www.ietf.org/archive/id/draft-dkg-openpgp-external-secrets-03.html#name-example-transferable-secret">
     *     Example Transferable Secret Key Test Vector</a>
     */
    private static final String V6_TSK = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB\n" +
            "exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ\n" +
            "BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
            "2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh\n" +
            "RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe\n" +
            "7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/\n" +
            "LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG\n" +
            "GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
            "2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE\n" +
            "M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr\n" +
            "k0mXubZvyl4GBg==\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    /**
     * RFC 9580's locked (S2K + AEAD protected) sample version 6 secret key. Unrelated to the draft's
     * example key; kept here so packet round-tripping is also exercised against a v6 key that carries a
     * real S2K specifier and IV, rather than only against unprotected and external ones.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-version-6-secret-key">
     *     RFC9580: Sample Version 6 Secret Key</a>
     */
    private static final String V6_LOCKED_TSK = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
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

    /**
     * The same TSK as {@link #V6_TSK}, but with external secret keys for both the primary and subkey.
     * <p>
     * Added to the draft in revision 03.
     *
     * @see <a href="https://www.ietf.org/archive/id/draft-dkg-openpgp-external-secrets-03.html#name-as-an-external-secret-key">
     *     External Key Test Vector</a>
     */
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
        testConversionMatchesTestVectors();
        testV4PacketProperties();
        testV6PacketProperties();
        testOverlongLocatorHintRejected();
    }

    /**
     * Strip the private key material from every secret key packet of the given key, replacing it with a
     * best-effort (empty locator hint) external secret key packet, and return the resulting raw packet
     * stream.
     */
    private byte[] toExternalKey(String asciiArmoredKey)
            throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(asciiArmoredKey.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = ArmoredInputStream.builder().build(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut, PacketFormat.ROUNDTRIP);

        ContainedPacket p;
        while ((p = (ContainedPacket)pIn.readPacket()) != null)
        {
            if (p instanceof SecretSubkeyPacket)
            {
                SecretSubkeyPacket s = (SecretSubkeyPacket)p;
                p = new SecretSubkeyPacket((PublicSubkeyPacket)s.getPublicKeyPacket(), new byte[0]);
            }
            else if (p instanceof SecretKeyPacket)
            {
                SecretKeyPacket s = (SecretKeyPacket)p;
                p = new SecretKeyPacket(s.getPublicKeyPacket(), new byte[0]);
            }
            p.encode(pOut);
        }

        pOut.close();

        return bOut.toByteArray();
    }

    /**
     * Return the raw packet stream of an ASCII-armored key, i.e. the armor payload.
     */
    private byte[] dearmor(String asciiArmoredKey)
            throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(asciiArmoredKey.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = ArmoredInputStream.builder().build(bIn);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        Streams.pipeAll(aIn, bOut);
        return bOut.toByteArray();
    }

    /**
     * Convert each of the draft's example transferable secret keys to an external secret key and check
     * the result is byte-for-byte the external key the draft publishes for it.
     * <p>
     * This is the interop assertion of the pair: the round-trip test below only proves that what BC
     * parses it re-encodes unchanged, which says nothing about whether BC <em>produces</em> the format
     * the draft specifies.
     */
    private void testConversionMatchesTestVectors()
            throws IOException
    {
        isEncodingEqual("v4 TSK converted to an external secret key must match the draft test vector",
                dearmor(V4_TSK_AS_EXTERNAL_KEY), toExternalKey(V4_TSK));
        isEncodingEqual("v6 TSK converted to an external secret key must match the draft test vector",
                dearmor(V6_TSK_AS_EXTERNAL_KEY), toExternalKey(V6_TSK));
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

    /**
     * A version 5 or 6 secret key prefixes its conditional parameters - for an external key, the locator
     * hint - with a ONE-octet count, so a hint longer than 255 octets cannot be encoded: the count wraps
     * (256 is written as 0) while the hint is still emitted in full, giving a packet that does not
     * round-trip. The constructor must reject it rather than produce that. A version 4 key has no count
     * (the hint runs to the end of the packet), so the same length is fine there.
     */
    private void testOverlongLocatorHintRejected()
            throws IOException
    {
        PublicKeyPacket v6Pub = readPrimaryPublicKeyPacket(V6_TSK);
        PublicKeyPacket v4Pub = readPrimaryPublicKeyPacket(V4_TSK);

        // 255 octets is the largest a v6 count can express - must be accepted
        SecretKeyPacket ok = new SecretKeyPacket(v6Pub, new byte[255]);
        isEquals("255-octet v6 locator hint should round-trip", 255,
                ok.getExternalKeyLocatorHint().length);

        try
        {
            new SecretKeyPacket(v6Pub, new byte[256]);
            fail("expected IllegalArgumentException for a 256-octet locator hint on a v6 key");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        // the v4 encoding has no one-octet count, so it can carry a longer hint
        SecretKeyPacket v4 = new SecretKeyPacket(v4Pub, new byte[256]);
        isEquals("256-octet v4 locator hint should be accepted", 256,
                v4.getExternalKeyLocatorHint().length);
    }

    private PublicKeyPacket readPrimaryPublicKeyPacket(String asciiArmoredKey)
            throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(asciiArmoredKey.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = ArmoredInputStream.builder().build(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        return ((SecretKeyPacket)pIn.readPacket()).getPublicKeyPacket();
    }

    private void testPacketRoundTripping()
            throws IOException
    {
        assertPacketsCanBeRoundTripped(V4_TSK);
        assertPacketsCanBeRoundTripped(V4_TSK_AS_EXTERNAL_KEY);
        assertPacketsCanBeRoundTripped(V6_TSK);
        assertPacketsCanBeRoundTripped(V6_LOCKED_TSK);
        assertPacketsCanBeRoundTripped(V6_TSK_AS_EXTERNAL_KEY);
    }

    private void assertPacketsCanBeRoundTripped(String asciiArmoredPackets)
            throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(asciiArmoredPackets.getBytes());
        ArmoredInputStream aIn = ArmoredInputStream.builder()
                .build(bIn);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        Streams.pipeAll(aIn, bOut);
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
