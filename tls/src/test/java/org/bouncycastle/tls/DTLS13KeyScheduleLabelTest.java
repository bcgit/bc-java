package org.bouncycastle.tls;

import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.tls.crypto.CryptoHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsSecret;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * RFC 9147 5.9: "Section 7.1 of [TLS13] specifies that HKDF-Expand-Label uses a label prefix of 'tls13 '. For
 * DTLS 1.3, that label SHALL be 'dtls13'." Every DTLS 1.3 secret, traffic key, record number key, Finished key and
 * exporter value depends on it, so a wrong prefix fails against every non-BC peer while passing every BC-to-BC
 * test. The expected values are therefore computed here with an independent HKDF-Expand (javax.crypto HMAC), not
 * with another BC code path.
 */
public class DTLS13KeyScheduleLabelTest
    extends TestCase
{
    private static final byte[] SECRET = Strings.toByteArray("0123456789abcdef0123456789abcdef");
    private static final byte[] CONTEXT = Strings.toByteArray("transcript-hash-stand-in-value!!");

    public void testDTLS13PrefixIsDtls13WithoutTrailingSpace() throws Exception
    {
        checkLabel(true, "dtls13", "key", 16);
        checkLabel(true, "dtls13", "iv", 12);
        checkLabel(true, "dtls13", "sn", 16);
        checkLabel(true, "dtls13", "s hs traffic", 32);
        checkLabel(true, "dtls13", "finished", 32);
        checkLabel(true, "dtls13", "exporter", 60);
    }

    public void testTLS13PrefixIsUnchanged() throws Exception
    {
        checkLabel(false, "tls13 ", "key", 16);
        checkLabel(false, "tls13 ", "s hs traffic", 32);
    }

    public void testTheTwoPrefixesGiveDifferentKeys() throws Exception
    {
        TlsSecret secret = secret();
        byte[] tls = TlsCryptoUtils.hkdfExpandLabel(secret, CryptoHashAlgorithm.sha256, "key", CONTEXT, 16, false)
            .extract();
        byte[] dtls = TlsCryptoUtils.hkdfExpandLabel(secret, CryptoHashAlgorithm.sha256, "key", CONTEXT, 16, true)
            .extract();
        assertFalse("DTLS 1.3 and TLS 1.3 must derive different keys from the same secret",
            Arrays.areEqual(tls, dtls));
    }

    public void testFiveArgumentOverloadIsTheTLSForm() throws Exception
    {
        TlsSecret secret = secret();
        byte[] implicit = TlsCryptoUtils.hkdfExpandLabel(secret, CryptoHashAlgorithm.sha256, "key", CONTEXT, 16)
            .extract();
        byte[] explicit = TlsCryptoUtils.hkdfExpandLabel(secret, CryptoHashAlgorithm.sha256, "key", CONTEXT, 16,
            false).extract();
        assertTrue(Arrays.areEqual(explicit, implicit));
    }

    private void checkLabel(boolean isDTLS, String expectedPrefix, String label, int length) throws Exception
    {
        byte[] actual = TlsCryptoUtils.hkdfExpandLabel(secret(), CryptoHashAlgorithm.sha256, label, CONTEXT, length,
            isDTLS).extract();
        byte[] expected = hkdfExpandLabel(SECRET, expectedPrefix + label, CONTEXT, length);
        assertTrue("HKDF-Expand-Label(\"" + expectedPrefix + label + "\")", Arrays.areEqual(expected, actual));
    }

    private static TlsSecret secret()
    {
        return new BcTlsSecret(new BcTlsCrypto(new SecureRandom()), Arrays.clone(SECRET));
    }

    /**
     * RFC 8446 7.1 HKDF-Expand-Label, built from the RFC 5869 HKDF-Expand definition with javax.crypto's
     * HMAC-SHA256, independently of BC's TLS code.
     */
    private static byte[] hkdfExpandLabel(byte[] secret, String fullLabel, byte[] context, int length)
        throws Exception
    {
        byte[] labelBytes = Strings.toByteArray(fullLabel);

        byte[] hkdfLabel = new byte[2 + 1 + labelBytes.length + 1 + context.length];
        hkdfLabel[0] = (byte)(length >>> 8);
        hkdfLabel[1] = (byte)length;
        hkdfLabel[2] = (byte)labelBytes.length;
        System.arraycopy(labelBytes, 0, hkdfLabel, 3, labelBytes.length);
        hkdfLabel[3 + labelBytes.length] = (byte)context.length;
        System.arraycopy(context, 0, hkdfLabel, 4 + labelBytes.length, context.length);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret, "HmacSHA256"));

        byte[] okm = new byte[length];
        byte[] t = new byte[0];
        int pos = 0;
        for (int counter = 1; pos < length; ++counter)
        {
            mac.reset();
            mac.update(t);
            mac.update(hkdfLabel);
            mac.update((byte)counter);
            t = mac.doFinal();
            int n = Math.min(t.length, length - pos);
            System.arraycopy(t, 0, okm, pos, n);
            pos += n;
        }
        return okm;
    }
}
