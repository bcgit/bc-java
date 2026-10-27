package org.bouncycastle.tls.test;

import java.io.ByteArrayOutputStream;
import java.util.Random;
import java.util.Vector;

import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsUtils;

import junit.framework.TestCase;

public class TlsUtilsTest
    extends TestCase
{
    public void testChooseSignatureAndHash()
        throws Exception
    {
        int keyExchangeAlgorithm = KeyExchangeAlgorithm.ECDHE_RSA;
        short signatureAlgorithm = TlsUtils.getLegacySignatureAlgorithmServer(keyExchangeAlgorithm);

        Vector supportedSignatureAlgorithms = getSignatureAlgorithms(false);
        SignatureAndHashAlgorithm sigAlg = TlsUtils.chooseSignatureAndHashAlgorithm(ProtocolVersion.TLSv12,
            supportedSignatureAlgorithms, signatureAlgorithm);
        assertEquals(HashAlgorithm.sha256, sigAlg.getHash());

        for (int count = 0; count < 10; ++count)
        {
            supportedSignatureAlgorithms = getSignatureAlgorithms(true);
            sigAlg = TlsUtils.chooseSignatureAndHashAlgorithm(ProtocolVersion.TLSv12, supportedSignatureAlgorithms,
                signatureAlgorithm);
            assertEquals(HashAlgorithm.sha256, sigAlg.getHash());
        }
    }

    /**
     * RFC 9147 5.3: "only suites with DTLS-OK=Y may be used", and 4.2.3 defines the record number mask only
     * for the AES and ChaCha20 ciphers, so a TLS 1.3 cipher suite is not automatically a DTLS 1.3 one: the
     * RFC 8998 SM4 suites (DTLS-OK=N, no mask definition) are not valid under DTLS 1.3, while remaining valid
     * for TLS 1.3.
     */
    public void testCipherSuiteValidityForDTLSv13()
    {
        int[] valid = { CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_AES_128_CCM_SHA256, CipherSuite.TLS_AES_128_CCM_8_SHA256,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256 };
        int[] excluded = { CipherSuite.TLS_SM4_GCM_SM3, CipherSuite.TLS_SM4_CCM_SM3 };

        for (int i = 0; i < valid.length; ++i)
        {
            assertTrue("valid under DTLS 1.3: " + valid[i],
                TlsUtils.isValidVersionForCipherSuite(valid[i], ProtocolVersion.DTLSv13));
            assertTrue("valid under TLS 1.3: " + valid[i],
                TlsUtils.isValidVersionForCipherSuite(valid[i], ProtocolVersion.TLSv13));
        }

        for (int i = 0; i < excluded.length; ++i)
        {
            assertFalse("DTLS-OK=N, so not valid under DTLS 1.3: " + excluded[i],
                TlsUtils.isValidVersionForCipherSuite(excluded[i], ProtocolVersion.DTLSv13));
            assertTrue("still valid for TLS 1.3: " + excluded[i],
                TlsUtils.isValidVersionForCipherSuite(excluded[i], ProtocolVersion.TLSv13));
        }

        // DTLS 1.2 is untouched by the rule: a 1.3-only suite is invalid there as before
        assertFalse(TlsUtils.isValidVersionForCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256,
            ProtocolVersion.DTLSv12));
        assertTrue(TlsUtils.isValidVersionForCipherSuite(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            ProtocolVersion.DTLSv12));
    }

    public void testEncodeSupportedSignatureAlgorithmsRejectsAnonymous()
        throws Exception
    {
        // RFC 5246 7.4.1.4.1: SignatureAlgorithm.anonymous MUST NOT appear in the
        // signature_algorithms extension. This is what CertificateRequest.encode relies on.
        Vector supportedSignatureAlgorithms = new Vector();
        supportedSignatureAlgorithms.addElement(
            new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.anonymous));

        try
        {
            TlsUtils.encodeSupportedSignatureAlgorithms(supportedSignatureAlgorithms, new ByteArrayOutputStream());
            fail("expected IllegalArgumentException for SignatureAlgorithm.anonymous");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("SignatureAlgorithm.anonymous MUST NOT appear in the signature_algorithms extension",
                e.getMessage());
        }
    }

    private static Vector getSignatureAlgorithms(boolean randomise)
    {
        short[] hashAlgorithms = new short[]{ HashAlgorithm.sha1, HashAlgorithm.sha224, HashAlgorithm.sha256,
            HashAlgorithm.sha384, HashAlgorithm.sha512, HashAlgorithm.md5 };
        short[] signatureAlgorithms = new short[]{ SignatureAlgorithm.rsa, SignatureAlgorithm.dsa,
            SignatureAlgorithm.ecdsa };

        Vector result = new Vector();
        for (int i = 0; i < signatureAlgorithms.length; ++i)
        {
            for (int j = 0; j < hashAlgorithms.length; ++j)
            {
                result.addElement(new SignatureAndHashAlgorithm(hashAlgorithms[j], signatureAlgorithms[i]));
            }
        }

        if (randomise)
        {
            Random r = new Random();
            int count = result.size();
            for (int src = 0; src < count; ++src)
            {
                int dst = r.nextInt(count);
                if (src != dst)
                {
                    Object a = result.elementAt(src), b = result.elementAt(dst);
                    result.setElementAt(a, dst);
                    result.setElementAt(b, src);
                }
            }
        }

        return result;
    }
}
