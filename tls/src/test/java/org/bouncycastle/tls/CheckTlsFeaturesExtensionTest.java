package org.bouncycastle.tls;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsEncryptor;
import org.bouncycastle.tls.crypto.TlsVerifier;
import org.bouncycastle.tls.crypto.Tls13Verifier;

import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Regression tests for {@link TlsUtils#checkTlsFeatures} handling of the RFC 7633 id-pe-tlsfeature
 * (1.3.6.1.5.5.7.1.24) certificate extension. Lives in the {@code org.bouncycastle.tls} package so
 * that it can drive the package-private {@code checkTlsFeatures} method directly.
 */
public class CheckTlsFeaturesExtensionTest
    extends TestCase
{
    /**
     * A non-SEQUENCE top-level object in the extension (here an INTEGER) must be rejected with a
     * {@link TlsFatalAlert} -- previously the bare cast in checkTlsFeatures threw an unchecked
     * ClassCastException out of the IOException-declared handshake path.
     */
    public void testNonSequenceTlsFeaturesRejected()
        throws Exception
    {
        // id-pe-tlsfeature extension whose content is an INTEGER, not the RFC 7633 SEQUENCE OF INTEGER.
        byte[] nonSequence = new ASN1Integer(5).getEncoded(ASN1Encoding.DER);

        Certificate serverCertificate = makeCertificate(nonSequence);

        try
        {
            TlsUtils.checkTlsFeatures(serverCertificate, new Hashtable(), new Hashtable());
            fail("expected TlsFatalAlert for non-SEQUENCE TLS Features extension");
        }
        catch (TlsFatalAlert e)
        {
            assertEquals(AlertDescription.bad_certificate, e.getAlertDescription());
            // TlsFatalAlert prefixes the alert text; the detail message is appended after "; ".
            assertTrue(e.getMessage().endsWith("Server certificate has invalid TLS Features extension"));
        }
    }

    /**
     * A well-formed SEQUENCE OF INTEGER extension whose features are all satisfied by the offered
     * server extensions passes the check (no exception) -- proves the new guard never fires for a
     * conforming certificate.
     */
    public void testValidTlsFeaturesAccepted()
        throws Exception
    {
        ASN1Encodable[] features = new ASN1Encodable[]{ new ASN1Integer(5) };
        byte[] seq = new DERSequence(features).getEncoded(ASN1Encoding.DER);

        Certificate serverCertificate = makeCertificate(seq);

        // No client extensions requested, so nothing to enforce: must complete cleanly.
        TlsUtils.checkTlsFeatures(serverCertificate, new Hashtable(), new Hashtable());
    }

    /**
     * No id-pe-tlsfeature extension present at all -- must complete cleanly.
     */
    public void testNoTlsFeaturesExtension()
        throws Exception
    {
        Certificate serverCertificate = makeCertificate(null);

        TlsUtils.checkTlsFeatures(serverCertificate, new Hashtable(), new Hashtable());
    }

    private static Certificate makeCertificate(byte[] tlsFeaturesExtensionContent)
    {
        TlsCertificate stub = new StubTlsCertificate(tlsFeaturesExtensionContent);
        return new Certificate(new TlsCertificate[]{ stub });
    }

    public static TestSuite suite()
    {
        return new TestSuite(CheckTlsFeaturesExtensionTest.class);
    }

    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }

    /**
     * Minimal {@link TlsCertificate} that only answers {@link #getExtension} for the id-pe-tlsfeature
     * OID; every other method is unused by {@code checkTlsFeatures}.
     */
    private static class StubTlsCertificate
        implements TlsCertificate
    {
        private final byte[] tlsFeaturesExtensionContent;

        StubTlsCertificate(byte[] tlsFeaturesExtensionContent)
        {
            this.tlsFeaturesExtensionContent = tlsFeaturesExtensionContent;
        }

        public byte[] getExtension(ASN1ObjectIdentifier extensionOID)
            throws IOException
        {
            if (TlsObjectIdentifiers.id_pe_tlsfeature.equals(extensionOID))
            {
                return Arrays_clone(tlsFeaturesExtensionContent);
            }
            return null;
        }

        public TlsEncryptor createEncryptor(int tlsCertificateRole)
            throws IOException
        {
            throw new UnsupportedOperationException();
        }

        public TlsVerifier createVerifier(short signatureAlgorithm)
            throws IOException
        {
            throw new UnsupportedOperationException();
        }

        public Tls13Verifier createVerifier(int signatureScheme)
            throws IOException
        {
            throw new UnsupportedOperationException();
        }

        public byte[] getEncoded()
            throws IOException
        {
            throw new UnsupportedOperationException();
        }

        public BigInteger getSerialNumber()
        {
            throw new UnsupportedOperationException();
        }

        public String getSigAlgOID()
        {
            throw new UnsupportedOperationException();
        }

        public ASN1Encodable getSigAlgParams()
            throws IOException
        {
            throw new UnsupportedOperationException();
        }

        public short getLegacySignatureAlgorithm()
            throws IOException
        {
            throw new UnsupportedOperationException();
        }

        public boolean supportsSignatureAlgorithm(short signatureAlgorithm)
            throws IOException
        {
            throw new UnsupportedOperationException();
        }

        public boolean supportsSignatureAlgorithmCA(short signatureAlgorithm)
            throws IOException
        {
            throw new UnsupportedOperationException();
        }

        public TlsCertificate checkUsageInRole(int tlsCertificateRole)
            throws IOException
        {
            throw new UnsupportedOperationException();
        }

        private static byte[] Arrays_clone(byte[] data)
        {
            return data == null ? null : (byte[])data.clone();
        }
    }
}
