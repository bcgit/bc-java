package org.bouncycastle.cert.test;

import java.math.BigInteger;
import org.bouncycastle.jce.cert.X509CertSelector;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.selector.X509CertificateHolderSelector;
import org.bouncycastle.cert.selector.jcajce.JcaSelectorConverter;
import org.bouncycastle.cert.selector.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.util.Arrays;

public class ConverterTest
    extends TestCase
{
    public void testCertificateSelectorConversion()
        throws Exception
    {
        JcaX509CertSelectorConverter converter = new JcaX509CertSelectorConverter();
        JcaSelectorConverter toSelector = new JcaSelectorConverter();

        X509CertificateHolderSelector sid1 = new X509CertificateHolderSelector(new X500Name("CN=Test"), BigInteger.valueOf(1), new byte[20]);

        X509CertSelector conv = converter.getCertSelector(sid1);

        assertTrue(conv.getIssuerAsString().equals("CN=Test"));
        assertTrue(Arrays.areEqual(conv.getSubjectKeyIdentifier(), new DEROctetString(new byte[20]).getEncoded()));
        assertEquals(conv.getSerialNumber(), sid1.getSerialNumber());

        X509CertificateHolderSelector sid2 = toSelector.getCertificateHolderSelector(conv);

        assertEquals(sid1, sid2);

        sid1 = new X509CertificateHolderSelector(new X500Name("CN=Test"), BigInteger.valueOf(1));

        conv = converter.getCertSelector(sid1);

        assertTrue(conv.getIssuerAsString().equals("CN=Test"));
        assertNull(conv.getSubjectKeyIdentifier());
        assertEquals(conv.getSerialNumber(), sid1.getSerialNumber());

        sid2 = toSelector.getCertificateHolderSelector(conv);

        assertEquals(sid1, sid2);

        sid1 = new X509CertificateHolderSelector(new byte[20]);

        conv = converter.getCertSelector(sid1);

        assertNull(conv.getIssuerAsString());
        assertTrue(Arrays.areEqual(conv.getSubjectKeyIdentifier(), new DEROctetString(new byte[20]).getEncoded()));
        assertNull(conv.getSerialNumber());

        sid2 = toSelector.getCertificateHolderSelector(conv);

        assertEquals(sid1, sid2);
    }
    
    public static Test suite() 
    {
        return new TestSuite(ConverterTest.class);
    }
}
