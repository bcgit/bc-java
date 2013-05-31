package org.bouncycastle.cms.test;

import java.math.BigInteger;
import java.security.cert.X509CertSelector;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.jcajce.JcaSelectorConverter;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.util.Arrays;

public class ConverterTest
    extends TestCase
{
    public void testSignerIdConversion()
        throws Exception
    {
        JcaX509CertSelectorConverter converter = new JcaX509CertSelectorConverter();
        JcaSelectorConverter toSelector = new JcaSelectorConverter();

        SignerId sid1 = new SignerId(new X500Name("CN=Test"), BigInteger.valueOf(1), new byte[20]);

        X509CertSelector conv = converter.getCertSelector(sid1);

        assertTrue(conv.getIssuerAsString().equals("CN=Test"));
        assertTrue(Arrays.areEqual(conv.getSubjectKeyIdentifier(), new DEROctetString(new byte[20]).getEncoded()));
        assertEquals(conv.getSerialNumber(), sid1.getSerialNumber());

        SignerId sid2 = toSelector.getSignerId(conv);

        assertEquals(sid1, sid2);

        sid1 = new SignerId(new X500Name("CN=Test"), BigInteger.valueOf(1));

        conv = converter.getCertSelector(sid1);

        assertTrue(conv.getIssuerAsString().equals("CN=Test"));
        assertNull(conv.getSubjectKeyIdentifier());
        assertEquals(conv.getSerialNumber(), sid1.getSerialNumber());

        sid2 = toSelector.getSignerId(conv);

        assertEquals(sid1, sid2);

        sid1 = new SignerId(new byte[20]);

        conv = converter.getCertSelector(sid1);

        assertNull(conv.getIssuerAsString());
        assertTrue(Arrays.areEqual(conv.getSubjectKeyIdentifier(), new DEROctetString(new byte[20]).getEncoded()));
        assertNull(conv.getSerialNumber());

        sid2 = toSelector.getSignerId(conv);

        assertEquals(sid1, sid2);
    }

    public void testRecipientIdConversion()
        throws Exception
    {
        JcaX509CertSelectorConverter converter = new JcaX509CertSelectorConverter();
        JcaSelectorConverter toSelector = new JcaSelectorConverter();

        KeyTransRecipientId ktid1 = new KeyTransRecipientId(new X500Name("CN=Test"), BigInteger.valueOf(1), new byte[20]);

        X509CertSelector conv = converter.getCertSelector(ktid1);

        assertTrue(conv.getIssuerAsString().equals("CN=Test"));
        assertTrue(Arrays.areEqual(conv.getSubjectKeyIdentifier(), new DEROctetString(new byte[20]).getEncoded()));
        assertEquals(conv.getSerialNumber(), ktid1.getSerialNumber());

        KeyTransRecipientId ktid2 = toSelector.getKeyTransRecipientId(conv);

        assertEquals(ktid1, ktid2);

        ktid1 = new KeyTransRecipientId(new X500Name("CN=Test"), BigInteger.valueOf(1));

        conv = converter.getCertSelector(ktid1);

        assertTrue(conv.getIssuerAsString().equals("CN=Test"));
        assertNull(conv.getSubjectKeyIdentifier());
        assertEquals(conv.getSerialNumber(), ktid1.getSerialNumber());

        ktid2 = toSelector.getKeyTransRecipientId(conv);

        assertEquals(ktid1, ktid2);

        ktid1 = new KeyTransRecipientId(new byte[20]);

        conv = converter.getCertSelector(ktid1);

        assertNull(conv.getIssuerAsString());
        assertTrue(Arrays.areEqual(conv.getSubjectKeyIdentifier(), new DEROctetString(new byte[20]).getEncoded()));
        assertNull(conv.getSerialNumber());

        ktid2 = toSelector.getKeyTransRecipientId(conv);

        assertEquals(ktid1, ktid2);
    }

    public static Test suite()
        throws Exception
    {
        return new TestSuite(ConverterTest.class);
    }
}
