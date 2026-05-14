package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QcType;
import org.bouncycastle.util.test.SimpleTest;

public class QcTypeUnitTest
    extends SimpleTest
{
    public String getName()
    {
        return "QcType";
    }

    public void performTest()
        throws Exception
    {
        // Single-type construction.
        QcType esign = new QcType(ETSIQCObjectIdentifiers.id_etsi_qct_esign);
        checkRoundTrip(esign, new ASN1ObjectIdentifier[]{ ETSIQCObjectIdentifiers.id_etsi_qct_esign });

        if (!esign.hasType(ETSIQCObjectIdentifiers.id_etsi_qct_esign))
        {
            fail("hasType failed to find esign");
        }
        if (esign.hasType(ETSIQCObjectIdentifiers.id_etsi_qct_eseal))
        {
            fail("hasType reported eseal in an esign-only QcType");
        }

        // Multi-type construction.
        ASN1ObjectIdentifier[] all = new ASN1ObjectIdentifier[]{
            ETSIQCObjectIdentifiers.id_etsi_qct_esign,
            ETSIQCObjectIdentifiers.id_etsi_qct_eseal,
            ETSIQCObjectIdentifiers.id_etsi_qct_web
        };
        QcType multi = new QcType(all);
        checkRoundTrip(multi, all);

        if (!multi.hasType(ETSIQCObjectIdentifiers.id_etsi_qct_esign)
            || !multi.hasType(ETSIQCObjectIdentifiers.id_etsi_qct_eseal)
            || !multi.hasType(ETSIQCObjectIdentifiers.id_etsi_qct_web))
        {
            fail("hasType missed a declared type");
        }

        // Constructor defensively copies.
        all[0] = ETSIQCObjectIdentifiers.id_etsi_qct_web;
        if (!multi.hasType(ETSIQCObjectIdentifiers.id_etsi_qct_esign))
        {
            fail("QcType constructor did not copy the input array");
        }

        // getInstance(null).
        if (QcType.getInstance(null) != null)
        {
            fail("null getInstance() failed.");
        }

        // getInstance() rejects garbage.
        try
        {
            QcType.getInstance(new Object());
            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkRoundTrip(QcType qcType, ASN1ObjectIdentifier[] expected)
        throws Exception
    {
        checkTypes(qcType, expected);

        // through getInstance directly
        checkTypes(QcType.getInstance(qcType), expected);

        // through encode -> parse
        byte[] encoded = qcType.toASN1Primitive().getEncoded();
        ASN1InputStream aIn = new ASN1InputStream(encoded);
        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();
        checkTypes(QcType.getInstance(seq), expected);
    }

    private void checkTypes(QcType qcType, ASN1ObjectIdentifier[] expected)
    {
        ASN1ObjectIdentifier[] actual = qcType.getTypes();
        if (actual.length != expected.length)
        {
            fail("type count mismatch: expected " + expected.length + ", got " + actual.length);
        }
        for (int i = 0; i != expected.length; i++)
        {
            if (!expected[i].equals(actual[i]))
            {
                fail("type[" + i + "] mismatch: expected " + expected[i] + ", got " + actual[i]);
            }
        }
    }

    public static void main(String[] args)
    {
        runTest(new QcTypeUnitTest());
    }
}
