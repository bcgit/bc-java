package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class CertHashUnitTest
    extends ASN1UnitTest
{
    public String getName()
    {
        return "CertHash";
    }

    public void performTest()
        throws Exception
    {
        AlgorithmIdentifier algId = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.2.3"));
        byte[]              digest = new byte[20];
        
        CertHash certID = new CertHash(algId, digest);

        checkConstruction(certID, algId, digest);

        certID = CertHash.getInstance(null);

        if (certID != null)
        {
            fail("null getInstance() failed.");
        }

        try
        {
            CertHash.getInstance(new Object());

            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        CertHash certHash,
        AlgorithmIdentifier algId,
        byte[] digest)
        throws IOException
    {
        checkValues(certHash, algId, digest);

        certHash = CertHash.getInstance(certHash);

        checkValues(certHash, algId, digest);

        ASN1InputStream aIn = new ASN1InputStream(certHash.toASN1Primitive().getEncoded());

        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

        certHash = CertHash.getInstance(seq);

        checkValues(certHash, algId, digest);
    }

    private void checkValues(
        CertHash certHash,
        AlgorithmIdentifier algId,
        byte[] digest)
    {
        checkMandatoryField("algorithmHash", algId, certHash.getHashAlgorithm());

        checkMandatoryField("certificateHash", digest, certHash.getCertificateHash());
    }

    public static void main(
        String[]    args)
    {
        runTest(new CertHashUnitTest());
    }
}
