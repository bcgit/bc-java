package org.bouncycastle.asn1.cms.test;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Confirms org.bouncycastle.asn1.cms.SignerInfo decodes its version and trailing unsignedAttrs
 * elements through getInstance rather than a direct cast, so a malformed-but-parseable SignerInfo
 * fails with IllegalArgumentException (the getInstance contract) rather than leaking a
 * ClassCastException. Relates to github #2342.
 */
public class SignerInfoTest
    extends SimpleTest
{
    public String getName()
    {
        return "SignerInfoTest";
    }

    public void performTest()
        throws Exception
    {
        SignerIdentifier sid = new SignerIdentifier(new DEROctetString(new byte[]{1, 2, 3, 4, 5}));
        AlgorithmIdentifier digAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"));
        AlgorithmIdentifier encAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.1"));
        DEROctetString encryptedDigest = new DEROctetString(new byte[]{6, 7, 8, 9});

        SignerInfo signerInfo = new SignerInfo(sid, digAlg, (ASN1Set)null, encAlg, encryptedDigest, (ASN1Set)null);

        ASN1Sequence seq = ASN1Sequence.getInstance(signerInfo.toASN1Primitive());

        // well-formed round-trip
        isTrue("SignerInfo round-trip", areEqual(signerInfo.getEncoded(), SignerInfo.getInstance(seq).getEncoded()));

        // version element is not an INTEGER
        ASN1EncodableVector badVersion = new ASN1EncodableVector();
        badVersion.add(new DERUTF8String("not an integer"));
        for (int i = 1; i != seq.size(); i++)
        {
            badVersion.add(seq.getObjectAt(i));
        }
        expectIllegalArgument("non-INTEGER version", new DERSequence(badVersion));

        // trailing unsignedAttrs element is not a tagged object
        ASN1EncodableVector badUnsigned = new ASN1EncodableVector();
        for (int i = 0; i != seq.size(); i++)
        {
            badUnsigned.add(seq.getObjectAt(i));
        }
        badUnsigned.add(new ASN1Integer(99));
        expectIllegalArgument("non-tagged unsignedAttrs", new DERSequence(badUnsigned));
    }

    private void expectIllegalArgument(String label, ASN1Sequence malformed)
    {
        try
        {
            SignerInfo.getInstance(malformed);
            fail("malformed SignerInfo (" + label + ") not rejected");
        }
        catch (IllegalArgumentException e)
        {
            // expected - the getInstance contract, not a leaked ClassCastException
        }
    }

    public static void main(String[] args)
    {
        runTest(new SignerInfoTest());
    }
}
