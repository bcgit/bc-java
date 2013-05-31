package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERBoolean;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Set sorting test example
 */
public class SetTest
    extends SimpleTest
{

    public String getName()
    {
        return "Set";
    }

    private void checkedSortedSet(int attempt, ASN1Set s)
    {
        if (s.getObjectAt(0) instanceof DERBoolean
            && s.getObjectAt(1) instanceof DERInteger
            && s.getObjectAt(2) instanceof DERBitString
            && s.getObjectAt(3) instanceof DEROctetString)
        {
            return;
        }

        fail("sorting failed on attempt: " + attempt);
    }

    public void performTest()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        byte[] data = new byte[10];

        v.add(new DEROctetString(data));
        v.add(new DERBitString(data));
        v.add(new DERInteger(100));
        v.add(new DERBoolean(true));

        checkedSortedSet(0, new DERSet(v));

        v = new ASN1EncodableVector();
        v.add(new DERInteger(100));
        v.add(new DERBoolean(true));
        v.add(new DEROctetString(data));
        v.add(new DERBitString(data));

        checkedSortedSet(1, new DERSet(v));

        v = new ASN1EncodableVector();
        v.add(new DERBoolean(true));
        v.add(new DEROctetString(data));
        v.add(new DERBitString(data));
        v.add(new DERInteger(100));


        checkedSortedSet(2, new DERSet(v));

        v = new ASN1EncodableVector();
        v.add(new DERBitString(data));
        v.add(new DEROctetString(data));
        v.add(new DERInteger(100));
        v.add(new DERBoolean(true));

        checkedSortedSet(3, new DERSet(v));

        v = new ASN1EncodableVector();
        v.add(new DEROctetString(data));
        v.add(new DERBitString(data));
        v.add(new DERInteger(100));
        v.add(new DERBoolean(true));

        ASN1Set s = new BERSet(v);

        if (!(s.getObjectAt(0) instanceof DEROctetString))
        {
            fail("BER set sort order changed.");
        }

        // create an implicitly tagged "set" without sorting
        ASN1TaggedObject tag = new DERTaggedObject(false, 1, new DERSequence(v));
        s = ASN1Set.getInstance(tag, false);

        if (s.getObjectAt(0) instanceof DERBoolean)
        {
            fail("sorted when shouldn't be.");
        }

        // equality test
        v = new ASN1EncodableVector();

        v.add(new DERBoolean(true));
        v.add(new DERBoolean(true));
        v.add(new DERBoolean(true));

        s = new DERSet(v);
    }

    public static void main(
        String[]    args)
    {
        runTest(new SetTest());
    }
}
