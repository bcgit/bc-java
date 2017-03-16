package org.bouncycastle.asn1.test;

import java.util.Random;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.BodyPartList;
import org.bouncycastle.util.test.SimpleTest;


/**
 * Test the creation of BodyPartListTest and encoding and decoding.
 */
public class BodyPartListTest
    extends SimpleTest
{

    public void performTest()
        throws Exception
    {
        Random rand = new Random();
        {
            BodyPartID[] bpid = new BodyPartID[Math.abs(rand.nextInt()) % 20];
            for (int t = 0; t < bpid.length; t++)
            {
                bpid[t] = new BodyPartID(Math.abs(rand.nextLong() % 4294967295L));
            }
            BodyPartList bpl = new BodyPartList(bpid);
            DERSequence _bpl = (DERSequence)bpl.toASN1Primitive();
            byte[] b = bpl.getEncoded();

            //
            // Decode and compare results.
            //

            BodyPartList resList = BodyPartList.getInstance(b);
            DERSequence _resList = (DERSequence)resList.toASN1Primitive();

            isEquals(_bpl.size(), _resList.size());

            for (int j = 0; j < _bpl.size(); j++)
            {
                isEquals(_resList.getObjectAt(j), _bpl.getObjectAt(j));
            }
        }
        {
            //
            // Compare when same thing instantiated via different constructors.
            //

            BodyPartID bpid = new BodyPartID(Math.abs(rand.nextLong() % 4294967295L));
            BodyPartList bpidList = new BodyPartList(bpid); // Single entry constructor.
            BodyPartList resList = new BodyPartList(new BodyPartID[]{bpid}); // Array constructor.

            DERSequence _bpidList = (DERSequence)bpidList.toASN1Primitive();
            DERSequence _resList = (DERSequence)resList.toASN1Primitive();

            isEquals(_bpidList, _resList);
        }
    }

    public String getName()
    {
        return "BodyPartListTest";
    }

    public static void main(String[] args)
    {
        runTest(new BodyPartListTest());
    }
}
