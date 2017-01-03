package org.bouncycastle.asn1.test;


import java.util.Random;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.BodyPartPath;
import org.bouncycastle.util.test.SimpleTest;

public class BodyPartPathTest
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
            BodyPartPath bpp = new BodyPartPath(bpid);
            DERSequence _bpp = (DERSequence)bpp.toASN1Primitive();
            byte[] b = bpp.getEncoded();

            //
            // Decode and compare results.
            //

            BodyPartPath resList = BodyPartPath.getInstance(b);
            DERSequence _resList = (DERSequence)resList.toASN1Primitive();

            isEquals(_bpp.size(), _resList.size());

            for (int j = 0; j < _bpp.size(); j++)
            {
                isEquals(_resList.getObjectAt(j), _bpp.getObjectAt(j));
            }
        }
        {
            //
            // Compare when same thing instantiated via different constructors.
            //

            BodyPartID bpid = new BodyPartID(Math.abs(rand.nextLong() % 4294967295L));
            BodyPartPath bpidList = new BodyPartPath(bpid); // Single entry constructor.
            BodyPartPath resList = new BodyPartPath(new BodyPartID[]{bpid}); // Array constructor.

            DERSequence _bpidList = (DERSequence)bpidList.toASN1Primitive();
            DERSequence _resList = (DERSequence)resList.toASN1Primitive();

            isEquals(_bpidList, _resList);
        }
    }

    public String getName()
    {
        return "BodyPartPathTest";
    }

    public static void main(String[] args)
    {
        runTest(new BodyPartPathTest());
    }

}
