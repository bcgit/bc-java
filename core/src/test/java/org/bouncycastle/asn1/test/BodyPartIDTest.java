package org.bouncycastle.asn1.test;


import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.util.test.SimpleTest;

public class BodyPartIDTest
    extends SimpleTest
{


    public void performTest()
        throws Exception
    {
        // Test correct encode / decode


        {
            // Test encode and decode from Long and from other instance of BodyPartID
            BodyPartID bpd = new BodyPartID(10L);
            byte[] b = bpd.getEncoded();
            BodyPartID resBpd = BodyPartID.getInstance(b);
            isEquals("Correct / Encode byte array", resBpd.getID(), bpd.getID());

            BodyPartID rootPartID = new BodyPartID(12L);
            bpd = BodyPartID.getInstance(rootPartID);
            b = bpd.getEncoded();
            resBpd = BodyPartID.getInstance(b);
            isEquals("Correct / Encode byte array", resBpd.getID(), rootPartID.getID());
        }


        {
            // Test lower limit, should not throw exception
            try
            {
                new BodyPartID(0);
            }
            catch (Throwable t)
            {
                fail("Unexpected exception: " + t.getMessage(), t);
            }

            // Test below lower range
            try
            {
                new BodyPartID(-1);
                fail("Expecting IllegalArgumentException because of outside lower range");
            }
            catch (Throwable e)
            {
                if (!(e instanceof IllegalArgumentException))
                {
                    fail("Expecting only IllegalArgumentException, got:" + e.getMessage(), e);
                }
            }
        }

        {
            // Test upper limit, should not throw exception.
            try
            {
                new BodyPartID(4294967295L);
            }
            catch (Throwable t)
            {
                fail("Unexpected exception: " + t.getMessage(), t);
            }

            // Test above upper range
            try
            {
                new BodyPartID(4294967296L);
                fail("Expecting IllegalArgumentException because of outside upper range");
            }
            catch (Throwable e)
            {
                if (!(e instanceof IllegalArgumentException))
                {
                    fail("Expecting only IllegalArgumentException, got:" + e.getMessage(), e);
                }
            }
        }
    }

    public String getName()
    {
        return "BodyPartIDTest";
    }

    public static void main(String[] args)
        throws Exception
    {
        runTest(new BodyPartIDTest());
    }
}

