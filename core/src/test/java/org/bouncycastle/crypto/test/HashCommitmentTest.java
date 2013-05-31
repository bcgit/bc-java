package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Commitment;
import org.bouncycastle.crypto.Committer;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.commitments.HashCommitter;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class HashCommitmentTest
    extends SimpleTest
{
    public String getName()
    {
        return "HashCommitmentTest";
    }

    public void performTest()
        throws Exception
    {
        byte[] data = Hex.decode("4e6f77206973207468652074696d6520666f7220616c6c20");

        Committer committer = new HashCommitter(new SHA256Digest(), new SecureRandom());

        Commitment c = committer.commit(data);

        committer = new HashCommitter(new SHA256Digest(), new SecureRandom());

        if (!committer.isRevealed(c, data))
        {
            fail("commitment failed to validate");
        }

        committer = new HashCommitter(new SHA1Digest(), new SecureRandom());

        if (committer.isRevealed(c, data))
        {
            fail("commitment validated!!");
        }

        // SHA1 has a block size of 512 bits, try a message that's too big

        try
        {
            c = committer.commit(new byte[33]);
        }
        catch (DataLengthException e)
        {
            if (!e.getMessage().equals("Message to be committed to too large for digest."))
            {
                fail("exception thrown but wrong message");
            }
        }
    }

    public static void main(String[] args)
    {
        runTest(new HashCommitmentTest());
    }
}
