package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public abstract class DigestTest 
    extends SimpleTest
{
    private Digest digest;
    private String[] input;
    private String[] results;

    DigestTest(
        Digest digest,
        String[] input,
        String[] results)
    {
        this.digest = digest;
        this.input = input;
        this.results = results;
    }
    
    public String getName()
    {
        return digest.getAlgorithmName();
    }
    
    public void performTest()
    {
        byte[] resBuf = new byte[digest.getDigestSize()];
    
        for (int i = 0; i < input.length - 1; i++)
        {
            byte[] m = toByteArray(input[i]);
            
            vectorTest(digest, i, resBuf, m, Hex.decode(results[i]));
        }
        
        byte[] lastV = toByteArray(input[input.length - 1]);
        byte[] lastDigest = Hex.decode(results[input.length - 1]);
        
        vectorTest(digest, input.length - 1, resBuf, lastV, Hex.decode(results[input.length - 1]));
        
        //
        // clone test
        //
        digest.update(lastV, 0, lastV.length/2);

        // clone the Digest
        Digest d = cloneDigest(digest);
        
        digest.update(lastV, lastV.length/2, lastV.length - lastV.length/2);
        digest.doFinal(resBuf, 0);

        if (!areEqual(lastDigest, resBuf))
        {
            fail("failing clone vector test", results[results.length - 1], new String(Hex.encode(resBuf)));
        }

        d.update(lastV, lastV.length/2, lastV.length - lastV.length/2);
        d.doFinal(resBuf, 0);

        if (!areEqual(lastDigest, resBuf))
        {
            fail("failing second clone vector test", results[results.length - 1], new String(Hex.encode(resBuf)));
        }

        //
        // memo test
        //
        Memoable m = (Memoable)digest;

        digest.update(lastV, 0, lastV.length/2);

        // copy the Digest
        Memoable copy1 = m.copy();
        Memoable copy2 = copy1.copy();

        digest.update(lastV, lastV.length/2, lastV.length - lastV.length/2);
        digest.doFinal(resBuf, 0);

        if (!areEqual(lastDigest, resBuf))
        {
            fail("failing memo vector test", results[results.length - 1], new String(Hex.encode(resBuf)));
        }

        m.reset(copy1);

        digest.update(lastV, lastV.length/2, lastV.length - lastV.length/2);
        digest.doFinal(resBuf, 0);

        if (!areEqual(lastDigest, resBuf))
        {
            fail("failing memo reset vector test", results[results.length - 1], new String(Hex.encode(resBuf)));
        }

        Digest md = (Digest)copy2;

        md.update(lastV, lastV.length/2, lastV.length - lastV.length/2);
        md.doFinal(resBuf, 0);

        if (!areEqual(lastDigest, resBuf))
        {
            fail("failing memo copy vector test", results[results.length - 1], new String(Hex.encode(resBuf)));
        }
    }

    private byte[] toByteArray(String input)
    {
        byte[] bytes = new byte[input.length()];
        
        for (int i = 0; i != bytes.length; i++)
        {
            bytes[i] = (byte)input.charAt(i);
        }
        
        return bytes;
    }
    
    private void vectorTest(
        Digest digest,
        int count,
        byte[] resBuf,
        byte[] input,
        byte[] expected)
    {
        digest.update(input, 0, input.length);
        digest.doFinal(resBuf, 0);

        if (!areEqual(resBuf, expected))
        {
            fail("Vector " + count + " failed got " + new String(Hex.encode(resBuf)));
        }
    }
    
    protected abstract Digest cloneDigest(Digest digest);
    
    //
    // optional tests
    //
    protected void millionATest(
        String expected)
    {
        byte[] resBuf = new byte[digest.getDigestSize()];
        
        for (int i = 0; i < 1000000; i++)
        {
            digest.update((byte)'a');
        }
        
        digest.doFinal(resBuf, 0);

        if (!areEqual(resBuf, Hex.decode(expected)))
        {
            fail("Million a's failed", expected, new String(Hex.encode(resBuf)));
        }
    }
    
    protected void sixtyFourKTest(
        String expected)
    {
        byte[] resBuf = new byte[digest.getDigestSize()];
        
        for (int i = 0; i < 65536; i++)
        {
            digest.update((byte)(i & 0xff));
        }
        
        digest.doFinal(resBuf, 0);

        if (!areEqual(resBuf, Hex.decode(expected)))
        {
            fail("64k test failed", expected, new String(Hex.encode(resBuf)));
        }
    }
}
