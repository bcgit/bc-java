package org.bouncycastle.tsp.ers;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.tsp.PartialHashtree;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.util.io.Streams;

class ERSUtil
{
    private ERSUtil()
    {

    }

    private static final Comparator<byte[]> hashComp = new ByteArrayComparator();

    static byte[] calculateDigest(DigestCalculator digCalc, byte[] data)
    {
        try
        {
            OutputStream mdOut = digCalc.getOutputStream();

            mdOut.write(data);

            mdOut.close();

            return digCalc.getDigest();
        }
        catch (IOException e)
        {
            throw ExpUtil.createIllegalState("unable to calculate hash: " + e.getMessage(), e);
        }
    }

    static byte[] calculateBranchHash(DigestCalculator digCalc, byte[] a, byte[] b)
    {
          if (hashComp.compare(a, b) <= 0)
          {
              return calculateDigest(digCalc, a, b);
          }
          else
          {
              return calculateDigest(digCalc, b, a);
          }
    }

    static byte[] calculateBranchHash(DigestCalculator digCalc, byte[][] values)
    {
        if (values.length == 2)
        {
            return calculateBranchHash(digCalc, values[0], values[1]);
        }

        return calculateDigest(digCalc, buildHashList(values).iterator());
    }

    static byte[] calculateDigest(DigestCalculator digCalc, byte[] a, byte[] b)
    {
        try
        {
            OutputStream mdOut = digCalc.getOutputStream();

            mdOut.write(a);
            mdOut.write(b);

            mdOut.close();

            return digCalc.getDigest();
        }
        catch (IOException e)
        {
            throw ExpUtil.createIllegalState("unable to calculate hash: " + e.getMessage(), e);
        }
    }
    
    static byte[] calculateDigest(DigestCalculator digCalc, Iterator<byte[]> dataGroup)
    {
        try
        {
            OutputStream mdOut = digCalc.getOutputStream();
            while (dataGroup.hasNext())
            {
                mdOut.write((byte[])dataGroup.next());
            }

            mdOut.close();

            return digCalc.getDigest();
        }
        catch (IOException e)
        {
            throw ExpUtil.createIllegalState("unable to calculate hash: " + e.getMessage(), e);
        }
    }

    static byte[] calculateDigest(DigestCalculator digCalc, InputStream inStream)
    {
        try
        {
            OutputStream mdOut = digCalc.getOutputStream();

            Streams.pipeAll(inStream, mdOut);

            mdOut.close();

            return digCalc.getDigest();
        }
        catch (IOException e)
        {
            throw ExpUtil.createIllegalState("unable to calculate hash: " + e.getMessage(), e);
        }
    }

    static byte[] computeNodeHash(DigestCalculator digCalc, PartialHashtree node)
    {
        byte[][] values = node.getValues();

        if (values.length > 1)
        {
            return calculateDigest(digCalc, buildHashList(values).iterator());
        }

        return values[0];
    }

    static List<byte[]> buildHashList(byte[][] values)
    {
        SortedHashList hashes = new SortedHashList();

        for (int i = 0; i != values.length; i++)
        {
            hashes.add(values[i]);
        }

        return hashes.toList();
    }

    static List<byte[]> buildHashList(DigestCalculator digCalc, List<ERSData> dataObjects)
    {
        SortedHashList hashes = new SortedHashList();

        for (int i = 0; i != dataObjects.size(); i++)
        {
            hashes.add(((ERSData)dataObjects.get(i)).getHash(digCalc));
        }

        return hashes.toList();
    }
}
