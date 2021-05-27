package org.bouncycastle.tsp.ers;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.tsp.PartialHashtree;
import org.bouncycastle.operator.DigestCalculator;

class ERSUtil
{
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
          if (hashComp.compare(a, b) < 0)
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

    static byte[] calculateDigest(DigestCalculator digCalc, byte[][] data)
    {
        try
        {
            OutputStream mdOut = digCalc.getOutputStream();
            for (int i = 0; i != data.length; i++)
            {
                mdOut.write(data[i]);
            }

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

    static byte[] computeRootHash(DigestCalculator digCalc, PartialHashtree[] nodes)
    {
        List<byte[]> hashes = new ArrayList<byte[]>();
        for (int i = 0; i <= nodes.length - 2; i += 2)
        {
            byte[] left = computeNodeHash(digCalc, nodes[i]);
            byte[] right = computeNodeHash(digCalc, nodes[i + 1]);
 
            hashes.add(calculateBranchHash(digCalc, left, right));
        }

        if (nodes.length % 2 == 1)
        {
            hashes.add(computeNodeHash(digCalc, nodes[nodes.length - 1]));
        }

        List<byte[]> newHashes = new ArrayList<byte[]>((hashes.size() + 1 ) / 2);

        do
        {
            for (int i = 0; i <= hashes.size() - 2; i += 2)
            {
                newHashes.add(calculateBranchHash(digCalc, (byte[])hashes.get(i), (byte[])hashes.get(i + 1)));
            }

            if (hashes.size() % 2 == 1)
            {
                newHashes.add(hashes.get(hashes.size() - 1));
            }

            hashes = newHashes;
            newHashes = new ArrayList<byte[]>((hashes.size() + 1) / 2);
        }
        while (hashes.size() > 1);

        return (byte[])hashes.get(0);
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
        LinkedList<byte[]> hashes = new LinkedList<byte[]>();

        for (int i = 0; i != values.length; i++)
        {
            add(hashes, values[i]);
        }

        return hashes;
    }

    static List<byte[]> buildHashList(DigestCalculator digCalc, List<ERSData> dataObjects)
    {
        LinkedList<byte[]> hashes = new LinkedList<byte[]>();

        for (int i = 0; i != dataObjects.size(); i++)
        {
            add(hashes, ((ERSData)dataObjects.get(i)).getHash(digCalc));
        }

        return hashes;
    }

    private static void add(LinkedList<byte[]> hashes, byte[] hash)
    {
        if (hashes.size() == 0)
        {
             hashes.addFirst(hash);
        }
        else
        {
            if (hashComp.compare(hash, hashes.get(0)) < 0)
            {
                hashes.addFirst(hash);
            }
            else
            {
                int index = 1;
                while(index < hashes.size() && hashComp.compare(hash, hashes.get(index)) < 0)
                {
                    index++;
                }
                if (index == hashes.size())
                {
                    hashes.add(hash);
                }
                else
                {
                    hashes.add(index - 1, hash);
                }
            }
        }
    }
}
