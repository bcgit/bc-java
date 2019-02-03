package org.bouncycastle.tsp;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.TreeSet;

import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.util.Arrays;

/**
 * Representation of data groups according to the description provided in RFC4998.
 * <p>
 * Such data groups represent a set of one or more data objects (e.g. electronic documents) for
 * which an Evidence Record should be generated.
 */
public class DataGroup
{
    private List<byte[]> dataObjects;
    private byte[] groupHash;
    private TreeSet<byte[]> hashes;

    public DataGroup(final List<byte[]> dataObjects)
    {
        this.dataObjects = dataObjects;
    }

    public DataGroup(final byte[] dataObject)
    {
        this.dataObjects = new ArrayList();
        dataObjects.add(dataObject);
    }

    /**
     * Generates hashes for all the data objects included in the data group.
     *
     * @param digestCalculator the {@link DigestCalculator} to use for computing the hashes
     * @return the set of hashes, in ascending order
     */
    public TreeSet<byte[]> getHashes(DigestCalculator digestCalculator)
    {
        return getHashes(digestCalculator, null);
    }

    /**
     * Generates hashes for all the data objects included in the data group.
     *
     * @param digestCalculator the {@link DigestCalculator} to use for computing the hashes
     * @param ha a preceding hash, can be null.
     * @return the set of hashes, in ascending order
     */
    private TreeSet<byte[]> getHashes(
        final DigestCalculator digestCalculator,
        final byte[] ha)
    {
        if (hashes == null)
        {
            hashes = new TreeSet(new ByteArrayComparator());

            for (int i = 0; i != dataObjects.size(); i++)
            {
                byte[] dataObject = (byte[])dataObjects.get(i);
                if (ha != null)
                {
                    hashes.add(calcDigest(digestCalculator, Arrays.concatenate(calcDigest(digestCalculator, dataObject), ha)));
                }
                else
                {
                    hashes.add(calcDigest(digestCalculator, dataObject));
                }
            }
        }

        return hashes;
    }

    /**
     * Generates a hash for the whole DataGroup.
     *
     * @param digestCalculator the {@link DigestCalculator} to use for computing the hash
     * @return a hash that is representative of the whole DataGroup
     */
    public byte[] getHash(DigestCalculator digestCalculator)
    {
        if (groupHash == null)
        {
            TreeSet<byte[]> hashes = getHashes(digestCalculator);

            if (hashes.size() > 1)
            {
                byte[] concat = new byte[0];
                Iterator<byte[]> iterator = hashes.iterator();

                while (iterator.hasNext())
                {
                    concat = Arrays.concatenate(concat, (byte[])iterator.next());
                }

                groupHash = calcDigest(digestCalculator, concat);
            }
            else
            {
                groupHash = (byte[])hashes.first();
            }
        }

        return groupHash;
    }

    /**
     * Comparator for byte arrays
     */
    private class ByteArrayComparator
        implements Comparator
    {
        public int compare(Object l, Object r)
        {
            byte[] left = (byte[])l;
            byte[] right = (byte[])r;

            int len = left.length < right.length ? left.length : right.length;

            for (int i = 0; i != len; i++)
            {
                int a = (left[i] & 0xff);
                int b = (right[i] & 0xff);

                if (a != b)
                {
                    return a - b;
                }
            }

            return left.length - right.length;
        }
    }

    static byte[] calcDigest(DigestCalculator digCalc, byte[] data)
    {
        try
        {
            OutputStream dOut = digCalc.getOutputStream();

            dOut.write(data);

            dOut.close();

            return digCalc.getDigest();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("digest calculator failure: " + e.getMessage());
        }
    }
}
