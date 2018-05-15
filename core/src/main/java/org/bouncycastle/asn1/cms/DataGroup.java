package org.bouncycastle.asn1.cms;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.ByteArrayComparator;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.TreeSet;

/**
 * Representation of data groups according to the description provided in RFC4998.
 *
 * Such data groups represent a set of one or more data objects (e.g. electronic documents) for
 * which an Evidence Record should be generated.
 */
public class DataGroup {

    private List<byte[]>      dataObjects;
    private byte[]            groupHash;
    private TreeSet<byte[]>   hashes;

    public DataGroup(final List<byte[]> dataObjects)
    {
        this.dataObjects = dataObjects;
    }

    public DataGroup(final byte[] dataObject)
    {
        this.dataObjects = new ArrayList();
        dataObjects.add(dataObject);
    }

    public TreeSet<byte[]> getHashes(final MessageDigest md)
    {
        return getHashes(md, null);
    }

    /**
     * Generates hashes for all the data objects included in the data group.
     *
     * @param md the {@link MessageDigest} to use for computing the hashes
     * @return the set of hashes, in ascending order
     */
    public TreeSet<byte[]> getHashes(
        final MessageDigest md,
        final byte[] ha)
    {
        if (hashes == null)
        {
            hashes = new TreeSet(new ByteArrayComparator());

            for (final byte[] dataObject : dataObjects)
            {
                if (ha != null)
                {
                    hashes.add(md.digest(ByteUtils.concatenate(md.digest(dataObject), ha)));
                }
                else
                {
                    hashes.add(md.digest(dataObject));
                }
            }
        }

        return hashes;
    }

    /**
     * Generates a hash for the whole DataGroup.
     *
     * @param md the {@link MessageDigest} to use for computing the hash
     * @return a hash that is representative of the whole DataGroup
     */
    public byte[] getHash(final MessageDigest md)
    {
        if (groupHash == null)
        {
            TreeSet<byte[]> hashes = getHashes(md);

            if (hashes.size() > 1)
            {
                byte[] concat = new byte[0];
                Iterator<byte[]> iterator = hashes.iterator();

                while (iterator.hasNext())
                {
                    concat = ByteUtils.concatenate(concat, iterator.next());
                }

                groupHash = md.digest(concat);
            }
            else
            {
                groupHash = hashes.first();
            }
        }

        return groupHash;
    }
}
