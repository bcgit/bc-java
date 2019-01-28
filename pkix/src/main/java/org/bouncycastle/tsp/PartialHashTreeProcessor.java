package org.bouncycastle.tsp;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.tsp.PartialHashtree;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.util.Arrays;

public class PartialHashTreeProcessor
{
    private final byte[][] values;

    public PartialHashTreeProcessor(PartialHashtree tree)
    {
        this.values = tree.getValues();
    }

    /**
     * Compute a hash over the whole partialHashTree:
     * - Concatenate all the hashes contained in the partial hash tree;
     * - Generate a hash over the concatenated hashes, using a provided {@link DigestCalculator}.
     *
     * @param digestCalculator the {@link DigestCalculator} to use in order to generate the hash
     * @return a hash value that is representative of the whole partial hash tree.
     */
    public byte[] getHash(DigestCalculator digestCalculator)
    {
        if (values.length == 1)
        {
            return values[0];
        }

        try
        {
            OutputStream dOut = digestCalculator.getOutputStream();

            for (int i = 1; i != values.length; i++)
            {
                dOut.write(values[i]);
            }

            return digestCalculator.getDigest();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("calculator failed: " + e.getMessage());
        }
    }

    /**
     * Checks whether a PartialHashtree (RFC4998) contains a given hash.
     *
     * @param hash            the hash to check
     * @throws PartialHashTreeVerificationException if the hash is not present in the
     * PartialHashtree
     */
    public void verifyContainsHash(final byte[] hash)
        throws PartialHashTreeVerificationException
    {
        if (!containsHash(hash))
        {
            throw new PartialHashTreeVerificationException("calculated hash is not present in " + "partial hash tree");
        }
    }

    /**
     * Checks whether a PartialHashtree (RFC4998) contains a given hash.
     *
     * @param hash            the hash to check
     * @return true if the hash is present within the PartialHashtree's set of values, false
     * otherwise.
     */
    public boolean containsHash(final byte[] hash)
    {
        for (int i = 1; i != values.length; i++)
        {
            if (Arrays.areEqual(hash, values[i]))
            {
                return true;
            }
        }

        return false;
    }
}
