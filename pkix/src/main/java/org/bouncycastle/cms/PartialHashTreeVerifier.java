package org.bouncycastle.cms;

import org.bouncycastle.asn1.cms.PartialHashtree;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.security.MessageDigest;
import java.util.Enumeration;

public class PartialHashTreeVerifier {

    /**
     * Compute a hash over the whole partialHashTree:
     * - Concatenate all the hashes contained in the partial hash tree;
     * - Generate a hash over the concatenated hashes, using a provided {@link MessageDigest}.
     *
     * @param md the {@link MessageDigest} to use in order to generate the hash
     * @return a hash value that is representative of the whole partial hash tree.
     */
    public byte[] getHash (final PartialHashtree partialHashtree, final MessageDigest md)
    {
        if (partialHashtree.getValues().size() == 1)
        {
            return ((ASN1OctetString) partialHashtree.getValues().getObjectAt(0)).getOctets();
        }

        Enumeration hashes = partialHashtree.getValues().getObjects();
        byte[] a = ((ASN1OctetString) hashes.nextElement()).getOctets();

        while (hashes.hasMoreElements())
        {
            a = ByteUtils.concatenate(a, ((ASN1OctetString) hashes.nextElement()).getOctets());
        }

        return md.digest(a);
    }

    /**
     * Checks whether a PartialHashtree (RFC4998) contains a given hash.
     *
     * @param partialHashtree the PartialHashtree in which the given hash should be present
     * @param hash the hash to check
     * @throws PartialHashTreeVerificationException if the hash is not present in the
     * PartialHashtree
     */
    public void checkContainsHash (final PartialHashtree partialHashtree, final byte[] hash)
        throws PartialHashTreeVerificationException {
        if (! containsHash(partialHashtree, hash))
        {
            throw new PartialHashTreeVerificationException("calculated hash is not present in "
                + "partial hash tree");
        }
    }

    /**
     * Checks whether a PartialHashtree (RFC4998) contains a given hash.
     *
     * @param partialHashtree the PartialHashtree to check
     * @param hash the hash to check
     * @return true if the hash is present within the PartialHashtree's set of values, false
     * otherwise.
     */
    public boolean containsHash (final PartialHashtree partialHashtree, final byte[] hash)
    {
        Enumeration hashes = partialHashtree.getValues().getObjects();

        while (hashes.hasMoreElements())
        {
            byte[] currentHash = ((ASN1OctetString) hashes.nextElement()).getOctets();

            if (ByteUtils.equals(hash, currentHash))
            {
                return true;
            }
        }
        return false;
    }

}
