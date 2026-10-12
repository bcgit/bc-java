package org.bouncycastle.cert.plants;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.util.Arrays;

/**
 * A relying party's cosigner policy, as the "Trusted Cosigners" section of
 * <a href="https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/">draft-ietf-plants-merkle-tree-certs</a>
 * (Section 7.3) describes it: which combinations of cosigners must have
 * cosigned a subtree before a certificate in it is accepted.
 *
 * <p>A requirement is a tree. The leaves name a cosigner, either by its
 * cosigner ID ({@link #cosigner(byte[])}) or as the CA that issued the
 * certificate under validation ({@link #issuingCA()}, whose cosigner ID is
 * the CA ID in the certificate's issuer). The interior nodes are quorums over
 * their members ({@link #atLeast(int, CosignerRequirement[])}, with
 * {@link #anyOf(CosignerRequirement[])} and {@link #allOf(CosignerRequirement[])} as the
 * two common thresholds), so a policy such as "the CA and at least two
 * independent operators" is</p>
 *
 * <pre>
 * CosignerRequirement.allOf(
 *     CosignerRequirement.issuingCA(),
 *     CosignerRequirement.atLeast(2,
 *         CosignerRequirement.anyOf(operatorA1, operatorA2),
 *         CosignerRequirement.anyOf(operatorB1),
 *         CosignerRequirement.anyOf(operatorC1, operatorC2)))
 * </pre>
 *
 * <p>Section 7.3 recommends that a relying party require the CA cosigner, for
 * authenticity, together with a quorum of additional cosigners, for
 * transparency. {@link MerkleTreeCertificateValidator} evaluates the
 * requirements in {@link MerkleTreeCertificateValidator.ValidationParams}
 * against the cosignatures that verified under the registered
 * {@link MTCCosignerVerifierProvider}; a cosigner that is not registered
 * never satisfies a leaf. A certificate whose subtree matches a trusted
 * subtree (Section 7.4) is accepted without reference to the requirements,
 * since a trusted subtree is one already known to satisfy them.</p>
 *
 * <p>Instances are immutable.</p>
 */
public final class CosignerRequirement
{
    private final byte[] cosignerId;
    private final boolean issuingCA;
    private final int threshold;
    private final List<CosignerRequirement> members;

    private CosignerRequirement(byte[] cosignerId, boolean issuingCA, int threshold, List<CosignerRequirement> members)
    {
        this.cosignerId = cosignerId;
        this.issuingCA = issuingCA;
        this.threshold = threshold;
        this.members = members;
    }

    /**
     * A requirement satisfied by a valid cosignature from the cosigner with the
     * given binary cosigner ID (see {@link TrustAnchorIDs}).
     */
    public static CosignerRequirement cosigner(byte[] cosignerId)
    {
        if (cosignerId == null || cosignerId.length == 0)
        {
            throw new IllegalArgumentException("cosignerId must not be empty");
        }
        return new CosignerRequirement(Arrays.clone(cosignerId), false, 0, null);
    }

    /**
     * A requirement satisfied by a valid cosignature from the CA that issued
     * the certificate being validated: the cosigner whose ID equals the CA ID
     * carried in the certificate's issuer name. Section 7.3 recommends every
     * policy include this.
     */
    public static CosignerRequirement issuingCA()
    {
        return new CosignerRequirement(null, true, 0, null);
    }

    /**
     * A requirement satisfied when at least {@code threshold} of the member
     * requirements are satisfied.
     *
     * @param threshold the number of members that must be satisfied, from 1 to the number of members
     * @param members   the member requirements, at least one
     */
    public static CosignerRequirement atLeast(int threshold, CosignerRequirement... members)
    {
        if (members == null || members.length == 0)
        {
            throw new IllegalArgumentException("a quorum needs at least one member");
        }
        if (threshold < 1 || threshold > members.length)
        {
            throw new IllegalArgumentException("threshold " + threshold + " out of range [1, " + members.length + "]");
        }
        List<CosignerRequirement> list = new ArrayList<CosignerRequirement>(members.length);
        for (int i = 0; i != members.length; i++)
        {
            if (members[i] == null)
            {
                throw new IllegalArgumentException("member " + i + " is null");
            }
            list.add(members[i]);
        }
        return new CosignerRequirement(null, false, threshold, Collections.unmodifiableList(list));
    }

    /**
     * A requirement satisfied when any one of the member requirements is.
     */
    public static CosignerRequirement anyOf(CosignerRequirement... members)
    {
        return atLeast(1, members);
    }

    /**
     * A requirement satisfied only when every member requirement is.
     */
    public static CosignerRequirement allOf(CosignerRequirement... members)
    {
        if (members == null || members.length == 0)
        {
            throw new IllegalArgumentException("a quorum needs at least one member");
        }
        return atLeast(members.length, members);
    }

    /**
     * Evaluates this requirement against the cosigners whose cosignatures
     * verified.
     *
     * @param verifiedCosignerIds the binary cosigner IDs whose cosignatures over the subtree verified
     * @param caId                the binary CA ID of the certificate's issuer, which {@link #issuingCA()} leaves match, or null if unknown
     * @return true if the requirement is satisfied
     */
    public boolean isSatisfiedBy(Collection<byte[]> verifiedCosignerIds, byte[] caId)
    {
        if (members == null)
        {
            byte[] wanted = issuingCA ? caId : cosignerId;
            if (wanted == null)
            {
                return false;
            }
            for (Iterator<byte[]> it = verifiedCosignerIds.iterator(); it.hasNext();)
            {
                if (Arrays.areEqual(wanted, it.next()))
                {
                    return true;
                }
            }
            return false;
        }

        int satisfied = 0;
        for (int i = 0; i != members.size(); i++)
        {
            if (members.get(i).isSatisfiedBy(verifiedCosignerIds, caId))
            {
                satisfied++;
                if (satisfied >= threshold)
                {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * The cosigner ID a {@link #cosigner(byte[])} leaf names, or null for any other node.
     */
    public byte[] getCosignerId()
    {
        return Arrays.clone(cosignerId);
    }

    /**
     * True for the {@link #issuingCA()} leaf.
     */
    public boolean isIssuingCA()
    {
        return issuingCA;
    }

    /**
     * The number of members a quorum node needs satisfied, or 0 for a leaf.
     */
    public int getThreshold()
    {
        return threshold;
    }

    /**
     * The members of a quorum node, or an empty list for a leaf.
     */
    public List<CosignerRequirement> getMembers()
    {
        return members == null ? Collections.<CosignerRequirement>emptyList() : members;
    }

    /**
     * A readable form, with cosigner IDs in dotted decimal: {@code CA},
     * {@code 32473.2.1}, {@code atLeast(2: 32473.2.1, 32473.2.2, 32473.2.3)}.
     */
    public String toString()
    {
        if (members == null)
        {
            return issuingCA ? "CA" : TrustAnchorIDs.toDottedDecimal(cosignerId);
        }
        StringBuilder sb = new StringBuilder();
        if (threshold == members.size())
        {
            sb.append("allOf(");
        }
        else if (threshold == 1)
        {
            sb.append("anyOf(");
        }
        else
        {
            sb.append("atLeast(").append(threshold).append(": ");
        }
        for (int i = 0; i != members.size(); i++)
        {
            if (i != 0)
            {
                sb.append(", ");
            }
            sb.append(members.get(i));
        }
        return sb.append(')').toString();
    }
}
