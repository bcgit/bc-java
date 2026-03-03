package org.bouncycastle.asn1.plants;

import org.bouncycastle.asn1.*;
import java.util.Enumeration;

/**
 * ASN.1 representation of the MTCProof structure.
 *
 * <pre>
 * HashValue ::= OCTET STRING
 *
 * MTCSignature ::= SEQUENCE {
 *     cosigner_id   TrustAnchorID,
 *     signature     OCTET STRING
 * }
 *
 * MTCProof ::= SEQUENCE {
 *     start             INTEGER (0..2^64-1),
 *     end               INTEGER (0..2^64-1),
 *     inclusionProof    SEQUENCE OF OCTET STRING,
 *     signatures        SEQUENCE OF MTCSignature
 * }
 * </pre>
 *
 * <p>
 * The {@code inclusionProof} field contains the Merkle inclusion proof as
 * an ordered sequence of hash values. Each element represents one node in
 * the path required to reconstruct the Merkle root.
 * </p>
 *
 * <p>
 * The {@code signatures} field contains a sequence of cosigner signatures
 * over the proof, where each signature is associated with a specific
 * {@code TrustAnchorID}.
 * </p>
 */
public class MTCProof extends ASN1Object
{
    private final ASN1Integer start;
    private final ASN1Integer end;
    private final ASN1Sequence inclusionProof;
    private final ASN1Sequence signatures;

    public static MTCProof getInstance(Object obj)
    {
        if (obj instanceof MTCProof)
        {
            return (MTCProof)obj;
        }
        else if (obj != null)
        {
            return new MTCProof(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private MTCProof(ASN1Sequence seq)
    {
        if (seq.size() != 4)
        {
            throw new IllegalArgumentException("Invalid MTCProof sequence size");
        }

        Enumeration<?> e = seq.getObjects();

        this.start = ASN1Integer.getInstance(e.nextElement());
        this.end = ASN1Integer.getInstance(e.nextElement());
        this.inclusionProof = ASN1Sequence.getInstance(e.nextElement());
        this.signatures = ASN1Sequence.getInstance(e.nextElement());
    }

    public MTCProof(
        ASN1Integer start,
        ASN1Integer end,
        ASN1Sequence inclusionProof,
        ASN1Sequence signatures)
    {
        this.start = start;
        this.end = end;
        this.inclusionProof = inclusionProof;
        this.signatures = signatures;
    }

    /**
     * Returns the start index of the log range.
     */
    public ASN1Integer getStart()
    {
        return start;
    }

    /**
     * Returns the end index of the log range.
     */
    public ASN1Integer getEnd()
    {
        return end;
    }

    /**
     * Returns the Merkle inclusion proof hashes.
     *
     * @return sequence of {@link ASN1OctetString} hash values
     */
    public ASN1Sequence getInclusionProof()
    {
        return inclusionProof;
    }

    /**
     * Returns the cosigner signatures.
     *
     * @return sequence of {@link MTCSignature}
     */
    public ASN1Sequence getSignatures()
    {
        return signatures;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(4);

        v.add(start);
        v.add(end);
        v.add(inclusionProof);
        v.add(signatures);

        return new DERSequence(v);
    }
}
