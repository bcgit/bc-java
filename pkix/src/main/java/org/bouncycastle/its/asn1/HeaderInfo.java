package org.bouncycastle.its.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 *     HeaderInfo ::= SEQUENCE {
 *         psid Psid,,
 *         generationTime Time64 OPTIONAL,
 *         expiryTime Time64 OPTIONAL,
 *         generationLocation ThreeDLocation OPTIONAL,
 *         p2pcdLearningRequest HashedId3 OPTIONAL,
 *         missingCrlIdentifier MissingCrlIdentifier OPTIONAL,
 *         ...,
 *         inlineP2pcdRequest SequenceOfHashedId3 OPTIONAL,
 *         requestedCertificate Certificate OPTIONAL
 *     }
 * </pre>
 */
public class HeaderInfo
    extends ASN1Object
{
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        return new DERSequence(v);
    }
}