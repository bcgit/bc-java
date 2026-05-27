package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * RFC 9763 sec. 3 {@code RelatedCertificate} certificate extension value.
 * <pre>
 * RelatedCertificate ::= SEQUENCE {
 *     hashAlgorithm DigestAlgorithmIdentifier,
 *     hashValue     OCTET STRING
 * }
 * </pre>
 * The {@code hashValue} is the digest of the DER-encoded {@code Certificate}
 * structure (TBSCertificate + signatureAlgorithm + signatureValue) of the
 * single related end-entity certificate listed in the matching
 * {@code id-aa-relatedCertRequest} attribute of the CSR that produced this
 * certificate (RFC 9763 sec. 3.2).
 * <p>
 * Identified by {@link X509ObjectIdentifiers#id_pe_relatedCert} /
 * {@link Extension#relatedCertificate} (OID 1.3.6.1.5.5.7.1.36). RFC 9763
 * sec. 3.1 says the extension SHOULD NOT be marked critical.
 */
public class RelatedCertificate
    extends ASN1Object
{
    private final AlgorithmIdentifier hashAlgorithm;
    private final ASN1OctetString hashValue;

    public static RelatedCertificate getInstance(Object obj)
    {
        if (obj instanceof RelatedCertificate)
        {
            return (RelatedCertificate)obj;
        }
        if (obj != null)
        {
            return new RelatedCertificate(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public RelatedCertificate(AlgorithmIdentifier hashAlgorithm, ASN1OctetString hashValue)
    {
        if (hashAlgorithm == null)
        {
            throw new NullPointerException("'hashAlgorithm' cannot be null");
        }
        if (hashValue == null)
        {
            throw new NullPointerException("'hashValue' cannot be null");
        }
        this.hashAlgorithm = hashAlgorithm;
        this.hashValue = hashValue;
    }

    private RelatedCertificate(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        this.hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.hashValue = ASN1OctetString.getInstance(seq.getObjectAt(1));
    }

    public AlgorithmIdentifier getHashAlgorithm()
    {
        return hashAlgorithm;
    }

    public ASN1OctetString getHashValue()
    {
        return hashValue;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(hashAlgorithm, hashValue);
    }
}
