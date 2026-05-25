package org.bouncycastle.asn1.x509;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * ASN.1 structure for the {@code id-pe-mtcCertificationAuthority} extension
 * defined in Section 5.5 of draft-ietf-plants-merkle-tree-certs:
 *
 * <pre>
 * MTCCertificationAuthority ::= SEQUENCE {
 *     logHash   AlgorithmIdentifier{DIGEST-ALGORITHM, {...}},
 *     sigAlg    AlgorithmIdentifier{SIGNATURE-ALGORITHM, {...}},
 *     minSerial INTEGER
 * }
 * </pre>
 *
 * <p>{@code logHash} is the hash algorithm used by all issuance logs operated
 * by this CA. {@code sigAlg} is the CA cosigner's signature algorithm.
 * {@code minSerial} is the minimum allowed serial number from this CA; per
 * Section 6.1 of the draft a serial encodes the log number in its upper 16 bits
 * and the entry index in the lower 48 bits, so {@code minSerial} can constrain
 * either.</p>
 */
public class MTCCertificationAuthority
    extends ASN1Object
{
    private final AlgorithmIdentifier logHash;
    private final AlgorithmIdentifier sigAlg;
    private final BigInteger minSerial;

    public static MTCCertificationAuthority getInstance(Object obj)
    {
        if (obj instanceof MTCCertificationAuthority)
        {
            return (MTCCertificationAuthority)obj;
        }
        if (obj != null)
        {
            return new MTCCertificationAuthority(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    /**
     * Convenience constructor that wraps each algorithm OID in a parameterless
     * {@link AlgorithmIdentifier}. Equivalent to
     * {@link #MTCCertificationAuthority(AlgorithmIdentifier, AlgorithmIdentifier, BigInteger)}
     * with {@code new AlgorithmIdentifier(logHashOid)} and
     * {@code new AlgorithmIdentifier(sigAlgOid)}.
     */
    public MTCCertificationAuthority(
        ASN1ObjectIdentifier logHashOid,
        ASN1ObjectIdentifier sigAlgOid,
        BigInteger minSerial)
    {
        this(
            logHashOid != null ? new AlgorithmIdentifier(logHashOid) : null,
            sigAlgOid != null ? new AlgorithmIdentifier(sigAlgOid) : null,
            minSerial);
    }

    public MTCCertificationAuthority(
        AlgorithmIdentifier logHash,
        AlgorithmIdentifier sigAlg,
        BigInteger minSerial)
    {
        if (logHash == null)
        {
            throw new NullPointerException("logHash cannot be null");
        }
        if (sigAlg == null)
        {
            throw new NullPointerException("sigAlg cannot be null");
        }
        if (minSerial == null)
        {
            throw new NullPointerException("minSerial cannot be null");
        }
        if (minSerial.signum() < 0)
        {
            throw new IllegalArgumentException("minSerial must be non-negative");
        }
        this.logHash = logHash;
        this.sigAlg = sigAlg;
        this.minSerial = minSerial;
    }

    private MTCCertificationAuthority(ASN1Sequence seq)
    {
        if (seq.size() != 3)
        {
            throw new IllegalArgumentException("MTCCertificationAuthority must be a SEQUENCE of 3 elements, got " + seq.size());
        }
        this.logHash = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.sigAlg = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        this.minSerial = ASN1Integer.getInstance(seq.getObjectAt(2)).getValue();
        if (minSerial.signum() < 0)
        {
            throw new IllegalArgumentException("minSerial must be non-negative");
        }
    }

    public AlgorithmIdentifier getLogHash()
    {
        return logHash;
    }

    public AlgorithmIdentifier getSigAlg()
    {
        return sigAlg;
    }

    public BigInteger getMinSerial()
    {
        return minSerial;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(logHash);
        v.add(sigAlg);
        v.add(new ASN1Integer(minSerial));
        return new DERSequence(v);
    }
}
