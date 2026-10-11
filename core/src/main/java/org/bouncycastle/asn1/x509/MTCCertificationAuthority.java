package org.bouncycastle.asn1.x509;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.BigIntegers;

/**
 * ASN.1 structure for the {@code id-pe-mtcCertificationAuthority-SHA256}
 * extension defined in Section 5.5 of draft-ietf-plants-merkle-tree-certs:
 *
 * <pre>
 * -- This is 2^48, the minimum possible serial number in this protocol.
 * mtcMinSerial INTEGER ::= 281474976710656
 *
 * -- This is 2^64-1, the maximum possible serial number in this protocol.
 * mtcMaxSerial INTEGER ::= 18446744073709551615
 *
 * MTCCertificationAuthority ::= SEQUENCE {
 *     sigAlg    AlgorithmIdentifier{SIGNATURE-ALGORITHM, {...}},
 *     minSerial INTEGER (mtcMinSerial..mtcMaxSerial),
 *     maxSerial INTEGER (mtcMinSerial..mtcMaxSerial)
 * }
 * </pre>
 *
 * <p>{@code sigAlg} is the CA cosigner's signature algorithm. {@code minSerial}
 * and {@code maxSerial} are the inclusive bounds of the cert serial range this
 * CA is authorized for; per Section 6.2 of the draft a serial encodes the log
 * number in its upper 16 bits and the entry index in the lower 48 bits (a
 * 64-bit value), so the range can constrain either. The hash function used by
 * the CA's issuance logs is not a field of the structure: it is identified by
 * the extension type, {@code id-pe-mtcCertificationAuthority-SHA256} for
 * SHA-256 (draft-06 moved it out of the structure and into the OID).</p>
 */
public class MTCCertificationAuthority
    extends ASN1Object
{
    /**
     * {@code mtcMinSerial} - the smallest legal serial, 2^48, which is entry 0 of
     * log 1 (log number 0 is not used).
     */
    public static final BigInteger MIN_SERIAL = BigIntegers.ONE.shiftLeft(48);

    /**
     * {@code mtcMaxSerial} - the largest legal serial, 2^64 - 1 (a serial is the
     * 64-bit composition of a 16-bit log number and a 48-bit entry index).
     */
    public static final BigInteger MAX_SERIAL = BigIntegers.ONE.shiftLeft(64).subtract(BigIntegers.ONE);

    private final AlgorithmIdentifier sigAlg;
    private final BigInteger minSerial;
    private final BigInteger maxSerial;

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
     * Convenience constructor that wraps the algorithm OID in a parameterless
     * {@link AlgorithmIdentifier}. Equivalent to
     * {@link #MTCCertificationAuthority(AlgorithmIdentifier, BigInteger, BigInteger)}
     * with {@code new AlgorithmIdentifier(sigAlgOid)}.
     */
    public MTCCertificationAuthority(
        ASN1ObjectIdentifier sigAlgOid,
        BigInteger minSerial,
        BigInteger maxSerial)
    {
        this(sigAlgOid != null ? new AlgorithmIdentifier(sigAlgOid) : null, minSerial, maxSerial);
    }

    public MTCCertificationAuthority(
        AlgorithmIdentifier sigAlg,
        BigInteger minSerial,
        BigInteger maxSerial)
    {
        if (sigAlg == null)
        {
            throw new NullPointerException("sigAlg cannot be null");
        }
        checkSerialRange(minSerial, maxSerial);
        this.sigAlg = sigAlg;
        this.minSerial = minSerial;
        this.maxSerial = maxSerial;
    }

    private MTCCertificationAuthority(ASN1Sequence seq)
    {
        if (seq.size() != 3)
        {
            throw new IllegalArgumentException("MTCCertificationAuthority must be a SEQUENCE of 3 elements, got " + seq.size());
        }
        this.sigAlg = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.minSerial = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
        this.maxSerial = ASN1Integer.getInstance(seq.getObjectAt(2)).getValue();
        checkSerialRange(minSerial, maxSerial);
    }

    private static void checkSerialRange(BigInteger minSerial, BigInteger maxSerial)
    {
        if (minSerial == null)
        {
            throw new NullPointerException("minSerial cannot be null");
        }
        if (maxSerial == null)
        {
            throw new NullPointerException("maxSerial cannot be null");
        }
        if (minSerial.compareTo(MIN_SERIAL) < 0 || minSerial.compareTo(MAX_SERIAL) > 0)
        {
            throw new IllegalArgumentException("minSerial out of range [2^48, 2^64-1]: " + minSerial);
        }
        if (maxSerial.compareTo(MIN_SERIAL) < 0 || maxSerial.compareTo(MAX_SERIAL) > 0)
        {
            throw new IllegalArgumentException("maxSerial out of range [2^48, 2^64-1]: " + maxSerial);
        }
        if (minSerial.compareTo(maxSerial) > 0)
        {
            throw new IllegalArgumentException("minSerial (" + minSerial + ") must not exceed maxSerial (" + maxSerial + ")");
        }
    }

    public AlgorithmIdentifier getSigAlg()
    {
        return sigAlg;
    }

    public BigInteger getMinSerial()
    {
        return minSerial;
    }

    public BigInteger getMaxSerial()
    {
        return maxSerial;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(sigAlg);
        v.add(new ASN1Integer(minSerial));
        v.add(new ASN1Integer(maxSerial));
        return new DERSequence(v);
    }
}
