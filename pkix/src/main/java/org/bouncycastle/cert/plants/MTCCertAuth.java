package org.bouncycastle.cert.plants;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.MTCCertificationAuthority;
import org.bouncycastle.util.Arrays;

/**
 * Identity-side helper for an MTC Certification Authority, per Section 5 of
 * draft-ietf-plants-merkle-tree-certs. Bundles the CA's trust anchor ID (in
 * both dotted-decimal and binary forms) along with the log hash and cosigner
 * signature algorithm identifiers, and exposes the per-issuance derivations
 * that depend on this identity:
 *
 * <ul>
 *   <li>{@link #logId(long)} — the issuance log's binary trust anchor ID</li>
 *   <li>{@link #issuerName()} — the X.500 Name used in the cert's issuer field</li>
 *   <li>{@link #certSerial(long, long)} — a packed {@code (log_number, index)}
 *       cert serial</li>
 *   <li>{@link #authorityInfo(BigInteger)} — the {@link MTCCertificationAuthority}
 *       extension value the relying party needs out-of-band</li>
 * </ul>
 *
 * <p>Identity-only: the CA's signing keypair stays separate so the same
 * {@link MTCCertAuth} can be shared between an issuer (which holds the private
 * key for cosigning) and a relying party (which holds the matching public key
 * for verification).</p>
 */
public class MTCCertAuth
{
    private final String dottedCaId;
    private final byte[] caId;
    private final MerkleTreeHash hashFunc;
    private final ASN1ObjectIdentifier sigAlgOid;

    /**
     * @param dottedCaId dotted-decimal form of the CA's trust anchor ID
     *                   (e.g. {@code "32473.1"})
     * @param hashFunc   hash function used by all issuance logs operated by
     *                   this CA (Section 5.5) — its
     *                   {@link MerkleTreeHash#getAlgorithmIdentifier()
     *                   algorithm identifier} is published in the CA's
     *                   {@link org.bouncycastle.asn1.x509.MTCCertificationAuthority#getLogHash() logHash}
     * @param sigAlgOid  CA cosigner's signature algorithm (Section 5.5)
     */
    public MTCCertAuth(
        String dottedCaId,
        MerkleTreeHash hashFunc,
        ASN1ObjectIdentifier sigAlgOid)
    {
        this.dottedCaId = dottedCaId;
        this.caId = TrustAnchorIDs.fromDottedDecimal(dottedCaId);
        this.hashFunc = hashFunc;
        this.sigAlgOid = sigAlgOid;
    }

    /**
     * @param caId      binary form of the CA's trust anchor ID
     * @param hashFunc  hash function used by all issuance logs operated by
     *                  this CA (Section 5.5)
     * @param sigAlgOid CA cosigner's signature algorithm (Section 5.5)
     */
    public MTCCertAuth(
        byte[] caId,
        MerkleTreeHash hashFunc,
        ASN1ObjectIdentifier sigAlgOid)
    {
        this.caId = Arrays.clone(caId);
        this.dottedCaId = TrustAnchorIDs.toDottedDecimal(caId);
        this.hashFunc = hashFunc;
        this.sigAlgOid = sigAlgOid;
    }

    /** @return the CA's binary trust anchor ID (defensive copy). */
    public byte[] getCaId()
    {
        return Arrays.clone(caId);
    }

    /** @return the CA's trust anchor ID in dotted-decimal form. */
    public String getDottedCaId()
    {
        return dottedCaId;
    }

    /** @return the hash function used by all issuance logs operated by this CA. */
    public MerkleTreeHash getHashFunc()
    {
        return hashFunc;
    }

    /**
     * @param logNumber log number ({@code 1 <= logNumber <= 2^16-1}, Section 5.2)
     * @return the binary trust anchor ID of issuance log {@code logNumber}
     *         operated by this CA
     */
    public byte[] logId(long logNumber)
    {
        return TrustAnchorIDs.logId(caId, logNumber);
    }

    /**
     * @return the issuer {@link X500Name} for certs issued by this CA, carrying
     *         the trust anchor ID via the experimental
     *         {@code id_rdna_trustAnchorID} attribute
     */
    public X500Name issuerName()
    {
        return TrustAnchorIDs.issuerName(dottedCaId);
    }

    /**
     * @param logNumber log number ({@code 1 <= logNumber <= 2^16-1})
     * @param index     entry index in the log ({@code 0 <= index <= 2^48-1})
     * @return the 64-bit cert serial composed per Section 6.1
     */
    public BigInteger certSerial(long logNumber, long index)
    {
        return TrustAnchorIDs.certSerial(logNumber, index);
    }

    /**
     * Equivalent to {@link #certSerial(long, long)} with the log number taken
     * from {@code log.getLogNumber()}.
     */
    public BigInteger certSerial(MTCLog log, long index)
    {
        return TrustAnchorIDs.certSerial(log, index);
    }

    /**
     * Builds the {@link MTCCertificationAuthority} extension value that the
     * relying party needs to validate certs from this CA. Combines the CA's
     * log hash and cosigner signature algorithm with the supplied minSerial.
     *
     * @param minSerial minimum allowed cert serial from this CA (Section 6.1)
     */
    public MTCCertificationAuthority authorityInfo(BigInteger minSerial)
    {
        return new MTCCertificationAuthority(
            hashFunc.getAlgorithmIdentifier().getAlgorithm(), sigAlgOid, minSerial);
    }
}
