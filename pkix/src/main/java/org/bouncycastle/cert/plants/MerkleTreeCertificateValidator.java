package org.bouncycastle.cert.plants;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1RelativeOID;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.plants.MTCObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.MTCCertificationAuthority;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * Validates a Merkle Tree Certificate (MTC) per Section 7.2 of
 * <a href="https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/">draft-ietf-plants-merkle-tree-certs</a>.
 *
 * <p>The validator stands in for the per-certificate signature verification
 * step of RFC 5280 path validation (Section 6.1.3 step (a)(1)) when the issuer
 * is a Merkle Tree CA. {@link #validateCertificate} decodes the
 * {@link MTCProof} carried in the certificate's {@code signatureValue},
 * recomputes the entry hash from the TBSCertificate, evaluates the inclusion
 * proof against the supplied {@link MerkleTreeHash}, and then either matches
 * the resulting subtree hash against a {@link ValidationParams.TrustedSubtree}
 * or counts valid cosignatures against the relying party's
 * {@link MTCCosignerVerifierProvider} until {@code minCosignatures} is met.</p>
 */
public class MerkleTreeCertificateValidator
{
    /** Dotted-decimal form of {@link MTCObjectIdentifiers#id_alg_mtcProof}, the signatureAlgorithm of an MTC certificate. */
    public static final String ID_ALG_MTC_PROOF = MTCObjectIdentifiers.id_alg_mtcProof.getId();

    /**
     * Parameters supplied by the relying party for certificate validation.
     *
     * <p>{@code authorityInfo} is optional. When non-null it pins the validator
     * to the CA's published {@code MTCCertificationAuthority} extension and
     * enforces:</p>
     * <ul>
     *   <li>The cert's serial number lies within the CA's authorized range
     *       {@code [authorityInfo.getMinSerial(), authorityInfo.getMaxSerial()]}
     *       (Section 5.5 / 7.2).</li>
     *   <li>The {@code hashFunction} OID matches {@code authorityInfo.getLogHash()}
     *       (Section 7.1).</li>
     * </ul>
     * <p>{@code authorityInfo.getSigAlg()} is the CA cosigner's published signature
     * algorithm. {@link MTCSignatureVerifier#getAlgorithm()} surfaces the MTC
     * algorithm string a registered verifier is bound to, but the draft does
     * not pin OID identifiers for the plain (r||s) ECDSA forms, so the
     * validator does not map {@code sigAlg} to that string itself. Callers
     * building the provider for the CA cosigner remain responsible for
     * checking the verifier they register against
     * {@code authorityInfo.getSigAlg()}.</p>
     */
    public static class ValidationParams
    {
        private final MTCCosignerVerifierProvider cosignerVerifierProvider;
        private final List<TrustedSubtree> trustedSubtrees;
        private final List<RevokedRange> revokedRanges;
        private final int minCosignatures;
        private final MerkleTreeHash hashFunction;
        private final MTCCertificationAuthority authorityInfo;

        public ValidationParams(
            MTCCosignerVerifierProvider cosignerVerifierProvider,
            MerkleTreeHash hashFunction,
            List<TrustedSubtree> trustedSubtrees,
            List<RevokedRange> revokedRanges,
            int minCosignatures)
        {
            this(cosignerVerifierProvider, trustedSubtrees, revokedRanges,
                minCosignatures, hashFunction, null);
        }

        /**
         * Convenience constructor for the common case where the relying party
         * has no pre-distributed trusted subtrees and no revocations to apply.
         * Defaults {@code trustedSubtrees} and {@code revokedRanges} to empty
         * lists.
         */
        public ValidationParams(
            MTCCosignerVerifierProvider cosignerVerifierProvider,
            MerkleTreeHash hashFunction,
            int minCosignatures,
            MTCCertificationAuthority authorityInfo)
        {
            this(cosignerVerifierProvider,
                Collections.<TrustedSubtree>emptyList(),
                Collections.<RevokedRange>emptyList(),
                minCosignatures, hashFunction, authorityInfo);
        }

        public ValidationParams(
            MTCCosignerVerifierProvider cosignerVerifierProvider,
            List<TrustedSubtree> trustedSubtrees,
            List<RevokedRange> revokedRanges,
            int minCosignatures,
            MerkleTreeHash hashFunction,
            MTCCertificationAuthority authorityInfo)
        {
            this.cosignerVerifierProvider = cosignerVerifierProvider;
            this.trustedSubtrees = trustedSubtrees;
            this.revokedRanges = revokedRanges;
            this.minCosignatures = minCosignatures;
            this.hashFunction = hashFunction;
            this.authorityInfo = authorityInfo;
        }

        public MTCCosignerVerifierProvider getCosignerVerifierProvider()
        {
            return cosignerVerifierProvider;
        }

        public List<TrustedSubtree> getTrustedSubtrees()
        {
            return trustedSubtrees;
        }

        public List<RevokedRange> getRevokedRanges()
        {
            return revokedRanges;
        }

        public int getMinCosignatures()
        {
            return minCosignatures;
        }

        public MerkleTreeHash getHashFunction()
        {
            return hashFunction;
        }

        public MTCCertificationAuthority getAuthorityInfo()
        {
            return authorityInfo;
        }
    }

    /**
     * Represents a trusted subtree (typically a landmark subtree predistributed
     * to the relying party). Per Section 7.4 a trusted subtree carries the log
     * number of the containing log alongside the {@code [start, end)} window
     * and the subtree hash &mdash; Section 7.2 step 11 matches on all three, so
     * a subtree trusted for one issuance log never matches a certificate whose
     * serial claims a different log.
     */
    public static class TrustedSubtree
    {
        private final long logNumber;
        private final long start;
        private final long end;
        private final byte[] hash;

        public TrustedSubtree(long logNumber, long start, long end, byte[] hash)
        {
            if (logNumber < 1 || logNumber > 0xFFFFL)
            {
                throw new IllegalArgumentException("log_number out of range [1, 65535]: " + logNumber);
            }
            this.logNumber = logNumber;
            this.start = start;
            this.end = end;
            this.hash = hash.clone();
        }

        /**
         * Convenience constructor taking the log number and subtree window from
         * an {@link MTCLog}.
         */
        public TrustedSubtree(MTCLog log, byte[] hash)
        {
            this(log.getLogNumber(), log.getStart(), log.getEnd(), hash);
        }

        public long getLogNumber()
        {
            return logNumber;
        }

        public long getStart()
        {
            return start;
        }

        public long getEnd()
        {
            return end;
        }

        public byte[] getHash()
        {
            return hash.clone();
        }

        boolean matches(long logNumber, long start, long end)
        {
            return this.logNumber == logNumber && this.start == start && this.end == end;
        }

        boolean matchesHash(byte[] hash)
        {
            return Arrays.areEqual(this.hash, hash);
        }
    }

    /**
     * A half-open range {@code [start, end)} of revoked certificate serial
     * numbers, per Section 7.5 of the draft. The serial packs the log number
     * into the upper 16 bits and the entry index into the lower 48 (Section
     * 6.1), so ranges can revoke spans of entries within one log, whole logs,
     * or spans of logs. The relying party's list of ranges is checked against
     * the full serial before it is decomposed (Section 7.2 step 4).
     *
     * <p>Serial numbers are unsigned 64-bit values, so bounds are
     * {@link BigInteger}s; {@code 0 <= start < end <= 2^64}.</p>
     */
    public static class RevokedRange
    {
        private static final BigInteger TWO_POW_64 = BigInteger.ONE.shiftLeft(64);

        private final BigInteger start;
        private final BigInteger end;

        /**
         * @param startInclusive first revoked serial
         * @param endExclusive   first serial past the range (at most 2^64)
         */
        public RevokedRange(BigInteger startInclusive, BigInteger endExclusive)
        {
            if (startInclusive.signum() < 0)
            {
                throw new IllegalArgumentException("range start must be non-negative");
            }
            if (endExclusive.compareTo(startInclusive) <= 0)
            {
                throw new IllegalArgumentException("range end must be greater than range start");
            }
            if (endExclusive.compareTo(TWO_POW_64) > 0)
            {
                throw new IllegalArgumentException("range end must not exceed 2^64");
            }
            this.start = startInclusive;
            this.end = endExclusive;
        }

        /**
         * The range {@code [0, endExclusive)} &mdash; the shape of the CA's
         * published {@code minSerial} floor (Section 7.1).
         */
        public static RevokedRange before(BigInteger endExclusive)
        {
            return new RevokedRange(BigInteger.ZERO, endExclusive);
        }

        /**
         * The range {@code [startInclusive, 2^64)} &mdash; distrust everything
         * from a serial onwards, the analogue of the SCTNotAfter mechanism
         * cited in Section 7.5.
         */
        public static RevokedRange from(BigInteger startInclusive)
        {
            return new RevokedRange(startInclusive, TWO_POW_64);
        }

        /**
         * Every serial of issuance log {@code logNumber}:
         * {@code [logNumber << 48, (logNumber + 1) << 48)}.
         */
        public static RevokedRange ofLog(long logNumber)
        {
            checkLogNumber(logNumber);
            return new RevokedRange(
                BigInteger.valueOf(logNumber).shiftLeft(48),
                BigInteger.valueOf(logNumber + 1).shiftLeft(48));
        }

        /**
         * Indices {@code [startIndex, endIndex)} of issuance log
         * {@code logNumber}.
         *
         * @param startIndex first revoked index ({@code 0 <= startIndex < 2^48})
         * @param endIndex   first index past the range ({@code startIndex < endIndex <= 2^48})
         */
        public static RevokedRange ofIndices(long logNumber, long startIndex, long endIndex)
        {
            checkLogNumber(logNumber);
            if (startIndex < 0 || startIndex > 0xFFFFFFFFFFFFL)
            {
                throw new IllegalArgumentException("startIndex out of uint48 range: " + startIndex);
            }
            if (endIndex <= startIndex || endIndex > 0x1000000000000L)
            {
                throw new IllegalArgumentException("endIndex out of range: " + endIndex);
            }
            BigInteger base = BigInteger.valueOf(logNumber).shiftLeft(48);
            return new RevokedRange(
                base.add(BigInteger.valueOf(startIndex)),
                base.add(BigInteger.valueOf(endIndex)));
        }

        /** The single serial {@code [serial, serial + 1)}. */
        public static RevokedRange single(BigInteger serial)
        {
            return new RevokedRange(serial, serial.add(BigInteger.ONE));
        }

        public BigInteger getStart()
        {
            return start;
        }

        public BigInteger getEnd()
        {
            return end;
        }

        public boolean contains(BigInteger serial)
        {
            return serial.compareTo(start) >= 0 && serial.compareTo(end) < 0;
        }

        private static void checkLogNumber(long logNumber)
        {
            if (logNumber < 1 || logNumber > 0xFFFFL)
            {
                throw new IllegalArgumentException("log_number out of range [1, 65535]: " + logNumber);
            }
        }
    }

    /**
     * Validates a Merkle Tree certificate per Section 7.2. Always returns
     * {@code true} on success; any validation failure is signalled as a
     * {@link SecurityException}.
     *
     * @param certHolder the certificate to validate
     * @param params     validation parameters
     * @throws SecurityException        if the certificate is rejected
     * @throws IllegalArgumentException if the certificate is not a Merkle Tree certificate
     * @throws IOException              if the certificate cannot be parsed
     */
    public static boolean validateCertificate(
        X509CertificateHolder certHolder,
        ValidationParams params)
        throws IOException
    {
        // Step 1: signature algorithm must be id-alg-mtcProof with absent parameters.
        AlgorithmIdentifier sigAlgId = certHolder.getSignatureAlgorithm();
        if (!MTCObjectIdentifiers.id_alg_mtcProof.equals(sigAlgId.getAlgorithm()))
        {
            throw new IllegalArgumentException("Not a Merkle Tree certificate: expected id-alg-mtcProof");
        }
        if (sigAlgId.getParameters() != null)
        {
            throw new IllegalArgumentException("id-alg-mtcProof must have absent parameters");
        }

        // Cross-check the supplied hash function against the CA's published
        // logHash (Section 7.1). When authorityInfo is null, the relying
        // party is trusting itself to have wired the right hash.
        MTCCertificationAuthority authorityInfo = params.authorityInfo;
        if (authorityInfo != null)
        {
            if (!authorityInfo.getLogHash().getAlgorithm().equals(
                    params.hashFunction.getAlgorithmIdentifier().getAlgorithm()))
            {
                throw new SecurityException(
                    "hash function " + params.hashFunction.getAlgorithmIdentifier().getAlgorithm()
                    + " does not match CA logHash " + authorityInfo.getLogHash().getAlgorithm());
            }
        }

        // Step 2: decode the signatureValue as an MTCProof.
        MTCProof proof = new MTCProof(certHolder.getSignature());

        // Step 3: the serial number must be positive and fit in a uint64.
        BigInteger serialBig = certHolder.getSerialNumber();
        if (serialBig.signum() <= 0)
        {
            throw new SecurityException("Serial number must be positive");
        }
        if (serialBig.bitLength() > 64)
        {
            throw new SecurityException("Serial number exceeds uint64");
        }

        // Step 4: reject serials in any revoked range (Section 7.5), checked
        // against the full serial before it is decomposed. The CA's published
        // minSerial floor is the implicit range [0, minSerial) (Section 7.1).
        if (authorityInfo != null && serialBig.compareTo(authorityInfo.getMinSerial()) < 0)
        {
            throw new SecurityException(
                "Serial number " + serialBig + " is below CA minSerial " + authorityInfo.getMinSerial());
        }
        if (authorityInfo != null && serialBig.compareTo(authorityInfo.getMaxSerial()) > 0)
        {
            throw new SecurityException(
                "Serial number " + serialBig + " is above CA maxSerial " + authorityInfo.getMaxSerial());
        }
        for (RevokedRange range : params.revokedRanges)
        {
            if (range.contains(serialBig))
            {
                throw new SecurityException("Serial number " + serialBig + " is in a revoked range");
            }
        }

        // Step 5: decompose the serial number per Section 6.1 of the draft:
        //   serial = (log_number << 48) | index
        long index = serialBig.and(BigInteger.valueOf(0xFFFFFFFFFFFFL)).longValue();
        long logNumber = BigIntegers.longValueExact(serialBig.shiftRight(48));
        if (logNumber < 1 || logNumber > 0xFFFF)
        {
            throw new SecurityException("Invalid log_number " + logNumber + " in serial");
        }

        // Steps 7-9: derive the entry hash from the TBSCertificate. The
        // MTCProof's extensions list is prepended (per Section 7.2 step 8.2)
        // so that the leaf hash matches the log's view of the MerkleTreeCertEntry.
        byte[] entryHash = computeEntryHash(certHolder, proof.getExtensionsWire(), params.hashFunction);

        // Step 10: evaluate the inclusion proof to recover the expected subtree hash.
        List<byte[]> proofHashes;
        try
        {
            proofHashes = proof.getHashList(params.hashFunction.getHashSize());
        }
        catch (IllegalArgumentException e)
        {
            // The inclusion_proof length is attacker-controlled; a bad length is
            // a rejection of the certificate, not a caller error.
            throw new SecurityException("Invalid inclusion proof: " + e.getMessage(), e);
        }
        byte[] expectedSubtreeHash;
        try
        {
            expectedSubtreeHash = MerkleTreePrimitives.evaluateSubtreeInclusionProof(
                index,
                proof.getStart(),
                proof.getEnd(),
                entryHash,
                proofHashes,
                params.hashFunction);
        }
        catch (InvalidProofException e)
        {
            throw new SecurityException("Invalid inclusion proof: " + e.getMessage(), e);
        }

        // Step 11: if any trusted subtree matches (log_number, start, end), the
        // hash must equal it. Per Section 7.2: "Return success if it matches
        // and failure if it does not."
        for (TrustedSubtree trusted : params.trustedSubtrees)
        {
            if (trusted.matches(logNumber, proof.getStart(), proof.getEnd()))
            {
                if (trusted.matchesHash(expectedSubtreeHash))
                {
                    return true;
                }
                throw new SecurityException("Inclusion proof produced a hash that does not match the trusted subtree");
            }
        }

        // Step 12: otherwise verify cosignatures against the relying-party policy.
        // The issuer field carries the CA ID; the log ID is the CA ID concatenated
        // with the OID components 0 and the log_number from the serial number.
        byte[] caId = extractCaIdFromIssuer(certHolder.getIssuer());
        byte[] logId = TrustAnchorIDs.logId(caId, logNumber);

        int validCount = 0;
        for (MTCSignature sig : proof.getSignatures())
        {
            byte[] cosignerId = sig.getCosignerId();
            MTCCosignerVerifier verifier = params.cosignerVerifierProvider.get(cosignerId);
            if (verifier == null)
            {
                // Unrecognized cosigners MUST be ignored (Section 7.2 step 12).
                continue;
            }

            byte[] cosignedMessage = MTCCosignedMessage.encode(
                logId, proof.getStart(), proof.getEnd(), expectedSubtreeHash, cosignerId);

            OutputStream sOut = verifier.getOutputStream();
            sOut.write(cosignedMessage);
            sOut.close();
            if (verifier.verify(sig.getSignature()))
            {
                validCount++;
            }
        }

        if (validCount < params.minCosignatures)
        {
            throw new SecurityException("Insufficient valid cosignatures: " + validCount +
                " < " + params.minCosignatures);
        }

        return true;
    }

    /**
     * Convenience overload of
     * {@link #computeEntryHash(X509CertificateHolder, byte[], MerkleTreeHash)}
     * with an empty extensions list (the wire form is two zero bytes, the
     * uint16 length prefix). Use this when the certificate has no log-entry
     * extensions.
     */
    public static byte[] computeEntryHash(
        X509CertificateHolder certHolder,
        MerkleTreeHash hashFunc)
        throws IOException
    {
        return computeEntryHash(certHolder, EMPTY_EXTENSIONS_WIRE, hashFunc);
    }

    /**
     * Convenience overload of
     * {@link #computeEntryHash(TBSCertificate, byte[], MerkleTreeHash)} with an
     * empty extensions list. Useful when the caller has a {@link TBSCertificate}
     * in hand (for instance during issuance, before the signature is computed)
     * and doesn't want to build a placeholder {@link X509CertificateHolder}
     * solely to satisfy the holder-based overload.
     */
    public static byte[] computeEntryHash(
        TBSCertificate tbsCert,
        MerkleTreeHash hashFunc)
        throws IOException
    {
        return computeEntryHash(tbsCert, EMPTY_EXTENSIONS_WIRE, hashFunc);
    }

    /**
     * Convenience overload of
     * {@link #computeEntryHash(byte[], byte[], MerkleTreeHash)} with an empty
     * extensions list. Use this when the DER encoding of the TBSCertificate is
     * already in hand (e.g. captured from a streaming
     * {@link org.bouncycastle.operator.ContentSigner}) to avoid the parse +
     * re-encode round trip via {@link TBSCertificate}.
     */
    public static byte[] computeEntryHash(
        byte[] tbsCertDer,
        MerkleTreeHash hashFunc)
        throws IOException
    {
        return computeEntryHash(tbsCertDer, EMPTY_EXTENSIONS_WIRE, hashFunc);
    }

    /**
     * Combined "leaf hash + climb one level" for the simple case of a
     * size-two subtree {@code [0, 2)} where the EE has exactly one sibling
     * leaf. Equivalent to
     * {@code hashFunc.hashNode(computeEntryHash(tbsCertDer, hashFunc), inclusionProof)}.
     * The extensions list is empty.
     */
    public static byte[] computeSubtreeHash(
        byte[] tbsCertDer, byte[] inclusionProof, MerkleTreeHash hashFunc)
        throws IOException
    {
        return hashFunc.hashNode(
            computeEntryHash(tbsCertDer, EMPTY_EXTENSIONS_WIRE, hashFunc), inclusionProof);
    }

    /** Wire encoding of an empty {@code MerkleTreeCertEntryExtension extensions<0..2^16-1>} (the uint16 length prefix 0x0000). */
    private static final byte[] EMPTY_EXTENSIONS_WIRE = new byte[]{0, 0};

    /**
     * Computes the entry hash for a certificate by transforming its TBSCertificate
     * into the equivalent {@code MerkleTreeCertEntry} of type {@code tbs_cert_entry}
     * and hashing per Section 5.2.1 / Section 7.2.
     *
     * <p>The single-pass procedure (Section 7.2):</p>
     * <ol>
     *   <li>Write the {@code extensions} field from the MTCProof (the on-wire bytes
     *       including the 2-byte length prefix) to the hash.</li>
     *   <li>Write the big-endian, two-byte {@code tbs_cert_entry} value (0x0001).</li>
     *   <li>Write the TBSCertificate contents octets up to {@code subjectPublicKeyInfo}.</li>
     *   <li>Write the {@code subjectPublicKeyInfo}'s algorithm field.</li>
     *   <li>Write {@code 0x04 L H} where L is the hash length and H is HASH(SPKI).</li>
     *   <li>Write the remaining TBSCertificate contents octets.</li>
     *   <li>Finalize.</li>
     * </ol>
     *
     * @param extensionsWire the {@code extensions<0..2^16-1>} field exactly as it
     *                       appears at the start of the corresponding MTCProof
     *                       (use {@link MTCProof#getExtensionsWire()})
     */
    public static byte[] computeEntryHash(
        X509CertificateHolder certHolder,
        byte[] extensionsWire,
        MerkleTreeHash hashFunc)
        throws IOException
    {
        return computeEntryHash(certHolder.getTBSCertificate(), extensionsWire, hashFunc);
    }

    /**
     * TBSCertificate variant of
     * {@link #computeEntryHash(X509CertificateHolder, byte[], MerkleTreeHash)}.
     * The hash depends only on the to-be-signed structure, so callers that
     * haven't yet wrapped the TBSCertificate in a signed
     * {@link X509CertificateHolder} can compute the entry hash directly.
     */
    public static byte[] computeEntryHash(
        TBSCertificate tbsCert,
        byte[] extensionsWire,
        MerkleTreeHash hashFunc)
        throws IOException
    {
        return computeEntryHash(tbsCert.getEncoded(ASN1Encoding.DER), extensionsWire, hashFunc);
    }

    /**
     * Raw-DER variant of
     * {@link #computeEntryHash(TBSCertificate, byte[], MerkleTreeHash)} — skips
     * the parse + re-encode round trip when the TBSCertificate is already in
     * hand as DER bytes.
     */
    public static byte[] computeEntryHash(
        byte[] tbsCertDer,
        byte[] extensionsWire,
        MerkleTreeHash hashFunc)
        throws IOException
    {
        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        writeEntryHashInput(tbsCertDer, extensionsWire, hashFunc, entry);
        // MTH({entry}) = HASH(0x00 || entry).
        return hashFunc.hashLeaf(entry.toByteArray());
    }

    /**
     * Streams the byte sequence that {@link #computeEntryHash} hashes into the
     * supplied {@link OutputStream}. Equivalent in output to building a
     * {@link ByteArrayOutputStream} and finishing with
     * {@code hashFunc.hashLeaf(baos.toByteArray())}, but lets callers pipe the
     * bytes directly into a streaming digest (e.g.
     * {@code org.bouncycastle.crypto.io.DigestOutputStream} or
     * {@code java.security.DigestOutputStream}) so the {@code MerkleTreeCertEntry}
     * never lives fully in memory.
     *
     * <p>{@code hashFunc} is still required because Section 7.2's single-pass
     * procedure (step 8) hashes
     * the SubjectPublicKeyInfo separately via {@link MerkleTreeHash#hashRaw}
     * and writes only its hash into the entry stream.</p>
     *
     * @param certHolder     the X.509 certificate
     * @param extensionsWire the {@link MTCProof#getExtensionsWire()} bytes
     *                       (or {@code {0, 0}} for an empty extensions list)
     * @param hashFunc       hash function used for the SPKI hash; the caller
     *                       computes the leaf hash separately (typically by
     *                       feeding the leaf-tag byte {@code 0x00} into a
     *                       digest first, then piping {@code out} into the
     *                       same digest)
     * @param out            destination for the streamed entry bytes
     */
    public static void writeEntryHashInput(
        X509CertificateHolder certHolder,
        byte[] extensionsWire,
        MerkleTreeHash hashFunc,
        OutputStream out)
        throws IOException
    {
        writeEntryHashInput(certHolder.getTBSCertificate(), extensionsWire, hashFunc, out);
    }

    /**
     * TBSCertificate variant of
     * {@link #writeEntryHashInput(X509CertificateHolder, byte[], MerkleTreeHash, OutputStream)}.
     */
    public static void writeEntryHashInput(
        TBSCertificate tbsCert,
        byte[] extensionsWire,
        MerkleTreeHash hashFunc,
        OutputStream out)
        throws IOException
    {
        writeEntryHashInput(tbsCert.getEncoded(ASN1Encoding.DER), extensionsWire, hashFunc, out);
    }

    /**
     * Raw-DER variant of
     * {@link #writeEntryHashInput(TBSCertificate, byte[], MerkleTreeHash, OutputStream)} —
     * skips the parse + re-encode round trip when the TBSCertificate is already
     * in hand as DER bytes (e.g. captured from a streaming
     * {@link org.bouncycastle.operator.ContentSigner}).
     */
    public static void writeEntryHashInput(
        byte[] tbsCertDer,
        byte[] extensionsWire,
        MerkleTreeHash hashFunc,
        OutputStream out)
        throws IOException
    {
        ASN1Sequence tbsSeq = ASN1Sequence.getInstance(tbsCertDer);

        // Step 1 of the single-pass procedure: write the extensions wire bytes
        // (the uint16 length prefix plus each extension's bytes).
        out.write(extensionsWire);
        // MerkleTreeCertEntryType.tbs_cert_entry as a big-endian uint16.
        out.write((MerkleTreeCertEntryType.TBS_CERT_ENTRY >>> 8) & 0xFF);
        out.write(MerkleTreeCertEntryType.TBS_CERT_ENTRY & 0xFF);

        int size = tbsSeq.size();
        int idx = 0;

        // Optional [0] EXPLICIT Version.
        if (idx < size)
        {
            ASN1Encodable obj = tbsSeq.getObjectAt(idx);
            if (obj.toASN1Primitive() instanceof ASN1TaggedObject)
            {
                ASN1TaggedObject tagged = (ASN1TaggedObject)obj.toASN1Primitive();
                if (tagged.getTagNo() == 0)
                {
                    out.write(tagged.getEncoded(ASN1Encoding.DER));
                    idx++;
                }
            }
        }

        // Skip serialNumber, signature.
        idx += 2;

        if (idx + 4 > size)
        {
            throw new IOException("TBSCertificate is missing required fields");
        }

        // issuer, validity, subject.
        out.write(tbsSeq.getObjectAt(idx++).toASN1Primitive().getEncoded(ASN1Encoding.DER));
        out.write(tbsSeq.getObjectAt(idx++).toASN1Primitive().getEncoded(ASN1Encoding.DER));
        out.write(tbsSeq.getObjectAt(idx++).toASN1Primitive().getEncoded(ASN1Encoding.DER));

        // subjectPublicKeyInfo: emit algorithm field, then OCTET STRING(HASH(SPKI)).
        ASN1Encodable spkiObj = tbsSeq.getObjectAt(idx++);
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(spkiObj);
        byte[] spkiDer = spki.getEncoded(ASN1Encoding.DER);
        out.write(spki.getAlgorithm().getEncoded(ASN1Encoding.DER));

        byte[] spkiHash = hashFunc.hashRaw(spkiDer);
        if (spkiHash.length > 127)
        {
            // The TBSCertificateLogEntry definition uses an OCTET STRING, which we
            // emit in DER. Hashes longer than 127 bytes would require multi-byte
            // length encoding; SHA-256/384/512 are all under this limit.
            throw new IOException("Hash size exceeds DER short-form length: " + spkiHash.length);
        }
        out.write(new DEROctetString(spkiHash).getEncoded(ASN1Encoding.DER));

        // Remaining tagged optionals: [1] issuerUniqueID, [2] subjectUniqueID, [3] extensions.
        while (idx < size)
        {
            out.write(tbsSeq.getObjectAt(idx++).toASN1Primitive().getEncoded(ASN1Encoding.DER));
        }
    }

    /**
     * Extracts the binary CA trust anchor ID from the issuer field of a Merkle
     * Tree certificate. Per Section 5.1 of the draft the issuer name has a single
     * RDN with a single attribute. For initial experimentation the attribute
     * type is {@code id_rdna_trustAnchorID} ({@code 1.3.6.1.4.1.44363.47.1})
     * with a UTF8String value of the dotted-decimal trust anchor ID; for the
     * production encoding the value is a RELATIVE-OID. Both are accepted; the
     * return value is the binary trust anchor ID per Section 3 of
     * draft-ietf-tls-trust-anchor-ids.
     */
    public static byte[] extractCaIdFromIssuer(X500Name issuer)
        throws IOException
    {
        RDN[] rdns = issuer.getRDNs();
        if (rdns.length != 1)
        {
            throw new IOException("Issuer must have exactly one RDN");
        }
        AttributeTypeAndValue[] atav = rdns[0].getTypesAndValues();
        if (atav.length != 1)
        {
            throw new IOException("RDN must have exactly one attribute");
        }

        ASN1ObjectIdentifier type = atav[0].getType();
        if (!MTCObjectIdentifiers.id_rdna_trustAnchorID.equals(type))
        {
            throw new IOException("Issuer attribute is not id-rdna-trustAnchorID");
        }

        ASN1Encodable value = atav[0].getValue();
        ASN1Primitive prim = value.toASN1Primitive();

        if (prim instanceof ASN1RelativeOID)
        {
            return TrustAnchorIDs.fromDottedDecimal(((ASN1RelativeOID)prim).getId());
        }
        if (prim instanceof ASN1String)
        {
            return TrustAnchorIDs.fromDottedDecimal(((ASN1String)prim).getString());
        }
        if (prim instanceof ASN1OctetString)
        {
            // Tolerated for backward compatibility with very early prototypes that
            // stored the binary trust anchor ID inside an OCTET STRING.
            return ((ASN1OctetString)prim).getOctets();
        }
        throw new IOException("Unsupported attribute value type: " + prim.getClass().getName());
    }
}
