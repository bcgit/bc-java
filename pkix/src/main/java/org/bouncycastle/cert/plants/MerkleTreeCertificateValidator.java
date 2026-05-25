package org.bouncycastle.cert.plants;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Collections;
import java.util.List;
import java.util.Set;

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
     *   <li>The cert's serial number is at least {@code authorityInfo.getMinSerial()}
     *       (Section 5.5 / 7.2).</li>
     *   <li>The {@code hashFunction} OID matches {@code authorityInfo.getLogHash()}
     *       (Section 7.1).</li>
     * </ul>
     * <p>{@code authorityInfo.getSigAlg()} is the CA cosigner's published signature
     * algorithm; enforcing it requires the {@link MTCCosignerVerifierProvider}
     * to expose its bound algorithm, which the operator interface does not
     * currently surface. Callers building the provider for the CA cosigner are
     * responsible for ensuring the verifier they register uses
     * {@code authorityInfo.getSigAlg()}.</p>
     */
    public static class ValidationParams
    {
        private final MTCCosignerVerifierProvider cosignerVerifierProvider;
        private final List<TrustedSubtree> trustedSubtrees;
        private final Set<Long> revokedIndices;
        private final int minCosignatures;
        private final MerkleTreeHash hashFunction;
        private final MTCCertificationAuthority authorityInfo;

        public ValidationParams(
            MTCCosignerVerifierProvider cosignerVerifierProvider,
            MerkleTreeHash hashFunction,
            List<TrustedSubtree> trustedSubtrees,
            Set<Long> revokedIndices,
            int minCosignatures)
        {
            this(cosignerVerifierProvider, trustedSubtrees, revokedIndices,
                minCosignatures, hashFunction, null);
        }

        /**
         * Convenience constructor for the common case where the relying party
         * has no pre-distributed trusted subtrees and no revocations to apply.
         * Defaults {@code trustedSubtrees} to an empty list and
         * {@code revokedIndices} to an empty set.
         */
        public ValidationParams(
            MTCCosignerVerifierProvider cosignerVerifierProvider,
            MerkleTreeHash hashFunction,
            int minCosignatures,
            MTCCertificationAuthority authorityInfo)
        {
            this(cosignerVerifierProvider,
                Collections.<TrustedSubtree>emptyList(),
                Collections.<Long>emptySet(),
                minCosignatures, hashFunction, authorityInfo);
        }

        public ValidationParams(
            MTCCosignerVerifierProvider cosignerVerifierProvider,
            List<TrustedSubtree> trustedSubtrees,
            Set<Long> revokedIndices,
            int minCosignatures,
            MerkleTreeHash hashFunction,
            MTCCertificationAuthority authorityInfo)
        {
            this.cosignerVerifierProvider = cosignerVerifierProvider;
            this.trustedSubtrees = trustedSubtrees;
            this.revokedIndices = revokedIndices;
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

        public Set<Long> getRevokedIndices()
        {
            return revokedIndices;
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
     * to the relying party, per Section 7.4).
     */
    public static class TrustedSubtree
    {
        private final long start;
        private final long end;
        private final byte[] hash;

        public TrustedSubtree(long start, long end, byte[] hash)
        {
            this.start = start;
            this.end = end;
            this.hash = hash.clone();
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

        boolean matchesInterval(long start, long end)
        {
            return this.start == start && this.end == end;
        }

        boolean matchesHash(byte[] hash)
        {
            return Arrays.areEqual(this.hash, hash);
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

        // Step 3: decompose the serial number per Section 6.1 of the draft:
        //   serial = (log_number << 48) | index
        // and check revocation and the CA's minSerial floor.
        BigInteger serialBig = certHolder.getSerialNumber();
        if (serialBig.signum() <= 0)
        {
            throw new SecurityException("Serial number must be positive");
        }
        if (serialBig.bitLength() > 64)
        {
            throw new SecurityException("Serial number exceeds uint64");
        }
        if (authorityInfo != null && serialBig.compareTo(authorityInfo.getMinSerial()) < 0)
        {
            throw new SecurityException(
                "Serial number " + serialBig + " is below CA minSerial " + authorityInfo.getMinSerial());
        }
        long index = serialBig.and(BigInteger.valueOf(0xFFFFFFFFFFFFL)).longValue();
        long logNumber = serialBig.shiftRight(48).longValueExact();
        if (logNumber < 1 || logNumber > 0xFFFF)
        {
            throw new SecurityException("Invalid log_number " + logNumber + " in serial");
        }
        if (params.revokedIndices.contains(Long.valueOf(index)))
        {
            throw new SecurityException("Certificate index " + index + " is revoked");
        }

        // Steps 4 and 5: derive the entry hash from the TBSCertificate. The
        // MTCProof's extensions list is prepended (per Section 7.2 step 5.2)
        // so that the leaf hash matches the log's view of the MerkleTreeCertEntry.
        byte[] entryHash = computeEntryHash(certHolder, proof.getExtensionsWire(), params.hashFunction);

        // Step 6: evaluate the inclusion proof to recover the expected subtree hash.
        byte[] expectedSubtreeHash;
        try
        {
            expectedSubtreeHash = MerkleTreePrimitives.evaluateSubtreeInclusionProof(
                index,
                proof.getStart(),
                proof.getEnd(),
                entryHash,
                proof.getHashList(params.hashFunction.getHashSize()),
                params.hashFunction);
        }
        catch (InvalidProofException e)
        {
            throw new SecurityException("Invalid inclusion proof: " + e.getMessage(), e);
        }

        // Step 7: if any trusted subtree matches [start, end), the hash must equal it.
        // Per Section 7.2: "Return success if it matches and failure if it does not."
        for (TrustedSubtree trusted : params.trustedSubtrees)
        {
            if (trusted.matchesInterval(proof.getStart(), proof.getEnd()))
            {
                if (trusted.matchesHash(expectedSubtreeHash))
                {
                    return true;
                }
                throw new SecurityException("Inclusion proof produced a hash that does not match the trusted subtree");
            }
        }

        // Step 8: otherwise verify cosignatures against the relying-party policy.
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
                // Unrecognized cosigners MUST be ignored (Section 7.2 step 8).
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
     * Combined "leaf hash + climb one level" for the simple-case 2-leaf log
     * where the EE has exactly one sibling leaf. Equivalent to
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
     * <p>{@code hashFunc} is still required because Section 7.2 step 5 hashes
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
