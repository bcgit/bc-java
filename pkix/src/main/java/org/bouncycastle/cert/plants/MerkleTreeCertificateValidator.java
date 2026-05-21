package org.bouncycastle.cert.plants;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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
import org.bouncycastle.asn1.plants.CloudFlareObjectIdentifiers;
import org.bouncycastle.asn1.plants.MTCSignature;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.plants.MTCSignatureVerifier;
import org.bouncycastle.crypto.plants.MerkleTreePrimitives;
import org.bouncycastle.util.Arrays;

/**
 * Validates a Merkle Tree Certificate (MTC) as defined in
 * <a href="https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/">draft-ietf-plants-merkle-tree-certs</a>.
 *
 * <p>The validator performs the per-certificate signature verification step of
 * RFC 5280 path validation (Section 6.1.3 step (a)(1)) when the issuer is a
 * Merkle Tree CA, following Section 7.2 of the draft.</p>
 */
public class MerkleTreeCertificateValidator
{
    /** OID of the {@code id-alg-mtcProof} signature algorithm (experimental, Section 6.1). */
    public static final String ID_ALG_MTC_PROOF = CloudFlareObjectIdentifiers.id_alg_mtcProof.getId();

    /**
     * Parameters supplied by the relying party for certificate validation.
     */
    public static class ValidationParams
    {
        private final Map<ByteArrayKey, AsymmetricKeyParameter> cosignerPublicKeys;
        private final List<TrustedSubtree> trustedSubtrees;
        private final Set<Long> revokedIndices;
        private final int minCosignatures;
        private final MerkleTreePrimitives.MerkleTreeHash hashFunction;

        public ValidationParams(
            Map<ByteArrayKey, AsymmetricKeyParameter> cosignerPublicKeys,
            List<TrustedSubtree> trustedSubtrees,
            Set<Long> revokedIndices,
            int minCosignatures,
            MerkleTreePrimitives.MerkleTreeHash hashFunction)
        {
            this.cosignerPublicKeys = cosignerPublicKeys;
            this.trustedSubtrees = trustedSubtrees;
            this.revokedIndices = revokedIndices;
            this.minCosignatures = minCosignatures;
            this.hashFunction = hashFunction;
        }

        public Map<ByteArrayKey, AsymmetricKeyParameter> getCosignerPublicKeys()
        {
            return cosignerPublicKeys;
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

        public MerkleTreePrimitives.MerkleTreeHash getHashFunction()
        {
            return hashFunction;
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
     * Validates a Merkle Tree certificate per Section 7.2.
     *
     * @param certHolder the certificate to validate
     * @param params     validation parameters
     * @return {@code true} if the certificate is valid
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
        if (!CloudFlareObjectIdentifiers.id_alg_mtcProof.equals(sigAlgId.getAlgorithm()))
        {
            throw new IllegalArgumentException("Not a Merkle Tree certificate: expected id-alg-mtcProof");
        }
        if (sigAlgId.getParameters() != null)
        {
            throw new IllegalArgumentException("id-alg-mtcProof must have absent parameters");
        }

        // Step 2: decode the signatureValue as an MTCProof.
        MTCProof proof = new MTCProof(certHolder.getSignature());

        // Step 3: decompose the serial number per Section 6.1 of draft-04:
        //   serial = (log_number << 48) | index
        // and check revocation.
        BigInteger serialBig = certHolder.getSerialNumber();
        if (serialBig.signum() <= 0)
        {
            throw new SecurityException("Serial number must be positive");
        }
        if (serialBig.bitLength() > 64)
        {
            throw new SecurityException("Serial number exceeds uint64");
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

        // Steps 4 and 5: derive the entry hash from the TBSCertificate.
        byte[] entryHash = computeEntryHash(certHolder, params.hashFunction);

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
        catch (MerkleTreePrimitives.InvalidProofException e)
        {
            throw new SecurityException("Invalid inclusion proof: " + e.getMessage());
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
        byte[] logId = Utils.buildLogId(caId, logNumber);

        int validCount = 0;
        for (MTCSignature sig : proof.getSignatures())
        {
            byte[] cosignerId = sig.getCosignerId();
            if (verifyCosignature(
                logId,
                proof.getStart(),
                proof.getEnd(),
                expectedSubtreeHash,
                cosignerId,
                sig.getSignature(),
                params))
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

    private static boolean verifyCosignature(
        byte[] logId,
        long start,
        long end,
        byte[] subtreeHash,
        byte[] cosignerId,
        byte[] signature,
        ValidationParams params)
        throws IOException
    {
        AsymmetricKeyParameter pubKey = params.cosignerPublicKeys.get(new ByteArrayKey(cosignerId));
        if (pubKey == null)
        {
            // Unrecognized cosigners MUST be ignored (Section 7.2 step 8).
            return false;
        }

        String algorithm = getAlgorithmFromKey(pubKey);

        return MTCSignatureVerifier.verify(
            logId, start, end, subtreeHash, cosignerId, signature, pubKey, algorithm);
    }

    private static String getAlgorithmFromKey(AsymmetricKeyParameter key)
    {
        if (key instanceof ECPublicKeyParameters)
        {
            ECPublicKeyParameters ec = (ECPublicKeyParameters)key;
            int fieldSize = ec.getParameters().getCurve().getFieldSize();
            if (fieldSize == 256)
            {
                return "ECDSA-P256-SHA256";
            }
            if (fieldSize == 384)
            {
                return "ECDSA-P384-SHA384";
            }
            throw new IllegalArgumentException("Unsupported EC field size: " + fieldSize);
        }
        if (key instanceof Ed25519PublicKeyParameters)
        {
            return "Ed25519";
        }
        if (key.getClass().getName().contains("MLDSAPublicKeyParameters"))
        {
            // ML-DSA parameter sets share the same Signer class; the key carries the parameter set.
            return "ML-DSA-65";
        }
        throw new IllegalArgumentException("Unsupported public key type: " + key.getClass().getName());
    }

    /**
     * Computes the entry hash for a certificate by transforming its TBSCertificate
     * into the equivalent {@code MerkleTreeCertEntry} of type {@code tbs_cert_entry}
     * and hashing per Section 5.3 / Section 7.2.
     *
     * <p>The TBSCertificate's {@code serialNumber} and {@code signature} fields are
     * omitted (they have no counterpart in TBSCertificateLogEntry), and
     * {@code subjectPublicKeyInfo} is replaced by the algorithm field followed by
     * the OCTET STRING encoding of HASH(subjectPublicKeyInfo).</p>
     */
    public static byte[] computeEntryHash(
        X509CertificateHolder certHolder,
        MerkleTreePrimitives.MerkleTreeHash hashFunc)
        throws IOException
    {
        byte[] tbsCertBytes = certHolder.getTBSCertificate().getEncoded(ASN1Encoding.DER);
        ASN1Sequence tbsSeq = ASN1Sequence.getInstance(tbsCertBytes);

        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        // MerkleTreeCertEntryType.tbs_cert_entry (= 1), big-endian uint16.
        entry.write(0x00);
        entry.write(0x01);

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
                    entry.write(tagged.getEncoded(ASN1Encoding.DER));
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
        entry.write(tbsSeq.getObjectAt(idx++).toASN1Primitive().getEncoded(ASN1Encoding.DER));
        entry.write(tbsSeq.getObjectAt(idx++).toASN1Primitive().getEncoded(ASN1Encoding.DER));
        entry.write(tbsSeq.getObjectAt(idx++).toASN1Primitive().getEncoded(ASN1Encoding.DER));

        // subjectPublicKeyInfo: emit algorithm field, then OCTET STRING(HASH(SPKI)).
        ASN1Encodable spkiObj = tbsSeq.getObjectAt(idx++);
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(spkiObj);
        byte[] spkiDer = spki.getEncoded(ASN1Encoding.DER);
        entry.write(spki.getAlgorithm().getEncoded(ASN1Encoding.DER));

        byte[] spkiHash = hashFunc.hashRaw(spkiDer);
        if (spkiHash.length > 127)
        {
            // The TBSCertificateLogEntry definition uses an OCTET STRING, which we
            // emit in DER. Hashes longer than 127 bytes would require multi-byte
            // length encoding; SHA-256/384/512 are all under this limit.
            throw new IOException("Hash size exceeds DER short-form length: " + spkiHash.length);
        }
        entry.write(new DEROctetString(spkiHash).getEncoded(ASN1Encoding.DER));

        // Remaining tagged optionals: [1] issuerUniqueID, [2] subjectUniqueID, [3] extensions.
        while (idx < size)
        {
            entry.write(tbsSeq.getObjectAt(idx++).toASN1Primitive().getEncoded(ASN1Encoding.DER));
        }

        // MTH({entry}) = HASH(0x00 || entry).
        return hashFunc.hashLeaf(entry.toByteArray());
    }

    /**
     * Extracts the binary CA trust anchor ID from the issuer field of a Merkle
     * Tree certificate. Per Section 5.1 of draft-04 the issuer name has a single
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
        if (!CloudFlareObjectIdentifiers.id_rdna_trustAnchorID.equals(type))
        {
            throw new IOException("Issuer attribute is not id-rdna-trustAnchorID");
        }

        ASN1Encodable value = atav[0].getValue();
        ASN1Primitive prim = value.toASN1Primitive();

        if (prim instanceof ASN1RelativeOID)
        {
            return Utils.dottedDecimalToBinaryTrustAnchorID(((ASN1RelativeOID)prim).getId());
        }
        if (prim instanceof ASN1String)
        {
            return Utils.dottedDecimalToBinaryTrustAnchorID(((ASN1String)prim).getString());
        }
        if (prim instanceof ASN1OctetString)
        {
            // Tolerated for backward compatibility with very early prototypes that
            // stored the binary trust anchor ID inside an OCTET STRING.
            return ((ASN1OctetString)prim).getOctets();
        }
        throw new IOException("Unsupported attribute value type: " + prim.getClass().getName());
    }

    /**
     * Convenience wrapper around a {@code byte[]} that supports value-based
     * equality, suitable as a {@code Map} key for cosigner-ID lookups.
     */
    public static class ByteArrayKey
    {
        private final byte[] data;

        public ByteArrayKey(byte[] data)
        {
            this.data = data.clone();
        }

        public byte[] getData()
        {
            return data.clone();
        }

        @Override
        public boolean equals(Object o)
        {
            if (this == o)
            {
                return true;
            }
            if (!(o instanceof ByteArrayKey))
            {
                return false;
            }
            return Arrays.areEqual(this.data, ((ByteArrayKey)o).data);
        }

        @Override
        public int hashCode()
        {
            return Arrays.hashCode(data);
        }
    }
}
