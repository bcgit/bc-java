package org.bouncycastle.cades;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.esf.ESFAttributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

/**
 * Helpers for upgrading a CAdES B-LT signature to B-LTA by attaching an
 * archive-time-stamp covering the entire SignedData.
 * <p>
 * The helper emits the ETSI TS&nbsp;101&nbsp;733&nbsp;v1.7.4 "v2" form
 * ({@code id-aa-ets-archiveTimestampV2}, OID {@code 1.2.840.113549.1.9.16.2.48}).
 * The newer ETSI EN&nbsp;319&nbsp;122-1 "v3" form, which embeds an
 * {@code ats-hash-index-v3} signed attribute inside the TSA token, is not
 * yet supported &mdash; v3 generation requires custom signed-attribute
 * injection on the TSA token that is not yet exposed by the {@code tsp}
 * module.
 * <p>
 * The v2 imprint is the digest, under the caller-supplied algorithm, of
 * the canonical concatenation defined by ETSI TS&nbsp;101&nbsp;733 Annex A:
 * <ol>
 *   <li>the content octets of the encapsulated content (omitted if the
 *       signed-data is detached or has no eContent),</li>
 *   <li>each {@code Certificate} from the {@code certificates} field, in
 *       wire-encoding order, as its own DER encoding,</li>
 *   <li>each {@code CertificateList} from the {@code crls} field, in
 *       wire-encoding order, as its own DER encoding,</li>
 *   <li>for each {@code SignerInfo} (in wire-encoding order), its DER
 *       encoding with any archive-time-stamp attributes removed from
 *       the {@code unsignedAttrs} field.</li>
 * </ol>
 * Typical caller flow:
 * <ol>
 *   <li>{@link #computeArchiveTimestampImprint(CMSSignedData, AlgorithmIdentifier,
 *       DigestCalculatorProvider)} returns the digest bytes.</li>
 *   <li>The caller obtains a {@link TimeStampToken} from a TSA over those
 *       bytes (transport is out of scope for BC).</li>
 *   <li>{@link #applyArchiveTimestamp(CMSSignedData, SignerId, TimeStampToken)}
 *       returns a new CMSSignedData with the token attached as an
 *       {@code id-aa-ets-archiveTimestampV2} unsigned attribute on the
 *       chosen signer.</li>
 * </ol>
 */
public final class CAdESArchiveTimestampUtil
{
    /** ETSI TS 101 733 v1.7.4 id-aa-ets-archiveTimestampV2 OID. */
    public static final ASN1ObjectIdentifier id_aa_ets_archiveTimestampV2 =
        ESFAttributes.archiveTimestampV2;

    private CAdESArchiveTimestampUtil()
    {
    }

    /**
     * Digest the canonical archive-time-stamp v2 input for {@code signed}
     * under {@code digestAlg}.
     */
    public static byte[] computeArchiveTimestampImprint(CMSSignedData signed,
                                                        AlgorithmIdentifier digestAlg,
                                                        DigestCalculatorProvider digCalcProv)
        throws CAdESException, OperatorCreationException, IOException
    {
        if (signed == null)
        {
            throw new NullPointerException("signed");
        }
        if (digestAlg == null)
        {
            throw new NullPointerException("digestAlg");
        }

        DigestCalculator dc = digCalcProv.get(digestAlg);
        OutputStream out = dc.getOutputStream();
        feedCanonicalInput(signed, out);
        out.close();
        return dc.getDigest();
    }

    /**
     * Streaming variant: digest the canonical archive-time-stamp v2 input
     * directly from a {@link CMSSignedDataParser} without materialising the
     * whole SignedData. The parser's signed content is fully drained during
     * this call; cert/CRL/SignerInfo sections are then parsed in stream
     * order. After this method returns the parser's content stream has been
     * consumed and cannot be re-read from the same parser.
     * <p>
     * The supplied parser must be positioned at the start of the SignedData
     * (i.e. freshly constructed, with {@code getSignedContent()} not yet
     * drained).
     */
    public static byte[] computeArchiveTimestampImprint(CMSSignedDataParser parser,
                                                        AlgorithmIdentifier digestAlg,
                                                        DigestCalculatorProvider digCalcProv)
        throws CAdESException, CMSException, OperatorCreationException, IOException
    {
        if (parser == null)
        {
            throw new NullPointerException("parser");
        }
        if (digestAlg == null)
        {
            throw new NullPointerException("digestAlg");
        }

        DigestCalculator dc = digCalcProv.get(digestAlg);
        OutputStream out = dc.getOutputStream();

        // (1) eContent octets, streamed through the imprint digest.
        CMSTypedStream content = parser.getSignedContent();
        if (content != null)
        {
            Streams.pipeAll(content.getContentStream(), out);
        }

        // (2) certificates, in wire-encoding order, every choice DER-encoded as-is.
        ASN1Set certs = parser.getCertificateSet();
        if (certs != null)
        {
            Enumeration e = certs.getObjects();
            while (e.hasMoreElements())
            {
                ASN1Encodable c = (ASN1Encodable)e.nextElement();
                out.write(c.toASN1Primitive().getEncoded(ASN1Encoding.DER));
            }
        }

        // (3) CRLs, same treatment.
        ASN1Set crls = parser.getCRLSet();
        if (crls != null)
        {
            Enumeration e = crls.getObjects();
            while (e.hasMoreElements())
            {
                ASN1Encodable c = (ASN1Encodable)e.nextElement();
                out.write(c.toASN1Primitive().getEncoded(ASN1Encoding.DER));
            }
        }

        // (4) SignerInfos with archive-timestamps stripped and re-DER-encoded.
        for (SignerInformation s : parser.getSignerInfos().getSigners())
        {
            SignerInformation stripped = stripArchiveTimestamps(s);
            out.write(stripped.toASN1Structure().getEncoded(ASN1Encoding.DER));
        }

        out.close();
        return dc.getDigest();
    }

    /**
     * Attach an archive-time-stamp v2 to the signer matched by
     * {@code signerId}. If the signer already has one or more
     * archive-timestamp attributes the new token is appended into the
     * existing attribute's value-set; archive-timestamps form an ordered
     * chain so this preserves earlier timestamps.
     */
    public static CMSSignedData applyArchiveTimestamp(CMSSignedData signed,
                                                      SignerId signerId,
                                                      TimeStampToken token)
        throws CAdESException
    {
        if (signed == null)
        {
            throw new NullPointerException("signed");
        }
        if (signerId == null)
        {
            throw new NullPointerException("signerId");
        }
        if (token == null)
        {
            throw new NullPointerException("token");
        }

        SignerInformationStore signers = signed.getSignerInfos();
        Collection<SignerInformation> matched = signers.getSigners(signerId);
        if (matched.isEmpty())
        {
            throw new CAdESException("no signer matched in CMSSignedData");
        }

        ContentInfo tokenCi;
        try
        {
            tokenCi = ContentInfo.getInstance(
                ASN1Primitive.fromByteArray(token.getEncoded()));
        }
        catch (IOException e)
        {
            throw new CAdESException("unable to encode TimeStampToken: " + e.getMessage(), e);
        }

        List<SignerInformation> rebuilt = new ArrayList<SignerInformation>(signers.size());
        for (Iterator<SignerInformation> it = signers.getSigners().iterator(); it.hasNext(); )
        {
            SignerInformation cur = it.next();
            if (matched.contains(cur))
            {
                rebuilt.add(appendArchiveTimestamp(cur, tokenCi));
            }
            else
            {
                rebuilt.add(cur);
            }
        }
        return CMSSignedData.replaceSigners(signed, new SignerInformationStore(rebuilt));
    }

    /**
     * Return the archive-time-stamp tokens carried by the signer, drawn from
     * both the {@code id-aa-ets-archiveTimestampV2} attribute and the legacy
     * {@code id-aa-ets-archiveTimestamp} (RFC&nbsp;5126 sec. 6.4.1) attribute,
     * in attribute-value order (v2 first when both are present).
     * <p>
     * The list reflects the v2 chain: each entry independently covers the
     * canonical archive-time-stamp input (with all archive-time-stamps
     * stripped), so a chain of N tokens gives N independent integrity
     * witnesses over the same canonical bytes &mdash; chain renewability
     * relies on the most-recent token's TSA cert still being fresh.</p>
     *
     * @param signer the signer to inspect.
     * @return an unmodifiable list of timestamp tokens, empty when neither
     *         archive-time-stamp attribute is present (signer has not been
     *         upgraded to B-LTA).
     * @throws CAdESException if an attribute value cannot be parsed as a
     *                       {@link TimeStampToken}.
     */
    public static List<TimeStampToken> getArchiveTimestamps(SignerInformation signer)
        throws CAdESException
    {
        if (signer == null)
        {
            throw new NullPointerException("signer");
        }
        AttributeTable unsigned = signer.getUnsignedAttributes();
        if (unsigned == null)
        {
            return Collections.emptyList();
        }
        List<TimeStampToken> out = new ArrayList<TimeStampToken>();
        readTokensInto(unsigned.get(id_aa_ets_archiveTimestampV2), out);
        readTokensInto(unsigned.get(PKCSObjectIdentifiers.id_aa_ets_archiveTimestamp), out);
        return Collections.unmodifiableList(out);
    }

    /**
     * Self-consistency check on B-LTA material: for every archive-time-stamp
     * attached to the signer, verify the token's {@code MessageImprint}
     * equals {@link #computeArchiveTimestampImprint} run over the
     * canonical-stripped {@code signed} structure under the token's own
     * hash algorithm.
     * <p>The {@code signed} argument must be the {@link CMSSignedData} the
     * tokens were attached to (after {@code applyArchiveTimestamp}); a
     * different SignedData with the same signer will not produce matching
     * canonical bytes.</p>
     * <p>What this method does <i>not</i> do: validate the TSA's signature
     * on each token, walk the TSA cert chain to a trust anchor, or check
     * the archive-time-stamp dates against the signer cert's validity
     * window. Those steps are the caller's responsibility, built on
     * {@link #getArchiveTimestamps} plus the {@code tsp} module's token
     * validators.</p>
     *
     * @param signed      the SignedData carrying {@code signer}.
     * @param signer      the signer to validate. Must carry at least one
     *                    archive-time-stamp.
     * @param digCalcProv source of digest calculators.
     * @throws CAdESException if no archive-time-stamp is present, a token
     *                       cannot be parsed, or any token's imprint does
     *                       not match the canonical input.
     */
    public static void validateArchiveTimestamps(CMSSignedData signed,
                                                 SignerInformation signer,
                                                 DigestCalculatorProvider digCalcProv)
        throws CAdESException, OperatorCreationException, IOException
    {
        if (signed == null)
        {
            throw new NullPointerException("signed");
        }
        List<TimeStampToken> tokens = getArchiveTimestamps(signer);
        if (tokens.isEmpty())
        {
            throw new CAdESException(
                "no archive-time-stamp attribute (id-aa-ets-archiveTimestampV2 / "
                    + "id-aa-ets-archiveTimestamp) is present");
        }
        for (int i = 0; i != tokens.size(); ++i)
        {
            TimeStampToken token = tokens.get(i);
            AlgorithmIdentifier alg = token.getTimeStampInfo().getHashAlgorithm();
            byte[] embedded = token.getTimeStampInfo().getMessageImprintDigest();
            byte[] recomputed = computeArchiveTimestampImprint(signed, alg, digCalcProv);
            if (!Arrays.constantTimeAreEqual(embedded, recomputed))
            {
                throw new CAdESException(
                    "archive-time-stamp imprint mismatch at index " + i);
            }
        }
    }

    private static void readTokensInto(Attribute attr, List<TimeStampToken> out)
        throws CAdESException
    {
        if (attr == null)
        {
            return;
        }
        ASN1Set vals = attr.getAttrValues();
        for (int i = 0; i != vals.size(); ++i)
        {
            try
            {
                ContentInfo ci = ContentInfo.getInstance(vals.getObjectAt(i));
                out.add(new TimeStampToken(ci));
            }
            catch (IOException e)
            {
                throw new CAdESException(
                    "unable to parse " + attr.getAttrType() + " value at index "
                        + i + ": " + e.getMessage(), e);
            }
            catch (TSPException e)
            {
                throw new CAdESException(
                    "unable to parse " + attr.getAttrType() + " value at index "
                        + i + ": " + e.getMessage(), e);
            }
        }
    }

    private static SignerInformation appendArchiveTimestamp(SignerInformation signer,
                                                             ContentInfo tokenCi)
    {
        AttributeTable unsigned = signer.getUnsignedAttributes();

        Attribute existing = unsigned == null
            ? null
            : unsigned.get(id_aa_ets_archiveTimestampV2);

        ASN1EncodableVector vals = new ASN1EncodableVector();
        if (existing != null)
        {
            ASN1Set prev = existing.getAttrValues();
            for (int i = 0; i != prev.size(); i++)
            {
                vals.add(prev.getObjectAt(i));
            }
        }
        vals.add(tokenCi);
        Attribute merged = new Attribute(id_aa_ets_archiveTimestampV2, new DERSet(vals));

        ASN1EncodableVector all = unsigned == null
            ? new ASN1EncodableVector()
            : unsigned.toASN1EncodableVector();

        ASN1EncodableVector outVec = new ASN1EncodableVector();
        for (int i = 0; i != all.size(); ++i)
        {
            Attribute a = Attribute.getInstance(all.get(i));
            if (!id_aa_ets_archiveTimestampV2.equals(a.getAttrType()))
            {
                outVec.add(a);
            }
        }
        outVec.add(merged);

        return SignerInformation.replaceUnsignedAttributes(signer, new AttributeTable(outVec));
    }

    /**
     * Walk the SignedData and feed the canonical archive-time-stamp v2
     * input bytes to {@code out}.
     */
    private static void feedCanonicalInput(CMSSignedData signed, OutputStream out)
        throws CAdESException, IOException
    {
        SignedData sd;
        try
        {
            sd = SignedData.getInstance(signed.toASN1Structure().getContent());
        }
        catch (Exception e)
        {
            throw new CAdESException("unable to read SignedData: " + e.getMessage(),
                e instanceof Exception ? (Exception)e : new RuntimeException(e));
        }

        // (1) eContent octets, if present.
        ASN1Encodable encap = sd.getEncapContentInfo().getContent();
        if (encap instanceof ASN1OctetString)
        {
            out.write(((ASN1OctetString)encap).getOctets());
        }

        // (2) certificates, in wire-encoding order.
        ASN1Set certs = sd.getCertificates();
        if (certs != null)
        {
            Enumeration e = certs.getObjects();
            while (e.hasMoreElements())
            {
                ASN1Encodable c = (ASN1Encodable)e.nextElement();
                out.write(c.toASN1Primitive().getEncoded(ASN1Encoding.DER));
            }
        }

        // (3) CRLs, in wire-encoding order.
        ASN1Set crls = sd.getCRLs();
        if (crls != null)
        {
            Enumeration e = crls.getObjects();
            while (e.hasMoreElements())
            {
                ASN1Encodable c = (ASN1Encodable)e.nextElement();
                out.write(c.toASN1Primitive().getEncoded(ASN1Encoding.DER));
            }
        }

        // (4) Each SignerInfo, with archive-time-stamps stripped from
        //     unsignedAttrs and re-DER-encoded.
        for (SignerInformation s : signed.getSignerInfos().getSigners())
        {
            SignerInformation stripped = stripArchiveTimestamps(s);
            out.write(stripped.toASN1Structure().getEncoded(ASN1Encoding.DER));
        }
    }

    private static SignerInformation stripArchiveTimestamps(SignerInformation signer)
    {
        AttributeTable unsigned = signer.getUnsignedAttributes();
        if (unsigned == null)
        {
            return signer;
        }

        boolean hasAny = unsigned.get(id_aa_ets_archiveTimestampV2) != null
            || unsigned.get(PKCSObjectIdentifiers.id_aa_ets_archiveTimestamp) != null;
        if (!hasAny)
        {
            return signer;
        }

        ASN1EncodableVector kept = new ASN1EncodableVector();
        ASN1EncodableVector all = unsigned.toASN1EncodableVector();
        for (int i = 0; i != all.size(); ++i)
        {
            Attribute a = Attribute.getInstance(all.get(i));
            ASN1ObjectIdentifier type = a.getAttrType();
            if (!id_aa_ets_archiveTimestampV2.equals(type)
                && !PKCSObjectIdentifiers.id_aa_ets_archiveTimestamp.equals(type))
            {
                kept.add(a);
            }
        }
        AttributeTable filtered = kept.size() == 0 ? null : new AttributeTable(kept);
        return SignerInformation.replaceUnsignedAttributes(signer, filtered);
    }
}
