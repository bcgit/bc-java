package org.bouncycastle.cades;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

/**
 * Helpers for upgrading a CAdES B-B signature to B-T by attaching an
 * {@code id-aa-signatureTimeStampToken} unsigned attribute carrying a
 * caller-fetched RFC&nbsp;3161 TSA token.
 * <p>
 * Per RFC&nbsp;5126 sec. 6.1.1 / ETSI EN&nbsp;319&nbsp;122-1 sec. 5.3, the
 * timestamp covers <b>the value of the {@code signature} field within the
 * {@code SignerInfo}</b> being timestamped &mdash; not the whole CMS
 * structure. A typical caller flow is:
 * <ol>
 *   <li>{@link #computeSignatureImprint(SignerInformation, AlgorithmIdentifier,
 *       DigestCalculatorProvider)} returns the bytes to put in the TSP
 *       {@code MessageImprint}.</li>
 *   <li>The caller submits a {@code TimeStampRequest} to a TSA (over HTTP
 *       or any other transport &mdash; BC deliberately does not embed an
 *       HTTP client) and receives a {@link TimeStampToken}.</li>
 *   <li>{@link #applySignatureTimestamp(CMSSignedData, SignerId, TimeStampToken)}
 *       returns a new {@code CMSSignedData} with the token attached to the
 *       specified signer.</li>
 * </ol>
 * The original {@code CMSSignedData} is unchanged.
 */
public final class CAdESSignatureTimestampUtil
{
    private CAdESSignatureTimestampUtil()
    {
    }

    /**
     * Compute the {@code MessageImprint} input for a CAdES signature
     * time-stamp request &mdash; the digest of {@code SignerInfo.signature}
     * under the supplied algorithm.
     *
     * @param signer    the signer whose signature value will be timestamped.
     * @param digestAlg the digest algorithm to use (typically matched to what
     *                  the TSA supports / requires).
     * @param digCalcProv source of digest calculators.
     * @return the digest bytes, suitable for use as the
     *         {@code MessageImprint.hashedMessage}.
     */
    public static byte[] computeSignatureImprint(SignerInformation signer,
                                                 AlgorithmIdentifier digestAlg,
                                                 DigestCalculatorProvider digCalcProv)
        throws OperatorCreationException, IOException
    {
        if (signer == null)
        {
            throw new NullPointerException("signer");
        }
        if (digestAlg == null)
        {
            throw new NullPointerException("digestAlg");
        }
        DigestCalculator dc = digCalcProv.get(digestAlg);
        OutputStream out = dc.getOutputStream();
        out.write(signer.getSignature());
        out.close();
        return dc.getDigest();
    }

    /**
     * Return a new {@code CMSSignedData} whose {@link SignerInformation}
     * matching {@code signerId} has an {@code id-aa-signatureTimeStampToken}
     * unsigned attribute appended carrying {@code token}.
     * <p>
     * If the matched signer already has a signature-time-stamp attribute the
     * new token is appended (the attribute is multi-valued per RFC&nbsp;5126
     * sec. 6.1.1).
     *
     * @param signedData  the source CMSSignedData (unchanged).
     * @param signerId    selector identifying which signer to upgrade.
     * @param token       the RFC&nbsp;3161 token from the TSA.
     * @return a new CMSSignedData with the timestamp attached.
     * @throws CAdESException if no signer matches {@code signerId}.
     */
    public static CMSSignedData applySignatureTimestamp(CMSSignedData signedData,
                                                        SignerId signerId,
                                                        TimeStampToken token)
        throws CAdESException
    {
        if (signedData == null)
        {
            throw new NullPointerException("signedData");
        }
        if (signerId == null)
        {
            throw new NullPointerException("signerId");
        }
        if (token == null)
        {
            throw new NullPointerException("token");
        }

        SignerInformationStore signers = signedData.getSignerInfos();
        Collection<SignerInformation> matched = signers.getSigners(signerId);
        if (matched.isEmpty())
        {
            throw new CAdESException("no signer matched in CMSSignedData");
        }

        List<SignerInformation> rebuilt = new ArrayList<SignerInformation>(signers.size());
        for (Iterator<SignerInformation> it = signers.getSigners().iterator(); it.hasNext(); )
        {
            SignerInformation cur = (SignerInformation)it.next();
            if (matched.contains(cur))
            {
                rebuilt.add(addSignatureTimestamp(cur, token));
            }
            else
            {
                rebuilt.add(cur);
            }
        }

        return CMSSignedData.replaceSigners(signedData, new SignerInformationStore(rebuilt));
    }

    /**
     * Return the RFC&nbsp;3161 tokens carried by the signer's
     * {@code id-aa-signatureTimeStampToken} unsigned attribute, in
     * attribute-value order. The attribute is multi-valued (RFC&nbsp;5126
     * sec. 6.1.1), so the list typically has one entry but may have more
     * when multiple timestamps from different TSAs have been attached.
     *
     * @param signer the signer to inspect.
     * @return an unmodifiable list of timestamp tokens, empty when the
     *         attribute is absent (signer has not been upgraded to B-T).
     * @throws CAdESException if an attribute value cannot be parsed as a
     *                       {@link TimeStampToken}.
     */
    public static List<TimeStampToken> getSignatureTimestamps(SignerInformation signer)
        throws CAdESException
    {
        if (signer == null)
        {
            throw new NullPointerException("signer");
        }
        AttributeTable unsigned = signer.getUnsignedAttributes();
        if (unsigned == null)
        {
            return Collections.EMPTY_LIST;
        }
        Attribute attr = unsigned.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
        if (attr == null)
        {
            return Collections.EMPTY_LIST;
        }
        ASN1Set vals = attr.getAttrValues();
        List<TimeStampToken> out = new ArrayList<TimeStampToken>(vals.size());
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
                    "unable to parse id-aa-signatureTimeStampToken value at index "
                        + i + ": " + e.getMessage(), e);
            }
            catch (TSPException e)
            {
                throw new CAdESException(
                    "unable to parse id-aa-signatureTimeStampToken value at index "
                        + i + ": " + e.getMessage(), e);
            }
        }
        return Collections.unmodifiableList(out);
    }

    /**
     * Self-consistency check on B-T material: for every
     * {@code id-aa-signatureTimeStampToken} attached to the signer, verify
     * the token's {@code MessageImprint} equals
     * {@link #computeSignatureImprint computeSignatureImprint} run under
     * the token's own hash algorithm.
     * <p>What this method does <i>not</i> do: validate the TSA's signature
     * on the token, walk the TSA cert chain to a trust anchor, or check
     * that the timestamp falls within the signer cert's validity window.
     * Those steps are the caller's responsibility, built on
     * {@link #getSignatureTimestamps} plus the {@code tsp} module's token
     * validators.</p>
     *
     * @param signer      the signer to validate. Must carry at least one
     *                    {@code id-aa-signatureTimeStampToken}.
     * @param digCalcProv source of digest calculators.
     * @throws CAdESException if the attribute is absent, a token cannot be
     *                       parsed, or any token's imprint does not match
     *                       the signer's signature value.
     */
    public static void validateSignatureTimestamps(SignerInformation signer,
                                                   DigestCalculatorProvider digCalcProv)
        throws CAdESException, OperatorCreationException, IOException
    {
        List<TimeStampToken> tokens = getSignatureTimestamps(signer);
        if (tokens.isEmpty())
        {
            throw new CAdESException("id-aa-signatureTimeStampToken attribute is missing");
        }
        for (int i = 0; i != tokens.size(); ++i)
        {
            TimeStampToken token = (TimeStampToken)tokens.get(i);
            AlgorithmIdentifier alg = token.getTimeStampInfo().getHashAlgorithm();
            byte[] embedded = token.getTimeStampInfo().getMessageImprintDigest();
            byte[] recomputed = computeSignatureImprint(signer, alg, digCalcProv);
            if (!Arrays.constantTimeAreEqual(embedded, recomputed))
            {
                throw new CAdESException(
                    "id-aa-signatureTimeStampToken imprint mismatch at index " + i);
            }
        }
    }

    private static SignerInformation addSignatureTimestamp(SignerInformation signer,
                                                           TimeStampToken token)
    {
        AttributeTable unsigned = signer.getUnsignedAttributes();

        ContentInfo ci;
        try
        {
            // The attribute value is a CMS ContentInfo (the TSA token's
            // outer envelope) per RFC 5126 sec. 6.1.1.
            ci = ContentInfo.getInstance(
                ASN1Primitive.fromByteArray(token.getEncoded()));
        }
        catch (IOException e)
        {
            // TimeStampToken came back from a successful TSA round-trip;
            // getEncoded should not realistically fail.
            throw Exceptions.illegalStateException(
                "unable to encode TimeStampToken: " + e.getMessage(), e);
        }

        // When multiple tokens are attached, RFC 5126 sec. 6.1.1 permits
        // either multiple Attribute instances with the same OID or a single
        // Attribute carrying multiple values; we pack them into one
        // Attribute's value-set for compactness and to match what most
        // CAdES implementations produce.
        Attribute existing = unsigned == null
            ? null
            : unsigned.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);

        ASN1EncodableVector vals = new ASN1EncodableVector();
        if (existing != null)
        {
            ASN1Set prev = existing.getAttrValues();
            for (int i = 0; i != prev.size(); i++)
            {
                vals.add(prev.getObjectAt(i));
            }
        }
        vals.add(ci);

        Attribute merged = new Attribute(
            PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
            new DERSet(vals));

        if (unsigned == null)
        {
            unsigned = new AttributeTable(merged);
        }
        else
        {
            unsigned = unsigned.remove(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
            // AttributeTable.add wraps a single value; we already have the
            // Attribute with its complete value-set, so build a new table
            // from a vector.
            ASN1EncodableVector all = unsigned.toASN1EncodableVector();
            all.add(merged);
            unsigned = new AttributeTable(all);
        }

        return SignerInformation.replaceUnsignedAttributes(signer, unsigned);
    }
}
