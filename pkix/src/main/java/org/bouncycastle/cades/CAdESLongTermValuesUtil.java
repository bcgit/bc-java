package org.bouncycastle.cades;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.esf.CompleteRevocationRefs;
import org.bouncycastle.asn1.esf.CrlListID;
import org.bouncycastle.asn1.esf.CrlOcspRef;
import org.bouncycastle.asn1.esf.CrlValidatedID;
import org.bouncycastle.asn1.esf.OcspIdentifier;
import org.bouncycastle.asn1.esf.OcspListID;
import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.OtherHash;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;

/**
 * Helpers for upgrading a CAdES B-T signature to B-LT (RFC&nbsp;5126 X-L /
 * ETSI EN&nbsp;319&nbsp;122-1 B-LT) by attaching the four long-term
 * validation-data attributes:
 * <ul>
 *   <li>{@code id-aa-ets-certificateRefs} (RFC&nbsp;5126 sec. 6.2.1) &mdash;
 *       digest + IssuerSerial references for each non-signer cert.</li>
 *   <li>{@code id-aa-ets-revocationRefs} (RFC&nbsp;5126 sec. 6.2.2) &mdash;
 *       digest references for each CRL (and/or OCSP response).</li>
 *   <li>{@code id-aa-ets-certValues} (RFC&nbsp;5126 sec. 6.3.3) &mdash; the
 *       cert bytes themselves.</li>
 *   <li>{@code id-aa-ets-revocationValues} (RFC&nbsp;5126 sec. 6.3.4) &mdash;
 *       the CRL / OCSP response bytes themselves.</li>
 * </ul>
 * <p>
 * Both CRL ({@link X509CRLHolder}) and OCSP ({@link BasicOCSPResp}) revocation
 * material are supported. An OCSP response contributes:
 * <ul>
 *   <li>An {@link OcspResponsesID} entry under the {@code revocationRefs}
 *       attribute&apos;s {@link CrlOcspRef#getOcspids() ocspids} branch, holding
 *       the responder identifier, {@code producedAt} timestamp and a digest of
 *       the BasicOCSPResponse bytes (RFC&nbsp;5126 sec. 6.2.2).</li>
 *   <li>A {@link BasicOCSPResponse} entry under the {@code revocationValues}
 *       attribute&apos;s {@code ocspVals} branch (RFC&nbsp;5126 sec. 6.3.4).</li>
 * </ul>
 * The caller is responsible for fetching the long-term material out-of-band
 * (BC stays out of HTTP / OCSP transport); this helper only assembles the
 * attributes and attaches them.
 */
public final class CAdESLongTermValuesUtil
{
    private CAdESLongTermValuesUtil()
    {
    }

    /**
     * Convenience overload that takes no OCSP responses &mdash; equivalent to
     * {@link #applyLongTermValues(CMSSignedData, SignerId, List, List, List,
     * AlgorithmIdentifier, DigestCalculatorProvider)} with an empty OCSP list.
     */
    public static CMSSignedData applyLongTermValues(CMSSignedData signed,
                                                    SignerId signerId,
                                                    List<X509CertificateHolder> additionalCerts,
                                                    List<X509CRLHolder> crls,
                                                    AlgorithmIdentifier refDigestAlg,
                                                    DigestCalculatorProvider digCalcProv)
        throws CAdESException, OperatorCreationException, IOException
    {
        return applyLongTermValues(signed, signerId, additionalCerts, crls,
            Collections.<BasicOCSPResp>emptyList(), refDigestAlg, digCalcProv);
    }

    /**
     * Attach the four CAdES B-LT unsigned attributes to the signer matched
     * by {@code signerId}. Long-term references use {@code refDigestAlg}
     * (typically SHA-256); the corresponding values attributes hold the raw
     * cert / CRL / OCSP-response bytes.
     *
     * @param signed         the source CMSSignedData (unchanged).
     * @param signerId       selector identifying which signer to upgrade.
     * @param additionalCerts certs to include in {@code certValues} (typically
     *                       any intermediate / root not already in the
     *                       SignedData.certificates field). Cannot be null;
     *                       pass an empty list for none.
     * @param crls           CRLs to include in {@code revocationValues} /
     *                       {@code revocationRefs}. Cannot be null; pass an
     *                       empty list for none.
     * @param ocspResponses  OCSP responses to include in {@code revocationValues}
     *                       / {@code revocationRefs}. Cannot be null; pass an
     *                       empty list for none.
     * @param refDigestAlg   digest algorithm for the cert / CRL / OCSP refs;
     *                       null defaults to SHA-256.
     * @param digCalcProv    source of digest calculators for the reference
     *                       digests.
     * @return a new CMSSignedData with the B-LT attributes attached.
     * @throws CAdESException if {@code signerId} matches no signer, or a
     *                       structure cannot be encoded.
     */
    public static CMSSignedData applyLongTermValues(CMSSignedData signed,
                                                    SignerId signerId,
                                                    List<X509CertificateHolder> additionalCerts,
                                                    List<X509CRLHolder> crls,
                                                    List<BasicOCSPResp> ocspResponses,
                                                    AlgorithmIdentifier refDigestAlg,
                                                    DigestCalculatorProvider digCalcProv)
        throws CAdESException, OperatorCreationException, IOException
    {
        if (signed == null)
        {
            throw new NullPointerException("signed");
        }
        if (signerId == null)
        {
            throw new NullPointerException("signerId");
        }
        if (additionalCerts == null)
        {
            additionalCerts = Collections.emptyList();
        }
        if (crls == null)
        {
            crls = Collections.emptyList();
        }
        if (ocspResponses == null)
        {
            ocspResponses = Collections.emptyList();
        }
        if (refDigestAlg == null)
        {
            refDigestAlg = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        }

        SignerInformationStore signers = signed.getSignerInfos();
        Collection<SignerInformation> matched = signers.getSigners(signerId);
        if (matched.isEmpty())
        {
            throw new CAdESException("no signer matched in CMSSignedData");
        }

        // Pre-compute the four attribute values; the same instance is shared
        // across signers (legal: they reference the same long-term material).
        DigestCalculator dc = digCalcProv.get(refDigestAlg);

        Attribute certRefsAttr = buildCertificateRefs(additionalCerts, refDigestAlg, dc);
        Attribute certValuesAttr = buildCertificateValues(additionalCerts);
        Attribute revRefsAttr = buildRevocationRefs(crls, ocspResponses, refDigestAlg, dc);
        Attribute revValuesAttr = buildRevocationValues(crls, ocspResponses);

        List<SignerInformation> rebuilt = new ArrayList<SignerInformation>(signers.size());
        for (Iterator<SignerInformation> it = signers.getSigners().iterator(); it.hasNext(); )
        {
            SignerInformation cur = it.next();
            if (matched.contains(cur))
            {
                rebuilt.add(attach(cur, certRefsAttr, revRefsAttr, certValuesAttr, revValuesAttr));
            }
            else
            {
                rebuilt.add(cur);
            }
        }

        return CMSSignedData.replaceSigners(signed, new SignerInformationStore(rebuilt));
    }

    private static SignerInformation attach(SignerInformation signer,
                                            Attribute... attrs)
    {
        AttributeTable unsigned = signer.getUnsignedAttributes();
        ASN1EncodableVector v = unsigned == null
            ? new ASN1EncodableVector()
            : unsigned.toASN1EncodableVector();

        for (int i = 0; i != attrs.length; ++i)
        {
            Attribute a = attrs[i];
            // Drop any existing entry for this OID so a refresh replaces.
            v = removeOid(v, a.getAttrType());
            v.add(a);
        }

        return SignerInformation.replaceUnsignedAttributes(signer, new AttributeTable(v));
    }

    private static ASN1EncodableVector removeOid(ASN1EncodableVector in,
                                                 ASN1ObjectIdentifier oid)
    {
        ASN1EncodableVector out = new ASN1EncodableVector();
        for (int i = 0; i != in.size(); ++i)
        {
            Attribute a = Attribute.getInstance(in.get(i));
            if (!a.getAttrType().equals(oid))
            {
                out.add(a);
            }
        }
        return out;
    }

    private static Attribute buildCertificateRefs(List<X509CertificateHolder> certs,
                                                  AlgorithmIdentifier digestAlg,
                                                  DigestCalculator dc)
        throws CAdESException
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (X509CertificateHolder ch : certs)
        {
            byte[] hash = digestBytes(dc, encode(ch));
            IssuerSerial is = new IssuerSerial(
                new GeneralNames(new GeneralName(ch.getIssuer())),
                new ASN1Integer(ch.getSerialNumber()));
            v.add(new OtherCertID(digestAlg, hash, is));
        }
        // CompleteCertificateRefs ::= SEQUENCE OF OtherCertID
        return new Attribute(
            PKCSObjectIdentifiers.id_aa_ets_certificateRefs,
            new DERSet(new DERSequence(v)));
    }

    private static Attribute buildCertificateValues(List<X509CertificateHolder> certs)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (X509CertificateHolder ch : certs)
        {
            v.add(ch.toASN1Structure());
        }
        // CertificateValues ::= SEQUENCE OF Certificate
        return new Attribute(
            PKCSObjectIdentifiers.id_aa_ets_certValues,
            new DERSet(new DERSequence(v)));
    }

    private static Attribute buildRevocationRefs(List<X509CRLHolder> crls,
                                                 List<BasicOCSPResp> ocspResponses,
                                                 AlgorithmIdentifier digestAlg,
                                                 DigestCalculator dc)
        throws CAdESException
    {
        // CompleteRevocationRefs ::= SEQUENCE OF CrlOcspRef
        // We emit a single CrlOcspRef whose crlids / ocspids slots are
        // populated only when the corresponding list is non-empty.
        ASN1EncodableVector validatedIds = new ASN1EncodableVector();
        for (X509CRLHolder crl : crls)
        {
            byte[] hash = digestBytes(dc, encode(crl));
            validatedIds.add(new CrlValidatedID(toOtherHash(hash, digestAlg)));
        }
        CrlListID crlListID = crls.isEmpty()
            ? null
            : new CrlListID(toCrlValidatedIDArray(validatedIds));

        OcspListID ocspListID = null;
        if (!ocspResponses.isEmpty())
        {
            OcspResponsesID[] ocspIds = new OcspResponsesID[ocspResponses.size()];
            for (int i = 0; i != ocspIds.length; ++i)
            {
                BasicOCSPResp resp = ocspResponses.get(i);
                ResponderID responderID = resp.getResponderId().toASN1Primitive();
                ASN1GeneralizedTime producedAt = new ASN1GeneralizedTime(resp.getProducedAt());
                OcspIdentifier ocspIdentifier = new OcspIdentifier(responderID, producedAt);
                byte[] respHash = digestBytes(dc, encode(resp));
                ocspIds[i] = new OcspResponsesID(ocspIdentifier, toOtherHash(respHash, digestAlg));
            }
            ocspListID = new OcspListID(ocspIds);
        }

        CrlOcspRef crlOcspRef = new CrlOcspRef(crlListID, ocspListID, null);
        CompleteRevocationRefs refs = new CompleteRevocationRefs(new CrlOcspRef[]{crlOcspRef});

        return new Attribute(
            PKCSObjectIdentifiers.id_aa_ets_revocationRefs,
            new DERSet(refs));
    }

    private static OtherHash toOtherHash(byte[] hash, AlgorithmIdentifier digestAlg)
    {
        // RFC 5126: OtherHash uses the bare-octets v1 form only for SHA-1;
        // every other algorithm goes through OtherHashAlgAndValue.
        if (OIWObjectIdentifiers.idSHA1.equals(digestAlg.getAlgorithm()))
        {
            return new OtherHash(hash);
        }
        return new OtherHash(new OtherHashAlgAndValue(digestAlg,
            new DEROctetString(hash)));
    }

    private static CrlValidatedID[] toCrlValidatedIDArray(ASN1EncodableVector v)
    {
        CrlValidatedID[] out = new CrlValidatedID[v.size()];
        for (int i = 0; i != out.length; ++i)
        {
            out[i] = (CrlValidatedID)v.get(i);
        }
        return out;
    }

    private static Attribute buildRevocationValues(List<X509CRLHolder> crls,
                                                   List<BasicOCSPResp> ocspResponses)
        throws CAdESException
    {
        CertificateList[] crlVals = null;
        if (!crls.isEmpty())
        {
            crlVals = new CertificateList[crls.size()];
            for (int i = 0; i != crlVals.length; ++i)
            {
                crlVals[i] = crls.get(i).toASN1Structure();
            }
        }

        BasicOCSPResponse[] ocspVals = null;
        if (!ocspResponses.isEmpty())
        {
            ocspVals = new BasicOCSPResponse[ocspResponses.size()];
            for (int i = 0; i != ocspVals.length; ++i)
            {
                try
                {
                    ocspVals[i] = BasicOCSPResponse.getInstance(
                        ASN1Primitive.fromByteArray(
                            ocspResponses.get(i).getEncoded()));
                }
                catch (IOException e)
                {
                    throw new CAdESException("cannot encode OCSP response: "
                        + e.getMessage(), e);
                }
            }
        }

        // Null arrays produce absent fields per the OPTIONAL schema.
        RevocationValues rv = new RevocationValues(crlVals, ocspVals, null);

        return new Attribute(
            PKCSObjectIdentifiers.id_aa_ets_revocationValues,
            new DERSet(rv));
    }

    private static byte[] digestBytes(DigestCalculator dc, byte[] data)
        throws CAdESException
    {
        try
        {
            OutputStream out = dc.getOutputStream();
            out.write(data);
            out.close();
            return dc.getDigest();
        }
        catch (IOException e)
        {
            throw new CAdESException("digest failed: " + e.getMessage(), e);
        }
    }

    private static byte[] encode(X509CertificateHolder ch)
        throws CAdESException
    {
        try
        {
            return ch.getEncoded();
        }
        catch (IOException e)
        {
            throw new CAdESException("cannot encode certificate: " + e.getMessage(), e);
        }
    }

    private static byte[] encode(X509CRLHolder crl)
        throws CAdESException
    {
        try
        {
            return crl.getEncoded();
        }
        catch (IOException e)
        {
            throw new CAdESException("cannot encode CRL: " + e.getMessage(), e);
        }
    }

    private static byte[] encode(BasicOCSPResp resp)
        throws CAdESException
    {
        try
        {
            return resp.getEncoded();
        }
        catch (IOException e)
        {
            throw new CAdESException("cannot encode OCSP response: " + e.getMessage(), e);
        }
    }
}
