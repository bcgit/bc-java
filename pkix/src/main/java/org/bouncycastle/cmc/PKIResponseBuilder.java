package org.bouncycastle.cmc;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.cmc.CMCStatusInfoV2;
import org.bouncycastle.asn1.cmc.OtherMsg;
import org.bouncycastle.asn1.cmc.PKIResponse;
import org.bouncycastle.asn1.cmc.TaggedAttribute;
import org.bouncycastle.asn1.cmc.TaggedContentInfo;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Builder for a Simple PKI Response (RFC 5272 / RFC 7030 4.2.3 / 4.4.2),
 * delivered as a {@link SimplePKIResponse}.
 * <p>
 * Two shapes are supported, selected automatically at {@link #build()} time:
 * <ul>
 *   <li><b>Full PKI Response</b> (the error case used by EST server-generated
 *       errors): a CMS SignedData with no SignerInfos whose encapsulated
 *       content is an id-cct-PKIResponse PKIResponse SEQUENCE. Selected when
 *       any control attribute, CMS content or other message has been added.</li>
 *   <li><b>Simple PKI Response</b> (the cert-delivery case used by
 *       /simpleenroll): a degenerate CMS SignedData with no SignerInfos, no
 *       encapsulated content, and the issued certificates in the certificates
 *       field. Selected when only certificates have been added.</li>
 * </ul>
 */
public class PKIResponseBuilder
{
    private final List<TaggedAttribute> controlAttributes = new ArrayList<TaggedAttribute>();
    private final List<TaggedContentInfo> cmsContents = new ArrayList<TaggedContentInfo>();
    private final List<OtherMsg> otherMsgs = new ArrayList<OtherMsg>();
    private final List<X509CertificateHolder> certificates = new ArrayList<X509CertificateHolder>();

    public PKIResponseBuilder addControlAttribute(TaggedAttribute attr)
    {
        controlAttributes.add(attr);
        return this;
    }

    /**
     * Convenience for the EST server-generated error case: wrap the supplied
     * CMCStatusInfoV2 in a TaggedAttribute keyed by id-cmc-statusInfoV2 and
     * append it to the controlSequence. The supplied {@code bodyPartID}
     * identifies the {@link TaggedAttribute} itself within the controlSequence
     * (per RFC 5272 sec. 3.2.1); it is structurally distinct from the
     * {@code bodyList} entries inside {@code CMCStatusInfoV2}, which identify
     * which request body parts the status pertains to.
     */
    public PKIResponseBuilder addStatusInfoV2(BodyPartID bodyPartID, CMCStatusInfoV2 statusInfo)
    {
        controlAttributes.add(new TaggedAttribute(
            bodyPartID, CMCObjectIdentifiers.id_cmc_statusInfoV2, new DERSet(statusInfo)));
        return this;
    }

    /**
     * Convenience overload for the simple-error case where the outer
     * {@link TaggedAttribute}'s bodyPartID can be inherited from the first
     * entry of {@code statusInfo.getBodyList()}. Behaves identically to
     * {@link #addStatusInfoV2(BodyPartID, CMCStatusInfoV2)} when the caller
     * doesn't need an independent identifier for the TaggedAttribute.
     *
     * @throws IllegalArgumentException if {@code statusInfo}'s bodyList is empty.
     */
    public PKIResponseBuilder addStatusInfoV2(CMCStatusInfoV2 statusInfo)
    {
        BodyPartID[] bodyList = statusInfo.getBodyList();
        if (bodyList == null || bodyList.length == 0)
        {
            throw new IllegalArgumentException(
                "CMCStatusInfoV2 bodyList is empty - cannot derive outer bodyPartID");
        }
        return addStatusInfoV2(bodyList[0], statusInfo);
    }

    public PKIResponseBuilder addCmsContent(TaggedContentInfo cmsContent)
    {
        cmsContents.add(cmsContent);
        return this;
    }

    public PKIResponseBuilder addOtherMsg(OtherMsg otherMsg)
    {
        otherMsgs.add(otherMsg);
        return this;
    }

    /**
     * Add a certificate to deliver in the response. When the builder contains
     * only certificates (no control attributes, no CMS contents, no other
     * messages), {@link #build()} emits a degenerate SignedData with no
     * encapsulated content and the certificates in the certificates field
     * (the Simple PKI Response shape used by EST /simpleenroll). When other
     * payload has also been added, the certificates are carried alongside the
     * id-cct-PKIResponse encapsulated content.
     */
    public PKIResponseBuilder addCertificate(X509CertificateHolder cert)
    {
        certificates.add(cert);
        return this;
    }

    public SimplePKIResponse build()
        throws CMCException
    {
        boolean hasPayload = !controlAttributes.isEmpty()
            || !cmsContents.isEmpty()
            || !otherMsgs.isEmpty();

        ASN1EncodableVector certVec = null;
        if (!certificates.isEmpty())
        {
            certVec = new ASN1EncodableVector();
            for (int i = 0; i < certificates.size(); i++)
            {
                X509CertificateHolder ch = (X509CertificateHolder)certificates.get(i);
                certVec.add(ch.toASN1Structure());
            }
        }

        ContentInfo encap;
        if (hasPayload)
        {
            PKIResponse pkiResponse = new PKIResponse(
                (TaggedAttribute[])controlAttributes.toArray(new TaggedAttribute[0]),
                (TaggedContentInfo[])cmsContents.toArray(new TaggedContentInfo[0]),
                (OtherMsg[])otherMsgs.toArray(new OtherMsg[0]));

            try
            {
                encap = new ContentInfo(CMCObjectIdentifiers.id_cct_PKIResponse,
                    new DEROctetString(pkiResponse.getEncoded()));
            }
            catch (IOException e)
            {
                throw new CMCException("unable to encode PKIResponse: " + e.getMessage(), e);
            }
        }
        else
        {
            // Simple PKI Response: degenerate SignedData with no encap content.
            encap = new ContentInfo(CMSObjectIdentifiers.data, null);
        }

        SignedData signedData = new SignedData(
            new DERSet(),                                    // digestAlgorithms
            encap,
            certVec == null ? null : new DERSet(certVec),    // certificates
            null,                                            // crls
            new DERSet());                                   // signerInfos

        return new SimplePKIResponse(new ContentInfo(CMSObjectIdentifiers.signedData, signedData));
    }
}
