package org.bouncycastle.cmc;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

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

/**
 * Builder for an unsigned Full PKI Response (RFC 5272 / RFC 7030 4.2.3 / 4.4.2):
 * a CMS SignedData with no SignerInfos and no certificates whose encapsulated
 * content is an id-cct-PKIResponse PKIResponse SEQUENCE. The product is
 * delivered as a {@link SimplePKIResponse}, whose structured accessors expose
 * the embedded PKIResponse content.
 */
public class PKIResponseBuilder
{
    private final List<TaggedAttribute> controlAttributes = new ArrayList<TaggedAttribute>();
    private final List<TaggedContentInfo> cmsContents = new ArrayList<TaggedContentInfo>();
    private final List<OtherMsg> otherMsgs = new ArrayList<OtherMsg>();

    public PKIResponseBuilder addControlAttribute(TaggedAttribute attr)
    {
        controlAttributes.add(attr);
        return this;
    }

    /**
     * Convenience for the EST server-generated error case: wrap the supplied
     * CMCStatusInfoV2 in a TaggedAttribute keyed by id-cmc-statusInfoV2 and
     * append it to the controlSequence.
     */
    public PKIResponseBuilder addStatusInfoV2(BodyPartID bodyPartID, CMCStatusInfoV2 statusInfo)
    {
        controlAttributes.add(new TaggedAttribute(
            bodyPartID, CMCObjectIdentifiers.id_cmc_statusInfoV2, new DERSet(statusInfo)));
        return this;
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

    public SimplePKIResponse build()
        throws CMCException
    {
        PKIResponse pkiResponse = new PKIResponse(
            controlAttributes.toArray(new TaggedAttribute[0]),
            cmsContents.toArray(new TaggedContentInfo[0]),
            otherMsgs.toArray(new OtherMsg[0]));

        ContentInfo encap;
        try
        {
            encap = new ContentInfo(CMCObjectIdentifiers.id_cct_PKIResponse,
                new DEROctetString(pkiResponse.getEncoded()));
        }
        catch (IOException e)
        {
            throw new CMCException("unable to encode PKIResponse: " + e.getMessage(), e);
        }

        SignedData signedData = new SignedData(
            new DERSet(),    // digestAlgorithms
            encap,
            null,            // certificates
            null,            // crls
            new DERSet());   // signerInfos

        return new SimplePKIResponse(new ContentInfo(CMSObjectIdentifiers.signedData, signedData));
    }
}
