package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.AuthenticatedData;
import org.bouncycastle.asn1.cms.CMSAlgorithmProtection;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.OriginatorInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Exceptions;

/**
 * containing class for an CMS Authenticated Data object
 */
public class CMSAuthenticatedData
    implements Encodable
{
    private final ContentInfo contentInfo;
    private final AuthenticatedData authenticatedData;
    private final OriginatorInformation originatorInformation;
    private final RecipientInformationStore recipientInfoStore;

    // Derived
    private AttributeTable authAttributeTable;
    private AttributeTable unauthAttributeTable;

    public CMSAuthenticatedData(
        byte[]    authData)
        throws CMSException
    {
        this(CMSUtils.readContentInfo(authData));
    }

    public CMSAuthenticatedData(
        byte[]    authData,
        DigestCalculatorProvider digestCalculatorProvider)
        throws CMSException
    {
        this(CMSUtils.readContentInfo(authData), digestCalculatorProvider);
    }

    public CMSAuthenticatedData(
        InputStream    authData)
        throws CMSException
    {
        this(CMSUtils.readContentInfo(authData));
    }

    public CMSAuthenticatedData(
        InputStream    authData,
        DigestCalculatorProvider digestCalculatorProvider)
        throws CMSException
    {
        this(CMSUtils.readContentInfo(authData), digestCalculatorProvider);
    }

    public CMSAuthenticatedData(
        ContentInfo contentInfo)
        throws CMSException
    {
        this(contentInfo, null);
    }

    public CMSAuthenticatedData(
        ContentInfo contentInfo,
        DigestCalculatorProvider digestCalculatorProvider)
        throws CMSException
    {
        this.contentInfo = contentInfo;
        this.authenticatedData = getAuthenticatedData();

        OriginatorInfo originatorInfo = authenticatedData.getOriginatorInfo();
        this.originatorInformation = originatorInfo == null ? null : new OriginatorInformation(originatorInfo);

        //
        // read the recipients
        //
        AuthenticatedData authData = authenticatedData;
        ASN1Set recipientInfos = authData.getRecipientInfos();

        AlgorithmIdentifier macAlg = authData.getMacAlgorithm();

        //
        // read the authenticated content info
        //
        ContentInfo encInfo = authData.getEncapsulatedContentInfo();
        ASN1Encodable eContent = encInfo.getContent();
        if (eContent == null)
        {
            throw new CMSException("Missing content.");
        }
        ASN1OctetString encContent;
        try
        {
            encContent = ASN1OctetString.getInstance(eContent);
        }
        catch (ClassCastException e)
        {
            throw new CMSException("Malformed content.", e);
        }
        catch (IllegalArgumentException e)
        {
            throw new CMSException("Malformed content.", e);
        }
        CMSReadable readable = new CMSProcessableByteArray(
            encInfo.getContentType(),
            encContent.getOctets());

        // RFC 6211 Validate Algorithm Protection attribute if present
        verifyAlgorithmProtectionAttribute();

        // TODO Verify other attributes; for message-digest need the calculated content-digest (if any) to compare

        //
        // build the RecipientInformationStore
        //
        ASN1Set authAttrs = authData.getAuthAttrs();
        if (authAttrs == null)
        {
            CMSSecureReadable secureReadable = new CMSEnvelopedHelper.CMSAuthEnveSecureReadable(macAlg, encInfo.getContentType(), readable);
            this.recipientInfoStore = CMSEnvelopedHelper.buildRecipientInformationStore(recipientInfos, macAlg, secureReadable);
            return;
        }

        if (digestCalculatorProvider == null)
        {
            throw new CMSException("a digest calculator provider is required if authenticated attributes are present");
        }

        try
        {
            CMSSecureReadable secureReadable = new CMSEnvelopedHelper.CMSDigestAuthenticatedSecureReadable(
                digestCalculatorProvider.get(authData.getDigestAlgorithm()), encInfo.getContentType(), readable);
            secureReadable.setAuthAttrSet(authAttrs);
            this.recipientInfoStore = CMSEnvelopedHelper.buildRecipientInformationStore(recipientInfos, macAlg, secureReadable);
        }
        catch (OperatorCreationException e)
        {
            throw new CMSException("unable to create digest calculator: " + e.getMessage(), e);
        }
    }

    private AuthenticatedData getAuthenticatedData()
        throws CMSException
    {
        ASN1Encodable content = contentInfo.getContent();
        if (content == null)
        {
            throw new CMSException("Missing content.");
        }

        try
        {
            return AuthenticatedData.getInstance(content);
        }
        catch (ClassCastException e)
        {
            throw new CMSException("Malformed content.", e);
        }
        catch (IllegalArgumentException e)
        {
            throw new CMSException("Malformed content.", e);
        }
    }

    /**
     * Return the originator information associated with this message if present.
     *
     * @return OriginatorInformation, null if not present.
     */
    public OriginatorInformation getOriginatorInfo()
    {
        return originatorInformation;
    }

    public byte[] getMac()
    {
        return Arrays.clone(authenticatedData.getMac().getOctets());
    }

    /**
     * Return the MAC algorithm details for the MAC associated with the data in this object.
     *
     * @return AlgorithmIdentifier representing the MAC algorithm.
     */
    public AlgorithmIdentifier getMacAlgorithm()
    {
        return authenticatedData.getMacAlgorithm();
    }

    /**
     * return the object identifier for the content MAC algorithm.
     */
    public String getMacAlgOID()
    {
        return getMacAlgorithm().getAlgorithm().getId();
    }

    /**
     * return the ASN.1 encoded MAC algorithm parameters, or null if
     * there aren't any.
     */
    public byte[] getMacAlgParams()
    {
        try
        {
            return CMSUtils.encodeObj(getMacAlgorithm().getParameters());
        }
        catch (Exception e)
        {
            throw new RuntimeException("exception getting encryption parameters " + e);
        }
    }

    /**
     * return a store of the intended recipients for this message
     */
    public RecipientInformationStore getRecipientInfos()
    {
        return recipientInfoStore;
    }

    /**
     * return the ContentInfo
     * @deprecated use toASN1Structure()
     */
    public ContentInfo getContentInfo()
    {
        return contentInfo;
    }

    /**
     * return the ContentInfo
     */
    public ContentInfo toASN1Structure()
    {
        return contentInfo;
    }

    /**
     * return a table of the digested attributes indexed by the OID of the attribute.
     * @deprecated Use {@link #getAuthAttributes} instead.
     */
    public AttributeTable getAuthAttrs()
    {
        return getAuthAttributes();
    }

    /**
     * return a table of the authenticated attributes - indexed by the OID of the attribute.
     */
    public AttributeTable getAuthAttributes()
    {
        ASN1Set authAttrs = authenticatedData.getAuthAttrs();
        if (authAttrs != null && this.authAttributeTable == null)
        {
            this.authAttributeTable = new AttributeTable(authAttrs);
        }
        return this.authAttributeTable;
    }

    /**
     * return a table of the undigested attributes indexed by the OID of the attribute.
     * @deprecated Use {@link #getUnauthAttributes} instead.
     */
    public AttributeTable getUnauthAttrs()
    {
        return getUnauthAttributes();
    }

    /**
     * return a table of the unauthenticated attributes - indexed by the OID of the attribute.
     */
    public AttributeTable getUnauthAttributes()
    {
        ASN1Set unauthAttrs = authenticatedData.getUnauthAttrs();
        if (unauthAttrs != null && this.unauthAttributeTable == null)
        {
            this.unauthAttributeTable = new AttributeTable(unauthAttrs);
        }
        return this.unauthAttributeTable;
    }

    /**
     * return the ASN.1 encoded representation of this object.
     */
    public byte[] getEncoded()
        throws IOException
    {
        return contentInfo.getEncoded();
    }

    public byte[] getContentDigest()
    {
        try
        {
            // TODO Full validation; this is syntactic validation on access only; the actual digest is not checked 
            ASN1Encodable validMessageDigest = getSingleValuedAuthAttribute(CMSAttributes.messageDigest, "message-digest");
            if (validMessageDigest == null)
            {
                if (authenticatedData.getAuthAttrs() != null)
                {
                    throw new CMSException("the message-digest authenticated attribute type MUST be present when there are any authenticated attributes present");
                }
            }
            else
            {
                if (!(validMessageDigest instanceof ASN1OctetString))
                {
                    throw new CMSException("message-digest attribute value not of ASN.1 type 'OCTET STRING'");
                }

                ASN1OctetString authMessageDigest = (ASN1OctetString)validMessageDigest;

                return Arrays.clone(authMessageDigest.getOctets());
            }            
        }
        catch (CMSException e)
        {
            // TODO CMSException could be declared, but if validation is moved to an earlier phase that may be unnecessary.
            throw Exceptions.illegalStateException("Invalid content digest", e);
        }

        return null;
    }

    private ASN1Encodable getSingleValuedAuthAttribute(ASN1ObjectIdentifier attrOID, String printableName)
        throws CMSException
    {
        AttributeTable unauthAttrTable = getUnauthAttributes();
        if (unauthAttrTable != null && unauthAttrTable.hasAny(attrOID))
        {
            throw new CMSException("The " + printableName + " attribute MUST NOT be an unauthenticated attribute");
        }

        AttributeTable authAttrTable = getAuthAttributes();
        if (authAttrTable == null)
        {
            return null;
        }

        ASN1EncodableVector v = authAttrTable.getAll(attrOID);
        switch (v.size())
        {
        case 0:
            return null;
        case 1:
        {
            Attribute t = (Attribute)v.get(0);
            ASN1Set attrValues = t.getAttrValues();
            if (attrValues.size() != 1)
            {
                throw new CMSException("A " + printableName + " attribute MUST have a single attribute value");
            }

            return attrValues.getObjectAt(0);
        }
        default:
            throw new CMSException("The AuthAttributes in an AuthenticatedData MUST NOT include multiple instances of "
                + "the " + printableName + " attribute");
        }
    }

    /**
     * RFC 6211 Validate Algorithm Protection attribute if present
     *
     * @throws CMSException when cmsAlgorithmProtect attribute was rejected
     */
    private void verifyAlgorithmProtectionAttribute()
        throws CMSException
    {
        ASN1Encodable validAlgorithmProtection = getSingleValuedAuthAttribute(CMSAttributes.cmsAlgorithmProtect,
            "cmsAlgorithmProtect");
        if (validAlgorithmProtection != null)
        {
            CMSAlgorithmProtection algorithmProtection = CMSAlgorithmProtection.getInstance(validAlgorithmProtection);

            if (!CMSUtils.isEquivalent(algorithmProtection.getDigestAlgorithm(), authenticatedData.getDigestAlgorithm()))
            {
                throw new CMSException("CMS Algorithm Protection check failed for digestAlgorithm");
            }

            if (!CMSUtils.isEquivalent(algorithmProtection.getMacAlgorithm(), authenticatedData.getMacAlgorithm()))
            {
                throw new CMSException("CMS Algorithm Protection check failed for macAlgorithm");
            }
        }
    }
}
