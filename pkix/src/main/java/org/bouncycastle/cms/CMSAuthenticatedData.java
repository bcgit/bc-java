package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.AuthenticatedData;
import org.bouncycastle.asn1.cms.CMSAlgorithmProtection;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Encodable;

/**
 * containing class for an CMS Authenticated Data object
 */
public class CMSAuthenticatedData
    implements Encodable
{
    RecipientInformationStore   recipientInfoStore;
    ContentInfo                 contentInfo;

    private AlgorithmIdentifier macAlg;
    private ASN1Set authAttrs;
    private ASN1Set unauthAttrs;
    private byte[] mac;
    private OriginatorInformation originatorInfo;

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

        AuthenticatedData authData = AuthenticatedData.getInstance(contentInfo.getContent());

        if (authData.getOriginatorInfo() != null)
        {
            this.originatorInfo = new OriginatorInformation(authData.getOriginatorInfo());
        }

        //
        // read the recipients
        //
        ASN1Set recipientInfos = authData.getRecipientInfos();

        this.macAlg = authData.getMacAlgorithm();

        this.authAttrs = authData.getAuthAttrs();
        this.mac = authData.getMac().getOctets();
        this.unauthAttrs = authData.getUnauthAttrs();

        //
        // read the authenticated content info
        //
        ContentInfo encInfo = authData.getEncapsulatedContentInfo();
        CMSReadable readable = new CMSProcessableByteArray(
            ASN1OctetString.getInstance(encInfo.getContent()).getOctets());

        //
        // build the RecipientInformationStore
        //
        if (authAttrs != null)
        {
            if (digestCalculatorProvider == null)
            {
                throw new CMSException("a digest calculator provider is required if authenticated attributes are present");
            }

            AttributeTable table = new AttributeTable(authAttrs);

            ASN1EncodableVector protectionAttributes = table.getAll(CMSAttributes.cmsAlgorithmProtect);
            if (protectionAttributes.size() > 1)
            {
                throw new CMSException("Only one instance of a cmsAlgorithmProtect attribute can be present");
            }

            if (protectionAttributes.size() > 0)
            {
                Attribute attr = Attribute.getInstance(protectionAttributes.get(0));
                if (attr.getAttrValues().size() != 1)
                {
                    throw new CMSException("A cmsAlgorithmProtect attribute MUST contain exactly one value");
                }

                CMSAlgorithmProtection algorithmProtection = CMSAlgorithmProtection.getInstance(attr.getAttributeValues()[0]);

                if (!CMSUtils.isEquivalent(algorithmProtection.getDigestAlgorithm(), authData.getDigestAlgorithm()))
                {
                    throw new CMSException("CMS Algorithm Identifier Protection check failed for digestAlgorithm");
                }

                if (!CMSUtils.isEquivalent(algorithmProtection.getMacAlgorithm(), macAlg))
                {
                    throw new CMSException("CMS Algorithm Identifier Protection check failed for macAlgorithm");
                }
            }
            try
            {
                CMSSecureReadable secureReadable = new CMSEnvelopedHelper.CMSDigestAuthenticatedSecureReadable(digestCalculatorProvider.get(authData.getDigestAlgorithm()), readable);

                this.recipientInfoStore = CMSEnvelopedHelper.buildRecipientInformationStore(recipientInfos, this.macAlg, secureReadable, new AuthAttributesProvider()
                {
                    public ASN1Set getAuthAttributes()
                    {
                        return authAttrs;
                    }

                    public boolean isAead()
                    {
                        return false;
                    }
                });
            }
            catch (OperatorCreationException e)
            {
                throw new CMSException("unable to create digest calculator: " + e.getMessage(), e);
            }
        }
        else
        {
            CMSSecureReadable secureReadable = new CMSEnvelopedHelper.CMSAuthenticatedSecureReadable(this.macAlg, readable);

            this.recipientInfoStore = CMSEnvelopedHelper.buildRecipientInformationStore(recipientInfos, this.macAlg, secureReadable);
        }
    }

    /**
     * Return the originator information associated with this message if present.
     *
     * @return OriginatorInformation, null if not present.
     */
    public OriginatorInformation getOriginatorInfo()
    {
        return originatorInfo;
    }

    public byte[] getMac()
    {
        return Arrays.clone(mac);
    }

    private byte[] encodeObj(
        ASN1Encodable obj)
        throws IOException
    {
        if (obj != null)
        {
            return obj.toASN1Primitive().getEncoded();
        }

        return null;
    }

    /**
     * Return the MAC algorithm details for the MAC associated with the data in this object.
     *
     * @return AlgorithmIdentifier representing the MAC algorithm.
     */
    public AlgorithmIdentifier getMacAlgorithm()
    {
        return macAlg;
    }

    /**
     * return the object identifier for the content MAC algorithm.
     */
    public String getMacAlgOID()
    {
        return macAlg.getAlgorithm().getId();
    }

    /**
     * return the ASN.1 encoded MAC algorithm parameters, or null if
     * there aren't any.
     */
    public byte[] getMacAlgParams()
    {
        try
        {
            return encodeObj(macAlg.getParameters());
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
     * return a table of the digested attributes indexed by
     * the OID of the attribute.
     */
    public AttributeTable getAuthAttrs()
    {
        if (authAttrs == null)
        {
            return null;
        }

        return new AttributeTable(authAttrs);
    }

    /**
     * return a table of the undigested attributes indexed by
     * the OID of the attribute.
     */
    public AttributeTable getUnauthAttrs()
    {
        if (unauthAttrs == null)
        {
            return null;
        }

        return new AttributeTable(unauthAttrs);
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
        if (authAttrs != null)
        {
            return ASN1OctetString.getInstance(getAuthAttrs().get(CMSAttributes.messageDigest).getAttrValues().getObjectAt(0)).getOctets();
        }

        return null;
    }
}
