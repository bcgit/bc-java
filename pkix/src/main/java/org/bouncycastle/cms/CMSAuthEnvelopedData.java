package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.AuthEnvelopedData;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Encodable;

/**
 * containing class for an CMS AuthEnveloped Data object
 */
public class CMSAuthEnvelopedData
    implements Encodable
{
    RecipientInformationStore recipientInfoStore;
    ContentInfo contentInfo;

    private OriginatorInformation  originatorInfo;
    private AlgorithmIdentifier    authEncAlg;
    private ASN1Set                authAttrs;
    private byte[]                 mac;
    private ASN1Set                unauthAttrs;

    public CMSAuthEnvelopedData(byte[] authEnvData) throws CMSException
    {
        this(CMSUtils.readContentInfo(authEnvData));
    }

    public CMSAuthEnvelopedData(InputStream authEnvData) throws CMSException
    {
        this(CMSUtils.readContentInfo(authEnvData));
    }

    public CMSAuthEnvelopedData(ContentInfo contentInfo) throws CMSException
    {
        this.contentInfo = contentInfo;

        AuthEnvelopedData authEnvData = AuthEnvelopedData.getInstance(contentInfo.getContent());

        if (authEnvData.getOriginatorInfo() != null)
        {
            this.originatorInfo = new OriginatorInformation(authEnvData.getOriginatorInfo());
        }

        //
        // read the recipients
        //
        ASN1Set recipientInfos = authEnvData.getRecipientInfos();

        //
        // read the auth-encrypted content info
        //
        final EncryptedContentInfo authEncInfo = authEnvData.getAuthEncryptedContentInfo();
        this.authEncAlg = authEncInfo.getContentEncryptionAlgorithm();

        CMSSecureReadable secureReadable = new CMSSecureReadable()
        {

            public InputStream getInputStream()
                throws IOException, CMSException
            {
                return new ByteArrayInputStream(authEncInfo.getEncryptedContent().getOctets());
            }
        };

        this.authAttrs = authEnvData.getAuthAttrs();
        this.mac = authEnvData.getMac().getOctets();
        this.unauthAttrs = authEnvData.getUnauthAttrs();

        //
        // build the RecipientInformationStore
        //
        if (authAttrs != null)
        {
            this.recipientInfoStore = CMSEnvelopedHelper.buildRecipientInformationStore(
                recipientInfos, this.authEncAlg, secureReadable, new AuthAttributesProvider()
                {
                    public ASN1Set getAuthAttributes()
                    {
                        return authAttrs;
                    }

                    public boolean isAead()
                    {
                        return true;
                    }
                });
        }
        else
        {
            this.recipientInfoStore = CMSEnvelopedHelper.buildRecipientInformationStore(
                recipientInfos, this.authEncAlg, secureReadable);
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

    /**
     * return a store of the intended recipients for this message
     */
    public RecipientInformationStore getRecipientInfos()
    {
        return recipientInfoStore;
    }

    /**
     * return a table of the authenticated attributes (as in those used to provide associated data) indexed by
     * the OID of the attribute.
     * @return the authenticated attributes.
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
     * return a table of the unauthenticated attributes indexed by
     * the OID of the attribute.
     * @return the unauthenticated attributes.
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
     * Return the MAC value that was originally calculated for this AuthEnveloped data.
     * @return the MAC data associated with the stream.
     */
    public byte[] getMac()
    {
        return Arrays.clone(mac);
    }

    /**
     * return the ContentInfo
     */
    public ContentInfo toASN1Structure()
    {
        return contentInfo;
    }

    /**
     * return the ASN.1 encoded representation of this object.
     */
    public byte[] getEncoded()
        throws IOException
    {
        return contentInfo.getEncoded();
    }
}
