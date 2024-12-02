package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
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

    private OriginatorInformation originatorInfo;
    private AlgorithmIdentifier authEncAlg;
    private ASN1Set authAttrs;
    private byte[] mac;
    private ASN1Set unauthAttrs;

    public CMSAuthEnvelopedData(byte[] authEnvData)
        throws CMSException
    {
        this(CMSUtils.readContentInfo(authEnvData));
    }

    public CMSAuthEnvelopedData(InputStream authEnvData)
        throws CMSException
    {
        this(CMSUtils.readContentInfo(authEnvData));
    }

    public CMSAuthEnvelopedData(ContentInfo contentInfo)
        throws CMSException
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

        this.mac = authEnvData.getMac().getOctets();

        CMSSecureReadable secureReadable = new CMSSecureReadableWithAAD()
        {
            private OutputStream aadStream;

            @Override
            public ASN1Set getAuthAttrSet()
            {
                return authAttrs;
            }

            @Override
            public void setAuthAttrSet(ASN1Set set)
            {

            }

            @Override
            public boolean hasAdditionalData()
            {
                return (aadStream != null && authAttrs != null);
            }

            public ASN1ObjectIdentifier getContentType()
            {
                return authEncInfo.getContentType();
            }

            public InputStream getInputStream()
                throws IOException
            {
                if (aadStream != null && authAttrs != null)
                {
                    aadStream.write(authAttrs.getEncoded(ASN1Encoding.DER));
                }
                return new InputStreamWithMAC(new ByteArrayInputStream(authEncInfo.getEncryptedContent().getOctets()), mac);
            }

            @Override
            public void setAADStream(OutputStream stream)
            {
                aadStream = stream;
            }

            public OutputStream getAADStream()
            {
                return aadStream;
            }

            @Override
            public byte[] getMAC()
            {
                return Arrays.clone(mac);
            }
        };

        this.authAttrs = authEnvData.getAuthAttrs();

        this.unauthAttrs = authEnvData.getUnauthAttrs();

        //
        // build the RecipientInformationStore
        //
        this.recipientInfoStore = CMSEnvelopedHelper.buildRecipientInformationStore(
            recipientInfos, this.authEncAlg, secureReadable);
    }


    /**
     * return the object identifier for the content encryption algorithm.
     */
    public String getEncryptionAlgOID()
    {
        return authEncAlg.getAlgorithm().getId();
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
     *
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
     *
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
     *
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
