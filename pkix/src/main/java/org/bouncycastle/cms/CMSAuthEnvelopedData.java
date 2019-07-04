package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.AuthEnvelopedData;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.OriginatorInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * containing class for an CMS AuthEnveloped Data object
 */
public class CMSAuthEnvelopedData
{
    RecipientInformationStore recipientInfoStore;
    ContentInfo contentInfo;

    private OriginatorInfo      originator;
    private AlgorithmIdentifier authEncAlg;
    private ASN1Set             authAttrs;
    private byte[]              mac;
    private ASN1Set             unauthAttrs;

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

        this.originator = authEnvData.getOriginatorInfo();

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

        //
        // build the RecipientInformationStore
        //
        this.recipientInfoStore = CMSEnvelopedHelper.buildRecipientInformationStore(
            recipientInfos, this.authEncAlg, secureReadable);

        // FIXME These need to be passed to the AEAD cipher as AAD (Additional Authenticated Data)
        this.authAttrs = authEnvData.getAuthAttrs();
        this.mac = authEnvData.getMac().getOctets();
        this.unauthAttrs = authEnvData.getUnauthAttrs();
    }

    /**
     * return a store of the intended recipients for this message
     */
    public RecipientInformationStore getRecipientInfos()
    {
        return recipientInfoStore;
    }
}
