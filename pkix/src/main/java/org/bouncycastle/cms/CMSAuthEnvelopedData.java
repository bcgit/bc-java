package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.AuthEnvelopedData;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.OriginatorInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Containing class for an CMS AuthEnveloped Data object
 * per RFC 5083.
 * <p>
 * ASN.1:
 * <pre>
 *     id-ct-authEnvelopedData OBJECT IDENTIFIER ::= { iso(1)
 *       member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
 *       smime(16) ct(1) 23 }
 *
 *     AuthEnvelopedData ::= SEQUENCE {
 *       version CMSVersion,
 *       originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
 *       recipientInfos RecipientInfos,
 *       authEncryptedContentInfo EncryptedContentInfo,
 *       authAttrs [1] IMPLICIT AuthAttributes OPTIONAL,
 *       mac MessageAuthenticationCode,
 *       unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL }
 * </pre>
 */

class CMSAuthEnvelopedData
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
        EncryptedContentInfo authEncInfo = authEnvData.getAuthEncryptedContentInfo();
        this.authEncAlg = authEncInfo.getContentEncryptionAlgorithm();
//        final CMSProcessable processable = new CMSProcessableByteArray(
//            authEncInfo.getEncryptedContent().getOctets());
        CMSSecureReadable secureReadable = new CMSSecureReadable()
        {

            public InputStream getInputStream()
                throws IOException, CMSException
            {
                return null;
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
}
