package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.AuthEnvelopedData;
import org.bouncycastle.asn1.cms.ContentInfo;

import java.io.InputStream;

/**
 * containing class for an CMS AuthEnveloped Data object
 */
public class CMSAuthEnvelopedData extends CMSEnvelopedData
{

    private ASN1Set             authAttrs;
    private byte[]              mac;

    public CMSAuthEnvelopedData(byte[] authEnvData) throws CMSException
    {
        this(CMSUtils.readContentInfo(authEnvData));
    }

    public CMSAuthEnvelopedData(InputStream authEnvData) throws CMSException
    {
        this(CMSUtils.readContentInfo(authEnvData));
    }

    public CMSAuthEnvelopedData(ContentInfo contentInfo) throws CMSException {
        this(contentInfo, AuthEnvelopedData.getInstance(contentInfo.getContent()));
    }

   CMSAuthEnvelopedData(final ContentInfo contentInfo, final AuthEnvelopedData authEnvData) throws CMSException {
        super(contentInfo, authEnvData);

        this.authAttrs = authEnvData.getAuthAttrs();
        this.mac = authEnvData.getMac().getOctets();
    }

}
