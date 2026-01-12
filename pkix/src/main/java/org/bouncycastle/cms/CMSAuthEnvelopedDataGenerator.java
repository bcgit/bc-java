package org.bouncycastle.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AuthEnvelopedData;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.operator.OutputAEADEncryptor;

public class CMSAuthEnvelopedDataGenerator
    extends CMSAuthEnvelopedGenerator
{
    /**
     * base constructor
     */
    public CMSAuthEnvelopedDataGenerator()
    {
    }

    private CMSAuthEnvelopedData doGenerate(
        CMSTypedData content,
        OutputAEADEncryptor contentEncryptor)
        throws CMSException
    {
        ASN1EncodableVector recipientInfos = CMSUtils.getRecipentInfos(contentEncryptor.getKey(), recipientInfoGenerators);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1Set authenticatedAttrSet;
        try
        {
            OutputStream cOut = contentEncryptor.getOutputStream(bOut);
            if (CMSAlgorithm.ChaCha20Poly1305.equals(contentEncryptor.getAlgorithmIdentifier().getAlgorithm()))
            {
                // AEAD Ciphers process AAD at first
                authenticatedAttrSet = CMSUtils.processAuthAttrSet(authAttrsGenerator, contentEncryptor);
                content.write(cOut);
            }
            else
            {
                content.write(cOut);
                authenticatedAttrSet = CMSUtils.processAuthAttrSet(authAttrsGenerator, contentEncryptor);
            }

            cOut.close();
        }
        catch (IOException e)
        {
            throw new CMSException("unable to process authenticated content: " + e.getMessage(), e);
        }

        ASN1OctetString encryptedContent = new BEROctetString(bOut.toByteArray());
        ASN1OctetString mac = new DEROctetString(contentEncryptor.getMAC());

        EncryptedContentInfo encryptedContentInfo = CMSUtils.getEncryptedContentInfo(content, contentEncryptor,
            encryptedContent);

        ASN1Set unprotectedAttrSet = CMSUtils.getAttrDLSet(unauthAttrsGenerator);

        ASN1Encodable authEnvelopedData = new AuthEnvelopedData(originatorInfo, new DERSet(recipientInfos),
            encryptedContentInfo, authenticatedAttrSet, mac, unprotectedAttrSet);

        ContentInfo contentInfo = new ContentInfo(CMSObjectIdentifiers.authEnvelopedData, authEnvelopedData);

        return new CMSAuthEnvelopedData(contentInfo);
    }

    /**
     * generate an auth-enveloped object that contains an CMS Enveloped Data
     * object using the given provider.
     *
     * @param content          the content to be encrypted
     * @param contentEncryptor the symmetric key based encryptor to encrypt the content with.
     */
    public CMSAuthEnvelopedData generate(
        CMSTypedData content,
        OutputAEADEncryptor contentEncryptor)
        throws CMSException
    {
        return doGenerate(content, contentEncryptor);
    }
}
