package org.bouncycastle.cms;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.KEKRecipientInfo;
import org.bouncycastle.asn1.cms.KeyAgreeRecipientInfo;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.PasswordRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;

class CMSEnvelopedHelper
{
    static RecipientInformationStore buildRecipientInformationStore(
        ASN1Set recipientInfos, AlgorithmIdentifier messageAlgorithm, CMSSecureReadable secureReadable)
    {
        return buildRecipientInformationStore(recipientInfos, messageAlgorithm, secureReadable, null);
    }

    static RecipientInformationStore buildRecipientInformationStore(
        ASN1Set recipientInfos, AlgorithmIdentifier messageAlgorithm, CMSSecureReadable secureReadable, AuthAttributesProvider additionalData)
    {
        List infos = new ArrayList();
        for (int i = 0; i != recipientInfos.size(); i++)
        {
            RecipientInfo info = RecipientInfo.getInstance(recipientInfos.getObjectAt(i));

            readRecipientInfo(infos, info, messageAlgorithm, secureReadable, additionalData);
        }
        return new RecipientInformationStore(infos);
    }

    private static void readRecipientInfo(
        List infos, RecipientInfo info, AlgorithmIdentifier messageAlgorithm, CMSSecureReadable secureReadable, AuthAttributesProvider additionalData)
    {
        ASN1Encodable recipInfo = info.getInfo();
        if (recipInfo instanceof KeyTransRecipientInfo)
        {
            infos.add(new KeyTransRecipientInformation(
                (KeyTransRecipientInfo)recipInfo, messageAlgorithm, secureReadable, additionalData));
        }
        else if (recipInfo instanceof KEKRecipientInfo)
        {
            infos.add(new KEKRecipientInformation(
                (KEKRecipientInfo)recipInfo, messageAlgorithm, secureReadable, additionalData));
        }
        else if (recipInfo instanceof KeyAgreeRecipientInfo)
        {
            KeyAgreeRecipientInformation.readRecipientInfo(infos,
                (KeyAgreeRecipientInfo)recipInfo, messageAlgorithm, secureReadable, additionalData);
        }
        else if (recipInfo instanceof PasswordRecipientInfo)
        {
            infos.add(new PasswordRecipientInformation(
                (PasswordRecipientInfo)recipInfo, messageAlgorithm, secureReadable, additionalData));
        }
    }

    static class CMSDigestAuthenticatedSecureReadable
        implements CMSSecureReadable
    {
        private DigestCalculator digestCalculator;
        private CMSReadable readable;

        public CMSDigestAuthenticatedSecureReadable(DigestCalculator digestCalculator, CMSReadable readable)
        {
            this.digestCalculator = digestCalculator;
            this.readable = readable;
        }

        public InputStream getInputStream()
            throws IOException, CMSException
        {
            return new FilterInputStream(readable.getInputStream())
            {
                public int read()
                    throws IOException
                {
                    int b = in.read();

                    if (b >= 0)
                    {
                        digestCalculator.getOutputStream().write(b);
                    }

                    return b;
                }

                public int read(byte[] inBuf, int inOff, int inLen)
                    throws IOException
                {
                    int n = in.read(inBuf, inOff, inLen);
                    
                    if (n >= 0)
                    {
                        digestCalculator.getOutputStream().write(inBuf, inOff, n);
                    }

                    return n;
                }
            };
        }

        public byte[] getDigest()
        {
            return digestCalculator.getDigest();
        }
    }

    static class CMSAuthenticatedSecureReadable implements CMSSecureReadable
    {
        private AlgorithmIdentifier algorithm;
        private CMSReadable readable;

        CMSAuthenticatedSecureReadable(AlgorithmIdentifier algorithm, CMSReadable readable)
        {
            this.algorithm = algorithm;
            this.readable = readable;
        }

        public InputStream getInputStream()
            throws IOException, CMSException
        {
            return readable.getInputStream();
        }

    }

    static class CMSEnvelopedSecureReadable implements CMSSecureReadable
    {
        private AlgorithmIdentifier algorithm;
        private CMSReadable readable;

        CMSEnvelopedSecureReadable(AlgorithmIdentifier algorithm, CMSReadable readable)
        {
            this.algorithm = algorithm;
            this.readable = readable;
        }

        public InputStream getInputStream()
            throws IOException, CMSException
        {
            return readable.getInputStream();
        }

    }
}
