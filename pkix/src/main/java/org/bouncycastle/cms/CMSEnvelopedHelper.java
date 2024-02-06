package org.bouncycastle.cms;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.KEKRecipientInfo;
import org.bouncycastle.asn1.cms.KEMRecipientInfo;
import org.bouncycastle.asn1.cms.KeyAgreeRecipientInfo;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.OtherRecipientInfo;
import org.bouncycastle.asn1.cms.PasswordRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;

class CMSEnvelopedHelper
{
    static RecipientInformationStore buildRecipientInformationStore(
        ASN1Set recipientInfos, AlgorithmIdentifier messageAlgorithm, CMSSecureReadable secureReadable)
    {
        List infos = new ArrayList();
        for (int i = 0; i != recipientInfos.size(); i++)
        {
            RecipientInfo info = RecipientInfo.getInstance(recipientInfos.getObjectAt(i));

            readRecipientInfo(infos, info, messageAlgorithm, secureReadable);
        }
        return new RecipientInformationStore(infos);
    }

    private static void readRecipientInfo(
        List infos, RecipientInfo info, AlgorithmIdentifier messageAlgorithm, CMSSecureReadable secureReadable)
    {
        ASN1Encodable recipInfo = info.getInfo();
        if (recipInfo instanceof KeyTransRecipientInfo)
        {
            infos.add(new KeyTransRecipientInformation(
                (KeyTransRecipientInfo)recipInfo, messageAlgorithm, secureReadable));
        }
        else if (recipInfo instanceof OtherRecipientInfo)
        {
            OtherRecipientInfo otherRecipientInfo = OtherRecipientInfo.getInstance(recipInfo);
            if (CMSObjectIdentifiers.id_ori_kem.equals(otherRecipientInfo.getType()))
            {
                infos.add(new KEMRecipientInformation(
                    KEMRecipientInfo.getInstance(otherRecipientInfo.getValue()), messageAlgorithm, secureReadable));
            }
        }
        else if (recipInfo instanceof KEKRecipientInfo)
        {
            infos.add(new KEKRecipientInformation(
                (KEKRecipientInfo)recipInfo, messageAlgorithm, secureReadable));
        }
        else if (recipInfo instanceof KeyAgreeRecipientInfo)
        {
            KeyAgreeRecipientInformation.readRecipientInfo(infos,
                (KeyAgreeRecipientInfo)recipInfo, messageAlgorithm, secureReadable);
        }
        else if (recipInfo instanceof PasswordRecipientInfo)
        {
            infos.add(new PasswordRecipientInformation(
                (PasswordRecipientInfo)recipInfo, messageAlgorithm, secureReadable));
        }
    }

    static abstract class CMSDefaultSecureReadable
        implements CMSSecureReadable
    {
        protected final ASN1ObjectIdentifier contentType;
        protected CMSReadable readable;
        protected ASN1Set authAttrSet;

        CMSDefaultSecureReadable(ASN1ObjectIdentifier contentType, CMSReadable readable)
        {
            this.contentType = contentType;
            this.readable = readable;
        }

        public ASN1ObjectIdentifier getContentType()
        {
            return contentType;
        }

        @Override
        public ASN1Set getAuthAttrSet()
        {
            return authAttrSet;
        }

        @Override
        public void setAuthAttrSet(ASN1Set set)
        {
            authAttrSet = set;
        }

    }

    static class CMSDigestAuthenticatedSecureReadable
        extends CMSDefaultSecureReadable
    {
        private DigestCalculator digestCalculator;

        public CMSDigestAuthenticatedSecureReadable(DigestCalculator digestCalculator, ASN1ObjectIdentifier contentType, CMSReadable readable)
        {
            super(contentType, readable);
            this.digestCalculator = digestCalculator;
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

        @Override
        public boolean hasAdditionalData()
        {
            return true;
        }
    }

    static class CMSAuthEnveSecureReadable
        extends CMSDefaultSecureReadable
    {
        private AlgorithmIdentifier algorithm;

        CMSAuthEnveSecureReadable(AlgorithmIdentifier algorithm, ASN1ObjectIdentifier contentType, CMSReadable readable)
        {
            super(contentType, readable);
            this.algorithm = algorithm;
        }

        public InputStream getInputStream()
            throws IOException, CMSException
        {
            return readable.getInputStream();
        }

        @Override
        public boolean hasAdditionalData()
        {
            return false;
        }
    }
}
