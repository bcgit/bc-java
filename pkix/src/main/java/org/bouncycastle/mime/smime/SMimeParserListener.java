package org.bouncycastle.mime.smime;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.OriginatorInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.mime.ConstantMimeContext;
import org.bouncycastle.mime.Headers;
import org.bouncycastle.mime.MimeContext;
import org.bouncycastle.mime.MimeIOException;
import org.bouncycastle.mime.MimeParserContext;
import org.bouncycastle.mime.MimeParserListener;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.Streams;

public abstract class SMimeParserListener
    implements MimeParserListener
{
    private DigestCalculator[] digestCalculators;
    private SMimeMultipartContext parent;

    public MimeContext createContext(MimeParserContext parserContext, Headers headers)
    {
        if (headers.isMultipart())
        {
            parent = new SMimeMultipartContext(parserContext, headers);
            this.digestCalculators = parent.getDigestCalculators();
            return parent;
        }
        else
        {
            return new ConstantMimeContext();
        }
    }

    public void object(MimeParserContext parserContext, Headers headers, InputStream inputStream)
        throws IOException
    {
        try
        {
            if (headers.getContentType().equals("application/pkcs7-signature")
                || headers.getContentType().equals("application/x-pkcs7-signature"))
            {
                Map<ASN1ObjectIdentifier, byte[]> hashes = new HashMap<ASN1ObjectIdentifier, byte[]>();

                for (int i = 0; i != digestCalculators.length; i++)
                {
                    digestCalculators[i].getOutputStream().close();

                    hashes.put(digestCalculators[i].getAlgorithmIdentifier().getAlgorithm(), digestCalculators[i].getDigest());
                }

                byte[] sigBlock = Streams.readAll(inputStream);

                CMSSignedData signedData = new CMSSignedData(hashes, sigBlock);

                signedData(parserContext, headers, signedData.getCertificates(), signedData.getCRLs(), signedData.getAttributeCertificates(), signedData.getSignerInfos());
            }
            else if (headers.getContentType().equals("application/pkcs7-mime")
                  || headers.getContentType().equals("application/x-pkcs7-mime"))
            {
                CMSEnvelopedDataParser envelopedDataParser = new CMSEnvelopedDataParser(inputStream);

                envelopedData(parserContext, headers, envelopedDataParser.getOriginatorInfo(), envelopedDataParser.getRecipientInfos());

                envelopedDataParser.close();
            }
            else
            {
                content(parserContext, headers, inputStream);
            }
        }
        catch (CMSException e)
        {
            throw new MimeIOException("CMS failure: " + e.getMessage(), e);
        }
    }

    public void content(MimeParserContext parserContext, Headers headers, InputStream inputStream)
        throws IOException
    {
        throw new IllegalStateException("content handling not implemented");
    }

    public void signedData(MimeParserContext parserContext, Headers headers, Store certificates, Store CRLs, Store attributeCertificates, SignerInformationStore signers)
        throws IOException, CMSException
    {
        throw new IllegalStateException("signedData handling not implemented");
    }

    public void envelopedData(MimeParserContext parserContext, Headers headers, OriginatorInformation originatorInformation, RecipientInformationStore recipients)
        throws IOException, CMSException
    {
        throw new IllegalStateException("envelopedData handling not implemented");
    }
}
