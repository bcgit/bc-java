package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OctetStringParser;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1SetParser;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.AuthEnvelopedDataParser;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.EncryptedContentInfoParser;
import org.bouncycastle.asn1.cms.OriginatorInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;

public class CMSAuthEnvelopedDataParser
    extends CMSContentInfoParser
{
    private final RecipientInformationStore recipientInfoStore;
    private final AuthEnvelopedDataParser authEvnData;
    private final LocalMacProvider localMacProvider;
    private final AlgorithmIdentifier encAlg;
    private AttributeTable authAttrs;
    private ASN1Set authAttrSet;
    private AttributeTable unauthAttrs;

    private boolean authAttrNotRead;
    private boolean unauthAttrNotRead;
    private OriginatorInformation originatorInfo;

    public CMSAuthEnvelopedDataParser(
        byte[] envelopedData)
        throws CMSException, IOException
    {
        this(new ByteArrayInputStream(envelopedData));
    }

    public CMSAuthEnvelopedDataParser(
        InputStream envelopedData)
        throws CMSException, IOException
    {
        super(envelopedData);

        authAttrNotRead = true;
        unauthAttrNotRead = true;
        authEvnData = new AuthEnvelopedDataParser((ASN1SequenceParser)_contentInfo.getContent(BERTags.SEQUENCE));

        OriginatorInfo info = authEvnData.getOriginatorInfo();

        if (info != null)
        {
            this.originatorInfo = new OriginatorInformation(info);
        }
        //
        // read the recipients
        //
        ASN1Set recipientInfos = ASN1Set.getInstance(authEvnData.getRecipientInfos().toASN1Primitive());

        final EncryptedContentInfoParser encInfo = authEvnData.getAuthEncryptedContentInfo();
        
        encAlg = encInfo.getContentEncryptionAlgorithm();
        localMacProvider = new LocalMacProvider(authEvnData, this);

        final CMSReadable readable = new CMSProcessableInputStream(new InputStreamWithMAC(
            ((ASN1OctetStringParser)encInfo.getEncryptedContent(BERTags.OCTET_STRING)).getOctetStream(), localMacProvider));

        CMSSecureReadableWithAAD secureReadable = new CMSSecureReadableWithAAD()
        {
            private OutputStream aadStream;

            @Override
            public ASN1ObjectIdentifier getContentType()
            {
                return encInfo.getContentType();
            }

            @Override
            public InputStream getInputStream()
                throws IOException, CMSException
            {
                return readable.getInputStream();
            }

            @Override
            public ASN1Set getAuthAttrSet()
            {
                return authAttrSet;
            }

            @Override
            public void setAuthAttrSet(ASN1Set set)
            {

            }

            @Override
            public boolean hasAdditionalData()
            {
                return true;
            }

            @Override
            public void setAADStream(OutputStream stream)
            {
                aadStream = stream;
            }

            @Override
            public OutputStream getAADStream()
            {
                return aadStream;
            }

            @Override
            public byte[] getMAC()
            {
                return Arrays.clone(localMacProvider.getMAC());
            }
        };

        localMacProvider.setSecureReadable(secureReadable);
        //
        // build the RecipientInformationStore
        //
        this.recipientInfoStore = CMSEnvelopedHelper.buildRecipientInformationStore(recipientInfos, this.encAlg, secureReadable);
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
     * Return the MAC algorithm details for the MAC associated with the data in this object.
     *
     * @return AlgorithmIdentifier representing the MAC algorithm.
     */
    public AlgorithmIdentifier getEncryptionAlgOID()
    {
        return encAlg;
    }

    /**
     * return the object identifier for the mac algorithm.
     */
    public String getEncAlgOID()
    {
        return encAlg.getAlgorithm().toString();
    }

    /**
     * return the ASN.1 encoded encryption algorithm parameters, or null if
     * there aren't any.
     */
    public byte[] getEncAlgParams()
    {
        try
        {
            return CMSUtils.encodeObj(encAlg.getParameters());
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

    public byte[] getMac()
        throws IOException
    {
        return Arrays.clone(localMacProvider.getMAC());
    }

    private ASN1Set getAuthAttrSet()
        throws IOException
    {
        if (authAttrs == null && authAttrNotRead)
        {
            ASN1SetParser set = authEvnData.getAuthAttrs();

            if (set != null)
            {
                authAttrSet = (ASN1Set)set.toASN1Primitive();
            }

            authAttrNotRead = false;
        }

        return authAttrSet;
    }

    /**
     * return a table of the unauthenticated attributes indexed by
     * the OID of the attribute.
     */
    public AttributeTable getAuthAttrs()
        throws IOException
    {
        if (authAttrs == null && authAttrNotRead)
        {
            ASN1Set set = getAuthAttrSet();

            if (set != null)
            {
                authAttrs = new AttributeTable(set);
            }
        }

        return authAttrs;
    }

    /**
     * return a table of the unauthenticated attributes indexed by
     * the OID of the attribute.
     */
    public AttributeTable getUnauthAttrs()
        throws IOException
    {
        if (unauthAttrs == null && unauthAttrNotRead)
        {
            unauthAttrNotRead = false;
            unauthAttrs = CMSUtils.getAttributesTable(authEvnData.getUnauthAttrs());
        }

        return unauthAttrs;
    }

    /**
     * This will only be valid after the content has been read.
     *
     * @return the contents of the messageDigest attribute, if available. Null if not present.
     */
    public byte[] getContentDigest()
    {
        if (authAttrs != null)
        {
            return ASN1OctetString.getInstance(authAttrs.get(CMSAttributes.messageDigest).getAttrValues().getObjectAt(0)).getOctets();
        }

        return null;
    }

    static class LocalMacProvider
        implements MACProvider
    {
        private byte[] mac;
        private final AuthEnvelopedDataParser authEnvData;
        private final CMSAuthEnvelopedDataParser parser;
        private CMSSecureReadableWithAAD readable;

        LocalMacProvider(AuthEnvelopedDataParser authEnvData, CMSAuthEnvelopedDataParser parser)
        {
            this.authEnvData = authEnvData;
            this.parser = parser;
        }

        public void init()
            throws IOException
        {
            parser.authAttrs = parser.getAuthAttrs();
            if (parser.authAttrs != null)
            {
                readable.setAuthAttrSet(parser.authAttrSet);
                readable.getAADStream().write(parser.authAttrs.toASN1Structure().getEncoded(ASN1Encoding.DER));
            }
            mac = authEnvData.getMac().getOctets();
        }

        void setSecureReadable(CMSSecureReadableWithAAD secureReadable)
        {
            readable = secureReadable;
        }

        public byte[] getMAC()
        {
            return mac;
        }
    }
}

