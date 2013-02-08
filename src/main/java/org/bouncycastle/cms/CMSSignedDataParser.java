package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Generator;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetStringParser;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1SetParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.BERSetParser;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfoParser;
import org.bouncycastle.asn1.cms.SignedDataParser;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.x509.NoSuchStoreException;
import org.bouncycastle.x509.X509Store;

/**
 * Parsing class for an CMS Signed Data object from an input stream.
 * <p>
 * Note: that because we are in a streaming mode only one signer can be tried and it is important 
 * that the methods on the parser are called in the appropriate order.
 * </p>
 * <p>
 * A simple example of usage for an encapsulated signature.
 * </p>
 * <p>
 * Two notes: first, in the example below the validity of
 * the certificate isn't verified, just the fact that one of the certs 
 * matches the given signer, and, second, because we are in a streaming
 * mode the order of the operations is important.
 * </p>
 * <pre>
 *      CMSSignedDataParser     sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(), encapSigData);
 *
 *      sp.getSignedContent().drain();
 *
 *      Store                   certStore = sp.getCertificates();
 *      SignerInformationStore  signers = sp.getSignerInfos();
 *      
 *      Collection              c = signers.getSigners();
 *      Iterator                it = c.iterator();
 *
 *      while (it.hasNext())
 *      {
 *          SignerInformation   signer = (SignerInformation)it.next();
 *          Collection          certCollection = certStore.getMatches(signer.getSID());
 *
 *          Iterator        certIt = certCollection.iterator();
 *          X509CertificateHolder cert = (X509CertificateHolder)certIt.next();
 *
 *          System.out.println("verify returns: " + signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert)));
 *      }
 * </pre>
 *  Note also: this class does not introduce buffering - if you are processing large files you should create
 *  the parser with:
 *  <pre>
 *          CMSSignedDataParser     ep = new CMSSignedDataParser(new BufferedInputStream(encapSigData, bufSize));
 *  </pre>
 *  where bufSize is a suitably large buffer size.
 */
public class CMSSignedDataParser
    extends CMSContentInfoParser
{
    private static final CMSSignedHelper HELPER = CMSSignedHelper.INSTANCE;

    private SignedDataParser        _signedData;
    private ASN1ObjectIdentifier    _signedContentType;
    private CMSTypedStream          _signedContent;
    private Map                     digests;

    private SignerInformationStore  _signerInfoStore;
    private X509Store               _attributeStore;
    private ASN1Set                 _certSet, _crlSet;
    private boolean                 _isCertCrlParsed;
    private X509Store               _certificateStore;
    private X509Store               _crlStore;

    /**
     * @deprecated use method taking a DigestCalculatorProvider
     */
    public CMSSignedDataParser(
        byte[]      sigBlock)
        throws CMSException
    {
        this(createDefaultDigestProvider(), new ByteArrayInputStream(sigBlock));
    }


    public CMSSignedDataParser(
        DigestCalculatorProvider digestCalculatorProvider,
        byte[]      sigBlock)
        throws CMSException
    {
        this(digestCalculatorProvider, new ByteArrayInputStream(sigBlock));
    }

    /**
     * @deprecated use method taking digest calculator provider.
     * @param signedContent
     * @param sigBlock
     * @throws CMSException
     */
    public CMSSignedDataParser(
        CMSTypedStream  signedContent,
        byte[]          sigBlock)
        throws CMSException
    {
        this(createDefaultDigestProvider(), signedContent, new ByteArrayInputStream(sigBlock));
    }

    public CMSSignedDataParser(
        DigestCalculatorProvider digestCalculatorProvider,
        CMSTypedStream  signedContent,
        byte[]          sigBlock)
        throws CMSException
    {
        this(digestCalculatorProvider, signedContent, new ByteArrayInputStream(sigBlock));
    }

    private static DigestCalculatorProvider createDefaultDigestProvider()
        throws CMSException
    {
        return new BcDigestCalculatorProvider();
    }

    /**
     * base constructor - with encapsulated content
     *
     * @deprecated use method taking a DigestCalculatorProvider
     */
    public CMSSignedDataParser(
        InputStream sigData)
        throws CMSException
    {
        this(createDefaultDigestProvider(), null, sigData);
    }

     /**
     * base constructor - with encapsulated content
     */
    public CMSSignedDataParser(
        DigestCalculatorProvider digestCalculatorProvider,
        InputStream sigData)
        throws CMSException
    {
        this(digestCalculatorProvider, null, sigData);
    }

    /**
     * base constructor
     *
     * @param signedContent the content that was signed.
     * @param sigData the signature object stream.
     *      *
     * @deprecated use method taking a DigestCalculatorProvider
     */
    public CMSSignedDataParser(
        CMSTypedStream  signedContent,
        InputStream     sigData) 
        throws CMSException
    {
        this(createDefaultDigestProvider(), signedContent, sigData);
    }

    /**
     * base constructor
     *
     * @param digestCalculatorProvider for generating accumulating digests
     * @param signedContent the content that was signed.
     * @param sigData the signature object stream.
     */
    public CMSSignedDataParser(
        DigestCalculatorProvider digestCalculatorProvider,
        CMSTypedStream  signedContent,
        InputStream     sigData)
        throws CMSException
    {
        super(sigData);
        
        try
        {
            _signedContent = signedContent;
            _signedData = SignedDataParser.getInstance(_contentInfo.getContent(BERTags.SEQUENCE));
            digests = new HashMap();
            
            ASN1SetParser digAlgs = _signedData.getDigestAlgorithms();
            ASN1Encodable  o;
            
            while ((o = digAlgs.readObject()) != null)
            {
                AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(o);
                try
                {
                    DigestCalculator calculator = digestCalculatorProvider.get(algId);

                    if (calculator != null)
                    {
                        this.digests.put(algId.getAlgorithm(), calculator);
                    }
                }
                catch (OperatorCreationException e)
                {
                     //  ignore
                }
            }

            //
            // If the message is simply a certificate chain message getContent() may return null.
            //
            ContentInfoParser     cont = _signedData.getEncapContentInfo();
            ASN1OctetStringParser octs = (ASN1OctetStringParser)
                cont.getContent(BERTags.OCTET_STRING);

            if (octs != null)
            {
                CMSTypedStream ctStr = new CMSTypedStream(
                    cont.getContentType().getId(), octs.getOctetStream());

                if (_signedContent == null)
                {
                    _signedContent = ctStr; 
                }
                else
                {
                    //
                    // content passed in, need to read past empty encapsulated content info object if present
                    //
                    ctStr.drain();
                }
            }

            if (signedContent == null)
            {
                _signedContentType = cont.getContentType();
            }
            else
            {
                _signedContentType = _signedContent.getContentType();
            }
        }
        catch (IOException e)
        {
            throw new CMSException("io exception: " + e.getMessage(), e);
        }
        
        if (digests.isEmpty())
        {
            throw new CMSException("no digests could be created for message.");
        }
    }

    /**
     * Return the version number for the SignedData object
     *
     * @return the version number
     */
    public int getVersion()
    {
        return _signedData.getVersion().getValue().intValue();
    }

    /**
     * return the collection of signers that are associated with the
     * signatures for the message.
     * @throws CMSException 
     */
    public SignerInformationStore getSignerInfos() 
        throws CMSException
    {
        if (_signerInfoStore == null)
        {
            populateCertCrlSets();
            
            List      signerInfos = new ArrayList();
            Map       hashes = new HashMap();
            
            Iterator  it = digests.keySet().iterator();
            while (it.hasNext())
            {
                Object digestKey = it.next();

                hashes.put(digestKey, ((DigestCalculator)digests.get(digestKey)).getDigest());
            }
            
            try
            {
                ASN1SetParser     s = _signedData.getSignerInfos();
                ASN1Encodable      o;

                while ((o = s.readObject()) != null)
                {
                    SignerInfo info = SignerInfo.getInstance(o.toASN1Primitive());

                    byte[] hash = (byte[])hashes.get(info.getDigestAlgorithm().getAlgorithm());

                    signerInfos.add(new SignerInformation(info, _signedContentType, null, hash));
                }
            }
            catch (IOException e)
            {
                throw new CMSException("io exception: " + e.getMessage(), e);
            }

            _signerInfoStore = new SignerInformationStore(signerInfos);
        }

        return _signerInfoStore;
    }

    /**
     * return a X509Store containing the attribute certificates, if any, contained
     * in this message.
     *
     * @param type type of store to create
     * @param provider name of provider to use
     * @return a store of attribute certificates
     * @exception NoSuchProviderException if the provider requested isn't available.
     * @exception org.bouncycastle.x509.NoSuchStoreException if the store type isn't available.
     * @exception CMSException if a general exception prevents creation of the X509Store
     */
    public X509Store getAttributeCertificates(
        String type,
        String provider)
        throws NoSuchStoreException, NoSuchProviderException, CMSException
    {
        return getAttributeCertificates(type, CMSUtils.getProvider(provider));
    }

    /**
     * return a X509Store containing the attribute certificates, if any, contained
     * in this message.
     *
     * @param type type of store to create
     * @param provider provider to use
     * @return a store of attribute certificates
     * @exception org.bouncycastle.x509.NoSuchStoreException if the store type isn't available.
     * @exception CMSException if a general exception prevents creation of the X509Store
     */
    public X509Store getAttributeCertificates(
        String type,
        Provider provider)
        throws NoSuchStoreException, CMSException
    {
        if (_attributeStore == null)
        {
            populateCertCrlSets();

            _attributeStore = HELPER.createAttributeStore(type, provider, _certSet);
        }

        return _attributeStore;
    }

    /**
     * return a X509Store containing the public key certificates, if any, contained
     * in this message.
     *
     * @param type type of store to create
     * @param provider provider to use
     * @return a store of public key certificates
     * @exception NoSuchProviderException if the provider requested isn't available.
     * @exception NoSuchStoreException if the store type isn't available.
     * @exception CMSException if a general exception prevents creation of the X509Store
     * @deprecated use getCertificates()
     */
    public X509Store getCertificates(
        String type,
        String provider)
        throws NoSuchStoreException, NoSuchProviderException, CMSException
    {
        return getCertificates(type, CMSUtils.getProvider(provider));
    }

    /**
     * return a X509Store containing the public key certificates, if any, contained
     * in this message.
     *
     * @param type type of store to create
     * @param provider provider to use
     * @return a store of public key certificates
     * @exception NoSuchStoreException if the store type isn't available.
     * @exception CMSException if a general exception prevents creation of the X509Store
     * @deprecated use getCertificates()
     */
    public X509Store getCertificates(
        String type,
        Provider provider)
        throws NoSuchStoreException, CMSException
    {
        if (_certificateStore == null)
        {
            populateCertCrlSets();

            _certificateStore = HELPER.createCertificateStore(type, provider, _certSet);
        }

        return _certificateStore;
    }

    /**
     * return a X509Store containing CRLs, if any, contained
     * in this message.
     *
     * @param type type of store to create
     * @param provider name of provider to use
     * @return a store of CRLs
     * @exception NoSuchProviderException if the provider requested isn't available.
     * @exception NoSuchStoreException if the store type isn't available.
     * @exception CMSException if a general exception prevents creation of the X509Store
     * @deprecated use getCRLs()
     */
    public X509Store getCRLs(
        String type,
        String provider)
        throws NoSuchStoreException, NoSuchProviderException, CMSException
    {
        return getCRLs(type, CMSUtils.getProvider(provider));
    }

    /**
     * return a X509Store containing CRLs, if any, contained
     * in this message.
     *
     * @param type type of store to create
     * @param provider provider to use
     * @return a store of CRLs
     * @exception NoSuchStoreException if the store type isn't available.
     * @exception CMSException if a general exception prevents creation of the X509Store
     * @deprecated use getCRLs()
     */
    public X509Store getCRLs(
        String type,
        Provider provider)
        throws NoSuchStoreException, CMSException
    {
        if (_crlStore == null)
        {
            populateCertCrlSets();

            _crlStore = HELPER.createCRLsStore(type, provider, _crlSet);
        }

        return _crlStore;
    }

    /**
     * return a CertStore containing the certificates and CRLs associated with
     * this message.
     *
     * @exception NoSuchProviderException if the provider requested isn't available.
     * @exception NoSuchAlgorithmException if the cert store isn't available.
     * @exception CMSException if a general exception prevents creation of the CertStore
     * @deprecated use getCertificates()
     */
    public CertStore getCertificatesAndCRLs(
        String  type,
        String  provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        return getCertificatesAndCRLs(type, CMSUtils.getProvider(provider));
    }

    /**
     * return a CertStore containing the certificates and CRLs associated with
     * this message.
     *
     * @exception NoSuchProviderException if the provider requested isn't available.
     * @exception NoSuchAlgorithmException if the cert store isn't available.
     * @exception CMSException if a general exception prevents creation of the CertStore
     * @deprecated use getCertificates()
     */
    public CertStore getCertificatesAndCRLs(
        String  type,
        Provider  provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        populateCertCrlSets();

        return HELPER.createCertStore(type, provider, _certSet, _crlSet);
    }

    public Store getCertificates()
        throws CMSException
    {
        populateCertCrlSets();

        ASN1Set certSet = _certSet;

        if (certSet != null)
        {
            List    certList = new ArrayList(certSet.size());

            for (Enumeration en = certSet.getObjects(); en.hasMoreElements();)
            {
                ASN1Primitive obj = ((ASN1Encodable)en.nextElement()).toASN1Primitive();

                if (obj instanceof ASN1Sequence)
                {
                    certList.add(new X509CertificateHolder(Certificate.getInstance(obj)));
                }
            }

            return new CollectionStore(certList);
        }

        return new CollectionStore(new ArrayList());
    }

    public Store getCRLs()
        throws CMSException
    {
        populateCertCrlSets();

        ASN1Set crlSet = _crlSet;

        if (crlSet != null)
        {
            List    crlList = new ArrayList(crlSet.size());

            for (Enumeration en = crlSet.getObjects(); en.hasMoreElements();)
            {
                ASN1Primitive obj = ((ASN1Encodable)en.nextElement()).toASN1Primitive();

                if (obj instanceof ASN1Sequence)
                {
                    crlList.add(new X509CRLHolder(CertificateList.getInstance(obj)));
                }
            }

            return new CollectionStore(crlList);
        }

        return new CollectionStore(new ArrayList());
    }

    public Store getAttributeCertificates()
        throws CMSException
    {
        populateCertCrlSets();

        ASN1Set certSet = _certSet;

        if (certSet != null)
        {
            List    certList = new ArrayList(certSet.size());

            for (Enumeration en = certSet.getObjects(); en.hasMoreElements();)
            {
                ASN1Primitive obj = ((ASN1Encodable)en.nextElement()).toASN1Primitive();

                if (obj instanceof ASN1TaggedObject)
                {
                    ASN1TaggedObject tagged = (ASN1TaggedObject)obj;

                    if (tagged.getTagNo() == 2)
                    {
                        certList.add(new X509AttributeCertificateHolder(AttributeCertificate.getInstance(ASN1Sequence.getInstance(tagged, false))));
                    }
                }
            }

            return new CollectionStore(certList);
        }

        return new CollectionStore(new ArrayList());
    }

    private void populateCertCrlSets()
        throws CMSException
    {
        if (_isCertCrlParsed)
        {
            return;
        }

        _isCertCrlParsed = true;

        try
        {
            // care! Streaming - these must be done in exactly this order.
            _certSet = getASN1Set(_signedData.getCertificates());
            _crlSet = getASN1Set(_signedData.getCrls());
        }
        catch (IOException e)
        {
            throw new CMSException("problem parsing cert/crl sets", e);
        }
    }

    /**
     * Return the a string representation of the OID associated with the
     * encapsulated content info structure carried in the signed data.
     * 
     * @return the OID for the content type.
     */
    public String getSignedContentTypeOID()
    {
        return _signedContentType.getId();
    }

    public CMSTypedStream getSignedContent()
    {
        if (_signedContent == null)
        {
            return null;
        }

        InputStream digStream = CMSUtils.attachDigestsToInputStream(
            digests.values(), _signedContent.getContentStream());

        return new CMSTypedStream(_signedContent.getContentType(), digStream);
    }

    /**
     * Replace the signerinformation store associated with the passed
     * in message contained in the stream original with the new one passed in.
     * You would probably only want to do this if you wanted to change the unsigned
     * attributes associated with a signer, or perhaps delete one.
     * <p>
     * The output stream is returned unclosed.
     * </p>
     * @param original the signed data stream to be used as a base.
     * @param signerInformationStore the new signer information store to use.
     * @param out the stream to write the new signed data object to.
     * @return out.
     */
    public static OutputStream replaceSigners(
        InputStream             original,
        SignerInformationStore  signerInformationStore,
        OutputStream            out)
        throws CMSException, IOException
    {
        ASN1StreamParser in = new ASN1StreamParser(original);
        ContentInfoParser contentInfo = new ContentInfoParser((ASN1SequenceParser)in.readObject());
        SignedDataParser signedData = SignedDataParser.getInstance(contentInfo.getContent(BERTags.SEQUENCE));

        BERSequenceGenerator sGen = new BERSequenceGenerator(out);

        sGen.addObject(CMSObjectIdentifiers.signedData);

        BERSequenceGenerator sigGen = new BERSequenceGenerator(sGen.getRawOutputStream(), 0, true);

        // version number
        sigGen.addObject(signedData.getVersion());

        // digests
        signedData.getDigestAlgorithms().toASN1Primitive();  // skip old ones

        ASN1EncodableVector digestAlgs = new ASN1EncodableVector();

        for (Iterator it = signerInformationStore.getSigners().iterator(); it.hasNext();)
        {
            SignerInformation signer = (SignerInformation)it.next();
            digestAlgs.add(CMSSignedHelper.INSTANCE.fixAlgID(signer.getDigestAlgorithmID()));
        }

        sigGen.getRawOutputStream().write(new DERSet(digestAlgs).getEncoded());

        // encap content info
        ContentInfoParser encapContentInfo = signedData.getEncapContentInfo();

        BERSequenceGenerator eiGen = new BERSequenceGenerator(sigGen.getRawOutputStream());

        eiGen.addObject(encapContentInfo.getContentType());

        pipeEncapsulatedOctetString(encapContentInfo, eiGen.getRawOutputStream());

        eiGen.close();


        writeSetToGeneratorTagged(sigGen, signedData.getCertificates(), 0);
        writeSetToGeneratorTagged(sigGen, signedData.getCrls(), 1);


        ASN1EncodableVector signerInfos = new ASN1EncodableVector();
        for (Iterator it = signerInformationStore.getSigners().iterator(); it.hasNext();)
        {
            SignerInformation        signer = (SignerInformation)it.next();

            signerInfos.add(signer.toASN1Structure());
        }

        sigGen.getRawOutputStream().write(new DERSet(signerInfos).getEncoded());

        sigGen.close();

        sGen.close();

        return out;
    }

    /**
     * Replace the certificate and CRL information associated with this
     * CMSSignedData object with the new one passed in.
     * <p>
     * The output stream is returned unclosed.
     * </p>
     * @param original the signed data stream to be used as a base.
     * @param certsAndCrls the new certificates and CRLs to be used.
     * @param out the stream to write the new signed data object to.
     * @return out.
     * @exception CMSException if there is an error processing the CertStore
     * @deprecated use method that takes Store objects.
     */
    public static OutputStream replaceCertificatesAndCRLs(
        InputStream   original,
        CertStore     certsAndCrls,
        OutputStream  out)
        throws CMSException, IOException
    {
        ASN1StreamParser in = new ASN1StreamParser(original);
        ContentInfoParser contentInfo = new ContentInfoParser((ASN1SequenceParser)in.readObject());
        SignedDataParser signedData = SignedDataParser.getInstance(contentInfo.getContent(BERTags.SEQUENCE));

        BERSequenceGenerator sGen = new BERSequenceGenerator(out);

        sGen.addObject(CMSObjectIdentifiers.signedData);

        BERSequenceGenerator sigGen = new BERSequenceGenerator(sGen.getRawOutputStream(), 0, true);

        // version number
        sigGen.addObject(signedData.getVersion());

        // digests
        sigGen.getRawOutputStream().write(signedData.getDigestAlgorithms().toASN1Primitive().getEncoded());

        // encap content info
        ContentInfoParser encapContentInfo = signedData.getEncapContentInfo();

        BERSequenceGenerator eiGen = new BERSequenceGenerator(sigGen.getRawOutputStream());

        eiGen.addObject(encapContentInfo.getContentType());

        pipeEncapsulatedOctetString(encapContentInfo, eiGen.getRawOutputStream());

        eiGen.close();

        //
        // skip existing certs and CRLs
        //
        getASN1Set(signedData.getCertificates());
        getASN1Set(signedData.getCrls());

        //
        // replace the certs and crls in the SignedData object
        //
        ASN1Set certs;

        try
        {
            certs = CMSUtils.createBerSetFromList(CMSUtils.getCertificatesFromStore(certsAndCrls));
        }
        catch (CertStoreException e)
        {
            throw new CMSException("error getting certs from certStore", e);
        }

        if (certs.size() > 0)
        {
            sigGen.getRawOutputStream().write(new DERTaggedObject(false, 0, certs).getEncoded());
        }

        ASN1Set crls;

        try
        {
            crls = CMSUtils.createBerSetFromList(CMSUtils.getCRLsFromStore(certsAndCrls));
        }
        catch (CertStoreException e)
        {
            throw new CMSException("error getting crls from certStore", e);
        }

        if (crls.size() > 0)
        {
            sigGen.getRawOutputStream().write(new DERTaggedObject(false, 1, crls).getEncoded());
        }

        sigGen.getRawOutputStream().write(signedData.getSignerInfos().toASN1Primitive().getEncoded());

        sigGen.close();

        sGen.close();

        return out;
    }

    /**
     * Replace the certificate and CRL information associated with this
     * CMSSignedData object with the new one passed in.
     * <p>
     * The output stream is returned unclosed.
     * </p>
     * @param original the signed data stream to be used as a base.
     * @param certs new certificates to be used, if any.
     * @param crls new CRLs to be used, if any.
     * @param attrCerts new attribute certificates to be used, if any.
     * @param out the stream to write the new signed data object to.
     * @return out.
     * @exception CMSException if there is an error processing the CertStore
     */
    public static OutputStream replaceCertificatesAndCRLs(
        InputStream   original,
        Store         certs,
        Store         crls,
        Store         attrCerts,
        OutputStream  out)
        throws CMSException, IOException
    {
        ASN1StreamParser in = new ASN1StreamParser(original);
        ContentInfoParser contentInfo = new ContentInfoParser((ASN1SequenceParser)in.readObject());
        SignedDataParser signedData = SignedDataParser.getInstance(contentInfo.getContent(BERTags.SEQUENCE));

        BERSequenceGenerator sGen = new BERSequenceGenerator(out);

        sGen.addObject(CMSObjectIdentifiers.signedData);

        BERSequenceGenerator sigGen = new BERSequenceGenerator(sGen.getRawOutputStream(), 0, true);

        // version number
        sigGen.addObject(signedData.getVersion());

        // digests
        sigGen.getRawOutputStream().write(signedData.getDigestAlgorithms().toASN1Primitive().getEncoded());

        // encap content info
        ContentInfoParser encapContentInfo = signedData.getEncapContentInfo();

        BERSequenceGenerator eiGen = new BERSequenceGenerator(sigGen.getRawOutputStream());

        eiGen.addObject(encapContentInfo.getContentType());

        pipeEncapsulatedOctetString(encapContentInfo, eiGen.getRawOutputStream());

        eiGen.close();

        //
        // skip existing certs and CRLs
        //
        getASN1Set(signedData.getCertificates());
        getASN1Set(signedData.getCrls());

        //
        // replace the certs and crls in the SignedData object
        //
        if (certs != null || attrCerts != null)
        {
            List certificates = new ArrayList();

            if (certs != null)
            {
                certificates.addAll(CMSUtils.getCertificatesFromStore(certs));
            }
            if (attrCerts != null)
            {
                certificates.addAll(CMSUtils.getAttributeCertificatesFromStore(attrCerts));
            }

            ASN1Set asn1Certs = CMSUtils.createBerSetFromList(certificates);

            if (asn1Certs.size() > 0)
            {
                sigGen.getRawOutputStream().write(new DERTaggedObject(false, 0, asn1Certs).getEncoded());
            }
        }

        if (crls != null)
        {
            ASN1Set asn1Crls = CMSUtils.createBerSetFromList(CMSUtils.getCRLsFromStore(crls));

            if (asn1Crls.size() > 0)
            {
                sigGen.getRawOutputStream().write(new DERTaggedObject(false, 1, asn1Crls).getEncoded());
            }
        }

        sigGen.getRawOutputStream().write(signedData.getSignerInfos().toASN1Primitive().getEncoded());

        sigGen.close();

        sGen.close();

        return out;
    }

    private static void writeSetToGeneratorTagged(
        ASN1Generator asn1Gen,
        ASN1SetParser asn1SetParser,
        int           tagNo)
        throws IOException
    {
        ASN1Set asn1Set = getASN1Set(asn1SetParser);

        if (asn1Set != null)
        {
            if (asn1SetParser instanceof BERSetParser)
            {
                asn1Gen.getRawOutputStream().write(new BERTaggedObject(false, tagNo, asn1Set).getEncoded());
            }
            else
            {
                asn1Gen.getRawOutputStream().write(new DERTaggedObject(false, tagNo, asn1Set).getEncoded());
            }
        }
    }

    private static ASN1Set getASN1Set(
        ASN1SetParser asn1SetParser)
    {
        return asn1SetParser == null
            ?   null
            :   ASN1Set.getInstance(asn1SetParser.toASN1Primitive());
    }

    private static void pipeEncapsulatedOctetString(ContentInfoParser encapContentInfo,
        OutputStream rawOutputStream) throws IOException
    {
        ASN1OctetStringParser octs = (ASN1OctetStringParser)
            encapContentInfo.getContent(BERTags.OCTET_STRING);

        if (octs != null)
        {
            pipeOctetString(octs, rawOutputStream);
        }

//        BERTaggedObjectParser contentObject = (BERTaggedObjectParser)encapContentInfo.getContentObject();
//        if (contentObject != null)
//        {
//            // Handle IndefiniteLengthInputStream safely
//            InputStream input = ASN1StreamParser.getSafeRawInputStream(contentObject.getContentStream(true));
//
//            // TODO BerTaggedObjectGenerator?
//            BEROutputStream berOut = new BEROutputStream(rawOutputStream);
//            berOut.write(DERTags.CONSTRUCTED | DERTags.TAGGED | 0);
//            berOut.write(0x80);
//
//            pipeRawOctetString(input, rawOutputStream);
//
//            berOut.write(0x00);
//            berOut.write(0x00);
//
//            input.close();
//        }
    }

    private static void pipeOctetString(
        ASN1OctetStringParser octs,
        OutputStream          output)
        throws IOException
    {
        // TODO Allow specification of a specific fragment size?
        OutputStream outOctets = CMSUtils.createBEROctetOutputStream(
            output, 0, true, 0);
        Streams.pipeAll(octs.getOctetStream(), outOctets);
        outOctets.close();
    }

//    private static void pipeRawOctetString(
//        InputStream     rawInput,
//        OutputStream    rawOutput)
//        throws IOException
//    {
//        InputStream tee = new TeeInputStream(rawInput, rawOutput);
//        ASN1StreamParser sp = new ASN1StreamParser(tee);
//        ASN1OctetStringParser octs = (ASN1OctetStringParser)sp.readObject();
//        Streams.drain(octs.getOctetStream());
//    }
}
