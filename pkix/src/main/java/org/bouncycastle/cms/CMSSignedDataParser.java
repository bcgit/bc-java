package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Generator;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetStringParser;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1SetParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.BEROctetStringParser;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.BERSetParser;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfoParser;
import org.bouncycastle.asn1.cms.SignedDataParser;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.Streams;

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
 * <p>
 * <b>Stream handling note:</b>
 * <ul>
 *   <li>The constructor reads only enough of the supplied InputStream to expose the
 *       digest algorithms and signed-content metadata. The encapsulated content
 *       must be drained by the caller (e.g.
 *       {@link #getSignedContent()}.{@link CMSTypedStream#drain drain()}) before
 *       calling {@link #getSignerInfos()} so the running digests can be finalized.</li>
 *   <li>The supplied InputStream is <b>not closed automatically</b>. Call
 *       {@link #close()} on this parser (inherited from
 *       {@link CMSContentInfoParser}) to close the underlying InputStream, or close
 *       it yourself.</li>
 * </ul>
 */
public class CMSSignedDataParser
    extends CMSContentInfoParser
{
    private static final CMSSignedHelper HELPER = CMSSignedHelper.INSTANCE;
    private static final DefaultDigestAlgorithmIdentifierFinder dgstAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();

    private SignedDataParser        _signedData;
    private ASN1ObjectIdentifier    _signedContentType;
    private CMSTypedStream          _signedContent;
    private Map                     digests;
    private Set<AlgorithmIdentifier> digestAlgorithms;
    private ASN1Set                 _digestAlgorithmsSet;
    private boolean                 _contentBerEncoded;

    private SignerInformationStore  _signerInfoStore;
    private ASN1Set                 _certSet, _crlSet;
    private boolean                 _isCertCrlParsed;

    public CMSSignedDataParser(
        DigestCalculatorProvider digestCalculatorProvider,
        byte[]      sigBlock)
        throws CMSException
    {
        this(digestCalculatorProvider, new ByteArrayInputStream(sigBlock));
    }

    public CMSSignedDataParser(
        DigestCalculatorProvider digestCalculatorProvider,
        CMSTypedStream  signedContent,
        byte[]          sigBlock)
        throws CMSException
    {
        this(digestCalculatorProvider, signedContent, new ByteArrayInputStream(sigBlock));
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

            boolean digestAlgsBer = digAlgs instanceof BERSetParser;
            ASN1EncodableVector digestAlgsVector = new ASN1EncodableVector();
            Set<AlgorithmIdentifier> algSet = new HashSet<AlgorithmIdentifier>();

            while ((o = digAlgs.readObject()) != null)
            {
                ASN1Primitive algPrim = o.toASN1Primitive();

                digestAlgsVector.add(algPrim);

                AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(algPrim);

                algSet.add(algId);

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

            digestAlgorithms = Collections.unmodifiableSet(algSet);
            _digestAlgorithmsSet = digestAlgsBer
                ?   (ASN1Set)new BERSet(digestAlgsVector)
                :   (ASN1Set)new DLSet(digestAlgsVector);

            //
            // If the message is simply a certificate chain message getContent() may return null.
            //
            ContentInfoParser     cont = _signedData.getEncapContentInfo();
            ASN1Encodable contentParser = cont.getContent(BERTags.OCTET_STRING);

            if (contentParser instanceof ASN1OctetStringParser)
            {
                ASN1OctetStringParser octs = (ASN1OctetStringParser)contentParser;

                _contentBerEncoded = octs instanceof BEROctetStringParser;

                CMSTypedStream ctStr = new CMSTypedStream(
                    cont.getContentType(), octs.getOctetStream());

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
            else if (contentParser != null)
            {
                PKCS7TypedStream pkcs7Stream = new PKCS7TypedStream(cont.getContentType(), contentParser);

                if (_signedContent == null)
                {
                    _signedContent = pkcs7Stream;
                }
                else
                {
                    //
                    // content passed in, need to read past empty encapsulated content info object if present
                    //
                    pkcs7Stream.drain();
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
    }

    /**
     * Return the version number for the SignedData object
     *
     * @return the version number
     */
    public int getVersion()
    {
        return _signedData.getVersion().intValueExact();
    }

    /**
     * Return the digest algorithm identifiers for the SignedData object
     *
     * @return the set of digest algorithm identifiers
     */
    public Set<AlgorithmIdentifier> getDigestAlgorithmIDs()
    {
        return digestAlgorithms;
    }

    /**
     * Return the <code>digestAlgorithms</code> field as parsed from the wire:
     * a {@link BERSet} if the field used the indefinite-length (BER) method,
     * a {@link DLSet} otherwise, with the algorithm identifiers in their
     * original wire order. Use this when the original coding needs to be
     * reproduced (e.g. re-emitting a SignedData covered by an
     * ETSI archive-time-stamp); otherwise prefer
     * {@link #getDigestAlgorithmIDs()} (which de-duplicates and does not
     * preserve order).
     *
     * @return the digestAlgorithms set, preserving wire form and order.
     */
    public ASN1Set getDigestAlgorithmsSet()
    {
        return _digestAlgorithmsSet;
    }

    /**
     * Return true if the <code>eContent</code> OCTET STRING of the
     * encapsulated content used a constructed/indefinite-length (BER)
     * encoding, false if it was a primitive definite-length OCTET STRING
     * (DL/DER), or if the signed data was detached (no eContent present).
     * Together with {@link #isBEREncoded()} this exposes the original coding
     * of the signed content without a second pass over the stream
     * (see github #1983).
     *
     * @return true for BER (constructed) eContent, false otherwise.
     */
    public boolean isContentBEREncoded()
    {
        return _contentBerEncoded;
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
     * Return any X.509 certificate objects in this SignedData structure as a Store of X509CertificateHolder objects.
     *
     * @return a Store of X509CertificateHolder objects.
     */
    public Store getCertificates()
        throws CMSException
    {
        populateCertCrlSets();

        return HELPER.getCertificates(_certSet);
    }

    /**
     * Return any X.509 CRL objects in this SignedData structure as a Store of X509CRLHolder objects.
     *
     * @return a Store of X509CRLHolder objects.
     */
    public Store getCRLs()
        throws CMSException
    {
        populateCertCrlSets();

        return HELPER.getCRLs(_crlSet);
    }

    /**
     * Return any X.509 attribute certificate objects in this SignedData structure as a Store of X509AttributeCertificateHolder objects.
     *
     * @return a Store of X509AttributeCertificateHolder objects.
     */
    public Store getAttributeCertificates()
        throws CMSException
    {
        populateCertCrlSets();

        return HELPER.getAttributeCertificates(_certSet);
    }

    /**
     * Return any OtherRevocationInfo OtherRevInfo objects of the type indicated by otherRevocationInfoFormat in
     * this SignedData structure.
     *
     * @param otherRevocationInfoFormat OID of the format type been looked for.
     *
     * @return a Store of ASN1Encodable objects representing any objects of otherRevocationInfoFormat found.
     */
    public Store getOtherRevocationInfo(ASN1ObjectIdentifier otherRevocationInfoFormat)
        throws CMSException
    {
        populateCertCrlSets();

        return HELPER.getOtherRevocationInfo(otherRevocationInfoFormat, _crlSet);
    }

    /**
     * Return the raw <code>certificates</code> field as parsed from the wire,
     * preserving every choice (X.509 SEQUENCE, attribute certificate
     * <code>[1]</code>, other <code>[2]</code>) in original encoding order.
     * Null if the field was absent. Forces a populate of the cert/CRL sets
     * (which is harmless to call multiple times). Use this when the wire
     * order or non-X.509 choices matter; otherwise prefer {@link #getCertificates()}.
     */
    public ASN1Set getCertificateSet()
        throws CMSException
    {
        populateCertCrlSets();

        return _certSet;
    }

    /**
     * Return the raw <code>crls</code> field as parsed from the wire,
     * preserving every choice (CertificateList, other revocation info
     * <code>[1]</code>) in original encoding order. Null if the field was
     * absent. Forces a populate of the cert/CRL sets. Use this when the
     * wire order or non-CertificateList choices matter; otherwise prefer
     * {@link #getCRLs()} or {@link #getOtherRevocationInfo}.
     */
    public ASN1Set getCRLSet()
        throws CMSException
    {
        populateCertCrlSets();

        return _crlSet;
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

        Set<AlgorithmIdentifier> digestAlgs = new HashSet<AlgorithmIdentifier>();
        for (Iterator it = signerInformationStore.getSigners().iterator(); it.hasNext(); )
        {
            SignerInformation signer = (SignerInformation)it.next();
            CMSUtils.addDigestAlgs(digestAlgs, signer, dgstAlgFinder);
            digestAlgs.add(HELPER.fixDigestAlgID(signer.getDigestAlgorithmID(), dgstAlgFinder));
        }
        AlgorithmIdentifier[] newDigestAlgIds = (AlgorithmIdentifier[])digestAlgs.toArray(new AlgorithmIdentifier[digestAlgs.size()]);
        sigGen.addObject(new DLSet(newDigestAlgIds));

        writeEncapContentInfoToGenerator(signedData, sigGen);

        writeSetToGeneratorTagged(sigGen, signedData.getCertificates(), 0);
        writeSetToGeneratorTagged(sigGen, signedData.getCrls(), 1);


        ASN1EncodableVector signerInfos = new ASN1EncodableVector();
        for (Iterator it = signerInformationStore.getSigners().iterator(); it.hasNext();)
        {
            SignerInformation        signer = (SignerInformation)it.next();

            signerInfos.add(signer.toASN1Structure());
        }

        sigGen.addObject(new DLSet(signerInfos));

        sigGen.close();

        sGen.close();

        return out;
    }

    /**
     * Replace the signers of the message contained in the stream
     * <code>original</code> with the store passed in, preserving the original
     * wire encoding of everything an ETSI archive-time-stamp imprint covers
     * (ETSI TS 101 733 Annex A, <code>id-aa-ets-archiveTimestampV2</code>).
     * <p>
     * Unlike {@link #replaceSigners(InputStream, SignerInformationStore, OutputStream)},
     * which re-encodes as it goes (recomputed <code>digestAlgorithms</code>,
     * re-chunked BER content, DER-sorted signerInfos), this method copies the
     * <code>version</code>, <code>digestAlgorithms</code>,
     * <code>encapContentInfo</code>, <code>certificates</code> and
     * <code>crls</code> elements <b>verbatim, byte for byte,</b> from the
     * original stream — the encapsulated content is piped, not buffered, so
     * the method is suitable for content larger than a byte array. Only the
     * <code>signerInfos</code> field is rebuilt: it is written as a
     * definite-length SET containing the signers <b>in store order, unsorted</b>
     * (a DER SET would sort, changing the wire order the imprint depends on).
     * The outer ContentInfo / SignedData framing is re-emitted using the
     * indefinite-length (BER) method, as with the other streaming generators;
     * the framing is outside the archive-time-stamp imprint.
     * </p>
     * <p>
     * The intended use is unsigned-attribute augmentation (e.g. attaching an
     * archive-time-stamp): because <code>digestAlgorithms</code> is copied
     * as-is, the replacement signers must not require digest algorithms beyond
     * those already present in the original message.
     * </p>
     * <p>
     * The output stream is returned unclosed.
     * </p>
     * @param original the signed data stream to be used as a base.
     * @param signerInformationStore the new signer information store to use.
     * @param out the stream to write the new signed data object to.
     * @return out.
     */
    public static OutputStream replaceSignersPreservingEncoding(
        InputStream             original,
        SignerInformationStore  signerInformationStore,
        OutputStream            out)
        throws CMSException, IOException
    {
        // raw walk of the input - the elements we preserve are copied at the
        // TLV level so chunking, length forms and element order all survive.
        boolean outerIndefinite = readDiscardedHeader(original, BERTags.CONSTRUCTED | BERTags.SEQUENCE, "ContentInfo");

        int tagHdr = readTag(original, "contentType");
        if (tagHdr != BERTags.OBJECT_IDENTIFIER)
        {
            throw new CMSException("contentType not found in ContentInfo");
        }
        ByteArrayOutputStream oidEnc = new ByteArrayOutputStream();
        copyTLV(tagHdr, original, oidEnc, COPY_DEPTH_LIMIT);
        if (!org.bouncycastle.util.Arrays.areEqual(oidEnc.toByteArray(), CMSObjectIdentifiers.signedData.getEncoded()))
        {
            throw new CMSException("not a CMS SignedData object");
        }

        boolean taggedIndefinite = readDiscardedHeader(original, BERTags.CONSTRUCTED | BERTags.CONTEXT_SPECIFIC | 0, "[0] content");
        boolean signedDataIndefinite = readDiscardedHeader(original, BERTags.CONSTRUCTED | BERTags.SEQUENCE, "SignedData");

        BERSequenceGenerator sGen = new BERSequenceGenerator(out);

        sGen.addObject(CMSObjectIdentifiers.signedData);

        BERSequenceGenerator sigGen = new BERSequenceGenerator(sGen.getRawOutputStream(), 0, true);

        OutputStream rawOut = sigGen.getRawOutputStream();

        // version - copied verbatim
        tagHdr = readTag(original, "version");
        if (tagHdr != BERTags.INTEGER)
        {
            throw new CMSException("version not found in SignedData");
        }
        copyTLV(tagHdr, original, rawOut, COPY_DEPTH_LIMIT);

        // digestAlgorithms - copied verbatim
        tagHdr = readTag(original, "digestAlgorithms");
        if (tagHdr != (BERTags.CONSTRUCTED | BERTags.SET))
        {
            throw new CMSException("digestAlgorithms not found in SignedData");
        }
        copyTLV(tagHdr, original, rawOut, COPY_DEPTH_LIMIT);

        // encapContentInfo - copied verbatim, streaming
        tagHdr = readTag(original, "encapContentInfo");
        if (tagHdr != (BERTags.CONSTRUCTED | BERTags.SEQUENCE))
        {
            throw new CMSException("encapContentInfo not found in SignedData");
        }
        copyTLV(tagHdr, original, rawOut, COPY_DEPTH_LIMIT);

        // optional certificates [0] and crls [1] - copied verbatim
        tagHdr = readTag(original, "signerInfos");
        if (tagHdr == (BERTags.CONSTRUCTED | BERTags.CONTEXT_SPECIFIC | 0))
        {
            copyTLV(tagHdr, original, rawOut, COPY_DEPTH_LIMIT);
            tagHdr = readTag(original, "signerInfos");
        }
        if (tagHdr == (BERTags.CONSTRUCTED | BERTags.CONTEXT_SPECIFIC | 1))
        {
            copyTLV(tagHdr, original, rawOut, COPY_DEPTH_LIMIT);
            tagHdr = readTag(original, "signerInfos");
        }

        // original signerInfos - skipped
        if (tagHdr != (BERTags.CONSTRUCTED | BERTags.SET))
        {
            throw new CMSException("signerInfos not found in SignedData");
        }
        copyTLV(tagHdr, original, DISCARD, COPY_DEPTH_LIMIT);

        // leave the input stream positioned at the end of the structure
        if (signedDataIndefinite)
        {
            readEndOfContents(original);
        }
        if (taggedIndefinite)
        {
            readEndOfContents(original);
        }
        if (outerIndefinite)
        {
            readEndOfContents(original);
        }

        // replacement signerInfos - store order, unsorted
        ASN1EncodableVector signerInfos = new ASN1EncodableVector();
        for (Iterator it = signerInformationStore.getSigners().iterator(); it.hasNext();)
        {
            SignerInformation        signer = (SignerInformation)it.next();

            signerInfos.add(signer.toASN1Structure());
        }

        sigGen.addObject(new DLSet(signerInfos));

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
        sigGen.addObject(signedData.getDigestAlgorithms());

        writeEncapContentInfoToGenerator(signedData, sigGen);

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
                sigGen.addObject(new DERTaggedObject(false, 0, asn1Certs));
            }
        }

        if (crls != null)
        {
            ASN1Set asn1Crls = CMSUtils.createBerSetFromList(CMSUtils.getCRLsFromStore(crls));

            if (asn1Crls.size() > 0)
            {
                sigGen.addObject(new DERTaggedObject(false, 1, asn1Crls));
            }
        }

        sigGen.addObject(signedData.getSignerInfos());

        sigGen.close();

        sGen.close();

        return out;
    }

    static void writeSetToGeneratorTagged(
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
                new BERTaggedObject(false, tagNo, asn1Set).encodeTo(asn1Gen.getRawOutputStream());
            }
            else
            {
                new DERTaggedObject(false, tagNo, asn1Set).encodeTo(asn1Gen.getRawOutputStream());
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

    // limit on indefinite-length nesting followed by the raw TLV copier,
    // mirroring the stream parser's default construction-depth limit.
    private static final int COPY_DEPTH_LIMIT = 64;

    private static final OutputStream DISCARD = new OutputStream()
    {
        public void write(int b)
        {
        }

        public void write(byte[] buf, int off, int len)
        {
        }
    };

    /**
     * Read the next identifier octet, failing with the name of the element
     * being looked for on end-of-stream.
     */
    private static int readTag(InputStream in, String element)
        throws IOException
    {
        int tagHdr = in.read();
        if (tagHdr < 0)
        {
            throw new EOFException("EOF found reading " + element);
        }
        return tagHdr;
    }

    /**
     * Read and discard the header (identifier and length octets) of an
     * element whose framing is being replaced, checking the identifier octet.
     *
     * @return true if the length was indefinite (an end-of-contents marker
     *         will follow the element's contents), false for definite.
     */
    private static boolean readDiscardedHeader(InputStream in, int expectedTagHdr, String element)
        throws IOException, CMSException
    {
        int tagHdr = readTag(in, element);
        if (tagHdr != expectedTagHdr)
        {
            throw new CMSException(element + " not found");
        }
        return copyLength(in, DISCARD) < 0;
    }

    /**
     * Copy one TLV, verbatim, from <code>in</code> to <code>out</code>.
     * The identifier octet has already been read and is passed in as
     * <code>tagHdr</code>. Definite lengths (including non-minimal length
     * octets) are copied through unchanged; indefinite-length elements are
     * copied by recursing over their child TLVs up to the end-of-contents
     * marker.
     */
    private static void copyTLV(int tagHdr, InputStream in, OutputStream out, int depth)
        throws IOException
    {
        out.write(tagHdr);

        if ((tagHdr & 0x1f) == 0x1f)
        {
            // high tag number - copy the continuation octets
            int b;
            do
            {
                b = readTag(in, "tag number");
                out.write(b);
            }
            while ((b & 0x80) != 0);
        }

        long length = copyLength(in, out);

        if (length >= 0)
        {
            copyContentOctets(length, in, out);
        }
        else
        {
            if (0 == (tagHdr & BERTags.CONSTRUCTED))
            {
                throw new IOException("indefinite-length primitive encoding encountered");
            }
            if (depth <= 0)
            {
                throw new IOException("maximum nested construction level reached");
            }

            for (;;)
            {
                int childHdr = readTag(in, "end-of-contents");
                if (childHdr == 0)
                {
                    if (in.read() != 0)
                    {
                        throw new IOException("malformed end-of-contents marker found");
                    }
                    out.write(0);
                    out.write(0);
                    return;
                }
                copyTLV(childHdr, in, out, depth - 1);
            }
        }
    }

    /**
     * Read one set of length octets, echoing them verbatim to
     * <code>out</code>.
     *
     * @return the definite length, or -1 for the indefinite-length method.
     */
    private static long copyLength(InputStream in, OutputStream out)
        throws IOException
    {
        int b = in.read();
        if (b < 0)
        {
            throw new EOFException("EOF found reading length");
        }
        out.write(b);

        if (b == 0x80)
        {
            return -1;
        }
        if (b <= 0x7f)
        {
            return b;
        }

        int octets = b & 0x7f;
        if (octets > 8)
        {
            throw new IOException("long form definite-length more than 63 bits");
        }

        long length = 0;
        for (int i = 0; i < octets; i++)
        {
            int next = in.read();
            if (next < 0)
            {
                throw new EOFException("EOF found reading length");
            }
            out.write(next);
            length = (length << 8) | next;
        }
        if (length < 0)
        {
            throw new IOException("long form definite-length more than 63 bits");
        }
        return length;
    }

    private static void copyContentOctets(long length, InputStream in, OutputStream out)
        throws IOException
    {
        byte[] buf = new byte[(int)Math.min(8192, Math.max(1, length))];
        long remaining = length;
        while (remaining > 0)
        {
            int numRead = in.read(buf, 0, (int)Math.min(buf.length, remaining));
            if (numRead < 0)
            {
                throw new EOFException("DEF length " + length + " object truncated by " + remaining);
            }
            out.write(buf, 0, numRead);
            remaining -= numRead;
        }
    }

    private static void readEndOfContents(InputStream in)
        throws IOException
    {
        int first = in.read();
        int second = in.read();
        if (first != 0 || second != 0)
        {
            throw new IOException("malformed end-of-contents marker found");
        }
    }

    static void writeEncapContentInfoToGenerator(SignedDataParser signedData, BERSequenceGenerator sigGen)
        throws IOException
    {
        // encap content info
        ContentInfoParser encapContentInfo = signedData.getEncapContentInfo();

        BERSequenceGenerator eiGen = new BERSequenceGenerator(sigGen.getRawOutputStream());
        eiGen.addObject(encapContentInfo.getContentType());

        pipeEncapsulatedOctetString(encapContentInfo, eiGen.getRawOutputStream());

        eiGen.close();
    }
}
