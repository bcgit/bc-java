package org.bouncycastle.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLGenerator;
import org.bouncycastle.asn1.DLOctetStringGenerator;
import org.bouncycastle.asn1.DLSequenceGenerator;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.util.io.TeeOutputStream;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;

/**
 * General class for generating a pkcs7-signature message stream.
 * <p>
 * A simple example of usage.
 * </p>
 * <pre>
 *      X509Certificate signCert = ...
 *      certList.add(signCert);
 *
 *      Store           certs = new JcaCertStore(certList);
 *      ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(signKP.getPrivate());
 *
 *      CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
 *
 *      gen.addSignerInfoGenerator(
 *                new JcaSignerInfoGeneratorBuilder(
 *                     new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
 *                     .build(sha1Signer, signCert));
 *
 *      gen.addCertificates(certs);
 *
 *      OutputStream sigOut = gen.open(bOut);
 *
 *      sigOut.write("Hello World!".getBytes());
 *
 *      sigOut.close();
 * </pre>
 * <p>
 * <b>Stream handling note:</b>
 * <ul>
 *   <li>The returned OutputStream must be closed to finalize the CMS structure
 *       (write certificates, CRLs, signer infos).</li>
 *   <li>Closing the returned stream <b>does not close</b> the underlying OutputStream
 *       passed to {@code open()}.</li>
 *   <li>Callers are responsible for closing the underlying OutputStream separately.</li>
 * </ul>
 */
public class CMSSignedDataStreamGenerator
    extends CMSSignedGenerator
{
    private int _bufferSize;

    /**
     * base constructor
     */
    public CMSSignedDataStreamGenerator()
    {
    }

    /**
     * base constructor with a custom DigestAlgorithmIdentifierFinder
     */
    public CMSSignedDataStreamGenerator(DigestAlgorithmIdentifierFinder digestAlgIdFinder)
    {
        super(digestAlgIdFinder);
    }

    /**
     * Set the underlying string size for encapsulated data
     *
     * @param bufferSize length of octet strings to buffer the data.
     */
    public void setBufferSize(
        int bufferSize)
    {
        _bufferSize = bufferSize;
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider.
     */
    public OutputStream open(
        OutputStream out)
        throws IOException
    {
        return open(out, false);
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature with the
     * default content type "data".
     */
    public OutputStream open(
        OutputStream out,
        boolean encapsulate)
        throws IOException
    {
        return open(CMSObjectIdentifiers.data, out, encapsulate);
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature with the
     * default content type "data". If dataOutputStream is non null the data
     * being signed will be written to the stream as it is processed.
     *
     * @param out              stream the CMS object is to be written to.
     * @param encapsulate      true if data should be encapsulated.
     * @param dataOutputStream output stream to copy the data being signed to.
     */
    public OutputStream open(
        OutputStream out,
        boolean encapsulate,
        OutputStream dataOutputStream)
        throws IOException
    {
        return open(CMSObjectIdentifiers.data, out, encapsulate, dataOutputStream);
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature. The content type
     * is set according to the OID represented by the string signedContentType.
     */
    public OutputStream open(
        ASN1ObjectIdentifier eContentType,
        OutputStream out,
        boolean encapsulate)
        throws IOException
    {
        return open(eContentType, out, encapsulate, null);
    }

    /**
     * Open an OutputStream that in closing will generate a signed object
     * for a CMS Signed Data object - if encapsulate is true a copy
     * of the message will be included in the signature. The content type
     * is set according to the OID represented by the string signedContentType.
     *
     * @param eContentType     OID for data to be signed.
     * @param out              stream the CMS object is to be written to.
     * @param encapsulate      true if data should be encapsulated.
     * @param dataOutputStream output stream to copy the data being signed to.
     */
    public OutputStream open(
        ASN1ObjectIdentifier eContentType,
        OutputStream out,
        boolean encapsulate,
        OutputStream dataOutputStream)
        throws IOException
    {
        // TODO
//        if (_signerInfs.isEmpty())
//        {
//            /* RFC 3852 5.2
//             * "In the degenerate case where there are no signers, the
//             * EncapsulatedContentInfo value being "signed" is irrelevant.  In this
//             * case, the content type within the EncapsulatedContentInfo value being
//             * "signed" MUST be id-data (as defined in section 4), and the content
//             * field of the EncapsulatedContentInfo value MUST be omitted."
//             */
//            if (encapsulate)
//            {
//                throw new IllegalArgumentException("no signers, encapsulate must be false");
//            }
//            if (!DATA.equals(eContentType))
//            {
//                throw new IllegalArgumentException("no signers, eContentType must be id-data");
//            }
//        }
//
//        if (!DATA.equals(eContentType))
//        {
//            /* RFC 3852 5.3
//             * [The 'signedAttrs']...
//             * field is optional, but it MUST be present if the content type of
//             * the EncapsulatedContentInfo value being signed is not id-data.
//             */
//            // TODO signedAttrs must be present for all signers
//        }


        Set<AlgorithmIdentifier> digestAlgs = new HashSet<AlgorithmIdentifier>();
        digestAlgs.addAll(extraDigestAlgorithms);

        //
        // add the precalculated SignerInfo digest algorithms.
        //
        for (Iterator it = _signers.iterator(); it.hasNext(); )
        {
            SignerInformation signer = (SignerInformation)it.next();

            CMSUtils.addDigestAlgs(digestAlgs, signer, digestAlgIdFinder);
        }

        //
        // add the new digests
        //
        for (Iterator it = signerGens.iterator(); it.hasNext(); )
        {
            SignerInfoGenerator signerGen = (SignerInfoGenerator)it.next();
            digestAlgs.add(CMSSignedHelper.INSTANCE.fixDigestAlgID(signerGen.getDigestAlgorithm(), digestAlgIdFinder));
        }

        if (ASN1Encoding.BER.equals(encoding))
        {
            // ContentInfo
            BERSequenceGenerator sGen = new BERSequenceGenerator(out);
            sGen.addObject(CMSObjectIdentifiers.signedData);

            // SignedData
            BERSequenceGenerator sigGen = new BERSequenceGenerator(sGen.getRawOutputStream(), 0, true);
            sigGen.addObject(calculateVersion(eContentType));

            sigGen.addObject(CMSUtils.convertToDlSet(digestAlgs));

            // EncapsulatedContentInfo
            BERSequenceGenerator eciGen = new BERSequenceGenerator(sigGen.getRawOutputStream());
            eciGen.addObject(eContentType);

            // eContent [0] EXPLICIT OCTET STRING OPTIONAL
            OutputStream ecStream = encapsulate
                ? CMSUtils.createBEROctetOutputStream(eciGen.getRawOutputStream(), 0, true, _bufferSize)
                : null;

            // Also send the data to 'dataOutputStream' if necessary
            OutputStream contentStream = CMSUtils.getSafeTeeOutputStream(dataOutputStream, ecStream);

            // Let all the signers see the data as it is written
            OutputStream sigStream = CMSUtils.attachSignersToOutputStream(signerGens, contentStream);

            return new CmsSignedDataOutputStream(sigStream, eContentType, sGen, sigGen, eciGen);
        }
        else
        {
            // ContentInfo
            ASN1EncodableVector sGen = new ASN1EncodableVector();
            sGen.add(CMSObjectIdentifiers.signedData);

            // SignedData
            ASN1EncodableVector sigGen = new ASN1EncodableVector();
            sigGen.add(calculateVersion(eContentType));

            sigGen.add(CMSUtils.convertToDlSet(digestAlgs));

            // EncapsulatedContentInfo
            ASN1EncodableVector eciGen = new ASN1EncodableVector();
            eciGen.add(eContentType);

            // eContent [0] EXPLICIT OCTET STRING OPTIONAL
            ByteArrayOutputStream ecStream = encapsulate
                ? new ByteArrayOutputStream()
                : null;

            // Also send the data to 'dataOutputStream' if necessary
            OutputStream contentStream = CMSUtils.getSafeTeeOutputStream(dataOutputStream, ecStream);

            // Let all the signers see the data as it is written
            OutputStream sigStream = CMSUtils.attachSignersToOutputStream(signerGens, contentStream);

            return new CmsDLSignedDataOutputStream(sigStream, eContentType, sigGen, eciGen, ecStream, out);
        }
    }

    /**
     * Generate a definite-length signed object with encapsulated content of
     * exactly {@code contentLength} octets, the content type marked as DATA.
     * See {@link #open(ASN1ObjectIdentifier, OutputStream, long, OutputStream)}.
     */
    public OutputStream open(OutputStream out, long contentLength)
        throws CMSException, IOException
    {
        return open(CMSObjectIdentifiers.data, out, contentLength, null);
    }

    /**
     * Generate a definite-length signed object with encapsulated content of
     * exactly {@code contentLength} octets.
     * See {@link #open(ASN1ObjectIdentifier, OutputStream, long, OutputStream)}.
     */
    public OutputStream open(ASN1ObjectIdentifier eContentType, OutputStream out, long contentLength)
        throws CMSException, IOException
    {
        return open(eContentType, out, contentLength, null);
    }

    /**
     * Generate a definite-length (DL or DER, per {@link #setEncoding(String)})
     * signed object with encapsulated content of exactly {@code contentLength}
     * octets, in a single pass with nothing buffered - so the content may
     * exceed the size of a Java array.
     * <p>
     * The SignerInfos trail the content in the encoding but their length feeds
     * the enclosing headers, which are written before any content flows. Every
     * {@link SignerInfoGenerator} must therefore be able to pre-commit its
     * encoded SignerInfo length (see
     * {@link SignerInfoGenerator#getPredictedEncodedLength}): the underlying
     * signer has to implement
     * {@link org.bouncycastle.operator.FixedLengthContentSigner} - RSA,
     * Ed25519/Ed448 and ML-DSA qualify; DER-encoded ECDSA/DSA do not - and any
     * attribute generators must be length-stable. Exactly {@code contentLength}
     * octets must then be written to the returned stream; any mismatch,
     * including a SignerInfo coming out at other than its predicted length,
     * fails with an IOException, by which point the output is unusable and
     * must be discarded.
     *
     * @param eContentType     the type of the data being written to the object.
     * @param out              stream the CMS object is to be written to.
     * @param contentLength    the exact number of content octets that will be written.
     * @param dataOutputStream output stream to copy the content to as it is processed (may be null).
     */
    public OutputStream open(ASN1ObjectIdentifier eContentType, OutputStream out, long contentLength,
        OutputStream dataOutputStream)
        throws CMSException, IOException
    {
        if (ASN1Encoding.BER.equals(encoding))
        {
            throw new CMSException(
                "single-pass definite-length encoding requires setEncoding(\"DL\") or setEncoding(\"DER\")");
        }
        if (contentLength < 0)
        {
            throw new CMSException("contentLength cannot be negative");
        }

        boolean der = ASN1Encoding.DER.equals(encoding);
        String enc = der ? ASN1Encoding.DER : ASN1Encoding.DL;

        Set<AlgorithmIdentifier> digestAlgs = new HashSet<AlgorithmIdentifier>();
        digestAlgs.addAll(extraDigestAlgorithms);
        for (Iterator it = _signers.iterator(); it.hasNext(); )
        {
            CMSUtils.addDigestAlgs(digestAlgs, (SignerInformation)it.next(), digestAlgIdFinder);
        }
        for (Iterator it = signerGens.iterator(); it.hasNext(); )
        {
            digestAlgs.add(CMSSignedHelper.INSTANCE.fixDigestAlgID(((SignerInfoGenerator)it.next()).getDigestAlgorithm(), digestAlgIdFinder));
        }

        // every SignerInfo's encoded length must be committed before the
        // headers are written.
        long siBody = 0;
        for (Iterator it = signerGens.iterator(); it.hasNext(); )
        {
            SignerInfoGenerator signerGen = (SignerInfoGenerator)it.next();
            long predicted = signerGen.getPredictedEncodedLength(eContentType);
            if (predicted < 0)
            {
                throw new CMSException("signer for " + signerGen.getDigestAlgorithm().getAlgorithm()
                    + " cannot pre-commit a fixed-length SignerInfo - signature length or attributes"
                    + " are not predictable; use the two-pass generate() or BER encoding");
            }
            siBody += predicted;
        }
        for (Iterator it = _signers.iterator(); it.hasNext(); )
        {
            siBody += ((SignerInformation)it.next()).toASN1Structure().getEncoded(enc).length;
        }

        // pre-encode everything other than the content; these all stay small.
        byte[] contentOid = CMSObjectIdentifiers.signedData.getEncoded(enc);
        byte[] versionEnc = calculateVersion(eContentType).getEncoded(enc);
        ASN1EncodableVector digestVec = new ASN1EncodableVector();
        for (Iterator it = digestAlgs.iterator(); it.hasNext(); )
        {
            digestVec.add((AlgorithmIdentifier)it.next());
        }
        byte[] digestSetEnc = (der ? (ASN1Set)new DERSet(digestVec) : new DLSet(digestVec)).getEncoded(enc);
        byte[] eContentTypeEnc = eContentType.getEncoded(enc);
        byte[] certsEnc = null;
        if (certs.size() != 0)
        {
            ASN1Set certSet = der ? CMSUtils.createDerSetFromList(certs) : CMSUtils.createDlSetFromList(certs);
            certsEnc = new DLTaggedObject(false, 0, certSet).getEncoded(enc);
        }
        byte[] crlsEnc = null;
        if (crls.size() != 0)
        {
            ASN1Set crlSet = der ? CMSUtils.createDerSetFromList(crls) : CMSUtils.createDlSetFromList(crls);
            crlsEnc = new DLTaggedObject(false, 1, crlSet).getEncoded(enc);
        }

        // bottom-up length arithmetic for the enclosing headers.
        long ecTLV = DLGenerator.getDLEncodingLength(DLGenerator.getDLEncodingLength(contentLength));   // [0] EXPLICIT OCTET STRING
        long eciBody = eContentTypeEnc.length + ecTLV;
        long eciTLV = DLGenerator.getDLEncodingLength(eciBody);
        long siTLV = DLGenerator.getDLEncodingLength(siBody);       // signerInfos SET
        long sdBody = versionEnc.length + digestSetEnc.length + eciTLV
            + (certsEnc != null ? certsEnc.length : 0)
            + (crlsEnc != null ? crlsEnc.length : 0)
            + siTLV;
        long sdTLV = DLGenerator.getDLEncodingLength(sdBody);
        long taggedTLV = DLGenerator.getDLEncodingLength(sdTLV);    // [0] EXPLICIT
        long ciBody = contentOid.length + taggedTLV;

        // ContentInfo
        DLSequenceGenerator ciGen = new DLSequenceGenerator(out, ciBody);
        ciGen.getRawOutputStream().write(contentOid);

        // SignedData, [0] EXPLICIT
        DLSequenceGenerator sdGen = new DLSequenceGenerator(ciGen.getRawOutputStream(), 0, true, sdBody);
        OutputStream sdRaw = sdGen.getRawOutputStream();
        sdRaw.write(versionEnc);
        sdRaw.write(digestSetEnc);

        // EncapsulatedContentInfo
        DLSequenceGenerator eciGen = new DLSequenceGenerator(sdRaw, eciBody);
        eciGen.getRawOutputStream().write(eContentTypeEnc);

        // eContent [0] EXPLICIT OCTET STRING - primitive, definite length.
        DLOctetStringGenerator octGen = new DLOctetStringGenerator(eciGen.getRawOutputStream(), 0, true, contentLength);

        // Also send the data to 'dataOutputStream' if necessary
        OutputStream contentStream = CMSUtils.getSafeTeeOutputStream(dataOutputStream, octGen.getOctetOutputStream());

        // Let all the signers see the data as it is written
        OutputStream sigStream = CMSUtils.attachSignersToOutputStream(signerGens, contentStream);

        return new CmsDLSinglePassSignedDataOutputStream(
            sigStream, eContentType, der, octGen, eciGen, sdGen, ciGen, certsEnc, crlsEnc);
    }

    /**
     * Write a definite-length (DL or DER, per {@link #setEncoding(String)})
     * signed object with encapsulated content in two passes over the supplied
     * content, with nothing buffered - so the content may exceed the size of a
     * Java array, and no length needs to be known in advance.
     * <p>
     * Pass one streams the content through the signers' digest calculators
     * and computes every signature, so all lengths are exact - unlike the
     * single-pass {@link #open(OutputStream, long)} this works with
     * variable-length signature algorithms such as DER-encoded ECDSA. Pass two
     * writes the structure, re-reading the content from {@code content} -
     * which must therefore be re-readable (e.g. file-backed) and stable: the
     * second pass is re-digested and compared against the first, so a source
     * that changed between passes fails with an IOException rather than
     * producing a structure whose signatures don't verify.
     *
     * @param content the content to sign and encapsulate; {@code write} is invoked twice.
     * @param out     stream the CMS object is to be written to.
     */
    public void generate(CMSTypedData content, OutputStream out)
        throws CMSException, IOException
    {
        if (ASN1Encoding.BER.equals(encoding))
        {
            throw new CMSException(
                "two-pass definite-length encoding requires setEncoding(\"DL\") or setEncoding(\"DER\")");
        }

        boolean der = ASN1Encoding.DER.equals(encoding);
        String enc = der ? ASN1Encoding.DER : ASN1Encoding.DL;
        ASN1ObjectIdentifier eContentType = content.getContentType();

        Set<AlgorithmIdentifier> digestAlgs = new HashSet<AlgorithmIdentifier>();
        digestAlgs.addAll(extraDigestAlgorithms);
        for (Iterator it = _signers.iterator(); it.hasNext(); )
        {
            CMSUtils.addDigestAlgs(digestAlgs, (SignerInformation)it.next(), digestAlgIdFinder);
        }
        for (Iterator it = signerGens.iterator(); it.hasNext(); )
        {
            digestAlgs.add(CMSSignedHelper.INSTANCE.fixDigestAlgID(((SignerInfoGenerator)it.next()).getDigestAlgorithm(), digestAlgIdFinder));
        }

        //
        // pass one: digest (and, for direct signers, sign) the content.
        //
        CountingOutputStream passOne = new CountingOutputStream(
            CMSUtils.getSafeOutputStream(CMSUtils.attachSignersToOutputStream(signerGens, null)));
        content.write(passOne);
        passOne.close();
        long contentLength = passOne.getCount();

        digests.clear();    // clear the current preserved digest state

        ASN1EncodableVector signerInfos = new ASN1EncodableVector();
        for (Iterator it = signerGens.iterator(); it.hasNext(); )
        {
            SignerInfoGenerator sigGen = (SignerInfoGenerator)it.next();

            signerInfos.add(sigGen.generate(eContentType));

            digests.put(sigGen.getDigestAlgorithm().getAlgorithm().getId(), sigGen.getCalculatedDigest());
        }
        for (Iterator it = _signers.iterator(); it.hasNext(); )
        {
            signerInfos.add(((SignerInformation)it.next()).toASN1Structure());
        }

        // every length is now exact.
        byte[] siSetEnc = (der ? (ASN1Set)new DERSet(signerInfos) : new DLSet(signerInfos)).getEncoded(enc);

        byte[] contentOid = CMSObjectIdentifiers.signedData.getEncoded(enc);
        byte[] versionEnc = calculateVersion(eContentType).getEncoded(enc);
        ASN1EncodableVector digestVec = new ASN1EncodableVector();
        for (Iterator it = digestAlgs.iterator(); it.hasNext(); )
        {
            digestVec.add((AlgorithmIdentifier)it.next());
        }
        byte[] digestSetEnc = (der ? (ASN1Set)new DERSet(digestVec) : new DLSet(digestVec)).getEncoded(enc);
        byte[] eContentTypeEnc = eContentType.getEncoded(enc);
        byte[] certsEnc = null;
        if (certs.size() != 0)
        {
            ASN1Set certSet = der ? CMSUtils.createDerSetFromList(certs) : CMSUtils.createDlSetFromList(certs);
            certsEnc = new DLTaggedObject(false, 0, certSet).getEncoded(enc);
        }
        byte[] crlsEnc = null;
        if (crls.size() != 0)
        {
            ASN1Set crlSet = der ? CMSUtils.createDerSetFromList(crls) : CMSUtils.createDlSetFromList(crls);
            crlsEnc = new DLTaggedObject(false, 1, crlSet).getEncoded(enc);
        }

        long ecTLV = DLGenerator.getDLEncodingLength(DLGenerator.getDLEncodingLength(contentLength));
        long eciBody = eContentTypeEnc.length + ecTLV;
        long eciTLV = DLGenerator.getDLEncodingLength(eciBody);
        long sdBody = versionEnc.length + digestSetEnc.length + eciTLV
            + (certsEnc != null ? certsEnc.length : 0)
            + (crlsEnc != null ? crlsEnc.length : 0)
            + siSetEnc.length;
        long sdTLV = DLGenerator.getDLEncodingLength(sdBody);
        long taggedTLV = DLGenerator.getDLEncodingLength(sdTLV);
        long ciBody = contentOid.length + taggedTLV;

        //
        // pass two: write the structure, re-reading and re-digesting the content.
        //
        DLSequenceGenerator ciGen = new DLSequenceGenerator(out, ciBody);
        ciGen.getRawOutputStream().write(contentOid);

        DLSequenceGenerator sdGen = new DLSequenceGenerator(ciGen.getRawOutputStream(), 0, true, sdBody);
        OutputStream sdRaw = sdGen.getRawOutputStream();
        sdRaw.write(versionEnc);
        sdRaw.write(digestSetEnc);

        DLSequenceGenerator eciGen = new DLSequenceGenerator(sdRaw, eciBody);
        eciGen.getRawOutputStream().write(eContentTypeEnc);

        DLOctetStringGenerator octGen = new DLOctetStringGenerator(eciGen.getRawOutputStream(), 0, true, contentLength);

        // tee the second pass back through the signers' digest calculators
        // (getDigest() resets them, in both the JCA and lightweight
        // implementations) so a source that changed between passes is caught.
        OutputStream verifyStream = octGen.getOctetOutputStream();
        for (Iterator it = signerGens.iterator(); it.hasNext(); )
        {
            SignerInfoGenerator sigGen = (SignerInfoGenerator)it.next();
            if (sigGen.getDigester() != null)
            {
                verifyStream = new TeeOutputStream(verifyStream, sigGen.getDigester().getOutputStream());
            }
        }

        content.write(verifyStream);
        verifyStream.close();
        octGen.close();     // verifies pass two produced the pass-one octet count

        for (Iterator it = signerGens.iterator(); it.hasNext(); )
        {
            SignerInfoGenerator sigGen = (SignerInfoGenerator)it.next();
            if (sigGen.getDigester() != null)
            {
                if (!org.bouncycastle.util.Arrays.areEqual(sigGen.getCalculatedDigest(), sigGen.getDigester().getDigest()))
                {
                    throw new IOException("content changed between passes");
                }
            }
        }

        eciGen.close();
        if (certsEnc != null)
        {
            sdRaw.write(certsEnc);
        }
        if (crlsEnc != null)
        {
            sdRaw.write(crlsEnc);
        }
        sdRaw.write(siSetEnc);
        sdGen.close();
        ciGen.close();
    }

    private static class CountingOutputStream
        extends OutputStream
    {
        private final OutputStream _target;
        private long _count = 0;

        CountingOutputStream(OutputStream target)
        {
            _target = target;
        }

        public void write(int b)
            throws IOException
        {
            _target.write(b);
            _count++;
        }

        public void write(byte[] buf, int off, int len)
            throws IOException
        {
            _target.write(buf, off, len);
            _count += len;
        }

        public void close()
            throws IOException
        {
            _target.close();
        }

        long getCount()
        {
            return _count;
        }
    }

    /**
     * Return a list of the current Digest AlgorithmIdentifiers applying to the next signature.
     *
     * @return a list of the Digest AlgorithmIdentifiers
     */
    public List<AlgorithmIdentifier> getDigestAlgorithms()
    {
        List digestAlorithms = new ArrayList();

        //
        // add the precalculated SignerInfo digest algorithms.
        //
        for (Iterator it = _signers.iterator(); it.hasNext(); )
        {
            SignerInformation signer = (SignerInformation)it.next();
            AlgorithmIdentifier digAlg = CMSSignedHelper.INSTANCE.fixDigestAlgID(signer.getDigestAlgorithmID(), digestAlgIdFinder);

            digestAlorithms.add(digAlg);
        }

        //
        // add the new digests
        //

        for (Iterator it = signerGens.iterator(); it.hasNext(); )
        {
            SignerInfoGenerator signerGen = (SignerInfoGenerator)it.next();

            digestAlorithms.add(signerGen.getDigestAlgorithm());
        }

        return digestAlorithms;
    }

    // RFC3852, section 5.1:
    // IF ((certificates is present) AND
    //    (any certificates with a type of other are present)) OR
    //    ((crls is present) AND
    //    (any crls with a type of other are present))
    // THEN version MUST be 5
    // ELSE
    //    IF (certificates is present) AND
    //       (any version 2 attribute certificates are present)
    //    THEN version MUST be 4
    //    ELSE
    //       IF ((certificates is present) AND
    //          (any version 1 attribute certificates are present)) OR
    //          (any SignerInfo structures are version 3) OR
    //          (encapContentInfo eContentType is other than id-data)
    //       THEN version MUST be 3
    //       ELSE version MUST be 1
    //
    private ASN1Integer calculateVersion(
        ASN1ObjectIdentifier contentOid)
    {
        boolean otherCert = false;
        boolean otherCrl = false;
        boolean attrCertV1Found = false;
        boolean attrCertV2Found = false;

        if (certs != null)
        {
            for (Iterator it = certs.iterator(); it.hasNext(); )
            {
                Object obj = it.next();
                if (obj instanceof ASN1TaggedObject)
                {
                    ASN1TaggedObject tagged = (ASN1TaggedObject)obj;

                    if (tagged.getTagNo() == 1)
                    {
                        attrCertV1Found = true;
                    }
                    else if (tagged.getTagNo() == 2)
                    {
                        attrCertV2Found = true;
                    }
                    else if (tagged.getTagNo() == 3)
                    {
                        otherCert = true;
                    }
                }
            }
        }

        if (otherCert)
        {
            return ASN1Integer.FIVE;
        }

        if (crls != null)         // no need to check if otherCert is true
        {
            for (Iterator it = crls.iterator(); it.hasNext(); )
            {
                Object obj = it.next();
                if (obj instanceof ASN1TaggedObject)
                {
                    otherCrl = true;
                }
            }
        }

        if (otherCrl)
        {
            return ASN1Integer.FIVE;
        }

        if (attrCertV2Found)
        {
            return ASN1Integer.FOUR;
        }

        if (attrCertV1Found)
        {
            return ASN1Integer.THREE;
        }

        if (checkForVersion3(_signers, signerGens))
        {
            return ASN1Integer.THREE;
        }

        if (!CMSObjectIdentifiers.data.equals(contentOid))
        {
            return ASN1Integer.THREE;
        }

        return ASN1Integer.ONE;
    }

    private static boolean checkForVersion3(List signerInfos, List signerInfoGens)
    {
        for (Iterator it = signerInfos.iterator(); it.hasNext(); )
        {
            SignerInfo s = ((SignerInformation)it.next()).toASN1Structure();

            if (s.getVersion().hasValue(3))
            {
                return true;
            }
        }

        for (Iterator it = signerInfoGens.iterator(); it.hasNext(); )
        {
            SignerInfoGenerator s = (SignerInfoGenerator)it.next();

            if (s.getGeneratedVersion() == 3)
            {
                return true;
            }
        }

        return false;
    }

    private class CmsSignedDataOutputStream
        extends OutputStream
    {
        private OutputStream _out;
        private ASN1ObjectIdentifier _contentOID;
        private BERSequenceGenerator _sGen;
        private BERSequenceGenerator _sigGen;
        private BERSequenceGenerator _eiGen;

        public CmsSignedDataOutputStream(
            OutputStream out,
            ASN1ObjectIdentifier contentOID,
            BERSequenceGenerator sGen,
            BERSequenceGenerator sigGen,
            BERSequenceGenerator eiGen)
        {
            _out = out;
            _contentOID = contentOID;
            _sGen = sGen;
            _sigGen = sigGen;
            _eiGen = eiGen;
        }

        public void write(
            int b)
            throws IOException
        {
            _out.write(b);
        }

        public void write(
            byte[] bytes,
            int off,
            int len)
            throws IOException
        {
            _out.write(bytes, off, len);
        }

        public void write(
            byte[] bytes)
            throws IOException
        {
            _out.write(bytes);
        }

        public void close()
            throws IOException
        {
            _out.close();
            _eiGen.close();

            digests.clear();    // clear the current preserved digest state

            if (certs.size() != 0)
            {
                ASN1Set certSet = CMSUtils.createBerSetFromList(certs);

                _sigGen.addObject(new BERTaggedObject(false, 0, certSet));
            }

            if (crls.size() != 0)
            {
                ASN1Set crlSet = CMSUtils.createBerSetFromList(crls);

                _sigGen.addObject(new BERTaggedObject(false, 1, crlSet));
            }

            //
            // collect all the SignerInfo objects
            //
            ASN1EncodableVector signerInfos = new ASN1EncodableVector();

            //
            // add the generated SignerInfo objects
            //

            for (Iterator it = signerGens.iterator(); it.hasNext(); )
            {
                SignerInfoGenerator sigGen = (SignerInfoGenerator)it.next();


                try
                {
                    signerInfos.add(sigGen.generate(_contentOID));

                    byte[] calculatedDigest = sigGen.getCalculatedDigest();

                    digests.put(sigGen.getDigestAlgorithm().getAlgorithm().getId(), calculatedDigest);
                }
                catch (CMSException e)
                {
                    throw new CMSStreamException("exception generating signers: " + e.getMessage(), e);
                }
            }

            //
            // add the precalculated SignerInfo objects
            //
            {
                Iterator it = _signers.iterator();
                while (it.hasNext())
                {
                    SignerInformation signer = (SignerInformation)it.next();

                    // TODO Verify the content type and calculated digest match the precalculated SignerInfo
//                    if (!signer.getContentType().equals(_contentOID))
//                    {
//                        // TODO The precalculated content type did not match - error?
//                    }
//                    
//                    byte[] calculatedDigest = (byte[])_digests.get(signer.getDigestAlgOID());
//                    if (calculatedDigest == null)
//                    {
//                        // TODO We can't confirm this digest because we didn't calculate it - error?
//                    }
//                    else
//                    {
//                        if (!Arrays.areEqual(signer.getContentDigest(), calculatedDigest))
//                        {
//                            // TODO The precalculated digest did not match - error?
//                        }
//                    }

                    signerInfos.add(signer.toASN1Structure());
                }
            }

            _sigGen.addObject(new DLSet(signerInfos));

            _sigGen.close();
            _sGen.close();
        }
    }

    private class CmsDLSinglePassSignedDataOutputStream
        extends OutputStream
    {
        private final OutputStream _out;
        private final ASN1ObjectIdentifier _contentOID;
        private final boolean _der;
        private final DLOctetStringGenerator _octGen;
        private final DLSequenceGenerator _eciGen;
        private final DLSequenceGenerator _sdGen;
        private final DLSequenceGenerator _ciGen;
        private final byte[] _certsEnc;
        private final byte[] _crlsEnc;

        CmsDLSinglePassSignedDataOutputStream(
            OutputStream out,
            ASN1ObjectIdentifier contentOID,
            boolean der,
            DLOctetStringGenerator octGen,
            DLSequenceGenerator eciGen,
            DLSequenceGenerator sdGen,
            DLSequenceGenerator ciGen,
            byte[] certsEnc,
            byte[] crlsEnc)
        {
            _out = out;
            _contentOID = contentOID;
            _der = der;
            _octGen = octGen;
            _eciGen = eciGen;
            _sdGen = sdGen;
            _ciGen = ciGen;
            _certsEnc = certsEnc;
            _crlsEnc = crlsEnc;
        }

        public void write(int b)
            throws IOException
        {
            _out.write(b);
        }

        public void write(byte[] bytes, int off, int len)
            throws IOException
        {
            _out.write(bytes, off, len);
        }

        public void write(byte[] bytes)
            throws IOException
        {
            _out.write(bytes);
        }

        public void close()
            throws IOException
        {
            _out.close();
            _octGen.close();    // verifies the declared content length
            _eciGen.close();

            digests.clear();    // clear the current preserved digest state

            OutputStream sdRaw = _sdGen.getRawOutputStream();
            if (_certsEnc != null)
            {
                sdRaw.write(_certsEnc);
            }
            if (_crlsEnc != null)
            {
                sdRaw.write(_crlsEnc);
            }

            //
            // collect all the SignerInfo objects
            //
            ASN1EncodableVector signerInfos = new ASN1EncodableVector();

            for (Iterator it = signerGens.iterator(); it.hasNext(); )
            {
                SignerInfoGenerator sigGen = (SignerInfoGenerator)it.next();

                try
                {
                    signerInfos.add(sigGen.generate(_contentOID));

                    digests.put(sigGen.getDigestAlgorithm().getAlgorithm().getId(), sigGen.getCalculatedDigest());
                }
                catch (CMSException e)
                {
                    throw new CMSStreamException("exception generating signers: " + e.getMessage(), e);
                }
            }

            for (Iterator it = _signers.iterator(); it.hasNext(); )
            {
                signerInfos.add(((SignerInformation)it.next()).toASN1Structure());
            }

            // a SignerInfo coming out at other than its predicted length fails
            // the enclosing length enforcement here.
            ASN1Set siSet = _der ? (ASN1Set)new DERSet(signerInfos) : (ASN1Set)new DLSet(signerInfos);
            sdRaw.write(siSet.getEncoded(_der ? ASN1Encoding.DER : ASN1Encoding.DL));

            _sdGen.close();
            _ciGen.close();
        }
    }

    private class CmsDLSignedDataOutputStream
        extends OutputStream
    {
        private OutputStream _out;
        private ASN1ObjectIdentifier _contentOID;
        private ASN1EncodableVector _sigGen;
        private ASN1EncodableVector _eiGen;
        private ByteArrayOutputStream _ecStream;
        private OutputStream _output;

        public CmsDLSignedDataOutputStream(
            OutputStream out,
            ASN1ObjectIdentifier contentOID,
            ASN1EncodableVector sigGen,
            ASN1EncodableVector eiGen,
            ByteArrayOutputStream ecStream,
            OutputStream output)
        {
            _out = out;
            _contentOID = contentOID;
            _sigGen = sigGen;
            _eiGen = eiGen;
            _ecStream = ecStream;
            _output = output;
        }

        public void write(
            int b)
            throws IOException
        {
            _out.write(b);
        }

        public void write(
            byte[] bytes,
            int off,
            int len)
            throws IOException
        {
            _out.write(bytes, off, len);
        }

        public void write(
            byte[] bytes)
            throws IOException
        {
            _out.write(bytes);
        }

        public void close()
            throws IOException
        {
            _out.close();
            if (_ecStream != null)
            {
                _eiGen.add(new DERTaggedObject(true, 0, new DEROctetString(_ecStream.toByteArray())));
            }
            
            digests.clear();    // clear the current preserved digest state

            _sigGen.add(new DLSequence(_eiGen));

            boolean isDER = ASN1Encoding.DER.equals(encoding);

            if (certs.size() != 0)
            {
                ASN1Set certSet = isDER ? CMSUtils.createDerSetFromList(certs) : CMSUtils.createDlSetFromList(certs);

                _sigGen.add(new DERTaggedObject(false, 0, certSet));
            }

            if (crls.size() != 0)
            {
                ASN1Set crlSet = isDER ? CMSUtils.createDerSetFromList(crls) : CMSUtils.createDlSetFromList(crls);

                _sigGen.add(new DERTaggedObject(false, 1, crlSet));
            }

            //
            // collect all the SignerInfo objects
            //
            ASN1EncodableVector signerInfos = new ASN1EncodableVector();

            //
            // add the generated SignerInfo objects
            //

            for (Iterator it = signerGens.iterator(); it.hasNext(); )
            {
                SignerInfoGenerator sigGen = (SignerInfoGenerator)it.next();

                try
                {
                    signerInfos.add(sigGen.generate(_contentOID));

                    byte[] calculatedDigest = sigGen.getCalculatedDigest();

                    digests.put(sigGen.getDigestAlgorithm().getAlgorithm().getId(), calculatedDigest);
                }
                catch (CMSException e)
                {
                    throw new CMSStreamException("exception generating signers: " + e.getMessage(), e);
                }
            }

            //
            // add the precalculated SignerInfo objects
            //
            {
                Iterator it = _signers.iterator();
                while (it.hasNext())
                {
                    SignerInformation signer = (SignerInformation)it.next();

                    // TODO Verify the content type and calculated digest match the precalculated SignerInfo
                    //                    if (!signer.getContentType().equals(_contentOID))
                    //                    {
                    //                        // TODO The precalculated content type did not match - error?
                    //                    }
                    //
                    //                    byte[] calculatedDigest = (byte[])_digests.get(signer.getDigestAlgOID());
                    //                    if (calculatedDigest == null)
                    //                    {
                    //                        // TODO We can't confirm this digest because we didn't calculate it - error?
                    //                    }
                    //                    else
                    //                    {
                    //                        if (!Arrays.areEqual(signer.getContentDigest(), calculatedDigest))
                    //                        {
                    //                            // TODO The precalculated digest did not match - error?
                    //                        }
                    //                    }

                    signerInfos.add(signer.toASN1Structure());
                }
            }

            _sigGen.add(isDER ? (ASN1Set)new DERSet(signerInfos) : (ASN1Set)new DLSet(signerInfos));

            ContentInfo content = new ContentInfo(CMSObjectIdentifiers.signedData, new DLSequence(_sigGen));

            _output.write(content.getEncoded(encoding));
        }
    }
}
