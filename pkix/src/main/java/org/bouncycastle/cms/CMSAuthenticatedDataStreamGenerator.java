package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Collections;
import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLGenerator;
import org.bouncycastle.asn1.DLOctetStringGenerator;
import org.bouncycastle.asn1.DLSequenceGenerator;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.asn1.cms.AuthenticatedData;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.util.io.TeeOutputStream;

/**
 * General class for generating a CMS authenticated-data message stream.
 * <p>
 * A simple example of usage.
 * <pre>
 *      CMSAuthenticatedDataStreamGenerator edGen = new CMSAuthenticatedDataStreamGenerator();
 *
 *      edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider("BC"));
 *
 *      ByteArrayOutputStream  bOut = new ByteArrayOutputStream();
 *
 *      OutputStream out = edGen.open(
 *                              bOut, new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider("BC").build());*
 *      out.write(data);
 *
 *      out.close();
 * </pre>
 * <p>
 * <b>Stream handling note:</b>
 * <ul>
 *   <li>The returned OutputStream must be closed to finalize the CMS structure and
 *       emit the MAC.</li>
 *   <li>Closing the returned stream <b>does not close</b> the underlying OutputStream
 *       passed to {@code open()}.</li>
 *   <li>Callers are responsible for closing the underlying OutputStream separately.</li>
 * </ul>
 */
public class CMSAuthenticatedDataStreamGenerator
    extends CMSAuthenticatedGenerator
{
    // Currently not handled
//    private Object              _originatorInfo = null;
//    private Object              _unprotectedAttributes = null;
    private int bufferSize;
    private boolean berEncodeRecipientSet;

    /**
     * base constructor
     */
    public CMSAuthenticatedDataStreamGenerator()
    {
    }

    /**
     * Set the underlying string size for encapsulated data
     *
     * @param bufferSize length of octet strings to buffer the data.
     */
    public void setBufferSize(
        int bufferSize)
    {
        this.bufferSize = bufferSize;
    }

    /**
     * Use a BER Set to store the recipient information. By default recipients are
     * stored in a DER encoding.
     *
     * @param useBerEncodingForRecipients true if a BER set should be used, false if DER.
     */
    public void setBEREncodeRecipients(
        boolean useBerEncodingForRecipients)
    {
        berEncodeRecipientSet = useBerEncodingForRecipients;
    }

    /**
     * generate an authenticated data structure with the encapsulated bytes marked as DATA.
     *
     * @param out the stream to store the authenticated structure in.
     * @param macCalculator calculator for the MAC to be attached to the data.
     */
    public OutputStream open(
        OutputStream    out,
        MacCalculator   macCalculator)
        throws CMSException
    {
        return open(CMSObjectIdentifiers.data, out, macCalculator);
    }

    public OutputStream open(
        OutputStream    out,
        MacCalculator   macCalculator,
        DigestCalculator digestCalculator)
        throws CMSException
    {
        return open(CMSObjectIdentifiers.data, out, macCalculator, digestCalculator);
    }

    /**
     * generate an authenticated data structure with the encapsulated bytes marked as type dataType.
     *
     * @param dataType the type of the data been written to the object.
     * @param out the stream to store the authenticated structure in.
     * @param macCalculator calculator for the MAC to be attached to the data.
     */
    public OutputStream open(
        ASN1ObjectIdentifier dataType,
        OutputStream         out,
        MacCalculator        macCalculator)
        throws CMSException
    {
        return open(dataType, out, macCalculator, null);
    }

    /**
     * generate an authenticated data structure with the encapsulated bytes marked as type dataType.
     *
     * @param dataType the type of the data been written to the object.
     * @param out the stream to store the authenticated structure in.
     * @param macCalculator calculator for the MAC to be attached to the data.
     * @param digestCalculator calculator for computing digest of the encapsulated data.
     */
    public OutputStream open(
        ASN1ObjectIdentifier dataType,
        OutputStream         out,
        MacCalculator        macCalculator,
        DigestCalculator     digestCalculator)
        throws CMSException
    {
        if (!ASN1Encoding.BER.equals(encoding))
        {
            throw new CMSException(
                "definite-length encoding requires the content length up front - use open(out, inputLength, macCalculator)");
        }

        try
        {
            ASN1EncodableVector recipientInfos = CMSUtils.getRecipentInfos(macCalculator.getKey(), recipientInfoGenerators);

            // ContentInfo
            BERSequenceGenerator cGen = new BERSequenceGenerator(out);
            cGen.addObject(CMSObjectIdentifiers.authenticatedData);

            // AuthenticatedData
            BERSequenceGenerator authGen = new BERSequenceGenerator(cGen.getRawOutputStream(), 0, true);
            authGen.addObject(ASN1Integer.valueOf(AuthenticatedData.calculateVersion(originatorInfo)));
            CMSUtils.addOriginatorInfoToGenerator(authGen, originatorInfo);
            CMSUtils.addRecipientInfosToGenerator(recipientInfos, authGen, berEncodeRecipientSet);
            authGen.addObject(macCalculator.getAlgorithmIdentifier());

            if (digestCalculator != null)
            {
                authGen.addObject(new DERTaggedObject(false, 1, digestCalculator.getAlgorithmIdentifier()));
            }

            // EncapsulatedContentInfo
            BERSequenceGenerator eciGen = new BERSequenceGenerator(authGen.getRawOutputStream());
            eciGen.addObject(dataType);

            // eContent [0] EXPLICIT OCTET STRING OPTIONAL
            OutputStream ecStream = CMSUtils.createBEROctetOutputStream(eciGen.getRawOutputStream(), 0, true, bufferSize);

            OutputStream mOut;
            if (digestCalculator != null)
            {
                mOut = new TeeOutputStream(ecStream, digestCalculator.getOutputStream());
            }
            else
            {
                mOut = new TeeOutputStream(ecStream, macCalculator.getOutputStream());
            }

            return new CmsAuthenticatedDataOutputStream(macCalculator, digestCalculator, dataType, mOut, cGen, authGen, eciGen);
        }
        catch (IOException e)
        {
            throw new CMSException("exception decoding algorithm parameters.", e);
        }
    }

    /**
     * Generate an authenticated data structure for {@code inputLength} content
     * octets, with the encapsulated bytes marked as DATA. In definite-length
     * mode (see {@link #setEncoding(String)}) the length is used to pre-compute
     * every enclosing header, so exactly that many content octets must then be
     * written to the returned stream - a mismatch fails with an IOException, by
     * which point the output is unusable and must be discarded. In BER mode the
     * length is ignored.
     * <p>
     * In definite-length mode the {@link #setBufferSize(int) buffer size} and
     * {@link #setBEREncodeRecipients(boolean) BER recipient set} settings are
     * ignored (an indefinite-length encoding may not appear inside a
     * definite-length one), and the MAC algorithm must have a spec-defined
     * output length (the HMAC family) so the mac field can be sized before the
     * content streams. Nothing is buffered, so content larger than a Java array
     * can carry is supported.
     *
     * @param out the stream to store the authenticated structure in.
     * @param inputLength the number of content octets that will be written.
     * @param macCalculator calculator for the MAC to be attached to the data.
     */
    public OutputStream open(
        OutputStream    out,
        long            inputLength,
        MacCalculator   macCalculator)
        throws CMSException, IOException
    {
        return open(CMSObjectIdentifiers.data, out, inputLength, macCalculator, null);
    }

    /**
     * Generate an authenticated data structure with authenticated attributes
     * for {@code inputLength} content octets, with the encapsulated bytes
     * marked as DATA - see {@link #open(OutputStream, long, MacCalculator)}.
     * <p>
     * In definite-length mode the authenticated (and any unauthenticated)
     * attribute sets are sized up front using a placeholder digest of the
     * digest algorithm's output length; attribute generators must produce
     * sets whose encoded length does not depend on the digest value, or the
     * enclosing length enforcement fails at close time.
     *
     * @param out the stream to store the authenticated structure in.
     * @param inputLength the number of content octets that will be written.
     * @param macCalculator calculator for the MAC to be attached to the data.
     * @param digestCalculator calculator for computing digest of the encapsulated data.
     */
    public OutputStream open(
        OutputStream     out,
        long             inputLength,
        MacCalculator    macCalculator,
        DigestCalculator digestCalculator)
        throws CMSException, IOException
    {
        return open(CMSObjectIdentifiers.data, out, inputLength, macCalculator, digestCalculator);
    }

    /**
     * Generate an authenticated data structure for {@code inputLength} content
     * octets, with the encapsulated bytes marked as type dataType - see
     * {@link #open(OutputStream, long, MacCalculator)}.
     *
     * @param dataType the type of the data been written to the object.
     * @param out the stream to store the authenticated structure in.
     * @param inputLength the number of content octets that will be written.
     * @param macCalculator calculator for the MAC to be attached to the data.
     */
    public OutputStream open(
        ASN1ObjectIdentifier dataType,
        OutputStream         out,
        long                 inputLength,
        MacCalculator        macCalculator)
        throws CMSException, IOException
    {
        return open(dataType, out, inputLength, macCalculator, null);
    }

    /**
     * Generate an authenticated data structure for {@code inputLength} content
     * octets, with the encapsulated bytes marked as type dataType - see
     * {@link #open(OutputStream, long, MacCalculator)} and
     * {@link #open(OutputStream, long, MacCalculator, DigestCalculator)}.
     *
     * @param dataType the type of the data been written to the object.
     * @param out the stream to store the authenticated structure in.
     * @param inputLength the number of content octets that will be written.
     * @param macCalculator calculator for the MAC to be attached to the data.
     * @param digestCalculator calculator for computing digest of the encapsulated data.
     */
    public OutputStream open(
        ASN1ObjectIdentifier dataType,
        OutputStream         out,
        long                 inputLength,
        MacCalculator        macCalculator,
        DigestCalculator     digestCalculator)
        throws CMSException, IOException
    {
        if (ASN1Encoding.BER.equals(encoding))
        {
            return open(dataType, out, macCalculator, digestCalculator);
        }

        return openDL(dataType, out, inputLength, macCalculator, digestCalculator);
    }

    private OutputStream openDL(
        ASN1ObjectIdentifier dataType,
        OutputStream         out,
        long                 inputLength,
        MacCalculator        macCalculator,
        DigestCalculator     digestCalculator)
        throws CMSException, IOException
    {
        if (inputLength < 0)
        {
            throw new CMSException("inputLength cannot be negative");
        }

        int macLength = CMSUtils.getMacOutputLength(macCalculator.getAlgorithmIdentifier());
        if (macLength < 0)
        {
            throw new CMSException("cannot predict MAC length for "
                + macCalculator.getAlgorithmIdentifier().getAlgorithm() + " - use BER encoding");
        }

        ASN1EncodableVector recipientInfos = CMSUtils.getRecipentInfos(macCalculator.getKey(), recipientInfoGenerators);

        boolean der = ASN1Encoding.DER.equals(encoding);
        String enc = der ? ASN1Encoding.DER : ASN1Encoding.DL;

        // pre-encode everything other than the content; only the content
        // itself streams, so these stay small.
        byte[] contentOid = CMSObjectIdentifiers.authenticatedData.getEncoded(enc);
        byte[] versionEnc = ASN1Integer.valueOf(AuthenticatedData.calculateVersion(originatorInfo)).getEncoded(enc);
        byte[] originatorEnc = (originatorInfo != null)
            ? new DLTaggedObject(false, 0, originatorInfo).getEncoded(enc)
            : null;
        ASN1Set riSet = der ? new DERSet(recipientInfos) : new DLSet(recipientInfos);
        byte[] riSetEnc = riSet.getEncoded(enc);
        byte[] macAlgEnc = macCalculator.getAlgorithmIdentifier().getEncoded(enc);
        byte[] digAlgEnc = null;
        byte[] dataTypeEnc = dataType.getEncoded(enc);

        // the authenticated attributes carry the digest of the content, so
        // their values are only known once the content has been written - but
        // their encoded length is needed now. Size them with a placeholder
        // digest of the right length; a length-unstable attribute generator
        // fails the enclosing length enforcement at close time.
        long authAttrsLength = 0;
        if (digestCalculator != null)
        {
            digAlgEnc = new DLTaggedObject(false, 1, digestCalculator.getAlgorithmIdentifier()).getEncoded(enc);

            int digestLength = CMSUtils.getDigestOutputLength(digestCalculator.getAlgorithmIdentifier());
            if (digestLength < 0)
            {
                throw new CMSException("cannot predict digest length for "
                    + digestCalculator.getAlgorithmIdentifier().getAlgorithm() + " - use BER encoding");
            }

            if (authGen == null)
            {
                authGen = new DefaultAuthenticatedAttributeTableGenerator();
            }

            Map parameters = Collections.unmodifiableMap(getBaseParameters(dataType,
                digestCalculator.getAlgorithmIdentifier(), macCalculator.getAlgorithmIdentifier(), new byte[digestLength]));
            ASN1Set authed = new DERSet(authGen.getAttributes(parameters).toASN1EncodableVector());
            authAttrsLength = new DLTaggedObject(false, 2, authed).getEncoded(enc).length;
        }

        // without a digest the unauthenticated attributes see empty parameters,
        // so they can be encoded once now; with one they see the digest-bearing
        // parameters and are sized the same way as the authenticated set.
        byte[] unauthAttrsEnc = null;
        long unauthAttrsLength = 0;
        if (unauthGen != null)
        {
            if (digestCalculator == null)
            {
                unauthAttrsEnc = encodeUnauthAttrs(CMSUtils.getEmptyParameters(), der, enc);
                unauthAttrsLength = unauthAttrsEnc.length;
            }
            else
            {
                int digestLength = CMSUtils.getDigestOutputLength(digestCalculator.getAlgorithmIdentifier());
                Map parameters = Collections.unmodifiableMap(getBaseParameters(dataType,
                    digestCalculator.getAlgorithmIdentifier(), macCalculator.getAlgorithmIdentifier(), new byte[digestLength]));
                unauthAttrsLength = encodeUnauthAttrs(parameters, der, enc).length;
            }
        }

        // bottom-up length arithmetic for the enclosing headers.
        long octTLV = DLGenerator.getDLEncodingLength(inputLength);
        long eContentTLV = DLGenerator.getDLEncodingLength(octTLV);     // eContent [0] EXPLICIT
        long eciBody = dataTypeEnc.length + eContentTLV;
        long eciTLV = DLGenerator.getDLEncodingLength(eciBody);
        long macTLV = DLGenerator.getDLEncodingLength(macLength);
        long adBody = versionEnc.length
            + (originatorEnc != null ? originatorEnc.length : 0)
            + riSetEnc.length
            + macAlgEnc.length
            + (digAlgEnc != null ? digAlgEnc.length : 0)
            + eciTLV
            + authAttrsLength
            + macTLV
            + unauthAttrsLength;
        long adTLV = DLGenerator.getDLEncodingLength(adBody);
        long taggedTLV = DLGenerator.getDLEncodingLength(adTLV);
        long ciBody = contentOid.length + taggedTLV;

        // ContentInfo
        DLSequenceGenerator cGen = new DLSequenceGenerator(out, ciBody);
        cGen.getRawOutputStream().write(contentOid);

        // AuthenticatedData, [0] EXPLICIT
        DLSequenceGenerator adGen = new DLSequenceGenerator(cGen.getRawOutputStream(), 0, true, adBody);
        OutputStream adRaw = adGen.getRawOutputStream();
        adRaw.write(versionEnc);
        if (originatorEnc != null)
        {
            adRaw.write(originatorEnc);
        }
        adRaw.write(riSetEnc);
        adRaw.write(macAlgEnc);
        if (digAlgEnc != null)
        {
            adRaw.write(digAlgEnc);
        }

        // EncapsulatedContentInfo
        DLSequenceGenerator eciGen = new DLSequenceGenerator(adRaw, eciBody);
        eciGen.getRawOutputStream().write(dataTypeEnc);

        // eContent [0] EXPLICIT OCTET STRING - primitive, definite length.
        DLOctetStringGenerator octGen = new DLOctetStringGenerator(eciGen.getRawOutputStream(), 0, true, inputLength);

        OutputStream mOut;
        if (digestCalculator != null)
        {
            mOut = new TeeOutputStream(octGen.getOctetOutputStream(), digestCalculator.getOutputStream());
        }
        else
        {
            mOut = new TeeOutputStream(octGen.getOctetOutputStream(), macCalculator.getOutputStream());
        }

        return new CmsAuthenticatedDLDataOutputStream(macCalculator, digestCalculator, dataType, inputLength,
            der, enc, mOut, octGen, eciGen, adGen, cGen, unauthAttrsEnc);
    }

    private byte[] encodeUnauthAttrs(Map parameters, boolean der, String enc)
        throws IOException
    {
        ASN1EncodableVector v = unauthGen.getAttributes(parameters).toASN1EncodableVector();
        ASN1Set unauthed = der ? (ASN1Set)new DERSet(v) : (ASN1Set)new DLSet(v);

        return new DLTaggedObject(false, 3, unauthed).getEncoded(enc);
    }

    private class CmsAuthenticatedDLDataOutputStream
        extends OutputStream
    {
        private final MacCalculator macCalculator;
        private final DigestCalculator digestCalculator;
        private final ASN1ObjectIdentifier contentType;
        private final long contentLength;
        private final boolean der;
        private final String enc;
        private final OutputStream dataStream;
        private final DLOctetStringGenerator octGen;
        private final DLSequenceGenerator eciGen;
        private final DLSequenceGenerator adGen;
        private final DLSequenceGenerator cGen;
        private final byte[] unauthAttrsEnc;
        private long written = 0;

        CmsAuthenticatedDLDataOutputStream(
            MacCalculator macCalculator,
            DigestCalculator digestCalculator,
            ASN1ObjectIdentifier contentType,
            long contentLength,
            boolean der,
            String enc,
            OutputStream dataStream,
            DLOctetStringGenerator octGen,
            DLSequenceGenerator eciGen,
            DLSequenceGenerator adGen,
            DLSequenceGenerator cGen,
            byte[] unauthAttrsEnc)
        {
            this.macCalculator = macCalculator;
            this.digestCalculator = digestCalculator;
            this.contentType = contentType;
            this.contentLength = contentLength;
            this.der = der;
            this.enc = enc;
            this.dataStream = dataStream;
            this.octGen = octGen;
            this.eciGen = eciGen;
            this.adGen = adGen;
            this.cGen = cGen;
            this.unauthAttrsEnc = unauthAttrsEnc;
        }

        public void write(
            int b)
            throws IOException
        {
            checkContentSpace(1);
            dataStream.write(b);
            written++;
        }

        public void write(
            byte[] bytes,
            int    off,
            int    len)
            throws IOException
        {
            checkContentSpace(len);
            dataStream.write(bytes, off, len);
            written += len;
        }

        public void write(
            byte[] bytes)
            throws IOException
        {
            write(bytes, 0, bytes.length);
        }

        private void checkContentSpace(int len)
            throws IOException
        {
            if (written + len > contentLength)
            {
                throw new IOException("attempt to write more content octets than the declared " + contentLength);
            }
        }

        public void close()
            throws IOException
        {
            if (written != contentLength)
            {
                throw new IOException("fewer content octets written (" + written + ") than the declared " + contentLength);
            }
            dataStream.close();
            octGen.close();     // verifies the declared content length
            eciGen.close();

            OutputStream adRaw = adGen.getRawOutputStream();

            Map parameters;
            if (digestCalculator != null)
            {
                parameters = Collections.unmodifiableMap(getBaseParameters(contentType,
                    digestCalculator.getAlgorithmIdentifier(), macCalculator.getAlgorithmIdentifier(),
                    digestCalculator.getDigest()));

                ASN1Set authed = new DERSet(authGen.getAttributes(parameters).toASN1EncodableVector());

                OutputStream mOut = macCalculator.getOutputStream();

                mOut.write(authed.getEncoded(ASN1Encoding.DER));

                mOut.close();

                // a set sized differently than at open() time fails the
                // enclosing length enforcement.
                adRaw.write(new DLTaggedObject(false, 2, authed).getEncoded(enc));
            }
            else
            {
                parameters = CMSUtils.getEmptyParameters();
            }

            // a MAC of unexpected size fails the enclosing length enforcement.
            adRaw.write(new DEROctetString(macCalculator.getMac()).getEncoded(enc));

            if (unauthAttrsEnc != null)
            {
                adRaw.write(unauthAttrsEnc);
            }
            else if (unauthGen != null)
            {
                adRaw.write(encodeUnauthAttrs(parameters, der, enc));
            }

            adGen.close();
            cGen.close();
        }
    }

    private class CmsAuthenticatedDataOutputStream
        extends OutputStream
    {
        private OutputStream dataStream;
        private BERSequenceGenerator cGen;
        private BERSequenceGenerator envGen;
        private BERSequenceGenerator eiGen;
        private MacCalculator macCalculator;
        private DigestCalculator digestCalculator;
        private ASN1ObjectIdentifier contentType;

        public CmsAuthenticatedDataOutputStream(
            MacCalculator   macCalculator,
            DigestCalculator digestCalculator,
            ASN1ObjectIdentifier contentType,
            OutputStream dataStream,
            BERSequenceGenerator cGen,
            BERSequenceGenerator envGen,
            BERSequenceGenerator eiGen)
        {
            this.macCalculator = macCalculator;
            this.digestCalculator = digestCalculator;
            this.contentType = contentType;
            this.dataStream = dataStream;
            this.cGen = cGen;
            this.envGen = envGen;
            this.eiGen = eiGen;
        }

        public void write(
            int b)
            throws IOException
        {
            dataStream.write(b);
        }

        public void write(
            byte[] bytes,
            int    off,
            int    len)
            throws IOException
        {
            dataStream.write(bytes, off, len);
        }

        public void write(
            byte[] bytes)
            throws IOException
        {
            dataStream.write(bytes);
        }

        public void close()
            throws IOException
        {
            dataStream.close();
            eiGen.close();

            Map parameters;

            if (digestCalculator != null)
            {
                AlgorithmIdentifier digestAlgID = digestCalculator.getAlgorithmIdentifier();
                AlgorithmIdentifier macAlgID = macCalculator.getAlgorithmIdentifier();

                parameters = Collections.unmodifiableMap(
                    getBaseParameters(contentType, digestAlgID, macAlgID, digestCalculator.getDigest()));

                if (authGen == null)
                {
                    authGen = new DefaultAuthenticatedAttributeTableGenerator();
                }
                
                ASN1Set authed = new DERSet(authGen.getAttributes(parameters).toASN1EncodableVector());

                OutputStream mOut = macCalculator.getOutputStream();

                mOut.write(authed.getEncoded(ASN1Encoding.DER));

                mOut.close();

                envGen.addObject(new DERTaggedObject(false, 2, authed));
            }
            else
            {
                parameters = CMSUtils.getEmptyParameters();
            }

            envGen.addObject(new DEROctetString(macCalculator.getMac()));

            CMSUtils.addAttriSetToGenerator(envGen, unauthGen, 3 , parameters);

            envGen.close();
            cGen.close();
        }
    }
}