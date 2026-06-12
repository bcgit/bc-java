package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DLGenerator;
import org.bouncycastle.asn1.DLOctetStringGenerator;
import org.bouncycastle.asn1.DLSequenceGenerator;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.operator.KnownLengthOutputEncryptor;
import org.bouncycastle.operator.OutputAEADEncryptor;
import org.bouncycastle.operator.OutputEncryptor;

/**
 * General class for generating a CMS enveloped-data message stream.
 * <p>
 * A simple example of usage.
 * <pre>
 *      CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();
 *
 *      edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipientCert).setProvider("BC"));
 *
 *      ByteArrayOutputStream  bOut = new ByteArrayOutputStream();
 *
 *      OutputStream out = edGen.open(
 *                              bOut, new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)
 *                                              .setProvider("BC").build());
 *      out.write(data);
 *
 *      out.close();
 * </pre>
 * <p>
 * <b>Stream handling note:</b>
 * <ul>
 *   <li>The returned OutputStream must be closed to finalize the CMS structure.</li>
 *   <li>Closing the returned stream <b>does not close</b> the underlying OutputStream
 *       passed to {@code open()}.</li>
 *   <li>Callers are responsible for closing the underlying OutputStream separately.
 *       If the underlying OutputStream is a buffering encoder whose tail state
 *       only flushes on close (e.g. Apache Commons {@code Base64OutputStream}),
 *       failing to close it will cause the encoded output to be truncated.</li>
 * </ul>
 */
public class CMSEnvelopedDataStreamGenerator
    extends CMSEnvelopedGenerator
{
    private int                 _bufferSize;
    private boolean             _berEncodeRecipientSet;

    /**
     * base constructor
     */
    public CMSEnvelopedDataStreamGenerator()
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
        _bufferSize = bufferSize;
    }

    /**
     * Use a BER Set to store the recipient information
     */
    public void setBEREncodeRecipients(
        boolean berEncodeRecipientSet)
    {
        _berEncodeRecipientSet = berEncodeRecipientSet;
    }

    private ASN1Integer getVersion(ASN1EncodableVector recipientInfos)
    {
        if (unprotectedAttributeGenerator != null)
        {
            // mark unprotected attributes as non-null.
            return ASN1Integer.valueOf(EnvelopedData.calculateVersion(originatorInfo, new DLSet(recipientInfos), new DLSet()));
        }
        return ASN1Integer.valueOf(EnvelopedData.calculateVersion(originatorInfo, new DLSet(recipientInfos), null));
    }

    protected OutputStream open(
        ASN1ObjectIdentifier dataType,
        OutputStream         out,
        ASN1EncodableVector  recipientInfos,
        OutputEncryptor      encryptor)
        throws IOException
    {
        // ContentInfo
        BERSequenceGenerator cGen = new BERSequenceGenerator(out);
        cGen.addObject(CMSObjectIdentifiers.envelopedData);

        // EnvelopedData
        BERSequenceGenerator envGen = new BERSequenceGenerator(cGen.getRawOutputStream(), 0, true);
        envGen.addObject(getVersion(recipientInfos));
        CMSUtils.addOriginatorInfoToGenerator(envGen, originatorInfo);
        CMSUtils.addRecipientInfosToGenerator(recipientInfos, envGen, _berEncodeRecipientSet);

        // EncryptedContentInfo
        BERSequenceGenerator eciGen = new BERSequenceGenerator(envGen.getRawOutputStream());
        eciGen.addObject(dataType);
        eciGen.addObject(encryptor.getAlgorithmIdentifier());

        // encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL (EncryptedContent ::= OCTET STRING)
        OutputStream ecStream = CMSUtils.createBEROctetOutputStream(eciGen.getRawOutputStream(), 0, false, _bufferSize);

        return new CmsEnvelopedDataOutputStream(encryptor, ecStream, cGen, envGen, eciGen);
    }

    protected OutputStream open(
        OutputStream        out,
        ASN1EncodableVector recipientInfos,
        OutputEncryptor     encryptor)
        throws CMSException
    {
        try
        {
            return open(CMSObjectIdentifiers.data, out, recipientInfos, encryptor);
        }
        catch (IOException e)
        {
            throw new CMSException("exception decoding algorithm parameters.", e);
        }
    }

    /**
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given encryptor.
     */
    public OutputStream open(OutputStream out, OutputEncryptor encryptor) throws CMSException, IOException
    {
        return open(CMSObjectIdentifiers.data, out, encryptor);
    }

    /**
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given encryptor and marking the data as being of the passed
     * in type.
     */
    public OutputStream open(ASN1ObjectIdentifier dataType, OutputStream out, OutputEncryptor encryptor)
        throws CMSException, IOException
    {
        if (!ASN1Encoding.BER.equals(encoding))
        {
            throw new CMSException(
                "definite-length encoding requires the content length up front - use open(out, inputLength, encryptor)");
        }

        ASN1EncodableVector recipientInfos = CMSUtils.getRecipentInfos(encryptor.getKey(), recipientInfoGenerators);

        return open(dataType, out, recipientInfos, encryptor);
    }

    /**
     * Generate an enveloped object that contains a CMS Enveloped Data object
     * for {@code inputLength} content octets, using the given encryptor. In
     * definite-length mode (see {@link #setEncoding(String)}) the length is
     * used to pre-compute every enclosing header, so exactly that many content
     * octets must then be written to the returned stream - a mismatch fails
     * with an IOException, by which point the output is unusable and must be
     * discarded. In BER mode the length is ignored.
     * <p>
     * In definite-length mode the {@link #setBufferSize(int) buffer size} and
     * {@link #setBEREncodeRecipients(boolean) BER recipient set} settings are
     * ignored (an indefinite-length encoding may not appear inside a
     * definite-length one). Nothing is buffered, so content larger than a Java
     * array can carry is supported.
     */
    public OutputStream open(OutputStream out, long inputLength, OutputEncryptor encryptor)
        throws CMSException, IOException
    {
        return open(CMSObjectIdentifiers.data, out, inputLength, encryptor);
    }

    /**
     * Generate an enveloped object that contains a CMS Enveloped Data object
     * for {@code inputLength} content octets of the passed in type, using the
     * given encryptor - see {@link #open(OutputStream, long, OutputEncryptor)}.
     */
    public OutputStream open(ASN1ObjectIdentifier dataType, OutputStream out, long inputLength, OutputEncryptor encryptor)
        throws CMSException, IOException
    {
        ASN1EncodableVector recipientInfos = CMSUtils.getRecipentInfos(encryptor.getKey(), recipientInfoGenerators);

        if (ASN1Encoding.BER.equals(encoding))
        {
            return open(dataType, out, recipientInfos, encryptor);
        }

        return openDL(dataType, out, inputLength, recipientInfos, encryptor);
    }

    private OutputStream openDL(
        ASN1ObjectIdentifier dataType,
        OutputStream out,
        long inputLength,
        ASN1EncodableVector recipientInfos,
        OutputEncryptor encryptor)
        throws CMSException, IOException
    {
        if (inputLength < 0)
        {
            throw new CMSException("inputLength cannot be negative");
        }

        long encLength = -1;
        if (encryptor instanceof KnownLengthOutputEncryptor)
        {
            encLength = ((KnownLengthOutputEncryptor)encryptor).getOutputLength(inputLength);
        }
        if (encLength < 0)
        {
            encLength = CMSUtils.getDefiniteLengthCipherOutput(encryptor.getAlgorithmIdentifier(), inputLength);
        }
        if (encLength < 0)
        {
            throw new CMSException(
                "encryptor cannot predict the encrypted content length - use BER encoding or a KnownLengthOutputEncryptor");
        }

        boolean der = ASN1Encoding.DER.equals(encoding);
        String enc = der ? ASN1Encoding.DER : ASN1Encoding.DL;

        // pre-encode everything other than the encrypted content; only the
        // content itself streams, so these stay small.
        byte[] contentOid = CMSObjectIdentifiers.envelopedData.getEncoded(enc);
        byte[] versionEnc = getVersion(recipientInfos).getEncoded(enc);
        byte[] originatorEnc = (originatorInfo != null)
            ? new DLTaggedObject(false, 0, originatorInfo).getEncoded(enc)
            : null;
        ASN1Set riSet = der ? new DERSet(recipientInfos) : new DLSet(recipientInfos);
        byte[] riSetEnc = riSet.getEncoded(enc);
        byte[] dataTypeEnc = dataType.getEncoded(enc);
        byte[] algIdEnc = encryptor.getAlgorithmIdentifier().getEncoded(enc);
        byte[] unprotEnc = null;
        if (unprotectedAttributeGenerator != null)
        {
            // note: generated at open() time in definite-length mode.
            AttributeTable attrTable = unprotectedAttributeGenerator.getAttributes(CMSUtils.getEmptyParameters());
            ASN1Set attrSet = der
                ? new DERSet(attrTable.toASN1EncodableVector())
                : new DLSet(attrTable.toASN1EncodableVector());
            unprotEnc = new DLTaggedObject(false, 1, attrSet).getEncoded(enc);
        }

        // bottom-up length arithmetic for the enclosing headers.
        long encContentTLV = DLGenerator.getDLEncodingLength(encLength);
        long eciBody = dataTypeEnc.length + algIdEnc.length + encContentTLV;
        long eciTLV = DLGenerator.getDLEncodingLength(eciBody);
        long envBody = versionEnc.length
            + (originatorEnc != null ? originatorEnc.length : 0)
            + riSetEnc.length
            + eciTLV
            + (unprotEnc != null ? unprotEnc.length : 0);
        long envTLV = DLGenerator.getDLEncodingLength(envBody);
        long taggedTLV = DLGenerator.getDLEncodingLength(envTLV);
        long ciBody = contentOid.length + taggedTLV;

        // ContentInfo
        DLSequenceGenerator cGen = new DLSequenceGenerator(out, ciBody);
        cGen.getRawOutputStream().write(contentOid);

        // EnvelopedData, [0] EXPLICIT
        DLSequenceGenerator envGen = new DLSequenceGenerator(cGen.getRawOutputStream(), 0, true, envBody);
        OutputStream envRaw = envGen.getRawOutputStream();
        envRaw.write(versionEnc);
        if (originatorEnc != null)
        {
            envRaw.write(originatorEnc);
        }
        envRaw.write(riSetEnc);

        // EncryptedContentInfo
        DLSequenceGenerator eciGen = new DLSequenceGenerator(envRaw, eciBody);
        eciGen.getRawOutputStream().write(dataTypeEnc);
        eciGen.getRawOutputStream().write(algIdEnc);

        // encryptedContent [0] IMPLICIT OCTET STRING - primitive, definite length.
        DLOctetStringGenerator octGen = new DLOctetStringGenerator(eciGen.getRawOutputStream(), 0, false, encLength);

        return new CmsEnvelopedDLDataOutputStream(encryptor, inputLength, octGen, eciGen, envGen, cGen, unprotEnc);
    }

    private class CmsEnvelopedDLDataOutputStream
        extends OutputStream
    {
        private final OutputEncryptor _encryptor;
        private final OutputStream _cOut;
        private final OutputStream _octetStream;
        private final DLOctetStringGenerator _octGen;
        private final DLSequenceGenerator _eciGen;
        private final DLSequenceGenerator _envGen;
        private final DLSequenceGenerator _cGen;
        private final byte[] _unprotEnc;
        private final long _contentLength;
        private long _written = 0;

        CmsEnvelopedDLDataOutputStream(
            OutputEncryptor encryptor,
            long contentLength,
            DLOctetStringGenerator octGen,
            DLSequenceGenerator eciGen,
            DLSequenceGenerator envGen,
            DLSequenceGenerator cGen,
            byte[] unprotEnc)
        {
            _encryptor = encryptor;
            _contentLength = contentLength;
            _octGen = octGen;
            _octetStream = octGen.getOctetOutputStream();
            _cOut = encryptor.getOutputStream(_octetStream);
            _eciGen = eciGen;
            _envGen = envGen;
            _cGen = cGen;
            _unprotEnc = unprotEnc;
        }

        public void write(int b)
            throws IOException
        {
            checkContentSpace(1);
            _cOut.write(b);
            _written++;
        }

        public void write(byte[] bytes, int off, int len)
            throws IOException
        {
            checkContentSpace(len);
            _cOut.write(bytes, off, len);
            _written += len;
        }

        public void write(byte[] bytes)
            throws IOException
        {
            write(bytes, 0, bytes.length);
        }

        private void checkContentSpace(int len)
            throws IOException
        {
            // padded ciphers can absorb small plaintext-count mismatches, so
            // the declared content length is enforced here as well as the
            // predicted ciphertext length below.
            if (_written + len > _contentLength)
            {
                throw new IOException("attempt to write more content octets than the declared " + _contentLength);
            }
        }

        public void close()
            throws IOException
        {
            if (_written != _contentLength)
            {
                throw new IOException("fewer content octets written (" + _written + ") than the declared " + _contentLength);
            }
            _cOut.close();
            if (_encryptor instanceof OutputAEADEncryptor)
            {
                // enveloped data so MAC appended to cipher text.
                _octetStream.write(((OutputAEADEncryptor)_encryptor).getMAC());
            }
            _octGen.close();    // verifies the predicted ciphertext length
            _eciGen.close();
            if (_unprotEnc != null)
            {
                _envGen.getRawOutputStream().write(_unprotEnc);
            }
            _envGen.close();
            _cGen.close();
        }
    }

    private class CmsEnvelopedDataOutputStream
        extends OutputStream
    {
        private final OutputEncryptor _encryptor;
        private final OutputStream _cOut;
        private OutputStream _octetStream;
        private BERSequenceGenerator _cGen;
        private BERSequenceGenerator _envGen;
        private BERSequenceGenerator _eiGen;

        public CmsEnvelopedDataOutputStream(
            OutputEncryptor encryptor,
            OutputStream   octetStream,
            BERSequenceGenerator cGen,
            BERSequenceGenerator envGen,
            BERSequenceGenerator eiGen)
        {
            _encryptor = encryptor;
            _octetStream = octetStream;
            _cOut = encryptor.getOutputStream(octetStream);
            _cGen = cGen;
            _envGen = envGen;
            _eiGen = eiGen;
        }

        public void write(
            int b)
            throws IOException
        {
            _cOut.write(b);
        }

        public void write(
            byte[] bytes,
            int    off,
            int    len)
            throws IOException
        {
            _cOut.write(bytes, off, len);
        }

        public void write(
            byte[] bytes)
            throws IOException
        {
            _cOut.write(bytes);
        }

        public void close()
            throws IOException
        {
            _cOut.close();
            if (_encryptor instanceof OutputAEADEncryptor)
            {
                // enveloped data so MAC appended to cipher text.
                _octetStream.write(((OutputAEADEncryptor)_encryptor).getMAC());
                _octetStream.close();
            }
            _eiGen.close();

            CMSUtils.addAttriSetToGenerator(_envGen, unprotectedAttributeGenerator, 1, CMSUtils.getEmptyParameters());

            _envGen.close();
            _cGen.close();
        }
    }
}
