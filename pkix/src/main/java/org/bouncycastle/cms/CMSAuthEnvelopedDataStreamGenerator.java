package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;

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
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.operator.OutputAEADEncryptor;

/**
 * Generate authenticated enveloped CMS data with streaming support.
 * <p>
 * When using this generator, note:
 * <ul>
 *   <li>The returned OutputStream must be closed to finalize encryption and authentication</li>
 *   <li>Closing the returned stream <b>does not close</b> the underlying OutputStream passed to {@code open()}</li>
 *   <li>Callers are responsible for closing the underlying OutputStream separately</li>
 * </ul>
 */
public class CMSAuthEnvelopedDataStreamGenerator
    extends CMSAuthEnvelopedGenerator
{

    private int _bufferSize;
    private boolean _berEncodeRecipientSet;

    public CMSAuthEnvelopedDataStreamGenerator()
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

    protected OutputStream open(
        ASN1ObjectIdentifier dataType,
        OutputStream out,
        ASN1EncodableVector recipientInfos,
        OutputAEADEncryptor encryptor)
        throws IOException
    {
        // ContentInfo
        BERSequenceGenerator ciGen = new BERSequenceGenerator(out);
        ciGen.addObject(CMSObjectIdentifiers.authEnvelopedData);

        // AuthEnvelopedData
        BERSequenceGenerator aedGen = new BERSequenceGenerator(ciGen.getRawOutputStream(), 0, true);
        aedGen.addObject(ASN1Integer.ZERO);
        CMSUtils.addOriginatorInfoToGenerator(aedGen, originatorInfo);
        CMSUtils.addRecipientInfosToGenerator(recipientInfos, aedGen, _berEncodeRecipientSet);

        // EncryptedContentInfo
        BERSequenceGenerator eciGen = new BERSequenceGenerator(aedGen.getRawOutputStream());
        eciGen.addObject(dataType);
        eciGen.addObject(encryptor.getAlgorithmIdentifier());

        // encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL (EncryptedContent ::= OCTET STRING)
        OutputStream ecStream = CMSUtils.createBEROctetOutputStream(eciGen.getRawOutputStream(), 0, false, _bufferSize);

        return new CMSAuthEnvelopedDataOutputStream(encryptor, ecStream, ciGen, aedGen, eciGen);
    }

    protected OutputStream open(
        OutputStream out,
        ASN1EncodableVector recipientInfos,
        OutputAEADEncryptor encryptor)
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
     * Generate authenticated-enveloped-data using the given encryptor, and marking the encapsulated
     * bytes as being of type DATA.
     * <p>
     * <b>Stream handling note:</b> Closing the returned stream finalizes the CMS structure but <b>does
     * not close</b> the underlying output stream. The caller remains responsible for managing the
     * lifecycle of {@code out}.
     *
     * @param out the output stream to write the CMS structure to
     * @param encryptor the cipher to use for encryption
     * @return an output stream that writes encrypted and authenticated content
     */
    public OutputStream open(OutputStream out, OutputAEADEncryptor encryptor) throws CMSException, IOException
    {
        return open(CMSObjectIdentifiers.data, out, encryptor);
    }

    /**
     * Generate authenticated-enveloped-data using the given encryptor, and marking the encapsulated
     * bytes as being of the passed in type.
     * <p>
     * <b>Stream handling note:</b> Closing the returned stream finalizes the CMS structure but
     * <b>does not close</b> the underlying output stream. The caller remains responsible for
     * managing the lifecycle of {@code out}.
     *
     * @param dataType the type of the data being written to the object.
     * @param out the output stream to write the CMS structure to
     * @param encryptor the cipher to use for encryption
     * @return an output stream that writes encrypted and authenticated content
     */
    public OutputStream open(ASN1ObjectIdentifier dataType, OutputStream out, OutputAEADEncryptor encryptor)
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
     * Generate an authenticated-enveloped object for {@code inputLength}
     * content octets, using the given encryptor. In definite-length mode (see
     * {@link #setEncoding(String)}) the length is used to pre-compute every
     * enclosing header, so exactly that many content octets must then be
     * written to the returned stream - a mismatch fails with an IOException,
     * by which point the output is unusable and must be discarded. In BER
     * mode the length is ignored.
     * <p>
     * In definite-length mode the {@link #setBufferSize(int) buffer size} and
     * {@link #setBEREncodeRecipients(boolean) BER recipient set} settings are
     * ignored (an indefinite-length encoding may not appear inside a
     * definite-length one). Nothing is buffered, so content larger than a Java
     * array can carry is supported. Note that in this mode any authenticated
     * attributes are generated and fed to the encryptor's AAD stream at
     * {@code open()} time, ahead of the content - the order AEAD modes
     * require.
     */
    public OutputStream open(OutputStream out, long inputLength, OutputAEADEncryptor encryptor)
        throws CMSException, IOException
    {
        return open(CMSObjectIdentifiers.data, out, inputLength, encryptor);
    }

    /**
     * Generate an authenticated-enveloped object for {@code inputLength}
     * content octets of the passed in type, using the given encryptor - see
     * {@link #open(OutputStream, long, OutputAEADEncryptor)}.
     */
    public OutputStream open(ASN1ObjectIdentifier dataType, OutputStream out, long inputLength, OutputAEADEncryptor encryptor)
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
        OutputAEADEncryptor encryptor)
        throws CMSException, IOException
    {
        if (inputLength < 0)
        {
            throw new CMSException("inputLength cannot be negative");
        }

        // AuthEnvelopedData carries the AEAD tag in the separate mac field, so
        // the encrypted content is the raw ciphertext and the mac length comes
        // from the algorithm parameters.
        long encLength = CMSUtils.getDefiniteLengthAEADOutput(encryptor.getAlgorithmIdentifier(), inputLength);
        int macLength = CMSUtils.getAEADMacLength(encryptor.getAlgorithmIdentifier());
        if (encLength < 0 || macLength < 0)
        {
            throw new CMSException(
                "encryptor cannot predict the encrypted content length - use BER encoding");
        }

        boolean der = ASN1Encoding.DER.equals(encoding);
        String enc = der ? ASN1Encoding.DER : ASN1Encoding.DL;

        // pre-encode everything other than the encrypted content; only the
        // content itself streams, so these stay small.
        byte[] contentOid = CMSObjectIdentifiers.authEnvelopedData.getEncoded(enc);
        byte[] versionEnc = ASN1Integer.ZERO.getEncoded(enc);
        byte[] originatorEnc = (originatorInfo != null)
            ? new DLTaggedObject(false, 0, originatorInfo).getEncoded(enc)
            : null;
        ASN1Set riSet = der ? new DERSet(recipientInfos) : new DLSet(recipientInfos);
        byte[] riSetEnc = riSet.getEncoded(enc);
        byte[] dataTypeEnc = dataType.getEncoded(enc);
        byte[] algIdEnc = encryptor.getAlgorithmIdentifier().getEncoded(enc);

        // authenticated attributes are content-independent; generate them now
        // and feed the AAD stream ahead of the content, as AEAD modes require.
        // The AAD is the DER encoding of the SET (RFC 5083 section 2.2).
        byte[] authAttrsEnc = null;
        if (authAttrsGenerator != null)
        {
            AttributeTable attrTable = authAttrsGenerator.getAttributes(CMSUtils.getEmptyParameters());
            ASN1Set authSet = new DERSet(attrTable.toASN1EncodableVector());
            encryptor.getAADStream().write(authSet.getEncoded(ASN1Encoding.DER));
            authAttrsEnc = new DLTaggedObject(false, 1, authSet).getEncoded(enc);
        }
        byte[] unauthAttrsEnc = null;
        if (unauthAttrsGenerator != null)
        {
            AttributeTable attrTable = unauthAttrsGenerator.getAttributes(CMSUtils.getEmptyParameters());
            ASN1Set unauthSet = der
                ? new DERSet(attrTable.toASN1EncodableVector())
                : new DLSet(attrTable.toASN1EncodableVector());
            unauthAttrsEnc = new DLTaggedObject(false, 2, unauthSet).getEncoded(enc);
        }

        // bottom-up length arithmetic for the enclosing headers.
        long encContentTLV = DLGenerator.getDLEncodingLength(encLength);
        long eciBody = dataTypeEnc.length + algIdEnc.length + encContentTLV;
        long eciTLV = DLGenerator.getDLEncodingLength(eciBody);
        long macTLV = DLGenerator.getDLEncodingLength(macLength);
        long aedBody = versionEnc.length
            + (originatorEnc != null ? originatorEnc.length : 0)
            + riSetEnc.length
            + eciTLV
            + (authAttrsEnc != null ? authAttrsEnc.length : 0)
            + macTLV
            + (unauthAttrsEnc != null ? unauthAttrsEnc.length : 0);
        long aedTLV = DLGenerator.getDLEncodingLength(aedBody);
        long taggedTLV = DLGenerator.getDLEncodingLength(aedTLV);
        long ciBody = contentOid.length + taggedTLV;

        // ContentInfo
        DLSequenceGenerator cGen = new DLSequenceGenerator(out, ciBody);
        cGen.getRawOutputStream().write(contentOid);

        // AuthEnvelopedData, [0] EXPLICIT
        DLSequenceGenerator aedGen = new DLSequenceGenerator(cGen.getRawOutputStream(), 0, true, aedBody);
        OutputStream aedRaw = aedGen.getRawOutputStream();
        aedRaw.write(versionEnc);
        if (originatorEnc != null)
        {
            aedRaw.write(originatorEnc);
        }
        aedRaw.write(riSetEnc);

        // EncryptedContentInfo
        DLSequenceGenerator eciGen = new DLSequenceGenerator(aedRaw, eciBody);
        eciGen.getRawOutputStream().write(dataTypeEnc);
        eciGen.getRawOutputStream().write(algIdEnc);

        // encryptedContent [0] IMPLICIT OCTET STRING - primitive, definite length.
        DLOctetStringGenerator octGen = new DLOctetStringGenerator(eciGen.getRawOutputStream(), 0, false, encLength);

        return new CMSAuthEnvelopedDLDataOutputStream(
            encryptor, inputLength, enc, octGen, eciGen, aedGen, cGen, authAttrsEnc, unauthAttrsEnc);
    }

    private class CMSAuthEnvelopedDLDataOutputStream
        extends OutputStream
    {
        private final OutputAEADEncryptor _encryptor;
        private final OutputStream _cOut;
        private final String _enc;
        private final DLOctetStringGenerator _octGen;
        private final DLSequenceGenerator _eciGen;
        private final DLSequenceGenerator _aedGen;
        private final DLSequenceGenerator _cGen;
        private final byte[] _authAttrsEnc;
        private final byte[] _unauthAttrsEnc;
        private final long _contentLength;
        private long _written = 0;

        CMSAuthEnvelopedDLDataOutputStream(
            OutputAEADEncryptor encryptor,
            long contentLength,
            String enc,
            DLOctetStringGenerator octGen,
            DLSequenceGenerator eciGen,
            DLSequenceGenerator aedGen,
            DLSequenceGenerator cGen,
            byte[] authAttrsEnc,
            byte[] unauthAttrsEnc)
        {
            _encryptor = encryptor;
            _contentLength = contentLength;
            _enc = enc;
            _octGen = octGen;
            _cOut = encryptor.getOutputStream(octGen.getOctetOutputStream());
            _eciGen = eciGen;
            _aedGen = aedGen;
            _cGen = cGen;
            _authAttrsEnc = authAttrsEnc;
            _unauthAttrsEnc = unauthAttrsEnc;
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
            _octGen.close();    // verifies the predicted ciphertext length
            _eciGen.close();

            OutputStream aedRaw = _aedGen.getRawOutputStream();
            if (_authAttrsEnc != null)
            {
                aedRaw.write(_authAttrsEnc);
            }
            // a MAC of unexpected size fails the enclosing length enforcement.
            aedRaw.write(new DEROctetString(_encryptor.getMAC()).getEncoded(_enc));
            if (_unauthAttrsEnc != null)
            {
                aedRaw.write(_unauthAttrsEnc);
            }
            _aedGen.close();
            _cGen.close();
        }
    }

    private class CMSAuthEnvelopedDataOutputStream
        extends OutputStream
    {
        private final OutputAEADEncryptor _encryptor;
        private final OutputStream _cOut;
        private final OutputStream _octetStream;
        private final BERSequenceGenerator _cGen;
        private final BERSequenceGenerator _envGen;
        private final BERSequenceGenerator _eiGen;

        public CMSAuthEnvelopedDataOutputStream(
            OutputAEADEncryptor encryptor,
            OutputStream octetStream,
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
            int off,
            int len)
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
            ASN1Set authenticatedAttrSet = CMSUtils.processAuthAttrSet(authAttrsGenerator, _encryptor);

            _cOut.close();
            _octetStream.close();
            _eiGen.close();

            if (authenticatedAttrSet != null)
            {
                _envGen.addObject(new DERTaggedObject(false, 1, authenticatedAttrSet));
            }

            _envGen.addObject(new DEROctetString(_encryptor.getMAC()));

            CMSUtils.addAttriSetToGenerator(_envGen, unauthAttrsGenerator, 2, CMSUtils.getEmptyParameters());

            _envGen.close();
            _cGen.close();
        }
    }

}
