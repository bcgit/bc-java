package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
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
        ASN1EncodableVector recipientInfos = CMSUtils.getRecipentInfos(encryptor.getKey(), recipientInfoGenerators);

        return open(dataType, out, recipientInfos, encryptor);
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
