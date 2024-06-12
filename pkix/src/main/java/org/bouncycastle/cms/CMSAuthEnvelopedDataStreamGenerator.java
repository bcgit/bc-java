package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Collections;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.OutputAEADEncryptor;

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

    private OutputStream doOpen(
        ASN1ObjectIdentifier dataType,
        OutputStream out,
        OutputAEADEncryptor encryptor)
        throws IOException, CMSException
    {
        ASN1EncodableVector recipientInfos = CMSUtils.getRecipentInfos(encryptor.getKey(), recipientInfoGenerators);

        return open(dataType, out, recipientInfos, encryptor);
    }

    protected OutputStream open(
        ASN1ObjectIdentifier dataType,
        OutputStream out,
        ASN1EncodableVector recipientInfos,
        OutputAEADEncryptor encryptor)
        throws IOException
    {
        //
        // ContentInfo
        //
        BERSequenceGenerator cGen = new BERSequenceGenerator(out);

        cGen.addObject(CMSObjectIdentifiers.authEnvelopedData);

        //
        // Encrypted Data
        //
        BERSequenceGenerator authEnvGen = new BERSequenceGenerator(cGen.getRawOutputStream(), 0, true);

        authEnvGen.addObject(new ASN1Integer(0));

        CMSUtils.addOriginatorInfoToGenerator(authEnvGen, originatorInfo);

        CMSUtils.addRecipientInfosToGenerator(recipientInfos, authEnvGen, _berEncodeRecipientSet);

        BERSequenceGenerator eiGen = new BERSequenceGenerator(authEnvGen.getRawOutputStream());

        eiGen.addObject(dataType);

        AlgorithmIdentifier encAlgId = encryptor.getAlgorithmIdentifier();

        eiGen.getRawOutputStream().write(encAlgId.getEncoded());

        OutputStream octetStream = CMSUtils.createBEROctetOutputStream(
            eiGen.getRawOutputStream(), 0, true, _bufferSize);

        return new CMSAuthEnvelopedDataOutputStream(encryptor, octetStream, cGen, authEnvGen, eiGen);
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
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given encryptor.
     */
    public OutputStream open(
        OutputStream out,
        OutputAEADEncryptor encryptor)
        throws CMSException, IOException
    {
        return doOpen(new ASN1ObjectIdentifier(CMSObjectIdentifiers.data.getId()), out, encryptor);
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

            CMSUtils.addAttriSetToGenerator(_envGen, unauthAttrsGenerator, 2, Collections.EMPTY_MAP);

            _envGen.close();
            _cGen.close();
        }
    }

}
