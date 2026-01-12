package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.operator.OutputCompressor;

/**
 * General class for generating a compressed CMS message stream.
 * <p>
 * A simple example of usage.
 * </p>
 * <pre>
 *      CMSCompressedDataStreamGenerator gen = new CMSCompressedDataStreamGenerator();
 *      
 *      OutputStream cOut = gen.open(outputStream, new ZlibCompressor());
 *      
 *      cOut.write(data);
 *      
 *      cOut.close();
 * </pre>
 */
public class CMSCompressedDataStreamGenerator
{
    public static final String ZLIB = CMSObjectIdentifiers.zlibCompress.getId();

    private int _bufferSize;
    
    /**
     * base constructor
     */
    public CMSCompressedDataStreamGenerator()
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
     * Open a compressing output stream with the PKCS#7 content type OID of "data".
     *
     * @param out the stream to encode to.
     * @param compressor the type of compressor to use.
     * @return an output stream to write the data be compressed to.
     * @throws IOException
     */
    public OutputStream open(
        OutputStream out,
        OutputCompressor compressor)
        throws IOException
    {
        return open(CMSObjectIdentifiers.data, out, compressor);
    }

    /**
     * Open a compressing output stream.
     *
     * @param contentOID the content type OID.
     * @param out the stream to encode to.
     * @param compressor the type of compressor to use.
     * @return an output stream to write the data be compressed to.
     * @throws IOException
     */
    public OutputStream open(
        ASN1ObjectIdentifier contentOID,
        OutputStream out,
        OutputCompressor compressor)
        throws IOException
    {
        // ContentInfo
        BERSequenceGenerator sGen = new BERSequenceGenerator(out);
        sGen.addObject(CMSObjectIdentifiers.compressedData);

        // CompressedData
        BERSequenceGenerator cGen = new BERSequenceGenerator(sGen.getRawOutputStream(), 0, true);
        cGen.addObject(ASN1Integer.ZERO);
        cGen.addObject(compressor.getAlgorithmIdentifier());

        // EncapsulatedContentInfo
        BERSequenceGenerator eciGen = new BERSequenceGenerator(cGen.getRawOutputStream());
        eciGen.addObject(contentOID);

        // eContent [0] EXPLICIT OCTET STRING OPTIONAL
        OutputStream ecStream = CMSUtils.createBEROctetOutputStream(eciGen.getRawOutputStream(), 0, true, _bufferSize);

        return new CmsCompressedOutputStream(compressor.getOutputStream(ecStream), sGen, cGen, eciGen);
    }

    private static class CmsCompressedOutputStream
        extends OutputStream
    {
        private OutputStream _out;
        private BERSequenceGenerator _sGen;
        private BERSequenceGenerator _cGen;
        private BERSequenceGenerator _eiGen;
        
        CmsCompressedOutputStream(
            OutputStream out,
            BERSequenceGenerator sGen,
            BERSequenceGenerator cGen,
            BERSequenceGenerator eiGen)
        {
            _out = out;
            _sGen = sGen;
            _cGen = cGen;
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
            int    off,
            int    len)
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
            _cGen.close();
            _sGen.close();
        }
    }
}
