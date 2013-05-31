package org.bouncycastle.openpgp;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.CompressedDataPacket;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.apache.bzip2.CBZip2InputStream;

/**
 * Compressed data objects.
 */
public class PGPCompressedData 
    implements CompressionAlgorithmTags
{
    CompressedDataPacket    data;
    
    public PGPCompressedData(
        BCPGInputStream    pIn)
        throws IOException
    {
        data = (CompressedDataPacket)pIn.readPacket();
    }
    
    /**
     * Return the algorithm used for compression
     * 
     * @return algorithm code
     */
    public int getAlgorithm()
    {
        return data.getAlgorithm();
    }
    
    /**
     * Return the raw input stream contained in the object.
     * 
     * @return InputStream
     */
    public InputStream getInputStream()
    {
        return data.getInputStream();
    }
    
    /**
     * Return an uncompressed input stream which allows reading of the 
     * compressed data.
     * 
     * @return InputStream
     * @throws PGPException
     */
    public InputStream getDataStream()
        throws PGPException
    {
      if (this.getAlgorithm() == UNCOMPRESSED)
      {
          return this.getInputStream();
      }
      if (this.getAlgorithm() == ZIP)
      {
          return new InflaterInputStream(this.getInputStream(), new Inflater(true)) 
          {
              // If the "nowrap" inflater option is used the stream can 
              // apparently overread - we override fill() and provide
              // an extra byte for the end of the input stream to get
              // around this.
              //
              // Totally weird...
              //
              protected void fill() throws IOException
              {
                  if (eof)
                  {
                      throw new EOFException("Unexpected end of ZIP input stream");
                  }
                  
                  len = this.in.read(buf, 0, buf.length);
                  
                  if (len == -1)
                  {
                      buf[0] = 0;
                      len = 1;
                      eof = true;
                  }
                  
                  inf.setInput(buf, 0, len);
              }

              private boolean eof = false;
          };
      }
      if (this.getAlgorithm() == ZLIB)
      {
          return new InflaterInputStream(this.getInputStream())
          {
              // If the "nowrap" inflater option is used the stream can 
              // apparently overread - we override fill() and provide
              // an extra byte for the end of the input stream to get
              // around this.
              //
              // Totally weird...
              //
              protected void fill() throws IOException
              {
                  if (eof)
                  {
                      throw new EOFException("Unexpected end of ZIP input stream");
                  }
                  
                  len = this.in.read(buf, 0, buf.length);
                  
                  if (len == -1)
                  {
                      buf[0] = 0;
                      len = 1;
                      eof = true;
                  }

                  inf.setInput(buf, 0, len);
              }

              private boolean eof = false;
          };
      }
      if (this.getAlgorithm() == BZIP2)
      {
          try
          {
              return new CBZip2InputStream(this.getInputStream());
          }
          catch (IOException e)
          {
              throw new PGPException("I/O problem with stream: " + e, e);
          }
      }
        
      throw new PGPException("can't recognise compression algorithm: " + this.getAlgorithm());
    }
}
