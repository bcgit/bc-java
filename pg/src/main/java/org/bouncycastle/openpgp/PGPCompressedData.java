package org.bouncycastle.openpgp;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import org.bouncycastle.apache.bzip2.CBZip2InputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.CompressedDataPacket;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.bcpg.PacketTags;

/**
 * A PGP compressed data object.
 */
public class PGPCompressedData
    implements CompressionAlgorithmTags
{
    CompressedDataPacket    data;

    /**
     * Construct a PGP compressed data object from the passed in byte array.
     *
     * @param encData an encoding of PGP compressed data.
     * @throws IOException if an error occurs reading from the PGP input.
     */
    public PGPCompressedData(
        byte[]    encData)
        throws IOException
    {
        this(Util.createBCPGInputStream(new ByteArrayInputStream(encData), PacketTags.COMPRESSED_DATA));
    }

    /**
     * Construct a PGP compressed data object from the passed in input stream.
     *
     * @param inStream an input stream containing an encoding of PGP compressed data.
     * @throws IOException if an error occurs reading from the PGP input.
     */
    public PGPCompressedData(
        InputStream    inStream)
        throws IOException
    {
        this(Util.createBCPGInputStream(inStream, PacketTags.COMPRESSED_DATA));
    }

    /**
     * Construct a compressed data object, reading a single {@link PacketTags#COMPRESSED_DATA}
     * packet from the stream.
     *
     * @param pIn a PGP input stream, with a compressed data packet as the current packet.
     * @throws IOException if an error occurs reading the packet from the stream.
     */
    public PGPCompressedData(
        BCPGInputStream    pIn)
        throws IOException
    {

        Packet packet = pIn.readPacket();
        if (!(packet instanceof CompressedDataPacket))
        {
            throw new IOException("unexpected packet in stream: " + packet);
        }
        data = (CompressedDataPacket)packet;
    }

    /**
     * Return the {@link CompressionAlgorithmTags compression algorithm} used for this packet.
     *
     * @return the compression algorithm code
     */
    public int getAlgorithm()
    {
        return data.getAlgorithm();
    }

    /**
     * Return the raw input stream contained in the object.
     * <p>
     * Note that this stream is shared with the decompression stream, so consuming the returned
     * stream will affect decompression.
     * </p>
     * @return the raw data in the compressed data packet.
     */
    public InputStream getInputStream()
    {
        return data.getInputStream();
    }

    /**
     * Return an input stream that decompresses and returns data in the compressed packet.
     *
     * @return a stream over the uncompressed data.
     * @throws PGPException if an error occurs constructing the decompression stream.
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
