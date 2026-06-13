package org.bouncycastle.openpgp;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.FilterInputStream;
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
import org.bouncycastle.util.io.StreamOverflowException;

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
     * <p>
     * The OpenPGP compressed data packet carries no decompressed-length field, so the returned
     * stream is unbounded: a small compressed packet can expand into an arbitrarily large amount
     * of data (a "decompression bomb"). When processing untrusted input, a caller that buffers
     * the full decompressed output should bound it &mdash; by reading incrementally, or by using
     * {@link #getDataStream(long)} to cap the number of decompressed bytes.
     * </p>
     *
     * @return a stream over the uncompressed data.
     * @throws PGPException if an error occurs constructing the decompression stream.
     */
    public InputStream getDataStream()
        throws PGPException
    {
        return createDataStream();
    }

    /**
     * Return an input stream that decompresses and returns data in the compressed packet,
     * failing with a {@link StreamOverflowException} (an {@link IOException}) once more than
     * {@code limit} decompressed bytes have been read. This caps the "decompression bomb"
     * amplification of an untrusted compressed packet for callers that buffer the decompressed
     * output.
     * <p>
     * The limit applies to the decompressed byte count. For BZIP2 the underlying decompressor
     * still allocates its fixed working buffers &mdash; sized by the packet's block-size header,
     * up to ~4.5MB &mdash; when the stream is constructed, independently of this limit.
     * </p>
     *
     * @param limit the maximum number of decompressed bytes that may be read, or a negative
     *              value for no limit (equivalent to {@link #getDataStream()}).
     * @return a stream over the uncompressed data, bounded to {@code limit} bytes.
     * @throws PGPException if an error occurs constructing the decompression stream.
     */
    public InputStream getDataStream(long limit)
        throws PGPException
    {
        InputStream dataIn = createDataStream();

        if (limit < 0)
        {
            return dataIn;
        }

        return new LimitedInputStream(dataIn, limit);
    }

    private InputStream createDataStream()
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

    private static class LimitedInputStream
        extends FilterInputStream
    {
        private long remaining;

        LimitedInputStream(InputStream input, long limit)
        {
            super(input);

            this.remaining = limit;
        }

        public int read()
            throws IOException
        {
            // Only a single 'extra' byte will ever be read
            if (remaining >= 0)
            {
                int b = super.in.read();
                if (b < 0 || --remaining >= 0)
                {
                    return b;
                }
            }

            throw new StreamOverflowException("decompressed data limit exceeded");
        }

        public int read(byte[] buf, int off, int len)
            throws IOException
        {
            if (len < 1)
            {
                // This will give correct exceptions/returns for strange lengths
                return super.read(buf, off, len);
            }

            if (remaining < 1)
            {
                // Will either return EOF or throw exception
                read();
                return -1;
            }

            /*
             * Limit the underlying request to 'remaining' bytes. This ensures the
             * caller will see the full 'limit' bytes before getting an exception.
             * Also, only one extra byte will ever be read.
             */
            int actualLen = (remaining > len ? len : (int)remaining);
            int numRead = super.in.read(buf, off, actualLen);
            if (numRead > 0)
            {
                remaining -= numRead;
            }
            return numRead;
        }
    }
}
