package javax.crypto;

import java.io.OutputStream;
import java.io.IOException;
import java.io.FilterOutputStream;

/**
 * A CipherOutputStream is composed of an OutputStream and a Cipher so
 * that write() methods first process the data before writing them out
 * to the underlying OutputStream.  The cipher must be fully
 * initialized before being used by a CipherOutputStream.
 * <p>
 * For example, if the cipher is initialized for encryption, the
 * CipherOutputStream will attempt to encrypt data before writing out the
 * encrypted data.
 * <p>
 * This class adheres strictly to the semantics, especially the
 * failure semantics, of its ancestor classes
 * java.io.OutputStream and java.io.FilterOutputStream.  This class
 * has exactly those methods specified in its ancestor classes, and
 * overrides them all.  Moreover, this class catches all exceptions
 * that are not thrown by its ancestor classes.
 * <p>
 * It is crucial for a programmer using this class not to use
 * methods that are not defined or overriden in this class (such as a
 * new method or constructor that is later added to one of the super
 * classes), because the design and implementation of those methods
 * are unlikely to have considered security impact with regard to
 * CipherOutputStream.
 *
 * @since JCE1.2
 * @see OutputStream
 * @see FilterOutputStream
 * @see Cipher
 * @see CipherInputStream
 */
public class CipherOutputStream
    extends FilterOutputStream
{
    private Cipher          c;

    private byte[]          oneByte = new byte[1];

    /**
     * Constructs a CipherOutputStream from an OutputStream and a
     * Cipher.
     */
    public CipherOutputStream(
        OutputStream    os,
        Cipher          c)
    {
        super(os);
        this.c = c;
    }

    /**
     * Constructs a CipherOutputStream from an OutputStream without
     * specifying a Cipher. This has the effect of constructing a
     * CipherOutputStream using a NullCipher.
     */
    protected CipherOutputStream(
        OutputStream    os)
    {
        this(os, new NullCipher());
    }

    /**
     * Writes the specified byte to this output stream.
     *
     * @param b the <code>byte</code>.
     * @exception IOException if an I/O error occurs.
     * @since JCE1.2
     */
    public void write(
        int b)
    throws IOException
    {
        oneByte[0] = (byte)b;

        byte[] bytes = c.update(oneByte, 0, 1);

        if (bytes != null)
        {
            out.write(bytes, 0, bytes.length);
        }
    }

    /**
     * Writes <code>b.length</code> bytes from the specified byte array 
     * to this output stream. 
     * <p>
     * The <code>write</code> method of
     * <code>CipherOutputStream</code> calls the <code>write</code>
     * method of three arguments with the three arguments
     * <code>b</code>, <code>0</code>, and <code>b.length</code>.
     *
     * @param b the data.
     * @exception IOException if an I/O error occurs.
     * @since JCE1.2
     * @see #write(byte[], int, int)
     */
    public void write(
        byte[]  b)
    throws IOException
    {
        write(b, 0, b.length);
    }

    /**
     * Writes <code>len</code> bytes from the specified byte array 
     * starting at offset <code>off</code> to this output stream.
     *
     * @param b the data.
     * @param off the start offset in the data.
     * @param len the number of bytes to write.
     * @exception IOException if an I/O error occurs.
     * @since JCE1.2
     */
    public void write(
        byte[]  b,
        int     off,
        int     len)
    throws IOException
    {
        byte[] bytes = c.update(b, off, len);

        if (bytes != null)
        {
            out.write(bytes, 0, bytes.length);
        }
    }

    /**
     * Flushes this output stream by forcing any buffered output bytes 
     * that have already been processed by the encapsulated cipher object
     * to be written out.
     * 
     * <p>
     * Any bytes buffered by the encapsulated cipher
     * and waiting to be processed by it will not be written out. For example,
     * if the encapsulated cipher is a block cipher, and the total number of
     * bytes written using one of the <code>write</code> methods is less than
     * the cipher's block size, no bytes will be written out.
     *
     * @exception IOException if an I/O error occurs.
     * @since JCE1.2
     */
    public void flush()
    throws IOException
    {
        super.flush();
    }

    /**
     * Closes this output stream and releases any system resources 
     * associated with this stream.
     * <p>
     * This method invokes the <code>doFinal</code> method of the encapsulated
     * cipher object, which causes any bytes buffered by the encapsulated
     * cipher to be processed. The result is written out by calling the
     * <code>flush</code> method of this output stream.
     * <p>
     * This method resets the encapsulated cipher object to its initial state
     * and calls the <code>close</code> method of the underlying output
     * stream.
     *
     * @exception IOException if an I/O error occurs.
     * @since JCE1.2
     */
    public void close()
           throws IOException
    {
        try
        {
                byte[]  bytes = c.doFinal();

                if (bytes != null)
                {
                    out.write(bytes, 0, bytes.length);
                }
        }
        catch (Exception e)
        {
            throw new IOException("Error closing stream: " + e.toString());
        }

        flush();

        super.close();
    }
}
