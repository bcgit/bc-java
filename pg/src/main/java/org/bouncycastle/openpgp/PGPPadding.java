package org.bouncycastle.openpgp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.bcpg.PaddingPacket;
import org.bouncycastle.crypto.CryptoServicesRegistrar;

/**
 * The PGPPadding contains random data, and can be used to defend against traffic analysis on version 2 SEIPD messages
 * and Transferable Public Keys.
 * <p>
 * Such a padding packet MUST be ignored when received.
 */
public class PGPPadding
{
    private PaddingPacket p;

    /**
     * Minimum random padding length in octets.
     * Chosen totally arbitrarily.
     */
    public static final int MIN_PADDING_LEN = 16;

    /**
     * Maximum random padding length.
     * Chosen somewhat arbitrarily, as SSH also uses max 255 bytes for random padding.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4253.html#section-6">
     *     rfc4253 - Binary Packet Protocol</a>
     */
    public static final int MAX_PADDING_LEN = 255;

    /**
     * Default constructor.
     *
     * @param in packet input stream
     * @throws IOException
     */
    public PGPPadding(
        BCPGInputStream in)
        throws IOException
    {
        Packet packet = in.readPacket();
        if (!(packet instanceof PaddingPacket))
        {
            throw new IOException("unexpected packet in stream: " + packet);
        }
        p = (PaddingPacket)packet;
    }

    /**
     * Generate a new, random {@link PGPPadding} object.
     * The padding consists of n random bytes, where n is a number between (inclusive) {@link #MIN_PADDING_LEN}
     * and {@link #MAX_PADDING_LEN}.
     */
    public PGPPadding()
    {
        this(CryptoServicesRegistrar.getSecureRandom());
    }

    /**
     * Generate a new, random {@link PGPPadding} object.
     * The padding consists of n random bytes, where n is a number between (inclusive) {@link #MIN_PADDING_LEN}
     * and {@link #MAX_PADDING_LEN}.
     *
     * @param random random number generator instance
     */
    public PGPPadding(SecureRandom random)
    {
        this(MIN_PADDING_LEN + random.nextInt(MAX_PADDING_LEN - MIN_PADDING_LEN + 1), random);
    }

    /**
     * Generate a new, random {@link PGPPadding} object.
     * The padding consists of <pre>len</pre> random bytes.
     */
    public PGPPadding(int len)
    {
        this(len, CryptoServicesRegistrar.getSecureRandom());
    }

    /**
     * Generate a new, random {@link PGPPadding} object.
     * The padding consists of <pre>len</pre> random bytes.
     *
     * @param len number of random octets
     * @param random random number generator instance
     */
    public PGPPadding(int len, SecureRandom random)
    {
        this.p = new PaddingPacket(len, random);
    }

    /**
     * Return the padding octets as a byte array.
     * @return padding octets
     */
    public byte[] getPadding()
    {
        return p.getPadding();
    }

    public void encode(OutputStream outStream)
            throws IOException
    {
        BCPGOutputStream pOut = BCPGOutputStream.wrap(outStream);
        p.encode(pOut);
    }

    public byte[] getEncoded()
        throws IOException
    {
        return getEncoded(PacketFormat.ROUNDTRIP);
    }

    public byte[] getEncoded(PacketFormat format)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut, format);
        encode(pOut);
        pOut.close();
        return bOut.toByteArray();
    }
}
