package org.bouncycastle.openpgp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.util.Iterable;

/**
 * A holder for a list of PGP encryption method packets and the encrypted data associated with them.
 * <p>
 * This holder supports reading a sequence of the following encryption methods, followed by an
 * encrypted data packet:</p>
 * <ul>
 * <li>{@link PacketTags#SYMMETRIC_KEY_ENC_SESSION} - produces a {@link PGPPBEEncryptedData}</li>
 * <li>{@link PacketTags#PUBLIC_KEY_ENC_SESSION} - produces a {@link PGPPublicKeyEncryptedData}</li>
 * </ul>
 * <p>
 * All of the objects returned from this holder share a reference to the same encrypted data input
 * stream, which can only be consumed once.
 * </p>
 */
public class PGPEncryptedDataList
    implements Iterable<PGPEncryptedData>
{
    List<PGPEncryptedData> methods = new ArrayList<PGPEncryptedData>();
    InputStreamPacket      data;

    /**
     * Construct an encrypted data packet holder, reading PGP encrypted method packets and an
     * encrypted data packet from a stream.
     * <p>
     * The first packet in the stream should be one of {@link PacketTags#SYMMETRIC_KEY_ENC_SESSION}
     * or {@link PacketTags#PUBLIC_KEY_ENC_SESSION}.
     * </p>
     * @param encData a byte array containing an encrypted stream.
     * @throws IOException if an error occurs reading from the PGP input.
     */
    public PGPEncryptedDataList(
        byte[] encData)
        throws IOException
    {
        this(Util.createBCPGInputStream(new ByteArrayInputStream(encData), PacketTags.PUBLIC_KEY_ENC_SESSION, PacketTags.SYMMETRIC_KEY_ENC_SESSION));
    }

    /**
     * Construct an encrypted data packet holder, reading PGP encrypted method packets and an
     * encrypted data packet from a stream.
     * <p>
     * The first packet in the stream should be one of {@link PacketTags#SYMMETRIC_KEY_ENC_SESSION}
     * or {@link PacketTags#PUBLIC_KEY_ENC_SESSION}.
     * </p>
     * @param inStream the input stream being read.
     * @throws IOException if an error occurs reading from the PGP input.
     */
    public PGPEncryptedDataList(
        InputStream inStream)
        throws IOException
    {
        this(Util.createBCPGInputStream(inStream, PacketTags.PUBLIC_KEY_ENC_SESSION, PacketTags.SYMMETRIC_KEY_ENC_SESSION));
    }

    /**
     * Construct an encrypted data packet holder, reading PGP encrypted method packets and an
     * encrypted data packet from the stream.
     * <p>
     * The next packet in the stream should be one of {@link PacketTags#SYMMETRIC_KEY_ENC_SESSION}
     * or {@link PacketTags#PUBLIC_KEY_ENC_SESSION}.
     * </p>
     * @param pIn the PGP object stream being read.
     * @throws IOException if an error occurs reading from the PGP input.
     */
    public PGPEncryptedDataList(
        BCPGInputStream    pIn)
        throws IOException
    {
        List list = new ArrayList();

        while (pIn.nextPacketTag() == PacketTags.PUBLIC_KEY_ENC_SESSION
            || pIn.nextPacketTag() == PacketTags.SYMMETRIC_KEY_ENC_SESSION)
        {
            list.add(pIn.readPacket());
        }

        Packet packet = pIn.readPacket();
        if (!(packet instanceof InputStreamPacket))
        {
            throw new IOException("unexpected packet in stream: " + packet);
        }

        data = (InputStreamPacket)packet;

        for (int i = 0; i != list.size(); i++)
        {
            if (list.get(i) instanceof SymmetricKeyEncSessionPacket)
            {
                methods.add(new PGPPBEEncryptedData((SymmetricKeyEncSessionPacket)list.get(i), data));
            }
            else
            {
                methods.add(new PGPPublicKeyEncryptedData((PublicKeyEncSessionPacket)list.get(i), data));
            }
        }
    }

    /**
     * Gets the encryption method object at the specified index.
     *
     * @param index the encryption method to obtain (0 based).
     */
    public PGPEncryptedData get(
        int    index)
    {
        return (PGPEncryptedData)methods.get(index);
    }

    /**
     * Gets the number of encryption methods in this list.
     */
    public int size()
    {
        return methods.size();
    }

    /**
     * Returns <code>true</code> iff there are 0 encryption methods in this list.
     */
    public boolean isEmpty()
    {
        return methods.isEmpty();
    }

    /**
     * Returns an iterator over the encryption method objects held in this list, in the order they
     * appeared in the stream they are read from.
     */
    public Iterator<PGPEncryptedData> getEncryptedDataObjects()
    {
        return methods.iterator();
    }

    /**
     * Support method for Iterable where available.
     */
    public Iterator<PGPEncryptedData> iterator()
    {
        return getEncryptedDataObjects();
    }
}
