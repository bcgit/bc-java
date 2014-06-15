package org.bouncycastle.openpgp;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;

/**
 * A holder for a list of PGP encryption method packets and the encrypted data associated with them.
 * <p/>
 * This holder supports reading a sequence of the following encryption methods, followed by an
 * encrypted data packet:
 * <ul>
 * <li>{@link PacketTags#SYMMETRIC_KEY_ENC_SESSION} - produces a {@link PGPPBEEncryptedData}</li>
 * <li>{@link PacketTags#PUBLIC_KEY_ENC_SESSION} - produces a {@link PGPPublicKeyEncryptedData}</li>
 * </ul>
 * <p/>
 * All of the objects returned from this holder share a reference to the same encrypted data input
 * stream, which can only be consumed once.
 */
public class PGPEncryptedDataList
{
    List                 list = new ArrayList();
    InputStreamPacket    data;

    /**
     * Construct an encrypted data packet holder, reading PGP encrypted method packets and an
     * encrytped data packet from the stream.
     * <p/>
     * The next packet in the stream should be one of {@link PacketTags#SYMMETRIC_KEY_ENC_SESSION}
     * or {@link PacketTags#PUBLIC_KEY_ENC_SESSION}.
     *
     * @param pIn the PGP object stream being read.
     * @throws IOException if an error occurs reading from the PGP input.
     */
    public PGPEncryptedDataList(
        BCPGInputStream    pIn)
        throws IOException
    {
        while (pIn.nextPacketTag() == PacketTags.PUBLIC_KEY_ENC_SESSION
            || pIn.nextPacketTag() == PacketTags.SYMMETRIC_KEY_ENC_SESSION)
        {
            list.add(pIn.readPacket());
        }

        data = (InputStreamPacket)pIn.readPacket();

        for (int i = 0; i != list.size(); i++)
        {
            if (list.get(i) instanceof SymmetricKeyEncSessionPacket)
            {
                list.set(i, new PGPPBEEncryptedData((SymmetricKeyEncSessionPacket)list.get(i), data));
            }
            else
            {
                list.set(i, new PGPPublicKeyEncryptedData((PublicKeyEncSessionPacket)list.get(i), data));
            }
        }
    }

    /**
     * Gets the encryption method object at the specified index.
     *
     * @param index the encryption method to obtain (0 based).
     */
    public Object get(
        int    index)
    {
        return list.get(index);
    }

    /**
     * Gets the number of encryption methods in this list.
     */
    public int size()
    {
        return list.size();
    }

    /**
     * Returns <code>true</code> iff there are 0 encryption methods in this list.
     */
    public boolean isEmpty()
    {
        return list.isEmpty();
    }

    /**
     * @deprecated misspelt - use getEncryptedDataObjects()
     */
    public Iterator getEncyptedDataObjects()
    {
        return list.iterator();
    }

    /**
     * Returns an iterator over the encryption method objects held in this list, in the order they
     * appeared in the stream they are read from.
     */
    public Iterator getEncryptedDataObjects()
    {
        return list.iterator();
    }
}
