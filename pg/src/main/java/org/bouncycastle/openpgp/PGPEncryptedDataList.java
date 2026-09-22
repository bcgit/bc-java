package org.bouncycastle.openpgp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.bcpg.UnsupportedPacketVersionException;
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
    private static final Logger LOG = Logger.getLogger(PGPEncryptedDataList.class.getName());

    List<PGPEncryptedData> methods = new ArrayList<PGPEncryptedData>();
    InputStreamPacket data;

    /**
     * Construct an encrypted data packet holder, reading PGP encrypted method packets and an
     * encrypted data packet from a stream.
     * <p>
     * The first packet in the stream should be one of {@link PacketTags#SYMMETRIC_KEY_ENC_SESSION}
     * or {@link PacketTags#PUBLIC_KEY_ENC_SESSION}.
     * </p>
     *
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
     *
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
     *
     * @param pIn the PGP object stream being read.
     * @throws IOException if an error occurs reading from the PGP input.
     */
    public PGPEncryptedDataList(
        BCPGInputStream pIn)
        throws IOException
    {
        List list = new ArrayList();

        while (pIn.nextPacketTag() == PacketTags.PUBLIC_KEY_ENC_SESSION
            || pIn.nextPacketTag() == PacketTags.SYMMETRIC_KEY_ENC_SESSION)
        {
            try
            {
                list.add(pIn.readPacket());
            }
            catch (UnsupportedPacketVersionException e)
            {
                // Skip unknown packet versions
                if (LOG.isLoggable(Level.FINE))
                {
                    LOG.fine("skipping unknown session packet: " + e.getMessage());
                }
            }
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
     * Checks whether the packet is integrity protected.
     *
     * @return <code>true</code> if there is a modification detection code package associated with
     * this stream
     */
    public boolean isIntegrityProtected()
    {
        return data instanceof SymmetricEncIntegrityPacket;
    }

    /**
     * Gets the encryption method object at the specified index.
     *
     * @param index the encryption method to obtain (0 based).
     */
    public PGPEncryptedData get(
        int index)
    {
        return (PGPEncryptedData)methods.get(index);
    }

    public InputStreamPacket getEncryptedData()
    {
        return data;
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

    /**
     * Create a decryption method using a {@link PGPSessionKey}. This method can be used to decrypt messages which do not
     * contain a SKESK or PKESK packet using a session key.
     *
     * @return session key encrypted data
     */
    public PGPSessionKeyEncryptedData extractSessionKeyEncryptedData()
    {
        return new PGPSessionKeyEncryptedData(data);
    }

    /**
     * Create a decryption method using a {@link PGPSessionKey}, stating whether the session key was recovered
     * from a password. This method can be used to decrypt messages which do not contain a SKESK or PKESK packet
     * using a session key.
     * <p>
     * A session key recovered from a SKESK packet with the wrong passphrase is a well formed key which simply
     * decrypts to garbage, and on a SEIPD v1 (or SED) packet the legacy CFB "quick check" on the two repeated
     * prefix bytes is what detects that - so passing true here makes the wrong passphrase surface as a
     * {@link PGPDataValidationException} from {@link PGPSessionKeyEncryptedData#getDataStream(org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory)},
     * as it does when the same packet is decrypted in one step through {@link PGPPBEEncryptedData}, rather than
     * as a parse failure further down the stream.
     * </p><p>
     * It must be passed true only for a session key that was recovered from a password. Reporting the quick
     * check for a session key that came from a public key operation - one recovered from a PKESK packet, or one
     * held from an earlier decryption - re-creates the Mister-Zuccherato oracle on the CFB prefix, which is why
     * {@link #extractSessionKeyEncryptedData()} never reports it. A SEIPD v2 (AEAD) packet carries no such
     * check and is unaffected either way.
     * </p>
     *
     * @param passwordDerivedSessionKey true if the session key was recovered from a password (a SKESK packet),
     *                                  false if it came from a public key operation or from anywhere else.
     * @return session key encrypted data
     */
    public PGPSessionKeyEncryptedData extractSessionKeyEncryptedData(boolean passwordDerivedSessionKey)
    {
        return new PGPSessionKeyEncryptedData(data, passwordDerivedSessionKey);
    }
}
