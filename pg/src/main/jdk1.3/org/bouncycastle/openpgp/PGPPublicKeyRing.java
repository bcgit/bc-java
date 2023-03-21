package org.bouncycastle.openpgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
//import java.util.logging.Level;
//import java.util.logging.Logger;

import org.bouncycastle.bcpg.ArmoredInputException;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.TrustPacket;
import org.bouncycastle.bcpg.UserDataPacket;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Iterable;
import org.bouncycastle.util.Longs;

/**
 * Class to hold a single master public key and its subkeys.
 * <p>
 * Often PGP keyring files consist of multiple master keys, if you are trying to process
 * or construct one of these you should use the PGPPublicKeyRingCollection class.
 */
public class PGPPublicKeyRing
    extends PGPKeyRing
    implements Iterable<PGPPublicKey>
{
    //private static final Logger LOG = Logger.getLogger(PGPPublicKeyRing.class.getName());

    List<PGPPublicKey> keys;

    public PGPPublicKeyRing(
        byte[] encoding,
        KeyFingerPrintCalculator fingerPrintCalculator)
        throws IOException
    {
        this(new ByteArrayInputStream(encoding), fingerPrintCalculator);
    }

    private static List<PGPPublicKey> checkKeys(List<PGPPublicKey> keys)
    {
        List<PGPPublicKey> rv = new ArrayList<PGPPublicKey>(keys.size());

        for (int i = 0; i != keys.size(); i++)
        {
            PGPPublicKey k = (PGPPublicKey)keys.get(i);

            if (i == 0)
            {
                if (!k.isMasterKey())
                {
                    throw new IllegalArgumentException("key 0 must be a master key");
                }
            }
            else
            {
                if (k.isMasterKey())
                {
                    throw new IllegalArgumentException("key 0 can be only master key");
                }
            }
            rv.add(k);
        }

        return rv;
    }

    /**
     * Base constructor from a list of keys representing a public key ring (a master key and its
     * associated sub-keys).
     *
     * @param pubKeys the list of keys making up the ring.
     */
    public PGPPublicKeyRing(
        List<PGPPublicKey> pubKeys)
    {
        this.keys = checkKeys(pubKeys);
    }

    public PGPPublicKeyRing(
        InputStream in,
        KeyFingerPrintCalculator fingerPrintCalculator)
        throws IOException
    {
        this.keys = new ArrayList<PGPPublicKey>();

        BCPGInputStream pIn = BCPGInputStream.wrap(in);

        int initialTag = pIn.skipMarkerPackets();
        if (initialTag != PacketTags.PUBLIC_KEY && initialTag != PacketTags.PUBLIC_SUBKEY)
        {
            throw new IOException(
                "public key ring doesn't start with public key tag: " +
                    "tag 0x" + Integer.toHexString(initialTag));
        }

        PublicKeyPacket pubPk = readPublicKeyPacket(pIn);
        TrustPacket trustPk = readOptionalTrustPacket(pIn);

        // direct signatures and revocations
        List<PGPSignature> keySigs = readSignaturesAndTrust(pIn);

        List<UserDataPacket> ids = new ArrayList<UserDataPacket>();
        List<TrustPacket> idTrusts = new ArrayList<TrustPacket>();
        List<List<PGPSignature>> idSigs = new ArrayList<List<PGPSignature>>();
        readUserIDs(pIn, ids, idTrusts, idSigs);

        try
        {
            keys.add(new PGPPublicKey(pubPk, trustPk, keySigs, ids, idTrusts, idSigs, fingerPrintCalculator));

            // Read subkeys
            while (pIn.nextPacketTag() == PacketTags.PUBLIC_SUBKEY)
            {
                // unrecognizable subkeys, where the packet can be loaded, will be ignored.
                PGPPublicKey publicKey = readSubkey(pIn, fingerPrintCalculator);
                if (publicKey != null)
                {
                    keys.add(publicKey);
                }
            }
        }
        catch (PGPException e)
        {
            throw new IOException("processing exception: " + e.toString());
        }
    }

    /**
     * Return the first public key in the ring.
     *
     * @return PGPPublicKey
     */
    public PGPPublicKey getPublicKey()
    {
        return (PGPPublicKey)keys.get(0);
    }

    /**
     * Return the public key referred to by the passed in keyID if it
     * is present.
     *
     * @param keyID the full keyID of the key of interest.
     * @return PGPPublicKey with matching keyID, null if it is not present.
     */
    public PGPPublicKey getPublicKey(
        long keyID)
    {
        for (int i = 0; i != keys.size(); i++)
        {
            PGPPublicKey k = (PGPPublicKey)keys.get(i);

            if (keyID == k.getKeyID())
            {
                return k;
            }
        }

        return null;
    }

    /**
     * Return the public key with the passed in fingerprint if it
     * is present.
     *
     * @param fingerprint the full fingerprint of the key of interest.
     * @return PGPPublicKey with the matching fingerprint, null if it is not present.
     */
    public PGPPublicKey getPublicKey(byte[] fingerprint)
    {
        for (int i = 0; i != keys.size(); i++)
        {
            PGPPublicKey k = (PGPPublicKey)keys.get(i);

            if (Arrays.areEqual(fingerprint, k.getFingerprint()))
            {
                return k;
            }
        }

        return null;
    }

    /**
     * Return any keys carrying a signature issued by the key represented by keyID.
     *
     * @param keyID the key id to be matched against.
     * @return an iterator (possibly empty) of PGPPublicKey objects carrying signatures from keyID.
     */
    public Iterator<PGPPublicKey> getKeysWithSignaturesBy(long keyID)
    {
        List<PGPPublicKey> keysWithSigs = new ArrayList<PGPPublicKey>();

        for (int i = 0; i != keys.size(); i++)
        {
            PGPPublicKey k = (PGPPublicKey)keys.get(i);

            Iterator<PGPSignature> sigIt = k.getSignaturesForKeyID(keyID);

            if (sigIt.hasNext())
            {
                keysWithSigs.add(k);
            }
        }

        return keysWithSigs.iterator();
    }

    /**
     * Return an iterator containing all the public keys.
     *
     * @return Iterator
     */
    public Iterator<PGPPublicKey> getPublicKeys()
    {
        return Collections.unmodifiableList(keys).iterator();
    }

    /**
     * Support method for Iterable where available.
     */
    public Iterator<PGPPublicKey> iterator()
    {
        return getPublicKeys();
    }

    public byte[] getEncoded()
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        this.encode(bOut);

        return bOut.toByteArray();
    }

    /**
     * Return an encoding of the key ring, with trust packets stripped out if forTransfer is true.
     *
     * @param forTransfer if the purpose of encoding is to send key to other users.
     * @return a encoded byte array representing the key.
     * @throws IOException in case of encoding error.
     */
    public byte[] getEncoded(boolean forTransfer)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        this.encode(bOut, forTransfer);

        return bOut.toByteArray();
    }

    public void encode(
        OutputStream outStream)
        throws IOException
    {
        encode(outStream, false);
    }

    /**
     * Encode the key ring to outStream, with trust packets stripped out if forTransfer is true.
     *
     * @param outStream   stream to write the key encoding to.
     * @param forTransfer if the purpose of encoding is to send key to other users.
     * @throws IOException in case of encoding error.
     */
    public void encode(
        OutputStream outStream,
        boolean forTransfer)
        throws IOException
    {
        for (int i = 0; i != keys.size(); i++)
        {
            PGPPublicKey k = (PGPPublicKey)keys.get(i);

            k.encode(outStream, forTransfer);
        }
    }

    /**
     * Returns a new key ring with the public key passed in
     * either added or replacing an existing one.
     *
     * @param pubRing the public key ring to be modified
     * @param pubKey  the public key to be inserted.
     * @return a new keyRing
     */
    public static PGPPublicKeyRing insertPublicKey(
        PGPPublicKeyRing pubRing,
        PGPPublicKey pubKey)
    {
        List<PGPPublicKey> keys = new ArrayList<PGPPublicKey>(pubRing.keys);
        boolean found = false;
        boolean masterFound = false;

        for (int i = 0; i != keys.size(); i++)
        {
            PGPPublicKey key = (PGPPublicKey)keys.get(i);

            if (key.getKeyID() == pubKey.getKeyID())
            {
                found = true;
                keys.set(i, pubKey);
            }
            if (key.isMasterKey())
            {
                masterFound = true;
            }
        }

        if (!found)
        {
            if (pubKey.isMasterKey())
            {
                if (masterFound)
                {
                    throw new IllegalArgumentException("cannot add a master key to a ring that already has one");
                }

                keys.add(0, pubKey);
            }
            else
            {
                keys.add(pubKey);
            }
        }

        return new PGPPublicKeyRing(keys);
    }

    /**
     * Returns a new key ring with the public key passed in
     * removed from the key ring.
     *
     * @param pubRing the public key ring to be modified
     * @param pubKey  the public key to be removed.
     * @return a new keyRing, null if pubKey is not found.
     */
    public static PGPPublicKeyRing removePublicKey(
        PGPPublicKeyRing pubRing,
        PGPPublicKey pubKey)
    {
        int count = pubRing.keys.size();
        long keyID = pubKey.getKeyID();

        ArrayList<PGPPublicKey> result = new ArrayList<PGPPublicKey>(count);
        boolean found = false;

        for (int i = 0; i < count; ++i)
        {
            PGPPublicKey key = (PGPPublicKey)pubRing.keys.get(i);

            if (key.getKeyID() == keyID)
            {
                found = true;
                continue;
            }

            result.add(key);
        }

        if (!found)
        {
            return null;
        }

        return new PGPPublicKeyRing(result);
    }

    static PublicKeyPacket readPublicKeyPacket(BCPGInputStream in)
        throws IOException
    {
        Packet packet = in.readPacket();
        if (!(packet instanceof PublicKeyPacket))
        {
            throw new IOException("unexpected packet in stream: " + packet);
        }

        return (PublicKeyPacket)packet;
    }

    static PGPPublicKey readSubkey(BCPGInputStream in, KeyFingerPrintCalculator fingerPrintCalculator)
        throws IOException, PGPException
    {
        try
        {
            PublicKeyPacket pk = readPublicKeyPacket(in);
            TrustPacket kTrust = readOptionalTrustPacket(in);

            // PGP 8 actually leaves out the signature.
            List<PGPSignature> sigList = readSignaturesAndTrust(in);

            return new PGPPublicKey(pk, kTrust, sigList, fingerPrintCalculator);
        }
        catch (EOFException e)
        {
            throw e;
        }
        catch (ArmoredInputException e)
        {
            throw e;
        }
        catch (IOException e)
        {
            // Skip unrecognizable subkey
//            if (LOG.isLoggable(Level.FINE))
//            {
//                LOG.fine("skipping unknown subkey: " + e.getMessage());
//            }
            return null;
        }
    }

    /**
     * Join two copies of the same certificate.
     * The certificates must have the same primary key, but may carry different subkeys, user-ids and signatures.
     * The resulting certificate will carry the sum of both certificates subkeys, user-ids and signatures.
     * <p>
     * This method will ignore trust packets on the second copy of the certificate and instead
     * copy the local certificate's trust packets to the joined certificate.
     *
     * @param first  local copy of the certificate
     * @param second remote copy of the certificate (e.g. from a key server)
     * @return joined key ring
     * @throws PGPException
     */
    public static PGPPublicKeyRing join(
        PGPPublicKeyRing first,
        PGPPublicKeyRing second)
        throws PGPException
    {
        return join(first, second, false, false);
    }

    /**
     * Join two copies of the same certificate.
     * The certificates must have the same primary key, but may carry different subkeys, user-ids and signatures.
     * The resulting certificate will carry the sum of both certificates subkeys, user-ids and signatures.
     * <p>
     * For each subkey holds: If joinTrustPackets is set to true and the second key is carrying a trust packet,
     * the trust packet will be copied to the joined key.
     * Otherwise, the joined key will carry the trust packet of the local copy.
     *
     * @param first                      local copy of the certificate
     * @param second                     remote copy of the certificate (e.g. from a key server)
     * @param joinTrustPackets           if true, trust packets from the second certificate copy will be carried over into the joined certificate
     * @param allowSubkeySigsOnNonSubkey if true, the resulting joined certificate may carry subkey signatures on its primary key
     * @return joined certificate
     * @throws PGPException
     */
    public static PGPPublicKeyRing join(
        PGPPublicKeyRing first,
        PGPPublicKeyRing second,
        boolean joinTrustPackets,
        boolean allowSubkeySigsOnNonSubkey)
        throws PGPException
    {
        if (!Arrays.areEqual(first.getPublicKey().getFingerprint(), second.getPublicKey().getFingerprint()))
        {
            throw new IllegalArgumentException("Cannot merge certificates with differing primary keys.");
        }

        Set<Long> secondKeys = new HashSet<Long>();
        for (Iterator<PGPPublicKey> it = second.iterator(); it.hasNext(); )
        {
            PGPPublicKey key = (PGPPublicKey)it.next();
            secondKeys.add(Longs.valueOf(key.getKeyID()));
        }

        List<PGPPublicKey> merged = new ArrayList<PGPPublicKey>();
        for (Iterator<PGPPublicKey> it = first.iterator(); it.hasNext(); )
        {
            PGPPublicKey key = (PGPPublicKey)it.next();
            PGPPublicKey copy = second.getPublicKey(key.getKeyID());
            if (copy != null)
            {
                merged.add(PGPPublicKey.join(key, copy, joinTrustPackets, allowSubkeySigsOnNonSubkey));
                secondKeys.remove(Longs.valueOf(key.getKeyID()));
            }
            else
            {
                merged.add(key);
            }
        }

        for (Iterator<Long> it = secondKeys.iterator(); it.hasNext(); )
        {
            Long additionalKeyId = (Long)it.next();
            merged.add(second.getPublicKey(additionalKeyId.longValue()));
        }

        return new PGPPublicKeyRing(merged);
    }
}
