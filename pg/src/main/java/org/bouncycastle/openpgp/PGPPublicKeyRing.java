package org.bouncycastle.openpgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.TrustPacket;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Iterable;

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
    List keys;

    public PGPPublicKeyRing(
        byte[]    encoding,
        KeyFingerPrintCalculator fingerPrintCalculator)
        throws IOException
    {
        this(new ByteArrayInputStream(encoding), fingerPrintCalculator);
    }

    private static List checkKeys(List keys)
    {
        List rv = new ArrayList(keys.size());

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
        List pubKeys)
    {
        this.keys = checkKeys(pubKeys);
    }

    public PGPPublicKeyRing(
        InputStream    in,
        KeyFingerPrintCalculator fingerPrintCalculator)
        throws IOException
    {
        this.keys = new ArrayList();

        BCPGInputStream pIn = wrap(in);

        int initialTag = pIn.nextPacketTag();
        if (initialTag != PacketTags.PUBLIC_KEY && initialTag != PacketTags.PUBLIC_SUBKEY)
        {
            throw new IOException(
                "public key ring doesn't start with public key tag: " +
                "tag 0x" + Integer.toHexString(initialTag));
        }

        PublicKeyPacket pubPk = readPublicKeyPacket(pIn);
        TrustPacket     trustPk = readOptionalTrustPacket(pIn);

        // direct signatures and revocations
        List keySigs = readSignaturesAndTrust(pIn);

        List ids = new ArrayList();
        List idTrusts = new ArrayList();
        List idSigs = new ArrayList();
        readUserIDs(pIn, ids, idTrusts, idSigs);

        try
        {
            keys.add(new PGPPublicKey(pubPk, trustPk, keySigs, ids, idTrusts, idSigs, fingerPrintCalculator));

            // Read subkeys
            while (pIn.nextPacketTag() == PacketTags.PUBLIC_SUBKEY)
            {
                keys.add(readSubkey(pIn, fingerPrintCalculator));
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
        long        keyID)
    {    
        for (int i = 0; i != keys.size(); i++)
        {
            PGPPublicKey    k = (PGPPublicKey)keys.get(i);
            
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
            PGPPublicKey    k = (PGPPublicKey)keys.get(i);

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
        List keysWithSigs = new ArrayList();

        for (int i = 0; i != keys.size(); i++)
        {
            PGPPublicKey    k = (PGPPublicKey)keys.get(i);

            Iterator sigIt = k.getSignaturesForKeyID(keyID);

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
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        
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
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();

        this.encode(bOut, forTransfer);

        return bOut.toByteArray();
    }

    public void encode(
        OutputStream    outStream)
        throws IOException
    {
        encode(outStream, false);
    }

    /**
     * Encode the key ring to outStream, with trust packets stripped out if forTransfer is true.
     *
     * @param outStream stream to write the key encoding to.
     * @param forTransfer if the purpose of encoding is to send key to other users.
     * @throws IOException in case of encoding error.
     */
    public void encode(
        OutputStream    outStream,
        boolean         forTransfer)
        throws IOException
    {
        for (int i = 0; i != keys.size(); i++)
        {
            PGPPublicKey    k = (PGPPublicKey)keys.get(i);

            k.encode(outStream, forTransfer);
        }
    }
    
    /**
     * Returns a new key ring with the public key passed in
     * either added or replacing an existing one.
     * 
     * @param pubRing the public key ring to be modified
     * @param pubKey the public key to be inserted.
     * @return a new keyRing
     */
    public static PGPPublicKeyRing insertPublicKey(
        PGPPublicKeyRing  pubRing,
        PGPPublicKey      pubKey)
    {
        List       keys = new ArrayList(pubRing.keys);
        boolean    found = false;
        boolean    masterFound = false;

        for (int i = 0; i != keys.size();i++)
        {
            PGPPublicKey   key = (PGPPublicKey)keys.get(i);
            
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
     * @param pubKey the public key to be removed.
     * @return a new keyRing, null if pubKey is not found.
     */
    public static PGPPublicKeyRing removePublicKey(
        PGPPublicKeyRing  pubRing,
        PGPPublicKey      pubKey)
    {
        List       keys = new ArrayList(pubRing.keys);
        boolean    found = false;
        
        for (int i = 0; i < keys.size();i++)
        {
            PGPPublicKey   key = (PGPPublicKey)keys.get(i);
            
            if (key.getKeyID() == pubKey.getKeyID())
            {
                found = true;
                keys.remove(i);
            }
        }
        
        if (!found)
        {
            return null;
        }
        
        return new PGPPublicKeyRing(keys);
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
        PublicKeyPacket pk = readPublicKeyPacket(in);
        TrustPacket kTrust = readOptionalTrustPacket(in);

        // PGP 8 actually leaves out the signature.
        List sigList = readSignaturesAndTrust(in);

        return new PGPPublicKey(pk, kTrust, sigList, fingerPrintCalculator);
    }
}
