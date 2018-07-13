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
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.PublicSubkeyPacket;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SecretSubkeyPacket;
import org.bouncycastle.bcpg.TrustPacket;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Iterable;

/**
 * Class to hold a single master secret key and its subkeys.
 * <p>
 * Often PGP keyring files consist of multiple master keys, if you are trying to process
 * or construct one of these you should use the {@link PGPSecretKeyRingCollection} class.
 */
public class PGPSecretKeyRing
    extends PGPKeyRing
    implements Iterable<PGPSecretKey>
{    
    List keys;
    List extraPubKeys;

    private static List checkKeys(List keys)
    {
        List rv = new ArrayList(keys.size());

        for (int i = 0; i != keys.size(); i++)
        {
            PGPSecretKey k = (PGPSecretKey)keys.get(i);

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
     * Base constructor from a list of keys representing a secret key ring (a master key and its
     * associated sub-keys).
     *
     * @param secKeys the list of keys making up the ring.
     */
    public PGPSecretKeyRing(List secKeys)
    {
        this(checkKeys(secKeys), new ArrayList());
    }

    private PGPSecretKeyRing(List keys, List extraPubKeys)
    {
        this.keys = keys;
        this.extraPubKeys = extraPubKeys;
    }

    public PGPSecretKeyRing(
        byte[]    encoding,
        KeyFingerPrintCalculator fingerPrintCalculator)
        throws IOException, PGPException
    {
        this(new ByteArrayInputStream(encoding), fingerPrintCalculator);
    }

    public PGPSecretKeyRing(
        InputStream              in,
        KeyFingerPrintCalculator fingerPrintCalculator)
        throws IOException, PGPException
    {
        this.keys = new ArrayList();
        this.extraPubKeys = new ArrayList();

        BCPGInputStream pIn = wrap(in);

        int initialTag = pIn.nextPacketTag();
        if (initialTag != PacketTags.SECRET_KEY && initialTag != PacketTags.SECRET_SUBKEY)
        {
            throw new IOException(
                "secret key ring doesn't start with secret key tag: " +
                "tag 0x" + Integer.toHexString(initialTag));
        }

        SecretKeyPacket secret = (SecretKeyPacket)pIn.readPacket();

        //
        // ignore GPG comment packets if found.
        //
        while (pIn.nextPacketTag() == PacketTags.EXPERIMENTAL_2)
        {
            pIn.readPacket();
        }
        
        TrustPacket trust = readOptionalTrustPacket(pIn);

        // revocation and direct signatures
        List keySigs = readSignaturesAndTrust(pIn);

        List ids = new ArrayList();
        List idTrusts = new ArrayList();
        List idSigs = new ArrayList();
        readUserIDs(pIn, ids, idTrusts, idSigs);

        keys.add(new PGPSecretKey(secret, new PGPPublicKey(secret.getPublicKeyPacket(), trust, keySigs, ids, idTrusts, idSigs, fingerPrintCalculator)));


        // Read subkeys
        while (pIn.nextPacketTag() == PacketTags.SECRET_SUBKEY
            || pIn.nextPacketTag() == PacketTags.PUBLIC_SUBKEY)
        {
            if (pIn.nextPacketTag() == PacketTags.SECRET_SUBKEY)
            {
                SecretSubkeyPacket    sub = (SecretSubkeyPacket)pIn.readPacket();

                //
                // ignore GPG comment packets if found.
                //
                while (pIn.nextPacketTag() == PacketTags.EXPERIMENTAL_2)
                {
                    pIn.readPacket();
                }

                TrustPacket subTrust = readOptionalTrustPacket(pIn);
                List        sigList = readSignaturesAndTrust(pIn);

                keys.add(new PGPSecretKey(sub, new PGPPublicKey(sub.getPublicKeyPacket(), subTrust, sigList, fingerPrintCalculator)));
            }
            else
            {
                PublicSubkeyPacket sub = (PublicSubkeyPacket)pIn.readPacket();

                TrustPacket subTrust = readOptionalTrustPacket(pIn);
                List        sigList = readSignaturesAndTrust(pIn);

                extraPubKeys.add(new PGPPublicKey(sub, subTrust, sigList, fingerPrintCalculator));
            }
        }
    }

    /**
     * Return the public key for the master key.
     * 
     * @return PGPPublicKey
     */
    public PGPPublicKey getPublicKey()
    {
        return ((PGPSecretKey)keys.get(0)).getPublicKey();
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
        PGPSecretKey key = getSecretKey(keyID);
        if (key != null)
        {
            return key.getPublicKey();
        }

        for (int i = 0; i != extraPubKeys.size(); i++)
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
        PGPSecretKey key = getSecretKey(fingerprint);
        if (key != null)
        {
            return key.getPublicKey();
        }

        for (int i = 0; i != extraPubKeys.size(); i++)
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

        for (Iterator keyIt = getPublicKeys(); keyIt.hasNext();)
        {
            PGPPublicKey    k = (PGPPublicKey)keyIt.next();

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
        List pubKeys = new ArrayList();

        for (Iterator it = getSecretKeys(); it.hasNext();)
        {            
            PGPPublicKey key = ((PGPSecretKey)it.next()).getPublicKey();
            pubKeys.add(key);
        }

        pubKeys.addAll(extraPubKeys);

        return Collections.unmodifiableList(pubKeys).iterator();
    }

    /**
     * Return the master private key.
     * 
     * @return PGPSecretKey
     */
    public PGPSecretKey getSecretKey()
    {
        return ((PGPSecretKey)keys.get(0));
    }
    
    /**
     * Return an iterator containing all the secret keys.
     * 
     * @return Iterator
     */
    public Iterator<PGPSecretKey> getSecretKeys()
    {
        return Collections.unmodifiableList(keys).iterator();
    }

    /**
     * Return the secret key referred to by the passed in keyID if it
     * is present.
     *
     * @param keyID the full keyID of the key of interest.
     * @return PGPSecretKey with matching keyID, null if it is not present.
     */
    public PGPSecretKey getSecretKey(
        long        keyID)
    {    
        for (int i = 0; i != keys.size(); i++)
        {
            PGPSecretKey    k = (PGPSecretKey)keys.get(i);
            
            if (keyID == k.getKeyID())
            {
                return k;
            }
        }
    
        return null;
    }

    /**
     * Return the secret key associated with the passed in fingerprint if it
     * is present.
     *
     * @param fingerprint the full fingerprint of the key of interest.
     * @return PGPSecretKey with the matching fingerprint, null if it is not present.
     */
    public PGPSecretKey getSecretKey(byte[] fingerprint)
    {
        for (int i = 0; i != keys.size(); i++)
        {
            PGPSecretKey    k = (PGPSecretKey)keys.get(i);

            if (Arrays.areEqual(fingerprint, k.getPublicKey().getFingerprint()))
            {
                return k;
            }
        }

        return null;
    }

    /**
     * Return an iterator of the public keys in the secret key ring that
     * have no matching private key. At the moment only personal certificate data
     * appears in this fashion.
     *
     * @return  iterator of unattached, or extra, public keys.
     */
    public Iterator<PGPPublicKey> getExtraPublicKeys()
    {
        return extraPubKeys.iterator();
    }

    public byte[] getEncoded() 
        throws IOException
    {
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        
        this.encode(bOut);
        
        return bOut.toByteArray();
    }
    
    public void encode(
        OutputStream    outStream) 
        throws IOException
    {
        for (int i = 0; i != keys.size(); i++)
        {
            PGPSecretKey    k = (PGPSecretKey)keys.get(i);
            
            k.encode(outStream);
        }
        for (int i = 0; i != extraPubKeys.size(); i++)
        {
            PGPPublicKey    k = (PGPPublicKey)extraPubKeys.get(i);

            k.encode(outStream);
        }
    }

    /**
     * Support method for Iterable where available.
     */
    public Iterator<PGPSecretKey> iterator()
    {
        return getSecretKeys();
    }

    /**
     * Replace the public key set on the secret ring with the corresponding key off the public ring.
     *
     * @param secretRing secret ring to be changed.
     * @param publicRing public ring containing the new public key set.
     */
    public static PGPSecretKeyRing replacePublicKeys(PGPSecretKeyRing secretRing, PGPPublicKeyRing publicRing)
    {
        List newList = new ArrayList(secretRing.keys.size());

        for (Iterator it = secretRing.keys.iterator(); it.hasNext();)
        {
            PGPSecretKey sk = (PGPSecretKey)it.next();
            PGPPublicKey pk = publicRing.getPublicKey(sk.getKeyID());

            newList.add(PGPSecretKey.replacePublicKey(sk, pk));
        }

        return new PGPSecretKeyRing(newList);
    }

    /**
     * Return a copy of the passed in secret key ring, with the private keys (where present) associated with the master key and sub keys
     * are encrypted using a new password and the passed in algorithm.
     *
     * @param ring the PGPSecretKeyRing to be copied.
     * @param oldKeyDecryptor the current decryptor based on the current password for key.
     * @param newKeyEncryptor a new encryptor based on a new password for encrypting the secret key material.
     * @return the updated key ring.
     */
    public static PGPSecretKeyRing copyWithNewPassword(
        PGPSecretKeyRing       ring,
        PBESecretKeyDecryptor  oldKeyDecryptor,
        PBESecretKeyEncryptor  newKeyEncryptor)
        throws PGPException
    {
        List newKeys = new ArrayList(ring.keys.size());

        for (Iterator keys = ring.getSecretKeys(); keys.hasNext();)
        {
            PGPSecretKey key = (PGPSecretKey)keys.next();

            if (key.isPrivateKeyEmpty())
            {
                newKeys.add(key);
            }
            else
            {
                newKeys.add(PGPSecretKey.copyWithNewPassword(key, oldKeyDecryptor, newKeyEncryptor));
            }
        }

        return new PGPSecretKeyRing(newKeys, ring.extraPubKeys);
    }

    /**
     * Returns a new key ring with the secret key passed in either added or
     * replacing an existing one with the same key ID.
     * 
     * @param secRing the secret key ring to be modified.
     * @param secKey the secret key to be added.
     * @return a new secret key ring.
     */
    public static PGPSecretKeyRing insertSecretKey(
        PGPSecretKeyRing  secRing,
        PGPSecretKey      secKey)
    {
        List       keys = new ArrayList(secRing.keys);
        boolean    found = false;
        boolean    masterFound = false;
        
        for (int i = 0; i != keys.size();i++)
        {
            PGPSecretKey   key = (PGPSecretKey)keys.get(i);
            
            if (key.getKeyID() == secKey.getKeyID())
            {
                found = true;
                keys.set(i, secKey);
            }
            if (key.isMasterKey())
            {
                masterFound = true;
            }
        }

        if (!found)
        {
            if (secKey.isMasterKey())
            {
                if (masterFound)
                {
                    throw new IllegalArgumentException("cannot add a master key to a ring that already has one");
                }

                keys.add(0, secKey);
            }
            else
            {
                keys.add(secKey);
            }
        }
        
        return new PGPSecretKeyRing(keys, secRing.extraPubKeys);
    }
    
    /**
     * Returns a new key ring with the secret key passed in removed from the
     * key ring.
     * 
     * @param secRing the secret key ring to be modified.
     * @param secKey the secret key to be removed.
     * @return a new secret key ring, or null if secKey is not found.
     */
    public static PGPSecretKeyRing removeSecretKey(
        PGPSecretKeyRing  secRing,
        PGPSecretKey      secKey)
    {
        List       keys = new ArrayList(secRing.keys);
        boolean    found = false;
        
        for (int i = 0; i < keys.size();i++)
        {
            PGPSecretKey   key = (PGPSecretKey)keys.get(i);
            
            if (key.getKeyID() == secKey.getKeyID())
            {
                found = true;
                keys.remove(i);
            }
        }
        
        if (!found)
        {
            return null;
        }
        
        return new PGPSecretKeyRing(keys, secRing.extraPubKeys);
    }
}
