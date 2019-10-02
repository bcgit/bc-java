package org.bouncycastle.openpgp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.TrustPacket;
import org.bouncycastle.bcpg.UserAttributePacket;
import org.bouncycastle.bcpg.UserIDPacket;

/**
 * Parent class for PGP public and secret key rings.
 */
public abstract class PGPKeyRing
{
    PGPKeyRing()
    {
    }

    static BCPGInputStream wrap(InputStream in)
    {
        if (in instanceof BCPGInputStream)
        {
            return (BCPGInputStream)in;
        }

        return new BCPGInputStream(in);
    }

    static TrustPacket readOptionalTrustPacket(
        BCPGInputStream pIn)
        throws IOException
    {
        return (pIn.nextPacketTag() == PacketTags.TRUST)
            ?   (TrustPacket)pIn.readPacket()
            :   null;
    }

    static List readSignaturesAndTrust(
        BCPGInputStream pIn)
        throws IOException
    {
        try
        {
            List sigList = new ArrayList();

            while (pIn.nextPacketTag() == PacketTags.SIGNATURE)
            {
                SignaturePacket signaturePacket = (SignaturePacket)pIn.readPacket();
                TrustPacket trustPacket = readOptionalTrustPacket(pIn);

                sigList.add(new PGPSignature(signaturePacket, trustPacket));
            }

            return sigList;
        }
        catch (PGPException e)
        {
            throw new IOException("can't create signature object: " + e.getMessage()
                + ", cause: " + e.getUnderlyingException().toString());
        }
    }

    static void readUserIDs(
        BCPGInputStream pIn,
        List ids,
        List idTrusts,
        List idSigs)
        throws IOException
    {
        while (pIn.nextPacketTag() == PacketTags.USER_ID
            || pIn.nextPacketTag() == PacketTags.USER_ATTRIBUTE)
        {
            Packet obj = pIn.readPacket();
            if (obj instanceof UserIDPacket)
            {
                UserIDPacket id = (UserIDPacket)obj;
                ids.add(id);
            }
            else
            {
                UserAttributePacket user = (UserAttributePacket)obj;
                ids.add(new PGPUserAttributeSubpacketVector(user.getSubpackets()));
            }

            idTrusts.add(readOptionalTrustPacket(pIn));
            idSigs.add(readSignaturesAndTrust(pIn));
        }
    }

    /**
     * Return the first public key in the ring.  In the case of a {@link PGPSecretKeyRing}
     * this is also the public key of the master key pair.
     *
     * @return PGPPublicKey
     */
    public abstract PGPPublicKey getPublicKey();

    /**
     * Return an iterator containing all the public keys.
     *
     * @return Iterator
     */
    public abstract Iterator<PGPPublicKey> getPublicKeys();

    /**
     * Return the public key referred to by the passed in keyID if it
     * is present.
     *
     * @param keyID the full keyID of the key of interest.
     * @return PGPPublicKey with matching keyID.
     */
    public abstract PGPPublicKey getPublicKey(long keyID);

    /**
     * Return the public key with the passed in fingerprint if it
     * is present.
     *
     * @param fingerprint the full fingerprint of the key of interest.
     * @return PGPPublicKey with the matching fingerprint.
     */
    public abstract PGPPublicKey getPublicKey(byte[] fingerprint);

    /**
     * Return an iterator containing all the public keys carrying signatures issued from key keyID.
     *
     * @return a an iterator (possibly empty) of the public keys associated with keyID.
     */
    public abstract Iterator<PGPPublicKey> getKeysWithSignaturesBy(long keyID);

    public abstract void encode(OutputStream outStream)
        throws IOException;

    public abstract byte[] getEncoded()
        throws IOException;

}