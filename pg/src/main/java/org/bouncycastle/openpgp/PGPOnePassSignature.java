package org.bouncycastle.openpgp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.OnePassSignaturePacket;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.openpgp.operator.PGPContentVerifier;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilder;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;

/**
 * A one pass signature object.
 */
public class PGPOnePassSignature
    extends PGPDefaultSignatureGenerator
{
    private OnePassSignaturePacket sigPack;
    private PGPContentVerifier verifier;

    private static OnePassSignaturePacket cast(Packet packet)
        throws IOException
    {
        if (!(packet instanceof OnePassSignaturePacket))
        {
            throw new IOException("unexpected packet in stream: " + packet);
        }
        return (OnePassSignaturePacket)packet;
    }

    public PGPOnePassSignature(
        BCPGInputStream    pIn)
        throws IOException, PGPException
    {
        this(cast(pIn.readPacket()));
    }
    
    PGPOnePassSignature(
        OnePassSignaturePacket sigPack)
    {
        this.sigPack = sigPack;
        this.sigType = sigPack.getSignatureType();
    }

    /**
     * Initialise the signature object for verification.
     *
     * @param verifierBuilderProvider provider for a content verifier builder for the signature type of interest.
     * @param pubKey                  the public key to use for verification
     * @throws PGPException if there's an issue with creating the verifier.
     */
    public void init(PGPContentVerifierBuilderProvider verifierBuilderProvider, PGPPublicKey pubKey)
        throws PGPException
    {
        PGPContentVerifierBuilder verifierBuilder = verifierBuilderProvider.get(sigPack.getKeyAlgorithm(), sigPack.getHashAlgorithm());

        verifier = verifierBuilder.build(pubKey);

        lastb = 0;
        sigOut = verifier.getOutputStream();
    }

    /**
     * Verify the calculated signature against the passed in PGPSignature.
     *
     * @param pgpSig
     * @return boolean
     * @throws PGPException
     */
    public boolean verify(
        PGPSignature pgpSig)
        throws PGPException
    {
        try
        {
            sigOut.write(pgpSig.getSignatureTrailer());

            sigOut.close();
        }
        catch (IOException e)
        {
            throw new PGPException("unable to add trailer: " + e.getMessage(), e);
        }

        return verifier.verify(pgpSig.getSignature());
    }

    /**
     * Return the packet version.
     *
     * @return packet version
     */
    public int getVersion()
    {
        return sigPack.getVersion();
    }

    /**
     * Return the key-ID of the issuer signing key.
     * For {@link OnePassSignaturePacket#VERSION_6} packets, the key-ID is derived from the fingerprint.
     *
     * @return key-ID
     */
    public long getKeyID()
    {
        return sigPack.getKeyID();
    }

    /**
     * Return the issuer key fingerprint.
     * Only for {@link OnePassSignaturePacket#VERSION_6} packets.
     * @return fingerprint
     */
    public byte[] getFingerprint()
    {
        return sigPack.getFingerprint();
    }

    /**
     * Return the salt used in the corresponding signature.
     * Only for {@link OnePassSignaturePacket#VERSION_6} packets.
     * @return salt
     */
    public byte[] getSalt()
    {
        return sigPack.getSalt();
    }

    public int getSignatureType()
    {
        return sigPack.getSignatureType();
    }

    public int getHashAlgorithm()
    {
        return sigPack.getHashAlgorithm();
    }

    public int getKeyAlgorithm()
    {
        return sigPack.getKeyAlgorithm();
    }

    /**
     * Return true, if the signature is contains any signatures that follow.
     * An bracketing OPS is followed by additional OPS packets and is calculated over all the data between itself
     * and its corresponding signature (it is an attestation for contained signatures).
     *
     * @return true if containing, false otherwise
     */
    public boolean isContaining()
    {
        return sigPack.isContaining();
    }

    public byte[] getEncoded()
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        this.encode(bOut);

        return bOut.toByteArray();
    }

    public void encode(OutputStream outStream)
        throws IOException
    {
        BCPGOutputStream.wrap(outStream).writePacket(sigPack);
    }
}
