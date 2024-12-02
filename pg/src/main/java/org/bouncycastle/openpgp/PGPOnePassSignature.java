package org.bouncycastle.openpgp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashUtils;
import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.OnePassSignaturePacket;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.openpgp.operator.PGPContentVerifier;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilder;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.util.Arrays;

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
        // v3 OPSs are typically used with v4 sigs
        super(sigPack.getVersion() == OnePassSignaturePacket.VERSION_3 ? SignaturePacket.VERSION_4 : sigPack.getVersion());
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

        checkSaltSize();
        updateWithSalt();
    }

    private void checkSaltSize()
        throws PGPException
    {
        if (getVersion() != SignaturePacket.VERSION_6)
        {
            return;
        }

        int expectedSaltSize = HashUtils.getV6SignatureSaltSizeInBytes(getHashAlgorithm());
        if (expectedSaltSize != getSalt().length)
        {
            throw new PGPException("RFC9580 defines the salt size for " + PGPUtil.getDigestName(getHashAlgorithm()) +
                " as " + expectedSaltSize + " octets, but signature has " + getSalt().length + " octets.");
        }
    }

    private void updateWithSalt()
        throws PGPException
    {
        if (version == SignaturePacket.VERSION_6)
        {
            try
            {
                sigOut.write(getSalt());
            }
            catch (IOException e)
            {
                throw new PGPException("Cannot salt the signature.", e);
            }
        }
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
        compareSalt(pgpSig);
        
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

    private void compareSalt(PGPSignature signature)
        throws PGPException
    {
        if (version != SignaturePacket.VERSION_6)
        {
            return;
        }
        if (!Arrays.constantTimeAreEqual(getSalt(), signature.getSalt()))
        {
            throw new PGPException("Salt in OnePassSignaturePacket does not match salt in SignaturePacket.");
        }
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
     * Return a {@link KeyIdentifier} identifying this {@link PGPOnePassSignature}.
     *
     * @return key identifier
     */
    public KeyIdentifier getKeyIdentifier()
    {
        return new KeyIdentifier(getFingerprint(), getKeyID());
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
     * Return true, if the signature contains any signatures that follow.
     * A bracketing OPS is followed by additional OPS packets and is calculated over all the data between itself
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
