package org.bouncycastle.openpgp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.OnePassSignaturePacket;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.openpgp.operator.PGPContentSigner;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Generator for PGP Signatures.
 */
public class PGPSignatureGenerator
    extends PGPDefaultSignatureGenerator
{
    private SignatureSubpacket[] unhashed = new SignatureSubpacket[0];
    private SignatureSubpacket[] hashed = new SignatureSubpacket[0];
    private PGPContentSignerBuilder contentSignerBuilder;
    private PGPContentSigner contentSigner;
    private int providedKeyAlgorithm = -1;

    /**
     * Create a signature generator built on the passed in contentSignerBuilder.
     *
     * @param contentSignerBuilder builder to produce PGPContentSigner objects for generating signatures.
     */
    public PGPSignatureGenerator(
        PGPContentSignerBuilder contentSignerBuilder)
    {
        this.contentSignerBuilder = contentSignerBuilder;
    }

    /**
     * Initialise the generator for signing.
     *
     * @param signatureType
     * @param key
     * @throws PGPException
     */
    public void init(
        int signatureType,
        PGPPrivateKey key)
        throws PGPException
    {
        contentSigner = contentSignerBuilder.build(signatureType, key);
        sigOut = contentSigner.getOutputStream();
        sigType = contentSigner.getType();
        lastb = 0;

        if (providedKeyAlgorithm >= 0 && providedKeyAlgorithm != contentSigner.getKeyAlgorithm())
        {
            throw new PGPException("key algorithm mismatch");
        }
    }

    public void setHashedSubpackets(
        PGPSignatureSubpacketVector hashedPcks)
    {
        if (hashedPcks == null)
        {
            hashed = new SignatureSubpacket[0];
            return;
        }

        hashed = hashedPcks.toSubpacketArray();
    }

    public void setUnhashedSubpackets(
        PGPSignatureSubpacketVector unhashedPcks)
    {
        if (unhashedPcks == null)
        {
            unhashed = new SignatureSubpacket[0];
            return;
        }

        unhashed = unhashedPcks.toSubpacketArray();
    }

    /**
     * Return the one pass header associated with the current signature.
     *
     * @param isNested true if the signature is nested, false otherwise.
     * @return PGPOnePassSignature
     * @throws PGPException
     */
    public PGPOnePassSignature generateOnePassVersion(
        boolean isNested)
        throws PGPException
    {
        return new PGPOnePassSignature(new OnePassSignaturePacket(sigType, contentSigner.getHashAlgorithm(), contentSigner.getKeyAlgorithm(), contentSigner.getKeyID(), isNested));
    }

    /**
     * Return a signature object containing the current signature state.
     *
     * @return PGPSignature
     * @throws PGPException
     */
    public PGPSignature generate()
        throws PGPException
    {
        MPInteger[] sigValues;
        int version = 4;
        ByteArrayOutputStream sOut = new ByteArrayOutputStream();
        SignatureSubpacket[] hPkts, unhPkts;

        if (packetNotPresent(hashed, SignatureSubpacketTags.CREATION_TIME))
        {
            hPkts = insertSubpacket(hashed, new SignatureCreationTime(false, new Date()));
        }
        else
        {
            hPkts = hashed;
        }

        if (packetNotPresent(hashed, SignatureSubpacketTags.ISSUER_KEY_ID) && packetNotPresent(unhashed, SignatureSubpacketTags.ISSUER_KEY_ID))
        {
            unhPkts = insertSubpacket(unhashed, new IssuerKeyID(false, contentSigner.getKeyID()));
        }
        else
        {
            unhPkts = unhashed;
        }

        try
        {
            sOut.write((byte)version);
            sOut.write((byte)sigType);
            sOut.write((byte)contentSigner.getKeyAlgorithm());
            sOut.write((byte)contentSigner.getHashAlgorithm());

            ByteArrayOutputStream hOut = new ByteArrayOutputStream();

            for (int i = 0; i != hPkts.length; i++)
            {
                hPkts[i].encode(hOut);
            }

            byte[] data = hOut.toByteArray();

            sOut.write((byte)(data.length >> 8));
            sOut.write((byte)data.length);
            sOut.write(data);
            byte[] hData = sOut.toByteArray();

            sOut.write((byte)version);
            sOut.write((byte)0xff);
            sOut.write((byte)(hData.length >> 24));
            sOut.write((byte)(hData.length >> 16));
            sOut.write((byte)(hData.length >> 8));
            sOut.write((byte)(hData.length));
        }
        catch (IOException e)
        {
            throw new PGPException("exception encoding hashed data.", e);
        }


        byte[] trailer = sOut.toByteArray();

        blockUpdate(trailer, 0, trailer.length);

        if (contentSigner.getKeyAlgorithm() == PublicKeyAlgorithmTags.RSA_SIGN
            || contentSigner.getKeyAlgorithm() == PublicKeyAlgorithmTags.RSA_GENERAL)    // an RSA signature
        {
            sigValues = new MPInteger[1];
            sigValues[0] = new MPInteger(new BigInteger(1, contentSigner.getSignature()));
        }
        else if (contentSigner.getKeyAlgorithm() == PublicKeyAlgorithmTags.EDDSA_LEGACY)
        {
            byte[] enc = contentSigner.getSignature();
            sigValues = new MPInteger[]{
                new MPInteger(new BigInteger(1, Arrays.copyOfRange(enc, 0, enc.length / 2))),
                new MPInteger(new BigInteger(1, Arrays.copyOfRange(enc, enc.length / 2, enc.length)))
            };
        }
        else if (contentSigner.getKeyAlgorithm() == PublicKeyAlgorithmTags.Ed25519 ||
            contentSigner.getKeyAlgorithm() == PublicKeyAlgorithmTags.Ed448)
        {
            // Contrary to EDDSA_LEGACY, the new PK algorithms Ed25519, Ed448 do not use MPI encoding
            sigValues = null;
        }
        else
        {
            sigValues = PGPUtil.dsaSigToMpi(contentSigner.getSignature());
        }

        byte[] digest = contentSigner.getDigest();
        byte[] fingerPrint = new byte[2];

        fingerPrint[0] = digest[0];
        fingerPrint[1] = digest[1];

        if (sigValues != null)
        {
            return new PGPSignature(new SignaturePacket(sigType, contentSigner.getKeyID(), contentSigner.getKeyAlgorithm(),
                    contentSigner.getHashAlgorithm(), hPkts, unhPkts, fingerPrint, sigValues));
        }
        else
        {
            // Ed25519, Ed448 use raw encoding instead of MPI
            return new PGPSignature(new SignaturePacket(4, sigType, contentSigner.getKeyID(), contentSigner.getKeyAlgorithm(),
                    contentSigner.getHashAlgorithm(), hPkts, unhPkts, fingerPrint, contentSigner.getSignature()));
        }
    }

    /**
     * Generate a certification for the passed in id and key.
     *
     * @param id     the id we are certifying against the public key.
     * @param pubKey the key we are certifying against the id.
     * @return the certification.
     * @throws PGPException
     */
    public PGPSignature generateCertification(
        String id,
        PGPPublicKey pubKey)
        throws PGPException
    {
        updateWithPublicKey(pubKey);

        //
        // hash in the id
        //
        updateWithIdData(0xb4, Strings.toUTF8ByteArray(id));

        return this.generate();
    }

    /**
     * Generate a certification for the passed in userAttributes
     *
     * @param userAttributes the id we are certifying against the public key.
     * @param pubKey         the key we are certifying against the id.
     * @return the certification.
     * @throws PGPException
     */
    public PGPSignature generateCertification(
        PGPUserAttributeSubpacketVector userAttributes,
        PGPPublicKey pubKey)
        throws PGPException
    {
        updateWithPublicKey(pubKey);

        getAttributesHash(userAttributes);

        return this.generate();
    }

    /**
     * Generate a certification for the passed in key against the passed in
     * master key.
     *
     * @param masterKey the key we are certifying against.
     * @param pubKey    the key we are certifying.
     * @return the certification.
     * @throws PGPException
     */
    public PGPSignature generateCertification(
        PGPPublicKey masterKey,
        PGPPublicKey pubKey)
        throws PGPException
    {
        updateWithPublicKey(masterKey);
        updateWithPublicKey(pubKey);

        return this.generate();
    }

    /**
     * Generate a certification, such as a revocation, for the passed in key.
     *
     * @param pubKey the key we are certifying.
     * @return the certification.
     * @throws PGPException
     */
    public PGPSignature generateCertification(
        PGPPublicKey pubKey)
        throws PGPException
    {
        if ((sigType == PGPSignature.SUBKEY_REVOCATION || sigType == PGPSignature.SUBKEY_BINDING) && !pubKey.isMasterKey())
        {
            throw new IllegalArgumentException("certifications involving subkey requires public key of revoking key as well.");
        }

        updateWithPublicKey(pubKey);

        return this.generate();
    }

    private boolean packetNotPresent(
        SignatureSubpacket[] packets,
        int type)
    {
        for (int i = 0; i != packets.length; i++)
        {
            if (packets[i].getType() == type)
            {
                return false;
            }
        }

        return true;
    }

    private SignatureSubpacket[] insertSubpacket(
        SignatureSubpacket[] packets,
        SignatureSubpacket subpacket)
    {
        SignatureSubpacket[] tmp = new SignatureSubpacket[packets.length + 1];

        tmp[0] = subpacket;
        System.arraycopy(packets, 0, tmp, 1, packets.length);

        return tmp;
    }
}
