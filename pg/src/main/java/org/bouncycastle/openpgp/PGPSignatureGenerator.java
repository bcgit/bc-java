package org.bouncycastle.openpgp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.bcpg.HashUtils;
import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.OnePassSignaturePacket;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
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
    //private int providedKeyAlgorithm = -1;
    private int providedKeyAlgorithm = -1;
    private PGPPublicKey signingPubKey;
    private byte[] salt;

    /**
     * Create a version 4 signature generator built on the passed in contentSignerBuilder.
     *
     * @param contentSignerBuilder builder to produce PGPContentSigner objects for generating signatures.
     * @deprecated use {@link #PGPSignatureGenerator(PGPContentSignerBuilder, PGPPublicKey)} instead.
     */
    public PGPSignatureGenerator(
        PGPContentSignerBuilder contentSignerBuilder)
    {
        this(contentSignerBuilder, SignaturePacket.VERSION_4);
    }

    /**
     * Create a signature generator built on the passed in contentSignerBuilder.
     *
     * @param contentSignerBuilder builder to produce PGPContentSigner objects for generating signatures.
     * @param version signature version
     */
    PGPSignatureGenerator(
        PGPContentSignerBuilder contentSignerBuilder,
        int version)
    {
        super(version);
        this.contentSignerBuilder = contentSignerBuilder;
    }

    /**
     * Create a signature generator built on the passed in contentSignerBuilder.
     * The produces signature version will match the version of the passed in signing key.
     *
     * @param contentSignerBuilder builder to produce PGPContentSigner objects for generating signatures
     * @param signingKey signing key
     */
    public PGPSignatureGenerator(
        PGPContentSignerBuilder contentSignerBuilder,
        PGPPublicKey signingKey)
    {
        this(contentSignerBuilder, signingKey, signingKey.getVersion());
    }

    public PGPSignatureGenerator(
        PGPContentSignerBuilder contentSignerBuilder,
        PGPPublicKey signingKey,
        int signatureVersion)
    {
        this(contentSignerBuilder, signatureVersion);
        this.signingPubKey = signingKey;
        if (signingKey.getVersion() == 6 && signatureVersion != 6)
        {
            throw new IllegalArgumentException("Version 6 keys MUST only generate version 6 signatures.");
        }
    }

    /**
     * Initialise the generator for signing.
     *
     * @param signatureType type of signature
     * @param key private signing key
     * @throws PGPException
     */
    public void init(
        int signatureType,
        PGPPrivateKey key)
        throws PGPException
    {
        if (signatureType == 0xFF)
        {
            throw new PGPException("Illegal signature type 0xFF provided.");
        }
        contentSigner = contentSignerBuilder.build(signatureType, key);
        sigOut = contentSigner.getOutputStream();
        sigType = contentSigner.getType();
        lastb = 0;

        if (providedKeyAlgorithm >= 0 && providedKeyAlgorithm != contentSigner.getKeyAlgorithm())
        {
            throw new PGPException("key algorithm mismatch");
        }

        if (key.getPublicKeyPacket().getVersion() != version)
        {
            throw new PGPException("Key version mismatch.");
        }

        if (version == SignaturePacket.VERSION_6)
        {
            int saltSize = HashUtils.getV6SignatureSaltSizeInBytes(contentSigner.getHashAlgorithm());
            salt = new byte[saltSize];
            CryptoServicesRegistrar.getSecureRandom().nextBytes(salt);
            try
            {
                sigOut.write(salt);
            }
            catch (IOException e)
            {
                throw new PGPException("Cannot update signature with salt.");
            }
        }
    }

    /**
     * Set the hashed signature subpackets.
     * Hashed signature subpackets are covered by the signature.
     * @param hashedPcks hashed signature subpackets
     */
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

    /**
     * Set the unhashed signature subpackets.
     * Unhashed signature subpackets are not covered by the signature.
     * @param unhashedPcks unhashed signature subpackets
     */
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
        if (version == SignaturePacket.VERSION_6)
        {
            return new PGPOnePassSignature(v6OPSPacket(isNested));
        }
        else
        {
            return new PGPOnePassSignature(v3OPSPacket(isNested));
        }
    }

    private OnePassSignaturePacket v3OPSPacket(boolean isNested)
    {
        return new OnePassSignaturePacket(sigType, contentSigner.getHashAlgorithm(), contentSigner.getKeyAlgorithm(),
                contentSigner.getKeyID(), isNested);
    }

    private OnePassSignaturePacket v6OPSPacket(boolean isNested)
    {
        return new OnePassSignaturePacket(sigType, contentSigner.getHashAlgorithm(), contentSigner.getKeyAlgorithm(),
                salt, signingPubKey.getFingerprint(), isNested);
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
        prepareSignatureSubpackets();

        ByteArrayOutputStream sOut = new ByteArrayOutputStream();
        try
        {
            // hash the "header"
            sOut.write((byte)version);
            sOut.write((byte)sigType);
            sOut.write((byte)contentSigner.getKeyAlgorithm());
            sOut.write((byte)contentSigner.getHashAlgorithm());

            // hash signature subpackets
            ByteArrayOutputStream hOut = new ByteArrayOutputStream();
            for (int i = 0; i != hashed.length; i++)
            {
                hashed[i].encode(hOut);
            }
            byte[] data = hOut.toByteArray();

            if (version == SignaturePacket.VERSION_6)
            {
                sOut.write((byte) (data.length >> 24));
                sOut.write((byte) (data.length >> 16));
            }
            sOut.write((byte)(data.length >> 8));
            sOut.write((byte)data.length);
            sOut.write(data);

            // hash the "footer"
            int dataLen = sOut.toByteArray().length;
            sOut.write((byte)version);
            sOut.write((byte)0xff);
            sOut.write((byte)(dataLen >> 24));
            sOut.write((byte)(dataLen >> 16));
            sOut.write((byte)(dataLen >> 8));
            sOut.write((byte)(dataLen));
        }
        catch (IOException e)
        {
            throw new PGPException("exception encoding hashed data.", e);
        }

        byte[] trailer = sOut.toByteArray();
        blockUpdate(trailer, 0, trailer.length);
        MPInteger[] sigValues;
        switch (contentSigner.getKeyAlgorithm())
        {
        case PublicKeyAlgorithmTags.RSA_SIGN:
        case PublicKeyAlgorithmTags.RSA_GENERAL:
        {
            sigValues = new MPInteger[1];
            sigValues[0] = new MPInteger(new BigInteger(1, contentSigner.getSignature()));
            break;
        }
        case PublicKeyAlgorithmTags.EDDSA_LEGACY:
        {
            byte[] enc = contentSigner.getSignature();
            sigValues = new MPInteger[]{
                new MPInteger(new BigInteger(1, Arrays.copyOfRange(enc, 0, enc.length / 2))),
                new MPInteger(new BigInteger(1, Arrays.copyOfRange(enc, enc.length / 2, enc.length)))
            };
            break;
        }
        case PublicKeyAlgorithmTags.Ed25519:
        case PublicKeyAlgorithmTags.Ed448:
            // Contrary to EDDSA_LEGACY, the new PK algorithms Ed25519, Ed448 do not use MPI encoding
            sigValues = null;
            break;
        default:
            sigValues = PGPUtil.dsaSigToMpi(contentSigner.getSignature());
            break;
        }

        byte[] digest = contentSigner.getDigest();
        byte[] fingerPrint = new byte[2];

        fingerPrint[0] = digest[0];
        fingerPrint[1] = digest[1];

        SignaturePacket sigPckt;
        if (sigValues != null) // MPI encoding
        {
            sigPckt = new SignaturePacket(version, sigType, contentSigner.getKeyID(), contentSigner.getKeyAlgorithm(),
                    contentSigner.getHashAlgorithm(), hashed, unhashed, fingerPrint, sigValues, salt);
        }
        else // native encoding
        {
            // Ed25519, Ed448 use raw encoding instead of MPI

            sigPckt = new SignaturePacket(version, sigType, contentSigner.getKeyID(), contentSigner.getKeyAlgorithm(),
                    contentSigner.getHashAlgorithm(), hashed, unhashed, fingerPrint, contentSigner.getSignature(), salt);
        }
        return new PGPSignature(sigPckt);
    }

    protected void prepareSignatureSubpackets()
            throws PGPException
    {
        switch (version)
        {
            case SignaturePacket.VERSION_4:
            case SignaturePacket.VERSION_5:
            {
                // Insert hashed signature creation time if missing
                if (packetNotPresent(hashed, SignatureSubpacketTags.CREATION_TIME))
                {
                    hashed = insertSubpacket(hashed, new SignatureCreationTime(true, new Date()));
                }

                // Insert unhashed issuer key-ID if missing
                if (packetNotPresent(hashed, SignatureSubpacketTags.ISSUER_KEY_ID) && packetNotPresent(unhashed, SignatureSubpacketTags.ISSUER_KEY_ID))
                {
                    unhashed = insertSubpacket(unhashed, new IssuerKeyID(false, contentSigner.getKeyID()));
                }

                break;
            }

            case SignaturePacket.VERSION_6:
            {
                // Insert hashed signature creation time if missing
                if (packetNotPresent(hashed, SignatureSubpacketTags.CREATION_TIME))
                {
                    hashed = insertSubpacket(hashed, new SignatureCreationTime(true, new Date()));
                }

                // Insert hashed issuer fingerprint subpacket if missing
                if (packetNotPresent(hashed, SignatureSubpacketTags.ISSUER_FINGERPRINT) &&
                        packetNotPresent(unhashed, SignatureSubpacketTags.ISSUER_FINGERPRINT) &&
                        signingPubKey != null)
                {
                    hashed = insertSubpacket(hashed, new IssuerFingerprint(true, version, signingPubKey.getFingerprint()));
                }

                break;
            }
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
