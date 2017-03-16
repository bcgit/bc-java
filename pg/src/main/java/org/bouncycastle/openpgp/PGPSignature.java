package org.bouncycastle.openpgp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.TrustPacket;
import org.bouncycastle.bcpg.UserAttributeSubpacket;
import org.bouncycastle.openpgp.operator.PGPContentVerifier;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilder;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;

/**
 *A PGP signature object.
 */
public class PGPSignature
{
    public static final int    BINARY_DOCUMENT = 0x00;
    public static final int    CANONICAL_TEXT_DOCUMENT = 0x01;
    public static final int    STAND_ALONE = 0x02;
    
    public static final int    DEFAULT_CERTIFICATION = 0x10;
    public static final int    NO_CERTIFICATION = 0x11;
    public static final int    CASUAL_CERTIFICATION = 0x12;
    public static final int    POSITIVE_CERTIFICATION = 0x13;
    
    public static final int    SUBKEY_BINDING = 0x18;
    public static final int    PRIMARYKEY_BINDING = 0x19;
    public static final int    DIRECT_KEY = 0x1f;
    public static final int    KEY_REVOCATION = 0x20;
    public static final int    SUBKEY_REVOCATION = 0x28;
    public static final int    CERTIFICATION_REVOCATION = 0x30;
    public static final int    TIMESTAMP = 0x40;
    
    private SignaturePacket    sigPck;
    private int                signatureType;
    private TrustPacket        trustPck;
    private PGPContentVerifier verifier;
    private byte               lastb;
    private OutputStream       sigOut;

    PGPSignature(
        BCPGInputStream    pIn)
        throws IOException, PGPException
    {
        this((SignaturePacket)pIn.readPacket());
    }
    
    PGPSignature(
        SignaturePacket    sigPacket)
        throws PGPException
    {
        sigPck = sigPacket;
        signatureType = sigPck.getSignatureType();
        trustPck = null;
    }
    
    PGPSignature(
        SignaturePacket    sigPacket,
        TrustPacket        trustPacket)
        throws PGPException
    {
        this(sigPacket);
        
        this.trustPck = trustPacket;
    }

    /**
     * Return the OpenPGP version number for this signature.
     * 
     * @return signature version number.
     */
    public int getVersion()
    {
        return sigPck.getVersion();
    }
    
    /**
     * Return the key algorithm associated with this signature.
     * @return signature key algorithm.
     */
    public int getKeyAlgorithm()
    {
        return sigPck.getKeyAlgorithm();
    }
    
    /**
     * Return the hash algorithm associated with this signature.
     * @return signature hash algorithm.
     */
    public int getHashAlgorithm()
    {
        return sigPck.getHashAlgorithm();
    }

    /**
     * Return true if this signature represents a certification.
     *
     * @return true if this signature represents a certification, false otherwise.
     */
    public boolean isCertification()
    {
        return isCertification(getSignatureType());
    }

    public void init(PGPContentVerifierBuilderProvider verifierBuilderProvider, PGPPublicKey pubKey)
        throws PGPException
    {
        PGPContentVerifierBuilder verifierBuilder = verifierBuilderProvider.get(sigPck.getKeyAlgorithm(), sigPck.getHashAlgorithm());

        verifier = verifierBuilder.build(pubKey);

        lastb = 0;
        sigOut = verifier.getOutputStream();
    }

    public void update(
        byte    b)
    {
        if (signatureType == PGPSignature.CANONICAL_TEXT_DOCUMENT)
        {
            if (b == '\r')
            {
                byteUpdate((byte)'\r');
                byteUpdate((byte)'\n');
            }
            else if (b == '\n')
            {
                if (lastb != '\r')
                {
                    byteUpdate((byte)'\r');
                    byteUpdate((byte)'\n');
                }
            }
            else
            {
                byteUpdate(b);
            }

            lastb = b;
        }
        else
        {
            byteUpdate(b);
        }
    }
        
    public void update(
        byte[]    bytes)
    {
        this.update(bytes, 0, bytes.length);
    }
        
    public void update(
        byte[]    bytes,
        int       off,
        int       length)
    {
        if (signatureType == PGPSignature.CANONICAL_TEXT_DOCUMENT)
        {
            int finish = off + length;
            
            for (int i = off; i != finish; i++)
            {
                this.update(bytes[i]);
            }
        }
        else
        {
            blockUpdate(bytes, off, length);
        }
    }

    private void byteUpdate(byte b)
    {
        try
        {
            sigOut.write(b);
        }
        catch (IOException e)
        {
            throw new PGPRuntimeOperationException(e.getMessage(), e);
        }
    }

    private void blockUpdate(byte[] block, int off, int len)
    {
        try
        {
            sigOut.write(block, off, len);
        }
        catch (IOException e)
        {
            throw new PGPRuntimeOperationException(e.getMessage(), e);
        }
    }

    public boolean verify()
        throws PGPException
    {
        try
        {
            sigOut.write(this.getSignatureTrailer());

            sigOut.close();
        }
        catch (IOException e)
        {
            throw new PGPException(e.getMessage(), e);
        }

        return verifier.verify(this.getSignature());
    }


    private void updateWithIdData(int header, byte[] idBytes)
    {
        this.update((byte)header);
        this.update((byte)(idBytes.length >> 24));
        this.update((byte)(idBytes.length >> 16));
        this.update((byte)(idBytes.length >> 8));
        this.update((byte)(idBytes.length));
        this.update(idBytes);
    }
    
    private void updateWithPublicKey(PGPPublicKey key)
        throws PGPException
    {
        byte[] keyBytes = getEncodedPublicKey(key);

        this.update((byte)0x99);
        this.update((byte)(keyBytes.length >> 8));
        this.update((byte)(keyBytes.length));
        this.update(keyBytes);
    }

    /**
     * Verify the signature as certifying the passed in public key as associated
     * with the passed in user attributes.
     *
     * @param userAttributes user attributes the key was stored under
     * @param key the key to be verified.
     * @return true if the signature matches, false otherwise.
     * @throws PGPException
     */
    public boolean verifyCertification(
        PGPUserAttributeSubpacketVector userAttributes,
        PGPPublicKey    key)
        throws PGPException
    {
        if (verifier == null)
        {
            throw new PGPException("PGPSignature not initialised - call init().");
        }

        updateWithPublicKey(key);

        //
        // hash in the userAttributes
        //
        try
        {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            UserAttributeSubpacket[] packets = userAttributes.toSubpacketArray();
            for (int i = 0; i != packets.length; i++)
            {
                packets[i].encode(bOut);
            }
            updateWithIdData(0xd1, bOut.toByteArray());
        }
        catch (IOException e)
        {
            throw new PGPException("cannot encode subpacket array", e);
        }

        addTrailer();

        return verifier.verify(this.getSignature());
    }

    /**
     * Verify the signature as certifying the passed in public key as associated
     * with the passed in id.
     * 
     * @param id id the key was stored under
     * @param key the key to be verified.
     * @return true if the signature matches, false otherwise.
     * @throws PGPException
     */
    public boolean verifyCertification(
        String          id,
        PGPPublicKey    key)
        throws PGPException
    {
        if (verifier == null)
        {
            throw new PGPException("PGPSignature not initialised - call init().");
        }

        updateWithPublicKey(key);
            
        //
        // hash in the id
        //
        updateWithIdData(0xb4, Strings.toUTF8ByteArray(id));

        addTrailer();

        return verifier.verify(this.getSignature());
    }

    /**
     * Verify the signature as certifying the passed in public key as associated
     * with the passed in rawID.
     *
     * @param rawID id the key was stored under in its raw byte form.
     * @param key the key to be verified.
     * @return true if the signature matches, false otherwise.
     * @throws PGPException
     */
    public boolean verifyCertification(
        byte[]          rawID,
        PGPPublicKey    key)
        throws PGPException
    {
        if (verifier == null)
        {
            throw new PGPException("PGPSignature not initialised - call init().");
        }

        updateWithPublicKey(key);

        //
        // hash in the rawID
        //
        updateWithIdData(0xb4, rawID);

        addTrailer();

        return verifier.verify(this.getSignature());
    }

    /**
     * Verify a certification for the passed in key against the passed in
     * master key.
     * 
     * @param masterKey the key we are verifying against.
     * @param pubKey the key we are verifying.
     * @return true if the certification is valid, false otherwise.
     * @throws PGPException
     */
    public boolean verifyCertification(
        PGPPublicKey    masterKey,
        PGPPublicKey    pubKey) 
        throws PGPException
    {
        if (verifier == null)
        {
            throw new PGPException("PGPSignature not initialised - call init().");
        }

        updateWithPublicKey(masterKey);
        updateWithPublicKey(pubKey);

        addTrailer();

        return verifier.verify(this.getSignature());
    }

    private void addTrailer()
    {
        try
        {
            sigOut.write(sigPck.getSignatureTrailer());

            sigOut.close();
        }
        catch (IOException e)
        {
            throw new PGPRuntimeOperationException(e.getMessage(), e);
        }
    }

    /**
     * Verify a key certification, such as a revocation, for the passed in key.
     * 
     * @param pubKey the key we are checking.
     * @return true if the certification is valid, false otherwise.
     * @throws PGPException
     */
    public boolean verifyCertification(
        PGPPublicKey    pubKey) 
        throws PGPException
    {
        if (verifier == null)
        {
            throw new PGPException("PGPSignature not initialised - call init().");
        }

        if (this.getSignatureType() != KEY_REVOCATION
            && this.getSignatureType() != SUBKEY_REVOCATION
            && this.getSignatureType() != DIRECT_KEY)
        {
            throw new PGPException("signature is not a key signature");
        }

        updateWithPublicKey(pubKey);

        addTrailer();

        return verifier.verify(this.getSignature());
    }

    public int getSignatureType()
    {
         return sigPck.getSignatureType();
    }
    
    /**
     * Return the id of the key that created the signature.
     * @return keyID of the signatures corresponding key.
     */
    public long getKeyID()
    {
         return sigPck.getKeyID();
    }
    
    /**
     * Return the creation time of the signature.
     * 
     * @return the signature creation time.
     */
    public Date getCreationTime()
    {
        return new Date(sigPck.getCreationTime());
    }
    
    public byte[] getSignatureTrailer()
    {
        return sigPck.getSignatureTrailer();
    }

    /**
     * Return true if the signature has either hashed or unhashed subpackets.
     * 
     * @return true if either hashed or unhashed subpackets are present, false otherwise.
     */
    public boolean hasSubpackets()
    {
        return sigPck.getHashedSubPackets() != null || sigPck.getUnhashedSubPackets() != null;
    }

    public PGPSignatureSubpacketVector getHashedSubPackets()
    {
        return createSubpacketVector(sigPck.getHashedSubPackets());
    }

    public PGPSignatureSubpacketVector getUnhashedSubPackets()
    {
        return createSubpacketVector(sigPck.getUnhashedSubPackets());
    }
    
    private PGPSignatureSubpacketVector createSubpacketVector(SignatureSubpacket[] pcks)
    {
        if (pcks != null)
        {
            return new PGPSignatureSubpacketVector(pcks);
        }
        
        return null;
    }
    
    public byte[] getSignature()
        throws PGPException
    {
        MPInteger[]    sigValues = sigPck.getSignature();
        byte[]         signature;

        if (sigValues != null)
        {
            if (sigValues.length == 1)    // an RSA signature
            {
                signature = BigIntegers.asUnsignedByteArray(sigValues[0].getValue());
            }
            else
            {
                try
                {
                    ASN1EncodableVector v = new ASN1EncodableVector();
                    v.add(new ASN1Integer(sigValues[0].getValue()));
                    v.add(new ASN1Integer(sigValues[1].getValue()));

                    signature = new DERSequence(v).getEncoded();
                }
                catch (IOException e)
                {
                    throw new PGPException("exception encoding DSA sig.", e);
                }
            }
        }
        else
        {
            signature = sigPck.getSignatureBytes();
        }
        
        return signature;
    }
    
    public byte[] getEncoded() 
        throws IOException
    {
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        
        this.encode(bOut);
        
        return bOut.toByteArray();
    }

    /**
     * Return an encoding of the signature, with trust packets stripped out if forTransfer is true.
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
     * Encode the signature to outStream, with trust packets stripped out if forTransfer is true.
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
        BCPGOutputStream    out;
        
        if (outStream instanceof BCPGOutputStream)
        {
            out = (BCPGOutputStream)outStream;
        }
        else
        {
            out = new BCPGOutputStream(outStream);
        }

        out.writePacket(sigPck);
        if (!forTransfer && trustPck != null)
        {
            out.writePacket(trustPck);
        }
    }
    
    private byte[] getEncodedPublicKey(
        PGPPublicKey pubKey) 
        throws PGPException
    {
        byte[]    keyBytes;
        
        try
        {
            keyBytes = pubKey.publicPk.getEncodedContents();
        }
        catch (IOException e)
        {
            throw new PGPException("exception preparing key.", e);
        }
        
        return keyBytes;
    }

    /**
     * Return true if the passed in signature type represents a certification, false if the signature type is not.
     *
     * @param signatureType
     * @return true if signatureType is a certification, false otherwise.
     */
    public static boolean isCertification(int signatureType)
    {
        return PGPSignature.DEFAULT_CERTIFICATION == signatureType
                || PGPSignature.NO_CERTIFICATION == signatureType
                || PGPSignature.CASUAL_CERTIFICATION == signatureType
                || PGPSignature.POSITIVE_CERTIFICATION == signatureType;
    }
}
