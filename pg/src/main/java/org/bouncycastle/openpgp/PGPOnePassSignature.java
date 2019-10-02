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
{
    private OnePassSignaturePacket sigPack;
    private int                    signatureType;

    private PGPContentVerifier verifier;
    private byte               lastb;
    private OutputStream       sigOut;

    private static OnePassSignaturePacket cast(Packet packet)
        throws IOException
    {
        if (!(packet instanceof OnePassSignaturePacket))
        {
            throw new IOException("unexpected packet in stream: " + packet);
        }
        return (OnePassSignaturePacket)packet;
    }

    PGPOnePassSignature(
        BCPGInputStream    pIn)
        throws IOException, PGPException
    {
        this(cast(pIn.readPacket()));
    }
    
    PGPOnePassSignature(
        OnePassSignaturePacket    sigPack)
        throws PGPException
    {
        this.sigPack = sigPack;
        this.signatureType = sigPack.getSignatureType();
    }

    /**
     * Initialise the signature object for verification.
     *
     * @param verifierBuilderProvider   provider for a content verifier builder for the signature type of interest.
     * @param pubKey  the public key to use for verification
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
        if (signatureType == PGPSignature.CANONICAL_TEXT_DOCUMENT)
        {
            for (int i = 0; i != bytes.length; i++)
            {
                this.update(bytes[i]);
            }
        }
        else
        {
            blockUpdate(bytes, 0, bytes.length);
        }
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

    /**
     * Verify the calculated signature against the passed in PGPSignature.
     * 
     * @param pgpSig
     * @return boolean
     * @throws PGPException
     */
    public boolean verify(
        PGPSignature    pgpSig)
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
    
    public long getKeyID()
    {
        return sigPack.getKeyID();
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
        BCPGOutputStream    out;
        
        if (outStream instanceof BCPGOutputStream)
        {
            out = (BCPGOutputStream)outStream;
        }
        else
        {
            out = new BCPGOutputStream(outStream);
        }

        out.writePacket(sigPack);
    }
}
