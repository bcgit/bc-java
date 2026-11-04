package org.bouncycastle.openpgp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.OnePassSignaturePacket;
import org.bouncycastle.openpgp.operator.PGPContentVerifier;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilder;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.util.Properties;

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
    private PGPContentVerifier legacyTextVerifier;
    private OutputStream       legacyTextSigOut;
    private boolean            sawBareCR;

    PGPOnePassSignature(
        BCPGInputStream    pIn)
        throws IOException, PGPException
    {
        this((OnePassSignaturePacket)pIn.readPacket());
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
        sawBareCR = false;
        legacyTextVerifier = null;
        legacyTextSigOut = null;

        if (signatureType == PGPSignature.CANONICAL_TEXT_DOCUMENT
            && !Properties.isOverrideSetTo(Properties.OPENPGP_TEXT_SIG_ALLOW_LEGACY_CR, false))
        {
            // a second hash over the pre-1.87 form, consulted only if the data held a bare CR
            // and the signature does not verify over the current form (github #2553).
            legacyTextVerifier = verifierBuilder.build(pubKey);
            legacyTextSigOut = legacyTextVerifier.getOutputStream();
        }
    }

    public void update(
        byte    b)
        throws PGPSignatureException
    {
        if (signatureType == PGPSignature.CANONICAL_TEXT_DOCUMENT)
        {
            if (lastb == '\r' && b != '\n')
            {
                sawBareCR = true;
            }

            // a LF not preceded by a CR is hashed as CR LF, every other byte, a bare CR
            // included, unaltered (github #2553).
            if (b == '\n' && lastb != '\r')
            {
                byteUpdate((byte)'\r');
                byteUpdate((byte)'\n');
            }
            else
            {
                byteUpdate(b);
            }

            if (legacyTextSigOut != null)
            {
                // the pre-1.87 form: CR, LF and CR LF are all hashed as CR LF
                if (b == '\r')
                {
                    legacyByteUpdate((byte)'\r');
                    legacyByteUpdate((byte)'\n');
                }
                else if (b == '\n')
                {
                    if (lastb != '\r')
                    {
                        legacyByteUpdate((byte)'\r');
                        legacyByteUpdate((byte)'\n');
                    }
                }
                else
                {
                    legacyByteUpdate(b);
                }
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
        throws PGPSignatureException
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
        throws PGPSignatureException
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
        throws PGPSignatureException
    {
        try
        {
            sigOut.write(b);
        }
        catch (IOException e)
        {
            throw new PGPSignatureException(e.getMessage(), e);
        }
    }

    private void legacyByteUpdate(byte b)
        throws PGPSignatureException
    {
        try
        {
            legacyTextSigOut.write(b);
        }
        catch (IOException e)
        {
            throw new PGPSignatureException(e.getMessage(), e);
        }
    }

    private void blockUpdate(byte[] block, int off, int len)
        throws PGPSignatureException
    {
        try
        {
            sigOut.write(block, off, len);
        }
        catch (IOException e)
        {
            throw new PGPSignatureException(e.getMessage(), e);
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
        byte[] trailer = pgpSig.getSignatureTrailer();
        try
        {
            sigOut.write(trailer);

            sigOut.close();
        }
        catch (IOException e)
        {
            throw new PGPException("unable to add trailer: " + e.getMessage(), e);
        }

        if (verifier.verify(pgpSig.getSignature()))
        {
            return true;
        }

        if (legacyTextSigOut == null || !(sawBareCR || lastb == '\r'))
        {
            return false;
        }

        try
        {
            legacyTextSigOut.write(trailer);

            legacyTextSigOut.close();
        }
        catch (IOException e)
        {
            throw new PGPException(e.getMessage(), e);
        }

        return legacyTextVerifier.verify(pgpSig.getSignature());
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

    public void encode(OutputStream outStream) 
        throws IOException
    {
        BCPGOutputStream.wrap(outStream).writePacket(sigPack);
    }
}
