package org.bouncycastle.openpgp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.UserAttributeSubpacket;
import org.bouncycastle.openpgp.operator.PGPContentVerifier;
import org.bouncycastle.util.Properties;

abstract class PGPDefaultSignatureGenerator
{
    protected byte lastb;
    protected OutputStream sigOut;
    protected int sigType;
    protected final int version;

    /**
     * Verification only: a second stream fed the pre-1.87 canonical text form, in which a bare CR
     * was hashed as CR LF, or null if no such fallback is wanted. See {@link #update(byte)}.
     */
    protected OutputStream legacyTextSigOut;
    /**
     * Set once the text-mode input has contained a CR not followed by LF, the only input on which
     * the current and the legacy canonical text forms differ.
     */
    protected boolean sawBareCR;

    public PGPDefaultSignatureGenerator(int version)
    {
        this.version = version;
    }

    /**
     * Reset the text canonicalisation state for a new signature calculation.
     */
    protected void resetTextState()
    {
        lastb = 0;
        sawBareCR = false;
        legacyTextSigOut = null;
    }

    /**
     * Update the signature with a byte of the signed data.
     * <p>
     * For a text signature (type 0x01) the data is hashed in canonical text form, as RFC 9580
     * sec. 5.2.1.2 describes: a LF not preceded by a CR is hashed as CR LF, and every other byte,
     * a CR not followed by a LF included, is hashed unaltered. A bare CR is therefore not a line
     * ending, which is what GnuPG, GopenPGP, OpenPGP.js, rpgpie, RNP and PGPy do (github #2553).
     * Releases before 1.87 hashed a bare CR as CR LF; when verifying, that form is also accepted
     * unless {@link org.bouncycastle.util.Properties#OPENPGP_TEXT_SIG_ALLOW_LEGACY_CR} is set to
     * false.
     * </p>
     */
    public void update(
        byte b)
    {
        if (sigType == PGPSignature.CANONICAL_TEXT_DOCUMENT)
        {
            if (lastb == '\r' && b != '\n')
            {
                sawBareCR = true;
            }

            if (b == '\n' && lastb != '\r')
            {
                byteUpdate(sigOut, (byte)'\r');
                byteUpdate(sigOut, (byte)'\n');
            }
            else
            {
                byteUpdate(sigOut, b);
            }

            if (legacyTextSigOut != null)
            {
                legacyTextUpdate(b);
            }

            lastb = b;
        }
        else
        {
            byteUpdate(sigOut, b);
        }
    }

    // the pre-1.87 canonical text form: CR, LF and CR LF are all hashed as CR LF.
    private void legacyTextUpdate(byte b)
    {
        if (b == '\r')
        {
            byteUpdate(legacyTextSigOut, (byte)'\r');
            byteUpdate(legacyTextSigOut, (byte)'\n');
        }
        else if (b == '\n')
        {
            if (lastb != '\r')
            {
                byteUpdate(legacyTextSigOut, (byte)'\r');
                byteUpdate(legacyTextSigOut, (byte)'\n');
            }
        }
        else
        {
            byteUpdate(legacyTextSigOut, b);
        }
    }

    /**
     * Return true if the text-mode data hashed so far is one the legacy canonical text form
     * hashes differently - that is, it holds a bare CR, a trailing CR included.
     */
    protected boolean isLegacyTextFormDifferent()
    {
        return sawBareCR || lastb == '\r';
    }

    /**
     * Return true if a text signature should also be checked against the pre-1.87 canonical text
     * form (see {@link #update(byte)}).
     */
    protected static boolean isLegacyTextFormAllowed()
    {
        return Properties.isOverrideSet(Properties.OPENPGP_TEXT_SIG_ALLOW_LEGACY_CR, true);
    }

    /**
     * Second chance for a text signature that did not verify over the current canonical form:
     * check it over the legacy form, if a legacy hash was kept and the data is one on which the two
     * forms differ (on any other data they are the same bytes, so the answer cannot change).
     */
    protected boolean verifyLegacyTextForm(PGPContentVerifier legacyVerifier, byte[] trailer, byte[] signature)
        throws PGPException
    {
        if (legacyVerifier == null || legacyTextSigOut == null || !isLegacyTextFormDifferent())
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

        return legacyVerifier.verify(signature);
    }

    public void update(
        byte[] b)
    {
        this.update(b, 0, b.length);
    }

    public void update(
        byte[]  b,
        int     off,
        int     len)
    {
        if (sigType == PGPSignature.CANONICAL_TEXT_DOCUMENT)
        {
            int finish = off + len;

            for (int i = off; i != finish; i++)
            {
                this.update(b[i]);
            }
        }
        else
        {
            blockUpdate(b, off, len);
        }
    }

    private static void byteUpdate(OutputStream out, byte b)
    {
        try
        {
            out.write(b);
        }
        catch (IOException e)
        {
            throw new PGPRuntimeOperationException(e.getMessage(), e);
        }
    }

    protected void blockUpdate(byte[] block, int off, int len)
    {
        try
        {
            sigOut.write(block, off, len);
        }
        catch (IOException e)
        {
            throw new PGPRuntimeOperationException("unable to update signature: " + e.getMessage(), e);
        }
    }

    protected void updateWithIdData(int header, byte[] idBytes)
    {
        this.update((byte)header);
        this.update((byte)(idBytes.length >> 24));
        this.update((byte)(idBytes.length >> 16));
        this.update((byte)(idBytes.length >> 8));
        this.update((byte)(idBytes.length));
        this.update(idBytes);
    }

    protected void updateWithPublicKey(PGPPublicKey key)
        throws PGPException
    {
        byte[] keyBytes = getEncodedPublicKey(key);

        if (version == SignaturePacket.VERSION_4)
        {
            this.update((byte) 0x99);
            this.update((byte) (keyBytes.length >> 8));
            this.update((byte) (keyBytes.length));
        }
        else if (version == SignaturePacket.VERSION_5)
        {
            this.update((byte) 0x9A);
            this.update((byte) (keyBytes.length >> 24));
            this.update((byte) (keyBytes.length >> 16));
            this.update((byte) (keyBytes.length >> 8));
            this.update((byte) (keyBytes.length));
        }
        else if (version == SignaturePacket.VERSION_6)
        {
            this.update((byte) 0x9B);
            this.update((byte) (keyBytes.length >> 24));
            this.update((byte) (keyBytes.length >> 16));
            this.update((byte) (keyBytes.length >> 8));
            this.update((byte) (keyBytes.length));
        }
        this.update(keyBytes);
    }

    private byte[] getEncodedPublicKey(
        PGPPublicKey pubKey)
        throws PGPException
    {
        byte[] keyBytes;

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

    protected void getAttributesHash(PGPUserAttributeSubpacketVector userAttributes)
        throws PGPException
    {
        //
        // hash in the attributes
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
    }
}
