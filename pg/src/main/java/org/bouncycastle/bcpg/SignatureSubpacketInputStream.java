package org.bouncycastle.bcpg;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.bcpg.sig.EmbeddedSignature;
import org.bouncycastle.bcpg.sig.Exportable;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.IntendedRecipientFingerprint;
import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.bcpg.sig.KeyExpirationTime;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.bcpg.sig.PrimaryUserID;
import org.bouncycastle.bcpg.sig.Revocable;
import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.bcpg.sig.SignatureExpirationTime;
import org.bouncycastle.bcpg.sig.SignatureTarget;
import org.bouncycastle.bcpg.sig.SignerUserID;
import org.bouncycastle.bcpg.sig.TrustSignature;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

/**
 * reader for signature sub-packets
 */
public class SignatureSubpacketInputStream
    extends InputStream
    implements SignatureSubpacketTags
{
    private final InputStream in;
    private final int         limit;

    public SignatureSubpacketInputStream(
        InputStream in)
    {
        this(in, StreamUtil.findLimit(in));
    }

    public SignatureSubpacketInputStream(
        InputStream in,
        int         limit)
    {
        this.in = in;
        this.limit = limit;
    }

    public int available()
        throws IOException
    {
        return in.available();
    }

    public int read()
        throws IOException
    {
        return in.read();
    }

    public SignatureSubpacket readPacket()
        throws IOException
    {
        int l = this.read();
        int bodyLen = 0;

        if (l < 0)
        {
            return null;
        }

        boolean isLongLength = false;

        if (l < 192)
        {
            bodyLen = l;
        }
        else if (l <= 223)
        {
            bodyLen = ((l - 192) << 8) + (in.read()) + 192;
        }
        else if (l == 255)
        {
            isLongLength = true;
            bodyLen = (in.read() << 24) | (in.read() << 16) | (in.read() << 8) | in.read();
        }
        else
        {
            throw new IOException("unexpected length header");
        }

        int tag = in.read();

        if (tag < 0)
        {
            throw new EOFException("unexpected EOF reading signature sub packet");
        }

        // see below about miscoding... we'll try not to panic about anything under 2K.
        if (bodyLen <= 0 || (bodyLen > limit && bodyLen > 2048))
        {
            throw new EOFException("out of range data found in signature sub packet");
        }

        byte[] data = new byte[bodyLen - 1];

        //
        // this may seem a bit strange but it turns out some applications miscode the length
        // in fixed length fields, so we check the length we do get, only throwing an exception if
        // we really cannot continue
        //
        int bytesRead = Streams.readFully(in, data);

        boolean isCritical = ((tag & 0x80) != 0);
        int type = tag & 0x7f;

        if (bytesRead != data.length)
        {
            switch (type)
            {
            case CREATION_TIME:
                data = checkData(data, 4, bytesRead, "Signature Creation Time");
                break;
            case ISSUER_KEY_ID:
                data = checkData(data, 8, bytesRead, "Issuer");
                break;
            case KEY_EXPIRE_TIME:
                data = checkData(data, 4, bytesRead, "Signature Key Expiration Time");
                break;
            case EXPIRE_TIME:
                data = checkData(data, 4, bytesRead, "Signature Expiration Time");
                break;
            default:
                throw new EOFException("truncated subpacket data.");
            }
        }

        switch (type)
        {
        case CREATION_TIME:
            return new SignatureCreationTime(isCritical, isLongLength, data);
        case EMBEDDED_SIGNATURE:
            return new EmbeddedSignature(isCritical, isLongLength, data);
        case KEY_EXPIRE_TIME:
            return new KeyExpirationTime(isCritical, isLongLength, data);
        case EXPIRE_TIME:
            return new SignatureExpirationTime(isCritical, isLongLength, data);
        case REVOCABLE:
            return new Revocable(isCritical, isLongLength, data);
        case EXPORTABLE:
            return new Exportable(isCritical, isLongLength, data);
        case FEATURES:
            return new Features(isCritical, isLongLength, data);
        case ISSUER_KEY_ID:
            return new IssuerKeyID(isCritical, isLongLength, data);
        case TRUST_SIG:
            return new TrustSignature(isCritical, isLongLength, data);
        case PREFERRED_COMP_ALGS:
        case PREFERRED_HASH_ALGS:
        case PREFERRED_SYM_ALGS:
        case PREFERRED_AEAD_ALGORITHMS:
            return new PreferredAlgorithms(type, isCritical, isLongLength, data);
        case KEY_FLAGS:
            return new KeyFlags(isCritical, isLongLength, data);
        case PRIMARY_USER_ID:
            return new PrimaryUserID(isCritical, isLongLength, data);
        case SIGNER_USER_ID:
            return new SignerUserID(isCritical, isLongLength, data);
        case NOTATION_DATA:
            return new NotationData(isCritical, isLongLength, data);
        case REVOCATION_REASON:
            return new RevocationReason(isCritical, isLongLength, data);
        case SIGNATURE_TARGET:
            return new SignatureTarget(isCritical, isLongLength, data);
        case ISSUER_FINGERPRINT:
            return new IssuerFingerprint(isCritical, isLongLength, data);
        case INTENDED_RECIPIENT_FINGERPRINT:
            return new IntendedRecipientFingerprint(isCritical, isLongLength, data);
        }

        return new SignatureSubpacket(type, isCritical, isLongLength, data);
    }

    private byte[] checkData(byte[] data, int expected, int bytesRead, String name)
        throws EOFException
    {
        if (bytesRead != expected)
        {
            throw new EOFException("truncated " + name + " subpacket data.");
        }

        return Arrays.copyOfRange(data, 0, expected);
    }
}
