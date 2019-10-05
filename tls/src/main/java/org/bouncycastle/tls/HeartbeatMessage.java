package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public class HeartbeatMessage
{
    public static HeartbeatMessage create(TlsContext context, short type, byte[] payload)
    {
        return create(context, type, payload, 16);
    }

    public static HeartbeatMessage create(TlsContext context, short type, byte[] payload, int paddingLength)
    {
        byte[] padding = context.getNonceGenerator().generateNonce(paddingLength);

        return new HeartbeatMessage(type, payload, padding);
    }

    protected short type;
    protected byte[] payload;
    protected byte[] padding;

    public HeartbeatMessage(short type, byte[] payload, byte[] padding)
    {
        if (!HeartbeatMessageType.isValid(type))
        {
            throw new IllegalArgumentException("'type' is not a valid HeartbeatMessageType value");
        }
        if (null == payload || payload.length >= (1 << 16))
        {
            throw new IllegalArgumentException("'payload' must have length < 2^16");
        }
        if (null == padding || padding.length < 16)
        {
            throw new IllegalArgumentException("'padding' must have length >= 16");
        }

        this.type = type;
        this.payload = payload;
        this.padding = padding;
    }

    public int getPaddingLength()
    {
        /*
         * RFC 6520 4. The padding of a received HeartbeatMessage message MUST be ignored
         */
        return padding.length;
    }

    public byte[] getPayload()
    {
        return payload;
    }

    public short getType()
    {
        return type;
    }

    /**
     * Encode this {@link HeartbeatMessage} to an {@link OutputStream}.
     * 
     * @param output
     *            the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output) throws IOException
    {
        TlsUtils.writeUint8(type, output);

        TlsUtils.checkUint16(payload.length);
        TlsUtils.writeUint16(payload.length, output);
        output.write(payload);

        output.write(padding);
    }

    /**
     * Parse a {@link HeartbeatMessage} from an {@link InputStream}.
     * 
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link HeartbeatMessage} object.
     * @throws IOException
     */
    public static HeartbeatMessage parse(InputStream input) throws IOException
    {
        short type = TlsUtils.readUint8(input);
        if (!HeartbeatMessageType.isValid(type))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        int payload_length = TlsUtils.readUint16(input);

        PayloadBuffer buf = new PayloadBuffer();
        Streams.pipeAll(input, buf);

        byte[] payload = buf.getPayload(payload_length);
        if (null == payload)
        {
            /*
             * RFC 6520 4. If the payload_length of a received HeartbeatMessage is too large, the
             * received HeartbeatMessage MUST be discarded silently.
             */
            return null;
        }

        byte[] padding = buf.getPadding(payload_length);

        return new HeartbeatMessage(type, payload, padding);
    }

    static class PayloadBuffer extends ByteArrayOutputStream
    {
        byte[] getPayload(int payloadLength)
        {
            /*
             * RFC 6520 4. The padding_length MUST be at least 16.
             */
            int maxPayloadLength = count - 16;
            if (payloadLength > maxPayloadLength)
            {
                return null;
            }
            return Arrays.copyOf(buf, payloadLength);
        }

        byte[] getPadding(int payloadLength)
        {
            return TlsUtils.copyOfRangeExact(buf, payloadLength, count);
        }
    }
}
