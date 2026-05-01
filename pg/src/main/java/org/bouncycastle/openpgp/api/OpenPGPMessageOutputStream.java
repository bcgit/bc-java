package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPadding;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.util.io.TeeOutputStream;

import java.io.IOException;
import java.io.OutputStream;
import java.util.List;
import java.util.Stack;

/**
 * Implementation of an {@link OutputStream} tailored to creating OpenPGP messages.
 * Since not all OpenPGP-related OutputStreams forward {@link #close()} calls, we need to keep track of nested streams
 * and close them in order.
 * This stream can create OpenPGP messages following the following EBNF (which is a subset of the EBNF defined in RFC9580):
 * <ul>
 *     <li>OpenPGP Message := ASCII-Armor(Optionally Encrypted Message) | Optionally Encrypted Message</li>
 *     <li>Literal Message := LiteralDataPacket</li>
 *     <li>Optionally Compressed Message := Literal Message |
 *                                          CompressedDataPacket(Literal Message)</li>
 *     <li>Optionally Signed Message := Optionally Compressed Message |
 *                                      OnePassSignaturePacket + Optionally Signed Message + SignaturePacket</li>
 *     <li>Optionally Padded Message := Optionally Signed Message | Optionally Signed Message + PaddingPacket</li>
 *     <li>Encrypted Message := SEIPDv1(Optionally Padded Message) |
 *                              SEIPDv2(Optionally Padded Message) |
 *                              OED(Optionally Padded Message)</li>
 *     <li>Optionally Encrypted Message := Optionally Padded Message | Encrypted Message</li>
 * </ul>
 * Therefore, this stream is capable of creating a wide variety of OpenPGP message, from simply
 * LiteralDataPacket-wrapped plaintext over signed messages to encrypted, signed and padded messages.
 * The following considerations lead to why this particular subset was chosen:
 * <ul>
 *     <li>An encrypted message is not distinguishable from randomness, so it makes no sense to compress it</li>
 *     <li>Since signatures also consist of data which is not distinguishable from randomness,
 *     it makes no sense to compress them either</li>
 *     <li>Padding packets are used to prevent traffic analysis.
 *     Since they contain random data, we do not compress them.
 *     If a message is encrypted, we want to encrypt the padding packet to prevent an intermediate from stripping it</li>
 *     <li>Since (v4) signatures leak some metadata about the message plaintext (the hash and the issuer),
 *     for encrypted messages we always place signatures inside the encryption container (sign-then-encrypt)</li>
 *     <li>Prefix-signed messages (where a SignaturePacket is prefixed to an OpenPGP message) are
 *     inferior to One-Pass-Signed messages, so this stream cannot produce those.</li>
 *     <li>Messages using the Cleartext-Signature Framework are "different enough" to deserve their own
 *     message generator / stream.</li>
 * </ul>
 */
public class OpenPGPMessageOutputStream
    extends OutputStream
{
    // sink for the OpenPGP message
    private final OutputStream baseOut; // non-null

    private final OutputStream armorOut; // nullable
    private final OutputStream encodeOut; // non-null
    private final OutputStream encryptOut; // nullable
    private final OutputStream paddingOut; // nullable
    private final OutputStream signOut; // nullable
    private final OutputStream compressOut; // nullable
    private final OutputStream literalOut; // non-null

    // pipe plaintext data into this stream
    private final OutputStream plaintextOut; // non-null

    OpenPGPMessageOutputStream(OutputStream baseOut, Builder builder)
        throws PGPException, IOException
    {
        this.baseOut = baseOut;
        OutputStream innermostOut = baseOut;

        // ASCII ARMOR
        if (builder.armorFactory != null)
        {
            armorOut = builder.armorFactory.get(innermostOut);
            innermostOut = armorOut;
        }
        else
        {
            armorOut = null;
        }

        // BCPG (decide packet length encoding format)
        encodeOut = new BCPGOutputStream(innermostOut, PacketFormat.CURRENT);
        innermostOut = encodeOut;

        // ENCRYPT
        if (builder.encryptionStreamFactory != null)
        {
            encryptOut = builder.encryptionStreamFactory.get(innermostOut);
            innermostOut = encryptOut;
        }
        else
        {
            encryptOut = null;
        }

        // PADDING
        if (builder.paddingStreamFactory != null)
        {
            paddingOut = builder.paddingStreamFactory.get(innermostOut);
            innermostOut = paddingOut;
        }
        else
        {
            paddingOut = null;
        }

        // SIGN
        if (builder.signatureStreamFactory != null)
        {
            signOut = builder.signatureStreamFactory.get(innermostOut);
            // signOut does not forward write() calls down, so we do *not* set innermostOut to it
        }
        else
        {
            signOut = null;
        }

        // COMPRESS
        if (builder.compressionStreamFactory != null)
        {
            compressOut = builder.compressionStreamFactory.get(innermostOut);
            innermostOut = compressOut;
        }
        else
        {
            compressOut = null;
        }

        // LITERAL DATA
        if (builder.literalDataStreamFactory == null)
        {
            throw new PGPException("Missing instructions for LiteralData encoding.");
        }
        literalOut = builder.literalDataStreamFactory.get(innermostOut);

        if (signOut != null)
        {
            this.plaintextOut = new TeeOutputStream(literalOut, signOut);
        }
        else
        {
            this.plaintextOut = literalOut;
        }
    }

    @Override
    public void write(int i)
        throws IOException
    {
        plaintextOut.write(i);
    }

    @Override
    public void write(byte[] b)
        throws IOException
    {
        write(b, 0, b.length);
    }

    @Override
    public void write(byte[] b, int off, int len)
        throws IOException
    {
        plaintextOut.write(b, off, len);
    }

    @Override
    public void flush()
        throws IOException
    {
        literalOut.flush();
        if (compressOut != null)
        {
            compressOut.flush();
        }
        if (signOut != null)
        {
            signOut.flush();
        }
        if (paddingOut != null)
        {
            paddingOut.flush();
        }
        if (encryptOut != null)
        {
            encryptOut.flush();
        }
        encodeOut.flush();
        if (armorOut != null)
        {
            armorOut.flush();
        }
        baseOut.flush();
    }

    @Override
    public void close()
            throws IOException
    {
        literalOut.close();
        if (compressOut != null)
        {
            compressOut.close();
        }
        if (signOut != null)
        {
            signOut.close();
        }
        if (paddingOut != null)
        {
            paddingOut.close();
        }
        if (encryptOut != null)
        {
            encryptOut.close();
        }
        encodeOut.close();
        if (armorOut != null)
        {
            armorOut.close();
        }
        baseOut.close();
    }

    /**
     * Factory class for wrapping output streams.
     */
    public interface OutputStreamFactory
    {
        /**
         * Wrap the given base stream with another {@link OutputStream} and return the result.
         * @param base base output stream
         * @return wrapped output stream
         * @throws PGPException if the wrapping stream cannot be instantiated
         */
        OutputStream get(OutputStream base) throws PGPException, IOException;
    }

    static Builder builder()
    {
        return new Builder();
    }

    /**
     * Builder class for {@link OpenPGPMessageOutputStream} instances.
     */
    static class Builder
    {
        private OpenPGPMessageGenerator.ArmoredOutputStreamFactory armorFactory;
        private OutputStreamFactory paddingStreamFactory;
        private OutputStreamFactory encryptionStreamFactory;
        private OutputStreamFactory signatureStreamFactory;
        private OutputStreamFactory compressionStreamFactory;
        private OutputStreamFactory literalDataStreamFactory;

        /**
         * Specify a factory for ASCII armoring the message.
         *
         * @param factory armor stream factory
         * @return this
         */
        public Builder armor(OpenPGPMessageGenerator.ArmoredOutputStreamFactory factory)
        {
            this.armorFactory = factory;
            return this;
        }

        /**
         * Specify a factory for encrypting the message.
         *
         * @param factory encryption stream factory
         * @return this
         */
        public Builder encrypt(OutputStreamFactory factory)
        {
            this.encryptionStreamFactory = factory;
            return this;
        }

        /**
         * Specify a factory for padding the message.
         *
         * @param factory padding stream factory
         * @return this
         */
        public Builder padding(OutputStreamFactory factory)
        {
            this.paddingStreamFactory = factory;
            return this;
        }

        /**
         * Specify a factory for signing the message.
         *
         * @param factory signing stream factory
         * @return this
         */
        public Builder sign(OutputStreamFactory factory)
        {
            this.signatureStreamFactory = factory;
            return this;
        }

        /**
         * Specify a factory for compressing the message.
         * '
         * @param factory compression stream factory
         * @return this
         */
        public Builder compress(OutputStreamFactory factory)
        {
            this.compressionStreamFactory = factory;
            return this;
        }

        /**
         * Specify a factory for literal-data-wrapping the message.
         *
         * @param factory literal data stream factory
         * @return this
         */
        public Builder literalData(OutputStreamFactory factory)
        {
            this.literalDataStreamFactory = factory;
            return this;
        }

        /**
         * Construct the {@link OpenPGPMessageOutputStream} over the base output stream.
         *
         * @param baseOut base output stream
         * @return OpenPGP message output stream
         * @throws PGPException if a stream cannot be created
         * @throws IOException  if a signature cannot be generated
         */
        public OpenPGPMessageOutputStream build(OutputStream baseOut)
            throws PGPException, IOException
        {
            return new OpenPGPMessageOutputStream(baseOut, this);
        }
    }

    /**
     * OutputStream which updates {@link PGPSignatureGenerator} instances with data that is written to it.
     * Note: Data written to this stream will *NOT* be forwarded to the underlying {@link OutputStream}.
     * Once {@link #close()} is called, it will generate {@link PGPSignature} objects from the generators and write
     * those to the underlying {@link OutputStream}.
     */
    static class SignatureGeneratorOutputStream
        extends OutputStream
    {

        private final OutputStream out;
        private final List<PGPSignatureGenerator> signatureGenerators;

        public SignatureGeneratorOutputStream(OutputStream out, List<PGPSignatureGenerator> signatureGenerators)
        {
            this.out = out;
            this.signatureGenerators = signatureGenerators;
        }

        @Override
        public void write(int i)
            throws IOException
        {
            for (PGPSignatureGenerator sigGen : signatureGenerators)
            {
                sigGen.update((byte)i);
            }
        }

        @Override
        public void write(byte[] b)
            throws IOException
        {
            for (PGPSignatureGenerator sigGen : signatureGenerators)
            {
                sigGen.update(b);
            }
        }

        @Override
        public void write(byte[] b, int off, int len)
            throws IOException
        {
            for (PGPSignatureGenerator sigGen : signatureGenerators)
            {
                sigGen.update(b, off, len);
            }
        }

        @Override
        public void close()
            throws IOException
        {
            for (int i = signatureGenerators.size() - 1; i >= 0; i--)
            {
                PGPSignatureGenerator gen = signatureGenerators.get(i);
                PGPSignature sig = null;
                try
                {
                    sig = gen.generate();
                }
                catch (PGPException e)
                {
                    throw new RuntimeException(e);
                }
                sig.encode(out);
            }
        }
    }

    /**
     * OutputStream which appends a {@link org.bouncycastle.bcpg.PaddingPacket} to the data
     * once {@link #close()} is called.
     */
    static class PaddingPacketAppenderOutputStream
        extends OutputStream
    {
        private final OutputStream out;
        private final PaddingPacketFactory packetFactory;

        public PaddingPacketAppenderOutputStream(OutputStream out, PaddingPacketFactory packetFactory)
        {
            this.out = out;
            this.packetFactory = packetFactory;
        }

        @Override
        public void write(byte[] b)
            throws IOException
        {
            out.write(b);
        }

        @Override
        public void write(byte[] b, int off, int len)
            throws IOException
        {
            out.write(b, off, len);
        }

        @Override
        public void write(int i)
            throws IOException
        {
            out.write(i);
        }

        @Override
        public void close()
            throws IOException
        {
            packetFactory.providePaddingPacket().encode(out);
            out.close();
        }
    }

    /**
     * Factory interface for creating PGPPadding objects.
     */
    public interface PaddingPacketFactory
    {
        PGPPadding providePaddingPacket();
    }
}
