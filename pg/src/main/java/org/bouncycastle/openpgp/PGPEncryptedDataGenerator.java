package org.bouncycastle.openpgp;

import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.BCPGHeaderObject;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.SymmetricEncDataPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.operator.PBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PGPAEADDataEncryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.TeeOutputStream;

/**
 * Generator for encrypted objects.
 * <p>
 * A PGPEncryptedDataGenerator is used by configuring one or more {@link #methods encryption
 * methods}, and then invoking one of the open functions to create an OutputStream that raw data can
 * be supplied to for encryption:</p>
 * <ul>
 * <li>If the length of the data to be written is known in advance, use
 * {@link #open(OutputStream, long)} to create a packet containing a single encrypted object.</li>
 * <li>If the length of the data is unknown, use {@link #open(OutputStream, byte[])} to create an
 * packet consisting of a series of encrypted objects (partials).</li>
 * </ul>
 * <p>
 * Raw data is not typically written directly to the OutputStream obtained from a
 * PGPEncryptedDataGenerator. The OutputStream is usually wrapped by a
 * {@link PGPLiteralDataGenerator}, and often with a {@link PGPCompressedDataGenerator} between.
 * </p><p>
 * Once plaintext data for encryption has been written to the constructed OutputStream, writing of
 * the encrypted object stream is completed by closing the OutputStream obtained from the
 * <code>open()</code> method, or equivalently invoking {@link #close()} on this generator.
 * </p>
 */
public class PGPEncryptedDataGenerator
    implements SymmetricKeyAlgorithmTags, StreamGenerator
{
    // TODO: These seem to belong on the PBE classes. Are they even used now?
    /**
     * Specifier for SHA-1 S2K PBE generator.
     */
    public static final int S2K_SHA1 = HashAlgorithmTags.SHA1;

    /**
     * Specifier for SHA-224 S2K PBE generator.
     */
    public static final int S2K_SHA224 = HashAlgorithmTags.SHA224;

    /**
     * Specifier for SHA-256 S2K PBE generator.
     */
    public static final int S2K_SHA256 = HashAlgorithmTags.SHA256;

    /**
     * Specifier for SHA-384 S2K PBE generator.
     */
    public static final int S2K_SHA384 = HashAlgorithmTags.SHA384;

    /**
     * Specifier for SHA-512 S2K PBE generator.
     */
    public static final int S2K_SHA512 = HashAlgorithmTags.SHA512;

    private BCPGOutputStream pOut;
    private OutputStream cOut;
    private boolean useOldFormat = false;
    private PGPDigestCalculator digestCalc;
    private OutputStream genOut;
    private PGPDataEncryptorBuilder dataEncryptorBuilder;
    // OpenPGP v6 AEAD uses salt
    private byte[] salt = new byte[32];

    private List<PGPKeyEncryptionMethodGenerator> methods = new ArrayList<PGPKeyEncryptionMethodGenerator>();
    private int defAlgorithm; // default symmetric key algorithm
    private SecureRandom rand;
    // If true, force generation of a session key, even if we only have a single password-based encryption method
    //  and could therefore use the S2K output as session key directly.
    private boolean forceSessionKey = true;
    private SessionKeyExtractionCallback sessionKeyExtractionCallback = null;

    /**
     * Base constructor.
     *
     * @param encryptorBuilder builder to create actual data encryptor.
     */
    public PGPEncryptedDataGenerator(PGPDataEncryptorBuilder encryptorBuilder)
    {
        this(encryptorBuilder, false);
    }

    /**
     * Base constructor with the option to turn on formatting for PGP 2.6.x compatibility.
     *
     * @param encryptorBuilder builder to create actual data encryptor.
     * @param oldFormat        PGP 2.6.x compatibility requested.
     */
    public PGPEncryptedDataGenerator(PGPDataEncryptorBuilder encryptorBuilder, boolean oldFormat)
    {
        this.dataEncryptorBuilder = encryptorBuilder;
        this.useOldFormat = oldFormat;

        this.defAlgorithm = dataEncryptorBuilder.getAlgorithm();
        this.rand = dataEncryptorBuilder.getSecureRandom();

        rand.nextBytes(salt);
    }

    /**
     * Some versions of PGP always expect a session key, this will force use
     * of a session key even if a single PBE encryptor is provided.
     *
     * @param forceSessionKey true if a session key should always be used, default is true.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#section-5.3.1-4">
     * RFC9580 - Description of the optional encrypted session key field</a>
     */
    public void setForceSessionKey(boolean forceSessionKey)
    {
        this.forceSessionKey = forceSessionKey;
    }

    /**
     * Add a key encryption method to be used to encrypt the session data associated with this
     * encrypted data.
     *
     * @param method key encryption method to use.
     */
    public void addMethod(PGPKeyEncryptionMethodGenerator method)
    {
        methods.add(method);
    }

    public void setSessionKeyExtractionCallback(SessionKeyExtractionCallback callback)
    {
        this.sessionKeyExtractionCallback = callback;
    }

    /**
     * Create an OutputStream based on the configured methods.
     * <p>
     * If the supplied buffer is non <code>null</code> the stream returned will write a sequence of
     * partial packets, otherwise the length will be used to output a fixed length packet.
     * <p>
     * The stream created can be closed off by either calling close() on the stream or close() on
     * the generator. Closing the returned stream does not close off the OutputStream parameter out.
     *
     * @param out    the stream to write encrypted packets to.
     * @param length the length of the data to be encrypted. Ignored if buffer is non
     *               <code>null</code>.
     * @param buffer a buffer to use to buffer and write partial packets.
     * @return the generator's output stream.
     * @throws IOException           if an error occurs writing stream header information to the provider
     *                               output stream.
     * @throws PGPException          if an error occurs initialising PGP encryption for the configured
     *                               encryption methods.
     * @throws IllegalStateException if this generator already has an open OutputStream, or no
     *                               {@link #addMethod(PGPKeyEncryptionMethodGenerator) encryption methods} are
     *                               configured.
     */
    private OutputStream open(
        OutputStream out,
        long length,
        byte[] buffer)
        throws IOException, PGPException, IllegalStateException
    {
        if (cOut != null)
        {
            throw new IllegalStateException("generator already in open state");
        }

        if (methods.size() == 0)
        {
            throw new IllegalStateException("no encryption methods specified");
        }

        pOut = new BCPGOutputStream(out, !useOldFormat);

        byte[] sessionKey;  // session key, either protected by - or directly derived from session key encryption mechanism.
        byte[] sessionInfo = null; // sessionKey with prepended alg-id, appended checksum, null indicates direct use of S2K output as sessionKey/messageKey
        byte[] messageKey;          // key used to encrypt the message. In OpenPGP v6 this is derived from sessionKey + salt.

        boolean directS2K = !forceSessionKey && methods.size() == 1 &&
            methods.get(0) instanceof PBEKeyEncryptionMethodGenerator; // not public key
        boolean isV5StyleAEAD = dataEncryptorBuilder.isV5StyleAEAD(); //v5
        if (dataEncryptorBuilder.getAeadAlgorithm() != -1 && !isV5StyleAEAD)
        {
            sessionKey = PGPUtil.makeRandomKey(defAlgorithm, rand);
            // In OpenPGP v6, we need an additional step to derive a message key and IV from the session info.
            // Since we cannot inject the IV into the data encryptor, we append it to the message key.
            byte[] info = SymmetricEncIntegrityPacket.createAAData(
                SymmetricEncIntegrityPacket.VERSION_2,
                defAlgorithm,
                dataEncryptorBuilder.getAeadAlgorithm(),
                dataEncryptorBuilder.getChunkSize());
            // messageKey = key and IV, will be separated in the data encryptor
            messageKey = AEADUtil.deriveMessageKeyAndIv(
                dataEncryptorBuilder.getAeadAlgorithm(), defAlgorithm, sessionKey, salt, info);
        }
        else if (directS2K)
        {
            sessionKey = ((PBEKeyEncryptionMethodGenerator)methods.get(0)).getKey(defAlgorithm);
            messageKey = sessionKey;
        }
        else
        {
            sessionKey = PGPUtil.makeRandomKey(defAlgorithm, rand);
            messageKey = sessionKey;
        }

        if (sessionKeyExtractionCallback != null)
        {
            sessionKeyExtractionCallback.extractSessionKey(new PGPSessionKey(defAlgorithm, sessionKey));
        }

        PGPDataEncryptor dataEncryptor = dataEncryptorBuilder.build(messageKey);
        digestCalc = dataEncryptor.getIntegrityCalculator();
        BCPGHeaderObject encOut;
        for (int i = 0; i < methods.size(); i++)
        {
            PGPKeyEncryptionMethodGenerator method = (PGPKeyEncryptionMethodGenerator)methods.get(i);
            pOut.writePacket(method.generate(dataEncryptorBuilder, sessionKey));
        }
        try
        {
            // OpenPGP v5 or v6
            if (dataEncryptor instanceof PGPAEADDataEncryptor)
            {
                PGPAEADDataEncryptor aeadDataEncryptor = (PGPAEADDataEncryptor)dataEncryptor;
                long ivOrSaltLen;
                // data is encrypted by AEAD Encrypted Data packet (rfc4880bis10), so write v5 SKESK packet
                if (isV5StyleAEAD)
                {
                    byte[] iv = aeadDataEncryptor.getIV();
                    encOut = new AEADEncDataPacket(
                        defAlgorithm, aeadDataEncryptor.getAEADAlgorithm(), aeadDataEncryptor.getChunkSize(), iv);
                    ivOrSaltLen = iv.length;
                }
                else // data is encrypted by v2 SEIPD (AEAD), so write v6 SKESK packet
                {
                    //AEAD(HKDF(S2K(passphrase), info), secrets, packetprefix)
                    encOut = SymmetricEncIntegrityPacket.createVersion2Packet(
                        defAlgorithm,
                        aeadDataEncryptor.getAEADAlgorithm(),
                        aeadDataEncryptor.getChunkSize(),
                        salt);
                    ivOrSaltLen = salt.length;
                }
                if (buffer == null)
                {
                    long chunkLength = 1L << (aeadDataEncryptor.getChunkSize() + 6);
                    long tagLengths = ((length + chunkLength - 1) / chunkLength) * 16L + 16L; // data blocks + final tag
                    pOut = new ClosableBCPGOutputStream(out, encOut, (length + tagLengths + 4L + ivOrSaltLen));
                }
                else
                {
                    pOut = new ClosableBCPGOutputStream(out, encOut, buffer);
                }
                genOut = cOut = dataEncryptor.getOutputStream(pOut);
            }
            // OpenPGP v4
            else // data is encrypted by v1 SEIPD or SED packet, so write v4 SKESK packet
            {
                if (digestCalc != null)
                {
                    encOut = SymmetricEncIntegrityPacket.createVersion1Packet();
                    if (useOldFormat)
                    {
                        throw new PGPException("symmetric-enc-integrity packets not supported in old PGP format");
                    }
                }
                else
                {
                    encOut = new SymmetricEncDataPacket();
                }

                if (buffer == null)
                {
                    //
                    // we have to add block size + 2 for the generated IV and + 1 + 22 if integrity protected
                    //
                    long outLength = (digestCalc == null) ? length + dataEncryptor.getBlockSize() + 2 : length + dataEncryptor.getBlockSize() + 2 + 1 + 22;

                    pOut = new ClosableBCPGOutputStream(out, encOut, outLength, useOldFormat);
                }
                else
                {
                    pOut = new ClosableBCPGOutputStream(out, encOut, buffer);
                }

                genOut = cOut = dataEncryptor.getOutputStream(pOut);

                if (digestCalc != null)
                {
                    genOut = new TeeOutputStream(digestCalc.getOutputStream(), cOut);
                }

                byte[] inLineIv = new byte[dataEncryptor.getBlockSize() + 2];
                rand.nextBytes(inLineIv);
                inLineIv[inLineIv.length - 1] = inLineIv[inLineIv.length - 3];
                inLineIv[inLineIv.length - 2] = inLineIv[inLineIv.length - 4];

                genOut.write(inLineIv);
            }
            return new WrappedGeneratorStream(genOut, this);
        }
        catch (IOException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Exception creating cipher", e);
        }
    }

    /**
     * Create an OutputStream based on the configured methods to write a single encrypted object of
     * known length.
     *
     * <p>
     * The stream created can be closed off by either calling close() on the stream or close() on
     * the generator. Closing the returned stream does not close off the OutputStream parameter out.
     *
     * @param out    the stream to write encrypted packets to.
     * @param length the length of the data to be encrypted.
     * @return the output stream to write data to for encryption.
     * @throws IOException           if an error occurs writing stream header information to the provider
     *                               output stream.
     * @throws PGPException          if an error occurs initialising PGP encryption for the configured
     *                               encryption methods.
     * @throws IllegalStateException if this generator already has an open OutputStream, or no
     *                               {@link #addMethod(PGPKeyEncryptionMethodGenerator) encryption methods} are
     *                               configured.
     */
    public OutputStream open(
        OutputStream out,
        long length)
        throws IOException, PGPException
    {
        return this.open(out, length, null);
    }

    /**
     * Create an OutputStream which will encrypt the data as it is written to it. The stream of
     * encrypted data will be written out in chunks (partial packets) according to the size of the
     * passed in buffer.
     * <p>
     * The stream created can be closed off by either calling close() on the stream or close() on
     * the generator. Closing the returned stream does not close off the OutputStream parameter out.
     * <p>
     * <b>Note</b>: if the buffer is not a power of 2 in length only the largest power of 2 bytes
     * worth of the buffer will be used.
     *
     * @param out    the stream to write encrypted packets to.
     * @param buffer a buffer to use to buffer and write partial packets. The returned stream takes
     *               ownership of the buffer and will use it to buffer plaintext data for encryption.
     * @return the output stream to write data to for encryption.
     * @throws IOException           if an error occurs writing stream header information to the provider
     *                               output stream.
     * @throws PGPException          if an error occurs initialising PGP encryption for the configured
     *                               encryption methods.
     * @throws IllegalStateException if this generator already has an open OutputStream, or no
     *                               {@link #addMethod(PGPKeyEncryptionMethodGenerator) encryption methods} are
     *                               configured.
     */
    public OutputStream open(
        OutputStream out,
        byte[] buffer)
        throws IOException, PGPException
    {
        return this.open(out, 0, buffer);
    }

    /**
     * Close off the encrypted object - this is equivalent to calling close on the stream returned
     * by the <code>open()</code> methods.
     * <p>
     * <b>Note</b>: This does not close the underlying output stream, only the stream on top of it
     * created by the <code>open()</code> method.
     *
     * @throws IOException if an error occurs writing trailing information (such as integrity check
     *                     information) to the underlying stream.
     */
    public void close()
        throws IOException
    {
        if (cOut != null)
        {
            if (digestCalc != null)
            {
                //
                // hand code a mod detection packet
                //
                BCPGOutputStream bOut = new BCPGOutputStream(genOut, PacketTags.MOD_DETECTION_CODE, 20);

                bOut.flush();

                byte[] dig = digestCalc.getDigest();

                cOut.write(dig);
            }

            cOut.close();

            cOut = null;
            pOut = null;
        }
    }

    private static class ClosableBCPGOutputStream
        extends BCPGOutputStream
    {
        public ClosableBCPGOutputStream(OutputStream out, BCPGHeaderObject header, byte[] buffer)
            throws IOException
        {
            super(out, header.getType(), buffer);

            header.encode(this);
        }

        public ClosableBCPGOutputStream(OutputStream out, BCPGHeaderObject header, long length, boolean useOldIfPossible)
            throws IOException
        {
            super(out, header.getType(), length, useOldIfPossible);

            header.encode(this);
        }

        public ClosableBCPGOutputStream(OutputStream out, BCPGHeaderObject header, long length)
            throws IOException
        {
            super(out, header.getType(), length);

            header.encode(this);
        }

        public void close()
            throws IOException
        {
            this.finish();
        }
    }

    public interface SessionKeyExtractionCallback
    {
        void extractSessionKey(PGPSessionKey sessionKey);
    }
}
