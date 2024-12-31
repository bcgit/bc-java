package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPMarker;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPadding;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * An {@link InputStream} that processes an OpenPGP message.
 * Its contents are the plaintext from the messages LiteralData packet.
 * You can get information about the message (signatures, encryption method, message metadata)
 * by reading ALL data from the stream, closing it with {@link #close()} and then retrieving a {@link Result} object
 * by calling {@link #getResult()}.
 */
public class OpenPGPMessageInputStream
        extends InputStream
{
    public static int MAX_RECURSION = 16;

    private final PGPObjectFactory objectFactory;
    private final OpenPGPImplementation implementation;

    private final OpenPGPMessageProcessor processor;

    private final Result.Builder resultBuilder;
    private final Layer layer; // the packet layer processed by this input stream

    private InputStream in;

    OpenPGPMessageInputStream(PGPObjectFactory objectFactory,
                              OpenPGPMessageProcessor processor)
    {
        this(objectFactory, processor, Result.builder());
    }

    private OpenPGPMessageInputStream(PGPObjectFactory objectFactory,
                                      OpenPGPMessageProcessor processor,
                                      Result.Builder resultBuilder)
    {
        this.objectFactory = objectFactory;
        this.processor = processor;
        this.implementation = processor.getImplementation();
        this.resultBuilder = resultBuilder;
        try
        {
            this.layer = resultBuilder.openLayer();
        }
        catch (PGPException e)
        {
            // cannot happen
            throw new AssertionError(e);
        }
    }

    void process()
            throws IOException, PGPException
    {
        Object next;
        while ((next = objectFactory.nextObject()) != null)
        {
            // prefixed packets

            if (next instanceof PGPSignatureList)
            {
                // prefixed-signed message (SIG MSG)
                PGPSignatureList prefixedSigs = (PGPSignatureList) next;
                resultBuilder.prefixedSignatures(prefixedSigs);
            }
            else if (next instanceof PGPOnePassSignatureList)
            {
                // one-pass-signed message (OPS MSG SIG)
                PGPOnePassSignatureList pgpOnePassSignatures = (PGPOnePassSignatureList) next;
                resultBuilder.onePassSignatures(pgpOnePassSignatures);
            }
            else if (next instanceof PGPMarker)
            {
                // prefixed marker packet (ignore)
            }

            else
            {
                // Init signatures of this layer
                resultBuilder.initSignatures(processor);

                if (next instanceof PGPLiteralData)
                {
                    // Literal Data \o/
                    PGPLiteralData literalData = (PGPLiteralData) next;
                    resultBuilder.literalData(
                            literalData.getFileName(),
                            (char) literalData.getFormat(),
                            literalData.getModificationTime());

                    in = literalData.getDataStream();
                    return;
                }
                else if (next instanceof PGPCompressedData)
                {
                    // Compressed Data
                    PGPCompressedData compressedData = (PGPCompressedData) next;
                    resultBuilder.compressed(compressedData.getAlgorithm());

                    InputStream decompressed = compressedData.getDataStream();
                    InputStream decodeIn = BCPGInputStream.wrap(decompressed);
                    PGPObjectFactory decFac = implementation.pgpObjectFactory(decodeIn);
                    OpenPGPMessageInputStream nestedIn = new OpenPGPMessageInputStream(decFac, processor, resultBuilder);
                    in = nestedIn;
                    nestedIn.process();
                    return;
                }
                else if (next instanceof PGPEncryptedDataList)
                {
                    // Encrypted Data
                    PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) next;
                    OpenPGPMessageProcessor.Decrypted decrypted = processor.decrypt(encryptedDataList);
                    InputStream decryptedIn = decrypted.inputStream;
                    resultBuilder.encrypted(decrypted);
                    InputStream decodeIn = BCPGInputStream.wrap(decryptedIn);
                    PGPObjectFactory decFac = implementation.pgpObjectFactory(decodeIn);
                    OpenPGPMessageInputStream nestedIn = new OpenPGPMessageInputStream(decFac, processor, resultBuilder);
                    in = nestedIn;
                    nestedIn.process();
                    return;
                }
                else
                {
                    processor.onException(new PGPException("Unexpected packet encountered: " +
                            next.getClass().getName()));
                }
            }
        }
    }

    @Override
    public void close()
            throws IOException
    {
        in.close();

        Object next;
        while ((next = objectFactory.nextObject()) != null)
        {
            if (next instanceof PGPSignatureList)
            {
                // one-pass-signed message (OPS MSG SIG)
                PGPSignatureList signatures = (PGPSignatureList) next;
                resultBuilder.last().onePassSignatures.addSignatures(signatures);
            }
            else if (next instanceof PGPPadding)
            {
                // padded message
            }
            else if (next instanceof PGPMarker)
            {
                // postfixed marker packet (ignore)
            }
            else
            {
                // unknown/unexpected packet
                processor.onException(new PGPException("Unexpected trailing packet encountered: " +
                        next.getClass().getName()));
            }
        }

        resultBuilder.verifySignatures(processor);
        resultBuilder.closeLayer();
    }

    @Override
    public int read()
            throws IOException
    {
        int i = in.read();
        if (i >= 0)
        {
            layer.onePassSignatures.update(i);
            layer.prefixedSignatures.update(i);
        }
        return i;
    }

    @Override
    public int read(byte[] b)
            throws IOException
    {
        int i = in.read(b);
        if (i >= 0)
        {
            layer.onePassSignatures.update(b, 0, i);
            layer.prefixedSignatures.update(b, 0, i);
        }
        return i;
    }

    @Override
    public int read(byte[] b, int off, int len)
            throws IOException
    {
        int i = in.read(b, off, len);
        if (i >= 0)
        {
            layer.onePassSignatures.update(b, off, i);
            layer.prefixedSignatures.update(b, off, i);
        }
        return i;
    }

    public Result getResult()
    {
        return resultBuilder.build();
    }

    public static class Result
    {
        private final List<OpenPGPSignature.OpenPGPDocumentSignature> documentSignatures = new ArrayList<>();
        private OpenPGPCertificate.OpenPGPComponentKey decryptionKey;
        private char[] decryptionPassphrase;
        private PGPSessionKey sessionKey;
        private MessageEncryptionMechanism encryptionMethod = MessageEncryptionMechanism.unencrypted();
        private int compressionAlgorithm = 0;
        private String filename;
        private char fileFormat;
        private Date fileModificationTime;

        private Result(List<Layer> layers)
        {
            for (Layer l : layers)
            {
                if (l.signatures != null)
                    documentSignatures.addAll(l.signatures);

                if (l.nested instanceof EncryptedData)
                {
                    EncryptedData encryptedData = (EncryptedData) l.nested;
                    encryptionMethod = encryptedData.encryption;
                    sessionKey = encryptedData.sessionKey;
                    decryptionKey = encryptedData.decryptionKey;
                    decryptionPassphrase = encryptedData.decryptionPassphrase;
                }
                else if (l.nested instanceof CompressedData)
                {
                    CompressedData compressedData = (CompressedData) l.nested;
                    compressionAlgorithm = compressedData.compressionAlgorithm;
                }
                else if (l.nested instanceof LiteralData)
                {
                    LiteralData literalData = (LiteralData) l.nested;
                    filename = literalData.filename;
                    fileFormat = literalData.encoding;
                    fileModificationTime = literalData.modificationTime;
                }
            }
        }

        static Builder builder()
        {
            return new Builder();
        }

        public MessageEncryptionMechanism getEncryptionMethod()
        {
            return encryptionMethod;
        }

        public OpenPGPCertificate.OpenPGPComponentKey getDecryptionKey()
        {
            return decryptionKey;
        }

        public char[] getDecryptionPassphrase()
        {
            return decryptionPassphrase;
        }

        public PGPSessionKey getSessionKey()
        {
            return sessionKey;
        }

        public int getCompressionAlgorithm()
        {
            return compressionAlgorithm;
        }

        public String getFilename()
        {
            return filename;
        }

        public char getFileFormat()
        {
            return fileFormat;
        }

        public Date getFileModificationTime()
        {
            return fileModificationTime;
        }

        public List<OpenPGPSignature.OpenPGPDocumentSignature> getSignatures()
        {
            return new ArrayList<>(documentSignatures);
        }

        static class Builder
        {
            private final List<Layer> layers = new ArrayList<>();

            private Builder()
            {

            }

            Layer last()
            {
                return layers.get(layers.size() - 1);
            }

            /**
             * Enter a nested OpenPGP packet layer.
             *
             * @return the new layer
             * @throws PGPException if the parser exceeded the maximum nesting depth ({@link #MAX_RECURSION}).
             */
            Layer openLayer()
                    throws PGPException
            {
                if (layers.size() >= MAX_RECURSION)
                {
                    throw new PGPException("Exceeded maximum packet nesting depth.");
                }
                Layer layer = new Layer();
                layers.add(layer);
                return layer;
            }

            /**
             * Close a nested OpenPGP packet layer.
             */
            void closeLayer()
            {
                for (int i = layers.size() - 1; i >= 0; i--)
                {
                    Layer l = layers.get(i);
                    if (l.isOpen())
                    {
                        l.close();
                        return;
                    }
                }
            }

            /**
             * Set the nested packet type of the current layer to {@link CompressedData}.
             *
             * @param compressionAlgorithm compression algorithm ID
             */
            void compressed(int compressionAlgorithm)
            {
                last().setNested(new CompressedData(compressionAlgorithm));
            }

            /**
             * Add One-Pass-Signature packets on the current layer.
             *
             * @param pgpOnePassSignatures one pass signature packets
             */
            void onePassSignatures(PGPOnePassSignatureList pgpOnePassSignatures)
            {
                last().onePassSignatures.addOnePassSignatures(pgpOnePassSignatures);
            }

            /**
             * Build the {@link Result}.
             *
             * @return result
             */
            Result build()
            {
                return new Result(layers);
            }

            /**
             * Add prefixed signatures on the current layer.
             *
             * @param prefixedSigs prefixed signatures
             */
            void prefixedSignatures(PGPSignatureList prefixedSigs)
            {
                last().prefixedSignatures.addAll(prefixedSigs);
            }

            /**
             * Initialize any signatures on the current layer, prefixed and one-pass-signatures.
             *
             * @param processor message processor
             */
            void initSignatures(OpenPGPMessageProcessor processor)
            {
                last().onePassSignatures.init(processor);
                last().prefixedSignatures.init(processor);
            }

            /**
             * Verify all signatures on the current layer, prefixed and one-pass-signatures.
             *
             * @param processor message processor
             */
            void verifySignatures(OpenPGPMessageProcessor processor)
            {
                Layer last = last();
                if (last.signatures != null)
                {
                    return;
                }

                last.signatures = new ArrayList<>();
                last.signatures.addAll(last.onePassSignatures.verify(processor));
                last.signatures.addAll(last.prefixedSignatures.verify(processor));
            }

            /**
             * Set literal data metadata on the current layer.
             *
             * @param fileName filename
             * @param format data format
             * @param modificationTime modification time
             */
            void literalData(String fileName, char format, Date modificationTime)
            {
                last().setNested(new LiteralData(fileName, format, modificationTime));
            }

            /**
             * Set metadata from an encrypted data packet on the current layer.
             *
             * @param decrypted decryption result
             */
            void encrypted(OpenPGPMessageProcessor.Decrypted decrypted)
            {
                last().setNested(new EncryptedData(decrypted));
            }
        }
    }

    static class Layer
    {
        private final OnePassSignatures onePassSignatures = new OnePassSignatures();
        private final PrefixedSignatures prefixedSignatures = new PrefixedSignatures();

        private List<OpenPGPSignature.OpenPGPDocumentSignature> signatures = null;

        private Nested nested;
        private boolean open = true;

        void setNested(Nested nested)
        {
            this.nested = nested;
        }

        void close()
        {
            this.open = false;
        }

        boolean isOpen()
        {
            return open;
        }
    }

    static class Nested
    {

    }

    static class CompressedData
            extends Nested
    {
        private final int compressionAlgorithm;

        public CompressedData(int algorithm)
        {
            this.compressionAlgorithm = algorithm;
        }
    }

    static class LiteralData
            extends Nested
    {
        private final String filename;
        private final char encoding;
        private final Date modificationTime;

        LiteralData(String filename, char encoding, Date modificationTime)
        {
            this.filename = filename;
            this.encoding = encoding;
            this.modificationTime = modificationTime;
        }
    }

    static class EncryptedData
            extends Nested
    {
        private final OpenPGPCertificate.OpenPGPComponentKey decryptionKey;
        private final char[] decryptionPassphrase;
        private final PGPSessionKey sessionKey;
        private final MessageEncryptionMechanism encryption;

        EncryptedData(OpenPGPMessageProcessor.Decrypted decrypted)
        {
            this.decryptionKey = decrypted.decryptionKey;
            this.decryptionPassphrase = decrypted.decryptionPassphrase;
            this.sessionKey = decrypted.sessionKey;
            if (decrypted.esk.getEncData() instanceof SymmetricEncIntegrityPacket)
            {
                SymmetricEncIntegrityPacket seipd = (SymmetricEncIntegrityPacket) decrypted.esk.getEncData();
                if (seipd.getVersion() == SymmetricEncIntegrityPacket.VERSION_2)
                {
                    encryption = MessageEncryptionMechanism.aead(
                            seipd.getCipherAlgorithm(), seipd.getAeadAlgorithm());
                }
                else
                {
                    encryption = MessageEncryptionMechanism.integrityProtected(sessionKey.getAlgorithm());
                }
            }
            else if (decrypted.esk.getEncData() instanceof AEADEncDataPacket)
            {
                encryption = MessageEncryptionMechanism.librePgp(sessionKey.getAlgorithm());
            }
            else
            {
                throw new RuntimeException("Unexpected encrypted data packet type: " + decrypted.esk.getClass().getName());
            }
        }
    }

    static class OnePassSignatures
    {
        private final List<PGPOnePassSignature> onePassSignatures = new ArrayList<>();
        private final List<PGPSignature> signatures = new ArrayList<>();
        private final Map<PGPOnePassSignature, OpenPGPCertificate.OpenPGPComponentKey> issuers = new HashMap<>();

        OnePassSignatures()
        {

        }

        void addOnePassSignatures(PGPOnePassSignatureList onePassSignatures)
        {
            for (PGPOnePassSignature ops : onePassSignatures)
            {
                this.onePassSignatures.add(ops);
            }
        }

        void addSignatures(PGPSignatureList signatures)
        {
            for (PGPSignature signature : signatures)
            {
                this.signatures.add(signature);
            }
        }

        void init(OpenPGPMessageProcessor processor)
        {

            for (PGPOnePassSignature ops : onePassSignatures)
            {
                KeyIdentifier identifier = ops.getKeyIdentifier();
                OpenPGPCertificate cert = processor.provideCertificate(identifier);
                if (cert == null)
                {
                    continue;
                }

                try
                {
                    OpenPGPCertificate.OpenPGPComponentKey key = cert.getKey(identifier);
                    issuers.put(ops, key);
                    ops.init(processor.getImplementation().pgpContentVerifierBuilderProvider(),
                            key.getPGPPublicKey());
                }
                catch (PGPException e)
                {
                    processor.onException(e);
                }
            }
        }

        void update(int i)
        {
            for (PGPOnePassSignature onePassSignature : onePassSignatures)
            {
                if (issuers.containsKey(onePassSignature))
                {
                    onePassSignature.update((byte) i);
                }
            }
        }

        void update(byte[] b, int off, int len)
        {
            for (PGPOnePassSignature onePassSignature : onePassSignatures)
            {
                if (issuers.containsKey(onePassSignature))
                {
                    onePassSignature.update(b, off, len);
                }
            }
        }

        List<OpenPGPSignature.OpenPGPDocumentSignature> verify(
                OpenPGPMessageProcessor processor)
        {
            OpenPGPPolicy policy = processor.getImplementation().policy();
            List<OpenPGPSignature.OpenPGPDocumentSignature> dataSignatures = new ArrayList<>();
            int num = onePassSignatures.size();
            for (int i = 0; i < signatures.size(); i++)
            {
                PGPSignature signature = signatures.get(i);
                PGPOnePassSignature ops = onePassSignatures.get(num - i - 1);
                OpenPGPCertificate.OpenPGPComponentKey key = issuers.get(ops);
                if (key == null)
                {
                    continue;
                }

                if (!policy.isAcceptablePublicKey(key.getPGPPublicKey()))
                {
                    continue;
                }
                if (!policy.isAcceptableSignature(signature))
                {
                    continue;
                }

                OpenPGPSignature.OpenPGPDocumentSignature dataSignature =
                        new OpenPGPSignature.OpenPGPDocumentSignature(signature, key);
                if (!dataSignature.createdInBounds(processor.getVerifyNotBefore(), processor.getVerifyNotAfter()))
                {
                    // sig is not in bounds
                    continue;
                }
                try
                {
                    dataSignature.verify(ops);
                }
                catch (PGPException e)
                {
                    processor.onException(e);
                }
                dataSignatures.add(dataSignature);
            }
            return dataSignatures;
        }
    }

    static class PrefixedSignatures
    {
        private final List<PGPSignature> prefixedSignatures = new ArrayList<>();
        private final List<OpenPGPSignature.OpenPGPDocumentSignature> dataSignatures = new ArrayList<>();

        PrefixedSignatures()
        {

        }

        void addAll(PGPSignatureList signatures)
        {
            for (PGPSignature signature : signatures)
            {
                this.prefixedSignatures.add(signature);
            }
        }

        void init(OpenPGPMessageProcessor processor)
        {
            for (PGPSignature sig : prefixedSignatures)
            {
                KeyIdentifier identifier = OpenPGPSignature.getMostExpressiveIdentifier(sig.getKeyIdentifiers());
                if (identifier == null)
                {
                    dataSignatures.add(new OpenPGPSignature.OpenPGPDocumentSignature(sig, null));
                    continue;
                }
                OpenPGPCertificate cert = processor.provideCertificate(identifier);
                if (cert == null)
                {
                    dataSignatures.add(new OpenPGPSignature.OpenPGPDocumentSignature(sig, null));
                    continue;
                }

                OpenPGPCertificate.OpenPGPComponentKey key = cert.getKey(identifier);
                OpenPGPSignature.OpenPGPDocumentSignature signature = new OpenPGPSignature.OpenPGPDocumentSignature(sig, key);
                dataSignatures.add(signature);
                try
                {
                    signature.signature.init(
                            processor.getImplementation().pgpContentVerifierBuilderProvider(),
                            cert.getKey(identifier).getPGPPublicKey());
                }
                catch (PGPException e)
                {
                    processor.onException(e);
                }
            }
        }

        void update(int i)
        {
            for(PGPSignature signature : prefixedSignatures)
            {
                signature.update((byte) i);
            }
        }

        void update(byte[] buf, int off, int len)
        {
            for (PGPSignature signature : prefixedSignatures)
            {
                signature.update(buf, off, len);
            }
        }

        List<OpenPGPSignature.OpenPGPDocumentSignature> verify(OpenPGPMessageProcessor processor)
        {
            OpenPGPPolicy policy = processor.getImplementation().policy();
            for (OpenPGPSignature.OpenPGPDocumentSignature sig : dataSignatures)
            {
                if (!policy.isAcceptablePublicKey(sig.getIssuer().getPGPPublicKey()))
                {
                    continue;
                }
                if (!policy.isAcceptableSignature(sig.signature))
                {
                    continue;
                }

                try
                {
                    sig.verify();
                }
                catch (PGPException e)
                {
                    processor.onException(e);
                }
            }
            return dataSignatures;
        }
    }
}
