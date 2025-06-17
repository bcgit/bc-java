package org.bouncycastle.openpgp.api;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
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
import org.bouncycastle.openpgp.PGPSignatureException;
import org.bouncycastle.openpgp.PGPSignatureList;

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
    private final List<PacketHandler> packetHandlers = new ArrayList<PacketHandler>()
    {{
        add(new SignatureListHandler());
        add(new OnePassSignatureHandler());
        add(new MarkerHandler());
        add(new LiteralDataHandler());
        add(new CompressedDataHandler());
        add(new EncryptedDataHandler());
        add(new DefaultPacketHandler()); // Must be last
    }};

    private final List<PacketHandler> closeHandlers = new ArrayList<PacketHandler>()
    {{
        add(new SignatureListHandler());
        add(new PaddingHandler());
        add(new MarkerHandler());
        add(new DefaultPacketHandler());
    }};

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
            for (PacketHandler handler : packetHandlers)
            {
                if (handler.canHandle(next))
                {
                    handler.handle(next);
                    break;
                }
            }

            if (in != null)
            {
                return; // Found data stream, stop processing
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
            boolean handled = false;
            for (Iterator it = closeHandlers.iterator(); it.hasNext();)
            {
                PacketHandler handler = (PacketHandler)it.next();
                if (handler.canHandle(next))
                {
                    handler.close(next);
                    handled = true;
                    break;
                }
            }

            if (!handled)
            {
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
//            byte b = (byte)i;
//            layer.onePassVerifier.update(b);
//            layer.prefixedVerifier.update(b);
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
//            layer.onePassVerifier.update(b, 0, i);
//            layer.prefixedVerifier.update(b, 0, i);
        }
        return i;
    }

    @Override
    public int read(byte[] b, int off, int len)
        throws IOException
    {
        int bytesRead = in.read(b, off, len);
        if (bytesRead > 0)
        {
            layer.onePassSignatures.update(b, off, bytesRead);
            layer.prefixedSignatures.update(b, off, bytesRead);
//            layer.onePassVerifier.update(b, off, bytesRead);
//            layer.prefixedVerifier.update(b, off, bytesRead);
        }
        return bytesRead;
    }

    public Result getResult()
    {
        return resultBuilder.build();
    }

    public static class Result
    {
        private final List<OpenPGPSignature.OpenPGPDocumentSignature> documentSignatures = new ArrayList<OpenPGPSignature.OpenPGPDocumentSignature>();
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
            for (Iterator<Layer> it = layers.iterator(); it.hasNext(); )
            {
                Layer l = it.next();
                if (l.signatures != null)
                {
                    documentSignatures.addAll(l.signatures);
                }

                if (l.nested instanceof EncryptedData)
                {
                    EncryptedData encryptedData = (EncryptedData)l.nested;
                    encryptionMethod = encryptedData.encryption;
                    sessionKey = encryptedData.sessionKey;
                    decryptionKey = encryptedData.decryptionKey;
                    decryptionPassphrase = encryptedData.decryptionPassphrase;
                }
                else if (l.nested instanceof CompressedData)
                {
                    CompressedData compressedData = (CompressedData)l.nested;
                    compressionAlgorithm = compressedData.compressionAlgorithm;
                }
                else if (l.nested instanceof LiteralData)
                {
                    LiteralData literalData = (LiteralData)l.nested;
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
            return new ArrayList<OpenPGPSignature.OpenPGPDocumentSignature>(documentSignatures);
        }

        static class Builder
        {
            private final List<Layer> layers = new ArrayList<Layer>();

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
//                last().onePassVerifier.addSignatures(pgpOnePassSignatures.iterator());
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
                //last().prefixedVerifier.addSignatures(prefixedSigs.iterator());
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
//                last().onePassVerifier.commonInit(processor);
//                last().prefixedVerifier.commonInit(processor);
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

                last.signatures = new ArrayList<OpenPGPSignature.OpenPGPDocumentSignature>();
                last.signatures.addAll(last.onePassSignatures.verify(processor));
                last.signatures.addAll(last.prefixedSignatures.verify(processor));
//                last.signatures.addAll(last.onePassVerifier.verify(processor));
//                last.signatures.addAll(last.prefixedVerifier.verify(processor));
            }

            /**
             * Set literal data metadata on the current layer.
             *
             * @param fileName         filename
             * @param format           data format
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
//        private final OnePassSignatureVerifier onePassVerifier = new OnePassSignatureVerifier();
//        private final PrefixedSignatureVerifier prefixedVerifier = new PrefixedSignatureVerifier();
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
                SymmetricEncIntegrityPacket seipd = (SymmetricEncIntegrityPacket)decrypted.esk.getEncData();
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

    private static class PacketHandler
    {
        public boolean canHandle(Object packet)
        {
            return false;
        }

        public void handle(Object packet)
            throws IOException, PGPException
        {

        }

        public void close(Object packet)
            throws IOException
        {

        }
    }

    private class SignatureListHandler
        extends PacketHandler
    {
        public boolean canHandle(Object packet)
        {
            return packet instanceof PGPSignatureList;
        }

        public void handle(Object packet)
        {
            PGPSignatureList prefixedSigs = (PGPSignatureList)packet;
            resultBuilder.prefixedSignatures(prefixedSigs);
        }

        public void close(Object packet)
        {
            PGPSignatureList sigList = (PGPSignatureList)packet;
            resultBuilder.last().onePassSignatures.addSignatures(sigList);
            //resultBuilder.last().onePassVerifier.addPGPSinatures(sigList.iterator());
        }
    }

    private class LiteralDataHandler
        extends PacketHandler
    {
        @Override
        public boolean canHandle(Object packet)
        {
            return packet instanceof PGPLiteralData;
        }

        @Override
        public void handle(Object packet)
            throws IOException, PGPException
        {
            PGPLiteralData literalData = (PGPLiteralData)packet;
            resultBuilder.literalData(
                literalData.getFileName(),
                (char)literalData.getFormat(),
                literalData.getModificationTime()
            );
            in = literalData.getDataStream();
            resultBuilder.initSignatures(processor);
        }
    }

    private class OnePassSignatureHandler
        extends PacketHandler
    {
        @Override
        public boolean canHandle(Object packet)
        {
            return packet instanceof PGPOnePassSignatureList;
        }

        @Override
        public void handle(Object packet)
            throws IOException, PGPException
        {
            PGPOnePassSignatureList pgpOnePassSignatures = (PGPOnePassSignatureList)packet;
            resultBuilder.onePassSignatures(pgpOnePassSignatures);
        }
    }

    private static class MarkerHandler
        extends PacketHandler
    {
        @Override
        public boolean canHandle(Object packet)
        {
            return packet instanceof PGPMarker;
        }
    }

    private class CompressedDataHandler
        extends PacketHandler
    {
        @Override
        public boolean canHandle(Object packet)
        {
            return packet instanceof PGPCompressedData;
        }

        @Override
        public void handle(Object packet)
            throws IOException, PGPException
        {
            PGPCompressedData compressedData = (PGPCompressedData)packet;
            resultBuilder.compressed(compressedData.getAlgorithm());

            InputStream decompressed = compressedData.getDataStream();
            processNestedStream(decompressed);
        }

        private void processNestedStream(InputStream input)
            throws IOException, PGPException
        {
            InputStream decodeIn = BCPGInputStream.wrap(input);
            PGPObjectFactory decFac = implementation.pgpObjectFactory(decodeIn);
            OpenPGPMessageInputStream nestedIn =
                new OpenPGPMessageInputStream(decFac, processor, resultBuilder);
            in = nestedIn;
            nestedIn.process();
        }
    }

    private class EncryptedDataHandler
        extends PacketHandler
    {
        @Override
        public boolean canHandle(Object packet)
        {
            return packet instanceof PGPEncryptedDataList;
        }

        @Override
        public void handle(Object packet)
            throws IOException, PGPException
        {
            PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList)packet;
            OpenPGPMessageProcessor.Decrypted decrypted = processor.decrypt(encryptedDataList);

            resultBuilder.encrypted(decrypted);
            processNestedStream(decrypted.inputStream);
        }

        private void processNestedStream(InputStream input)
            throws IOException, PGPException
        {
            InputStream decodeIn = BCPGInputStream.wrap(input);
            PGPObjectFactory decFac = implementation.pgpObjectFactory(decodeIn);
            OpenPGPMessageInputStream nestedIn =
                new OpenPGPMessageInputStream(decFac, processor, resultBuilder);
            in = nestedIn;
            nestedIn.process();
        }
    }

    private static class PaddingHandler
        extends PacketHandler
    {
        public boolean canHandle(Object packet)
        {
            return packet instanceof PGPPadding;
        }
    }

    private class DefaultPacketHandler
        extends PacketHandler
    {
        @Override
        public boolean canHandle(Object packet)
        {
            return true; // Catch-all handler
        }

        @Override
        public void handle(Object packet)
            throws PGPException
        {
            processor.onException(new PGPException("Unexpected packet: " + packet.getClass().getName()));
        }
    }

    static class OnePassSignatures
    {
        private final List<PGPOnePassSignature> onePassSignatures = new ArrayList<PGPOnePassSignature>();
        private final List<PGPSignature> signatures = new ArrayList<PGPSignature>();
        private final Map<PGPOnePassSignature, OpenPGPCertificate.OpenPGPComponentKey> issuers = new HashMap<PGPOnePassSignature, OpenPGPCertificate.OpenPGPComponentKey>();

        OnePassSignatures()
        {

        }

        void addOnePassSignatures(PGPOnePassSignatureList onePassSignatures)
        {
            for (Iterator it = onePassSignatures.iterator(); it.hasNext();)
            {
                PGPOnePassSignature ops = (PGPOnePassSignature)it.next();
                this.onePassSignatures.add(ops);
            }
        }

        void addSignatures(PGPSignatureList signatures)
        {
            for (Iterator it = signatures.iterator(); it.hasNext();)
            {
                PGPSignature signature = (PGPSignature)it.next();
                this.signatures.add(signature);
            }
        }

        void init(OpenPGPMessageProcessor processor)
        {

            for (Iterator it = onePassSignatures.iterator(); it.hasNext();)
            {
                PGPOnePassSignature ops = (PGPOnePassSignature)it.next();
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
            for (Iterator it = onePassSignatures.iterator(); it.hasNext();)
            {
                PGPOnePassSignature onePassSignature = (PGPOnePassSignature)it.next();
                if (issuers.containsKey(onePassSignature))
                {
                    onePassSignature.update((byte) i);
                }
            }
        }

        void update(byte[] b, int off, int len)
        {
            for (Iterator it = onePassSignatures.iterator(); it.hasNext();)
            {
                PGPOnePassSignature onePassSignature = (PGPOnePassSignature)it.next();
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
            List<OpenPGPSignature.OpenPGPDocumentSignature> dataSignatures = new ArrayList<OpenPGPSignature.OpenPGPDocumentSignature>();
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

                OpenPGPSignature.OpenPGPDocumentSignature dataSignature =
                    new OpenPGPSignature.OpenPGPDocumentSignature(signature, key);
                try
                {
                    dataSignature.sanitize(key, policy);
                }
                catch (PGPSignatureException e)
                {
                    // continue
                }

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
        private final List<PGPSignature> prefixedSignatures = new ArrayList<PGPSignature>();
        private final List<OpenPGPSignature.OpenPGPDocumentSignature> dataSignatures = new ArrayList<OpenPGPSignature.OpenPGPDocumentSignature>();

        PrefixedSignatures()
        {

        }

        void addAll(PGPSignatureList signatures)
        {
            for (Iterator it = signatures.iterator(); it.hasNext();)
            {
                PGPSignature signature = (PGPSignature)it.next();
                this.prefixedSignatures.add(signature);
            }
        }

        void init(OpenPGPMessageProcessor processor)
        {
            for (Iterator it = prefixedSignatures.iterator(); it.hasNext();)
            {
                PGPSignature sig = (PGPSignature)it.next();
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
            for (Iterator it = prefixedSignatures.iterator(); it.hasNext();)
            {
                PGPSignature signature = (PGPSignature)it.next();
                signature.update((byte) i);
            }
        }

        void update(byte[] buf, int off, int len)
        {
            for (Iterator it = prefixedSignatures.iterator(); it.hasNext();)
            {
                PGPSignature signature = (PGPSignature)it.next();
                signature.update(buf, off, len);
            }
        }

        List<OpenPGPSignature.OpenPGPDocumentSignature> verify(OpenPGPMessageProcessor processor)
        {
            List<OpenPGPSignature.OpenPGPDocumentSignature> verifiedSignatures = new ArrayList<OpenPGPSignature.OpenPGPDocumentSignature>();
            OpenPGPPolicy policy = processor.getImplementation().policy();
            for (Iterator it = dataSignatures.iterator(); it.hasNext();)
            {
                OpenPGPSignature.OpenPGPDocumentSignature sig = (OpenPGPSignature.OpenPGPDocumentSignature)it.next();
                try
                {
                    sig.sanitize(sig.issuer, policy);
                }
                catch (PGPSignatureException e)
                {
                    processor.onException(e);
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
                verifiedSignatures.add(sig);
            }
            return verifiedSignatures;
        }
    }

//    private static abstract class BaseSignatureVerifier<R>
//    {
//        protected final List<R> signatures = new ArrayList<>();
//        protected final Map<R, OpenPGPCertificate.OpenPGPComponentKey> issuers = new HashMap<>();
//
//        public void addSignatures(Iterator<R> it)
//        {
//            while (it.hasNext())
//            {
//                this.signatures.add(it.next());
//            }
//        }
//
//        protected void commonInit(OpenPGPMessageProcessor processor)
//            throws PGPException
//        {
//            for (R sig : signatures)
//            {
//                KeyIdentifier identifier = getKeyIdentifier(sig);
//                OpenPGPCertificate cert = processor.provideCertificate(identifier);
//
//                if (cert != null)
//                {
//                    OpenPGPCertificate.OpenPGPComponentKey key = cert.getKey(identifier);
//                    issuers.put(sig, key);
//                    initSignature(sig, key, processor);
//                }
//            }
//        }
//
//        public abstract void update(byte i);
//
//        public abstract void update(byte[] buf, int off, int len);
//
//        public List<OpenPGPSignature.OpenPGPDocumentSignature> verify(
//            OpenPGPMessageProcessor processor)
//        {
//            List<OpenPGPSignature.OpenPGPDocumentSignature> results = new ArrayList<>();
//            OpenPGPPolicy policy = processor.getImplementation().policy();
//
//            for (R sig : signatures)
//            {
//                KeyIdentifier keyId = getKeyIdentifier(sig);
//                OpenPGPCertificate.OpenPGPComponentKey key = issuers.get(keyId);
//
//                OpenPGPSignature.OpenPGPDocumentSignature docSig =
//                    new OpenPGPSignature.OpenPGPDocumentSignature((PGPSignature)sig, key);
//
//                try
//                {
//                    if (key != null)
//                    {
//                        docSig.verify();
//                    }
//                    docSig.sanitize(key, policy);
//                }
//                catch (PGPException e)
//                {
//                    processor.onException(e);
//                }
//
//                results.add(docSig);
//            }
//            return results;
//        }
//
//        protected abstract KeyIdentifier getKeyIdentifier(R sig);
//
//        protected abstract void initSignature(R sig,
//                                              OpenPGPCertificate.OpenPGPComponentKey key,
//                                              OpenPGPMessageProcessor processor)
//            throws PGPException;
//    }
//
//    private static class OnePassSignatureVerifier
//        extends BaseSignatureVerifier<PGPOnePassSignature>
//    {
//        private final List<PGPSignature> pgpSignatureList = new ArrayList<>();
//
//        public void addPGPSinatures(Iterator<PGPSignature> it)
//        {
//            while (it.hasNext())
//            {
//                pgpSignatureList.add(it.next());
//            }
//        }
//
//        @Override
//        protected KeyIdentifier getKeyIdentifier(PGPOnePassSignature sig)
//        {
//            // One-pass signatures directly include their key ID
//            return sig.getKeyIdentifier();
//        }
//
//        @Override
//        protected void initSignature(PGPOnePassSignature sig,
//                                     OpenPGPCertificate.OpenPGPComponentKey key,
//                                     OpenPGPMessageProcessor processor)
//            throws PGPException
//        {
//            // Initialize for one-pass signature verification
//            sig.init(processor.getImplementation().pgpContentVerifierBuilderProvider(),
//                key.getPGPPublicKey()
//            );
//        }
//
//        public void update(byte i)
//        {
//            for (PGPOnePassSignature sig : signatures)
//            {
//                sig.update(i);
//            }
//        }
//
//        public void update(byte[] buf, int off, int len)
//        {
//            for (PGPOnePassSignature sig : signatures)
//            {
//                sig.update(buf, off, len);
//            }
//        }
//
//        public List<OpenPGPSignature.OpenPGPDocumentSignature> verify(
//            OpenPGPMessageProcessor processor)
//        {
//            OpenPGPPolicy policy = processor.getImplementation().policy();
//            List<OpenPGPSignature.OpenPGPDocumentSignature> dataSignatures = new ArrayList<>();
//            int num = signatures.size();
//            for (int i = 0; i < signatures.size(); i++)
//            {
//                PGPSignature signature = pgpSignatureList.get(i);
//                PGPOnePassSignature ops = signatures.get(num - i - 1);
//                OpenPGPCertificate.OpenPGPComponentKey key = issuers.get(ops);
//                if (key == null)
//                {
//                    continue;
//                }
//
//                OpenPGPSignature.OpenPGPDocumentSignature dataSignature =
//                    new OpenPGPSignature.OpenPGPDocumentSignature(signature, key);
//                try
//                {
//                    dataSignature.sanitize(key, policy);
//                }
//                catch (PGPSignatureException e)
//                {
//                    // continue
//                }
//
//                if (!dataSignature.createdInBounds(processor.getVerifyNotBefore(), processor.getVerifyNotAfter()))
//                {
//                    // sig is not in bounds
//                    continue;
//                }
//
//                try
//                {
//                    dataSignature.verify(ops);
//                }
//                catch (PGPException e)
//                {
//                    processor.onException(e);
//                }
//                dataSignatures.add(dataSignature);
//            }
//            return dataSignatures;
//        }
//    }
//
//    private static class PrefixedSignatureVerifier
//        extends BaseSignatureVerifier<PGPSignature>
//    {
//        @Override
//        protected KeyIdentifier getKeyIdentifier(PGPSignature sig)
//        {
//            // Prefixed signatures may have multiple key identifiers
//            return OpenPGPSignature.getMostExpressiveIdentifier(sig.getKeyIdentifiers());
//        }
//
//        @Override
//        protected void initSignature(PGPSignature sig,
//                                     OpenPGPCertificate.OpenPGPComponentKey key,
//                                     OpenPGPMessageProcessor processor)
//            throws PGPException
//        {
//            // Initialize for prefixed signature verification
//            sig.init(
//                processor.getImplementation().pgpContentVerifierBuilderProvider(),
//                key.getPGPPublicKey()
//            );
//        }
//
//        public void update(byte i)
//        {
//            for (PGPSignature sig : signatures)
//            {
//                sig.update(i);
//            }
//        }
//
//        public void update(byte[] buf, int off, int len)
//        {
//            for (PGPSignature sig : signatures)
//            {
//                sig.update(buf, off, len);
//            }
//        }
//    }
}
