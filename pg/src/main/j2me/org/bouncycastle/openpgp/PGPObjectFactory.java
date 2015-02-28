package org.bouncycastle.openpgp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.util.Iterable;

/**
 * General class for reading a PGP object stream.
 * <p>
 * Note: if this class finds a {@link PGPPublicKey} or a {@link PGPSecretKey} it will create a
 * {@link PGPPublicKeyRing}, or a {@link PGPSecretKeyRing} for each key found. If all you are trying
 * to do is read a key ring file use either {@link PGPPublicKeyRingCollection} or
 * {@link PGPSecretKeyRingCollection}.
 * </p><p>
 * This factory supports reading the following types of objects:
 * <ul>
 * <li>{@link PacketTags#SIGNATURE} - produces a {@link PGPSignatureList}</li>
 * <li>{@link PacketTags#SECRET_KEY} - produces a {@link PGPSecretKeyRing}</li>
 * <li>{@link PacketTags#PUBLIC_KEY} - produces a {@link PGPPublicKeyRing}</li>
 * <li>{@link PacketTags#PUBLIC_SUBKEY} - produces a {@link PGPPublicKey}</li>
 * <li>{@link PacketTags#COMPRESSED_DATA} - produces a {@link PGPCompressedData}</li>
 * <li>{@link PacketTags#LITERAL_DATA} - produces a {@link PGPLiteralData}</li>
 * <li>{@link PacketTags#PUBLIC_KEY_ENC_SESSION} - produces a {@link PGPEncryptedDataList}</li>
 * <li>{@link PacketTags#SYMMETRIC_KEY_ENC_SESSION} - produces a {@link PGPEncryptedDataList}</li>
 * <li>{@link PacketTags#ONE_PASS_SIGNATURE} - produces a {@link PGPOnePassSignatureList}</li>
 * <li>{@link PacketTags#MARKER} - produces a {@link PGPMarker}</li>
 * </ul>
 * </p>
 */
public class PGPObjectFactory
    implements Iterable
{
    private BCPGInputStream in;
    private KeyFingerPrintCalculator fingerPrintCalculator;

    /**
     * Create an object factory suitable for reading PGP objects such as keys, key rings and key
     * ring collections, or PGP encrypted data.
     *
     * @param in stream to read PGP data from.
     * @param fingerPrintCalculator calculator to use in key finger print calculations.
     */
    public PGPObjectFactory(
        InputStream              in,
        KeyFingerPrintCalculator fingerPrintCalculator)
    {
        this.in = new BCPGInputStream(in);
        this.fingerPrintCalculator = fingerPrintCalculator;
    }

    /**
     * Create an object factory suitable for reading PGP objects such as keys, key rings and key
     * ring collections, or PGP encrypted data.
     *
     * @param bytes PGP encoded data.
     * @param fingerPrintCalculator calculator to use in key finger print calculations.
     */
    public PGPObjectFactory(
        byte[] bytes,
        KeyFingerPrintCalculator fingerPrintCalculator)
    {
        this(new ByteArrayInputStream(bytes), fingerPrintCalculator);
    }

    /**
     * Return the next object in the stream, or <code>null</code> if the end of stream is reached.
     *
     * @return one of the supported objects - see class docs for details.
     * @throws IOException if an error occurs reading from the wrapped stream or parsing data.
     */
    public Object nextObject()
        throws IOException
    {
        List l;

        switch (in.nextPacketTag())
        {
        case -1:
            return null;
        case PacketTags.SIGNATURE:
            l = new ArrayList();

            while (in.nextPacketTag() == PacketTags.SIGNATURE)
            {
                try
                {
                    l.add(new PGPSignature(in));
                }
                catch (PGPException e)
                {
                    throw new IOException("can't create signature object: " + e);
                }
            }

            return new PGPSignatureList((PGPSignature[])l.toArray(new PGPSignature[l.size()]));
        case PacketTags.SECRET_KEY:
            try
            {
                return new PGPSecretKeyRing(in, fingerPrintCalculator);
            }
            catch (PGPException e)
            {
                throw new IOException("can't create secret key object: " + e);
            }
        case PacketTags.PUBLIC_KEY:
            return new PGPPublicKeyRing(in, fingerPrintCalculator);
        case PacketTags.PUBLIC_SUBKEY:
            try
            {
                return PGPPublicKeyRing.readSubkey(in, fingerPrintCalculator);
            }
            catch (PGPException e)
            {
                throw new IOException("processing error: " + e.getMessage());
            }
        case PacketTags.COMPRESSED_DATA:
            throw new IOException("data compression not implemented");
        case PacketTags.LITERAL_DATA:
            return new PGPLiteralData(in);
        case PacketTags.PUBLIC_KEY_ENC_SESSION:
        case PacketTags.SYMMETRIC_KEY_ENC_SESSION:
            return new PGPEncryptedDataList(in);
        case PacketTags.ONE_PASS_SIGNATURE:
            l = new ArrayList();

            while (in.nextPacketTag() == PacketTags.ONE_PASS_SIGNATURE)
            {
                try
                {
                    l.add(new PGPOnePassSignature(in));
                }
                catch (PGPException e)
                {
                    throw new IOException("can't create one pass signature object: " + e);
                }
            }

            return new PGPOnePassSignatureList((PGPOnePassSignature[])l.toArray(new PGPOnePassSignature[l.size()]));
        case PacketTags.MARKER:
            return new PGPMarker(in);
        case PacketTags.EXPERIMENTAL_1:
        case PacketTags.EXPERIMENTAL_2:
        case PacketTags.EXPERIMENTAL_3:
        case PacketTags.EXPERIMENTAL_4:
            return in.readPacket();
        }

        throw new IOException("unknown object in stream: " + in.nextPacketTag());
    }

    /**
     * Support method for Iterable where available.
     */
    public Iterator iterator()
    {
        return new Iterator()
        {
            private Object obj = getObject();

            public boolean hasNext()
            {
                return obj != null;
            }

            public Object next()
            {
                Object rv = obj;

                obj = getObject();;

                return rv;
            }

            public void remove()
            {
                throw new RuntimeException("Cannot remove element from factory.");
            }

            private Object getObject()
            {
                try
                {
                    return PGPObjectFactory.this.nextObject();
                }
                catch (IOException e)
                {
                    throw new PGPRuntimeOperationException("Iterator failed to get next object: " + e.getMessage(), e);
                }
            }
        };
    }
}
