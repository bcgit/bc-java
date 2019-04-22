package org.bouncycastle.crypto.util;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.io.Streams;

/**
 * JournaledAlgorithm keeps state of the JournalingSecureRandom and the
 * AlgorithmIdentifier necessary to fully resume an encryption session. This
 * class can be used to retrieve a session even if a process is completely
 * stopped. NOTE: This should be used with a shutdown hook to save the state of
 * the journaling and the algorithm identifier even in the case of a forced
 * shutdown.
 * <p>
 * The raw encoding is in ASN.1 format.
 * </p>
 * <p>
 * Details: Use serialization of critical parameters of the the
 * JournalingSecureRandom and AlgorithmIdentifier. Because these two classes are
 * not serializable, create interior class to serialize only the critical
 * parameters in the form of byte[] arrays
 */

public class JournaledAlgorithm
    implements Encodable, Serializable
{
    private transient JournalingSecureRandom journaling;

    private transient AlgorithmIdentifier algID;

    public JournaledAlgorithm(AlgorithmIdentifier aid, JournalingSecureRandom journaling)
    {
        if (aid == null)
        {
            throw new NullPointerException("AlgorithmIdentifier passed to JournaledAlgorithm is null");
        }
        else if (journaling == null)
        {
            throw new NullPointerException("JournalingSecureRandom passed to JournaledAlgorithm is null");
        }

        this.journaling = journaling;

        this.algID = aid;
    }

    /**
     * Construct from a previous encoding, using CryptoServicesRegistrar.getSecureRandom() as the backup source of entropy.
     *
     * @param encoding raw encoding of a previous JournaledAlgorithm.
     */
    public JournaledAlgorithm(byte[] encoding)
    {
        this(encoding, CryptoServicesRegistrar.getSecureRandom());
    }

    /**
     * Construct from a previous encoding, using the passed in random as a source for when the existing entropy runs out.
     *
     * @param encoding raw encoding of a previous JournaledAlgorithm.
     * @param random back up source of entropy.
     */
    public JournaledAlgorithm(byte[] encoding, SecureRandom random)
    {
        if (encoding == null)
        {
            throw new NullPointerException("encoding passed to JournaledAlgorithm is null");
        }
        else if (random == null)
        {
            throw new NullPointerException("random passed to JournaledAlgorithm is null");
        }

        initFromEncoding(encoding, random);
    }

    private void initFromEncoding(byte[] encoding, SecureRandom random)
    {
        ASN1Sequence seq = ASN1Sequence.getInstance(encoding);

        this.algID = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.journaling = new JournalingSecureRandom(ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets(), random);
    }

    public JournalingSecureRandom getJournalingSecureRandom()
    {
        return journaling;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return algID;
    }

    /**
     * Store state of JournalingSecureRandom and AlgorithmIdentifier in temporary
     * file
     *
     * @param tempfile
     * @throws IOException
     */
    public void storeState(File tempfile)
        throws IOException
    {
        if (tempfile == null)
        {
            throw new NullPointerException("file for storage is null in JournaledAlgorithm");
        }

        // Extract key information in byte[] form
        FileOutputStream fOut = new FileOutputStream(tempfile);

        try
        {
            storeState(fOut);
        }
        finally
        {
            fOut.close();
        }
    }

    public void storeState(OutputStream out)
        throws IOException
    {
        if (out == null)
        {
            throw new NullPointerException("output stream for storage is null in JournaledAlgorithm");
        }

        out.write(this.getEncoded());
    }

    public static JournaledAlgorithm getState(InputStream stateIn, SecureRandom random)
        throws IOException, ClassNotFoundException
    {
        if (stateIn == null)
        {
            throw new NullPointerException("stream for loading is null in JournaledAlgorithm");
        }

        InputStream fIn = new BufferedInputStream(stateIn);

        try
        {
            return new JournaledAlgorithm(Streams.readAll(fIn), random);
        }
        finally
        {
            fIn.close();
        }
    }

    /**
     * Reconstructs JournaledAlgorithm session from file containing it's raw encoding.
     *
     * @param tempfile temporary file containing serialized state
     * @return
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public static JournaledAlgorithm getState(File tempfile, SecureRandom random)
        throws IOException, ClassNotFoundException
    {
        if (tempfile == null)
        {
            throw new NullPointerException("File for loading is null in JournaledAlgorithm");
        }

        InputStream fIn = new BufferedInputStream(new FileInputStream(tempfile));

        try
        {
            return new JournaledAlgorithm(Streams.readAll(fIn), random);
        }
        finally
        {
            fIn.close();
        }
    }

    public byte[] getEncoded()
        throws IOException
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(algID);
        v.add(new DEROctetString(journaling.getFullTranscript()));

        return new DERSequence(v).getEncoded();
    }

    private void readObject(
        ObjectInputStream   in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        initFromEncoding((byte[])in.readObject(), CryptoServicesRegistrar.getSecureRandom());
    }

    private void writeObject(
        ObjectOutputStream  out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(getEncoded());
    }
}
