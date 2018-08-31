package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ArchiveTimeStamp;
import org.bouncycastle.asn1.cms.ArchiveTimeStampChain;
import org.bouncycastle.asn1.cms.DataGroup;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.*;

public class ArchiveTimeStampChainVerifier
{

    private ArchiveTimeStampChain archiveTimeStampChain;
    private AlgorithmIdentifier algorithmIdentifier;
    private byte[] atsc;
    private Date prevGenTime;
    private Date prevExpTime;

    private ArchiveTimeStampVerifier archiveTimeStampVerifier;

    public ArchiveTimeStampChainVerifier () {

        this.archiveTimeStampVerifier = new ArchiveTimeStampVerifier();
    }

    public void validate(Object data, final AlgorithmIdentifier algorithmIdentifier)
        throws ArchiveTimeStampValidationException, NoSuchAlgorithmException, TSPException, IOException, PartialHashTreeVerificationException, CertificateException, OperatorCreationException
    {
        final ASN1Sequence archiveTimeStamps = ASN1Sequence.getInstance(archiveTimeStampChain
            .toASN1Primitive());

        if (atsc != null)
        {
            if (algorithmIdentifier != null && data instanceof byte[])
            {
                data = ByteUtils.concatenate((byte[]) data, getDataHash(atsc));
            }
            else if (algorithmIdentifier != null && data instanceof List)
            {
                data = ByteUtils.concatenate(getDataGroupHash(data), getDataHash(atsc));
            }
            else
            {
                data = ByteUtils.concatenate(getDataHash(data), getDataHash(atsc));
            }
            atsc = null; //reset it afterwards
        }

        Enumeration objects = archiveTimeStamps.getObjects();

        while (objects.hasMoreElements())
        {
            Object o = objects.nextElement();
            ArchiveTimeStamp ats = ArchiveTimeStamp.getInstance(o);
            archiveTimeStampVerifier.setArchiveTimeStamp(ats);

            if (algorithmIdentifier != null && data instanceof byte[])
            {
                archiveTimeStampVerifier.validateHash((byte[]) data, prevGenTime, prevExpTime, algorithmIdentifier);
            }
            else
            {
                archiveTimeStampVerifier.validate(data, prevGenTime, prevExpTime, algorithmIdentifier);
            }

            data = ats.getTimeStamp().getEncoded("DER");

            prevExpTime = archiveTimeStampVerifier.getExpiryDate();
            prevGenTime = archiveTimeStampVerifier.getGenTime();
        }
    }

    private byte[] getDataHash(final Object data) throws NoSuchAlgorithmException
    {
        final MessageDigest md = MessageDigest.getInstance(algorithmIdentifier.getAlgorithm()
            .getId());

        if (data instanceof byte[])
        {
            return md.digest((byte[]) data);
        }
        else if (data instanceof DataGroup)
        {
            return ((DataGroup) data).getHash(md);
        }

        throw new IllegalArgumentException("unknown object in getDataHash: " + data.getClass().getName());
    }

    private byte[] getDataGroupHash(final Object data) throws NoSuchAlgorithmException
    {
        final MessageDigest md = MessageDigest.getInstance(algorithmIdentifier.getAlgorithm().getId());
        final Collection dataGroupHashes = (Collection) data;

        byte[] concat = new byte[0];
        Iterator iterator = dataGroupHashes.iterator();

        while(iterator.hasNext()) {
            concat = ByteUtils.concatenate(concat, (byte[]) iterator.next());
        }

        return md.digest(concat);
    }

    public void setArchiveTimeStampChain(ArchiveTimeStampChain archiveTimeStampChain)
        throws IOException, TSPException
    {
        this.archiveTimeStampChain = archiveTimeStampChain;
        this.algorithmIdentifier = getAlgorithmIdentifierFromATSChain(archiveTimeStampChain);
    }

    private AlgorithmIdentifier getAlgorithmIdentifierFromATSChain(final ArchiveTimeStampChain
        chain) throws IOException, TSPException
    {
        ASN1Sequence timestamps = ASN1Sequence.getInstance(chain.toASN1Primitive());
        ArchiveTimeStamp ats = ArchiveTimeStamp.getInstance(timestamps.getObjectAt(0));
        TimeStampToken timeStampToken = new TimeStampToken(ats.getTimeStamp());

        return timeStampToken.getTimeStampInfo().getHashAlgorithm();
    }

    public void setPrevGenTime(Date prevGenTime)
    {
        this.prevGenTime = prevGenTime;
    }

    public void setPrevExpTime(Date prevExpTime)
    {
        this.prevExpTime = prevExpTime;
    }

    public void setAtsc(byte[] atsc) {
        this.atsc = atsc;
    }

    public ArchiveTimeStampVerifier getArchiveTimeStampVerifier() {
        return archiveTimeStampVerifier;
    }
}
