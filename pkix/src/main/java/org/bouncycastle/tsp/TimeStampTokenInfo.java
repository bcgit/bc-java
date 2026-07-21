package org.bouncycastle.tsp;

import java.io.IOException;
import java.math.BigInteger;
import java.text.ParseException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.tsp.Accuracy;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * Wrapper providing typed access to the {@code TSTInfo} structure carried by an RFC 3161
 * time-stamp token - the time of stamping (genTime), its accuracy, the TSA policy, serial
 * number, nonce and the message imprint that was stamped.
 */
public class TimeStampTokenInfo
{
    TSTInfo tstInfo;
    Date    genTime;

    TimeStampTokenInfo(TSTInfo tstInfo)
        throws TSPException, IOException
    {
        this.tstInfo = tstInfo;

        try
        {
            this.genTime = tstInfo.getGenTime().getDate();
        }
        catch (ParseException e)
        {
            throw new TSPException("unable to parse genTime field");
        }
    }

    /**
     * @return true if the genTime can be ordered against tokens from the same TSA, false otherwise.
     */
    public boolean isOrdered()
    {
        return tstInfo.getOrdering().isTrue();
    }

    /**
     * @return the accuracy of the genTime as an ASN.1 structure, null if not present.
     */
    public Accuracy getAccuracy()
    {
        return tstInfo.getAccuracy();
    }

    /**
     * @return the time the token was created (the genTime field).
     */
    public Date getGenTime()
    {
        return genTime;
    }

    /**
     * @return a wrapper over the accuracy of the genTime, null if no accuracy is present.
     */
    public GenTimeAccuracy getGenTimeAccuracy()
    {
        if (this.getAccuracy() != null)
        {
            return new GenTimeAccuracy(this.getAccuracy());
        }

        return null;
    }

    /**
     * @return the OID of the TSA policy under which the token was issued.
     */
    public ASN1ObjectIdentifier getPolicy()
    {
        return tstInfo.getPolicy();
    }

    /**
     * @return the serial number assigned to this token by the TSA.
     */
    public BigInteger getSerialNumber()
    {
        return tstInfo.getSerialNumber().getValue();
    }

    /**
     * @return the optional name of the TSA that issued the token, null if not present.
     */
    public GeneralName getTsa()
    {
        return tstInfo.getTsa();
    }

    /**
     * @return any extensions present in the token, null if there are none.
     */
    public Extensions getExtensions()
    {
        return tstInfo.getExtensions();
    }

    /**
     * @return the nonce value, null if there isn't one.
     */
    public BigInteger getNonce()
    {
        if (tstInfo.getNonce() != null)
        {
            return tstInfo.getNonce().getValue();
        }

        return null;
    }

    /**
     * @return the algorithm used to produce the stamped message imprint.
     */
    public AlgorithmIdentifier getHashAlgorithm()
    {
        return tstInfo.getMessageImprint().getHashAlgorithm();
    }

    /**
     * @return the OID of the algorithm used to produce the stamped message imprint.
     */
    public ASN1ObjectIdentifier getMessageImprintAlgOID()
    {
        return tstInfo.getMessageImprint().getHashAlgorithm().getAlgorithm();
    }

    /**
     * @return the digest value of the stamped message imprint.
     */
    public byte[] getMessageImprintDigest()
    {
        return tstInfo.getMessageImprint().getHashedMessage();
    }

    /**
     * @return the default ASN.1 encoding of the underlying TSTInfo.
     * @throws IOException if the structure cannot be encoded.
     */
    public byte[] getEncoded()
        throws IOException
    {
        return tstInfo.getEncoded();
    }

    /**
     * @deprecated use toASN1Structure
     */
    public TSTInfo toTSTInfo()
    {
        return tstInfo;
    }

    /**
     * @return the underlying ASN.1 TSTInfo structure.
     */
    public TSTInfo toASN1Structure()
    {
        return tstInfo;
    }
}
