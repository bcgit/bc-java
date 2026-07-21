package org.bouncycastle.tsp;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.asn1.tsp.TimeStampReq;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.util.Exceptions;

/**
 * Base class for an RFC 3161 Time Stamp Request.
 */
public class TimeStampRequest
{
    private static Set EMPTY_SET = Collections.unmodifiableSet(new HashSet());

    private static TimeStampReq parseTimeStampReq(byte[] encoding)
        throws IOException
    {
        try
        {
            return TimeStampReq.getInstance(encoding);
        }
        catch (ClassCastException e)
        {
            throw Exceptions.ioException("malformed request: " + e, e);
        }
        catch (IllegalArgumentException e)
        {
            throw Exceptions.ioException("malformed request: " + e, e);
        }
    }

    private static TimeStampReq parseTimeStampReq(InputStream in)
        throws IOException
    {
        try
        {
            ASN1Primitive obj = new ASN1InputStream(in).readObject();
            if (obj == null)
            {
                throw new IOException("no ASN.1 object found in request");
            }
            return TimeStampReq.getInstance(obj);
        }
        catch (ClassCastException e)
        {
            throw Exceptions.ioException("malformed request: " + e, e);
        }
        catch (IllegalArgumentException e)
        {
            throw Exceptions.ioException("malformed request: " + e, e);
        }
    }
    
    private TimeStampReq req;
    private Extensions extensions;

    /**
     * Create a TimeStampRequest from the passed in ASN.1 structure.
     *
     * @param req the ASN.1 TimeStampReq the request is based on.
     */
    public TimeStampRequest(TimeStampReq req)
    {
        this.req = req;
        this.extensions = req.getExtensions();
    }

    /**
     * Create a TimeStampRequest from the past in byte array.
     * 
     * @param req byte array containing the request.
     * @throws IOException if the request is malformed.
     */
    public TimeStampRequest(byte[] req) 
        throws IOException
    {
        this(parseTimeStampReq(req));
    }

    /**
     * Create a TimeStampRequest from the past in input stream.
     * 
     * @param in input stream containing the request.
     * @throws IOException if the request is malformed.
     */
    public TimeStampRequest(InputStream in) 
        throws IOException
    {
        this(parseTimeStampReq(in));
    }

    /**
     * @return the underlying ASN.1 TimeStampReq structure.
     */
    public TimeStampReq toASN1Structure()
    {
        return req;
    }

    /**
     * @return the version of the request (1 for RFC 3161).
     */
    public int getVersion()
    {
        return req.getVersion().intValueExact();
    }

    /**
     * @return the message imprint (hash algorithm plus digest) to be stamped.
     */
    public MessageImprint getMessageImprint()
    {
        return req.getMessageImprint();
    }

    /**
     * @return the OID of the hash algorithm used for the message imprint.
     */
    public ASN1ObjectIdentifier getMessageImprintAlgOID()
    {
        return req.getMessageImprint().getHashAlgorithm().getAlgorithm();
    }

    /**
     * @return the algorithm identifier of the hash used for the message imprint.
     */
    public AlgorithmIdentifier getMessageImprintAlgID()
    {
        return req.getMessageImprint().getHashAlgorithm();
    }

    /**
     * @return the digest value to be stamped.
     */
    public byte[] getMessageImprintDigest()
    {
        return req.getMessageImprint().getHashedMessage();
    }

    /**
     * @return the OID of the TSA policy the requester asks the token to be issued under, null if not set.
     */
    public ASN1ObjectIdentifier getReqPolicy()
    {
        if (req.getReqPolicy() != null)
        {
            return req.getReqPolicy();
        }
        else
        {
            return null;
        }
    }

    /**
     * @return the nonce included in the request, null if there is none.
     */
    public BigInteger getNonce()
    {
        if (req.getNonce() != null)
        {
            return req.getNonce().getValue();
        }
        else
        {
            return null;
        }
    }

    /**
     * @return true if the requester asked the TSA to include its certificate(s) in the response,
     *         false if absent (the RFC 3161 default).
     */
    public boolean getCertReq()
    {
        if (req.getCertReq() != null)
        {
            return req.getCertReq().isTrue();
        }
        else
        {
            return false;
        }
    }

    /**
     * Validate the timestamp request, checking the digest to see if it is of an
     * accepted type and whether it is of the correct length for the algorithm specified.
     *
     * @param algorithms a set of OIDs giving accepted algorithms.
     * @param policies if non-null a set of policies OIDs we are willing to sign under.
     * @param extensions if non-null a set of extensions OIDs we are willing to accept.
     * @throws TSPException if the request is invalid, or processing fails.
     */
    public void validate(
        Set    algorithms,
        Set    policies,
        Set    extensions)
        throws TSPException
    {
        algorithms = convert(algorithms);
        policies = convert(policies);
        extensions = convert(extensions);

        if (algorithms == null)
        {
            throw new TSPValidationException("no algorithms associated with request", PKIFailureInfo.badAlg);
        }

        if (!algorithms.contains(this.getMessageImprintAlgOID()))
        {
            throw new TSPValidationException("request contains unknown algorithm", PKIFailureInfo.badAlg);
        }

        if (policies != null && this.getReqPolicy() != null && !policies.contains(this.getReqPolicy()))
        {
            throw new TSPValidationException("request contains unknown policy", PKIFailureInfo.unacceptedPolicy);
        }

        if (this.getExtensions() != null && extensions != null)
        {
            Enumeration en = this.getExtensions().oids();
            while(en.hasMoreElements())
            {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)en.nextElement();
                if (!extensions.contains(oid))
                {
                    throw new TSPValidationException("request contains unknown extension", PKIFailureInfo.unacceptedExtension);
                }
            }
        }

        int digestLength = TSPUtil.getDigestLength(this.getMessageImprintAlgOID().getId());

        if (digestLength != this.getMessageImprint().getHashedMessageLength())
        {
            throw new TSPValidationException("imprint digest the wrong length", PKIFailureInfo.badDataFormat);
        }
    }

   /**
    * return the ASN.1 encoded representation of this object.
    * @return the default ASN.1 byte encoding for the object.
    */
    public byte[] getEncoded() throws IOException
    {
        return req.getEncoded();
    }

    Extensions getExtensions()
    {
        return extensions;
    }

    /**
     * @return true if the request carries any extensions, false otherwise.
     */
    public boolean hasExtensions()
    {
        return extensions != null;
    }

    /**
     * Return the extension with the passed in OID.
     *
     * @param oid the OID of the extension of interest.
     * @return the extension, null if not present.
     */
    public Extension getExtension(ASN1ObjectIdentifier oid)
    {
        if (extensions != null)
        {
            return extensions.getExtension(oid);
        }

        return null;
    }

    /**
     * @return a list of the OIDs of the extensions present, in order, empty if there are none.
     */
    public List getExtensionOIDs()
    {
        return TSPUtil.getExtensionOIDs(extensions);
    }

    /**
     * Returns a set of ASN1ObjectIdentifiers giving the non-critical extensions.
     * @return a set of ASN1ObjectIdentifiers.
     */
    public Set getNonCriticalExtensionOIDs()
    {
        if (extensions == null)
        {
            return EMPTY_SET;
        }

        return Collections.unmodifiableSet(new HashSet(Arrays.asList(extensions.getNonCriticalExtensionOIDs())));
    }

    /**
     * Returns a set of ASN1ObjectIdentifiers giving the critical extensions.
     * @return a set of ASN1ObjectIdentifiers.
     */
    public Set getCriticalExtensionOIDs()
    {
        if (extensions == null)
        {
            return EMPTY_SET;
        }

        return Collections.unmodifiableSet(new HashSet(Arrays.asList(extensions.getCriticalExtensionOIDs())));
    }

    private Set convert(Set orig)
    {
        if (orig == null)
        {
            return orig;
        }

        Set con = new HashSet(orig.size());

        for (Iterator it = orig.iterator(); it.hasNext();)
        {
            Object o = it.next();

            if (o instanceof String)
            {
                con.add(new ASN1ObjectIdentifier((String)o));
            }
            else
            {
                con.add(o);
            }
        }

        return con;
    }
}
