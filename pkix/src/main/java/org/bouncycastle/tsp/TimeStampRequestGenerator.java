package org.bouncycastle.tsp;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.asn1.tsp.TimeStampReq;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;

/**
 * Generator for RFC 3161 Time Stamp Request objects.
 */
public class TimeStampRequestGenerator
{
    private static final DefaultDigestAlgorithmIdentifierFinder DEFAULT_DIGEST_ALG_FINDER =
        new DefaultDigestAlgorithmIdentifierFinder();

    private final ExtensionsGenerator extGenerator = new ExtensionsGenerator();

    private final DigestAlgorithmIdentifierFinder digestAlgFinder;

    private ASN1ObjectIdentifier reqPolicy;
    private ASN1Boolean certReq;

    public TimeStampRequestGenerator()
    {
        this(DEFAULT_DIGEST_ALG_FINDER);
    }

    public TimeStampRequestGenerator(DigestAlgorithmIdentifierFinder digestAlgFinder)
    {
        if (digestAlgFinder == null)
        {
            throw new NullPointerException("'digestAlgFinder' cannot be null");
        }

        this.digestAlgFinder = digestAlgFinder;
    }

    /**
     * Set the OID of the TSA policy the request asks the token to be issued under.
     *
     * @param reqPolicy the policy OID to request.
     */
    public void setReqPolicy(ASN1ObjectIdentifier reqPolicy)
    {
        this.reqPolicy = reqPolicy;
    }
    
    /**
     * @deprecated use method taking ASN1ObjectIdentifier
     * @param reqPolicy
     */
    public void setReqPolicy(String reqPolicy)
    {
        setReqPolicy(new ASN1ObjectIdentifier(reqPolicy));
    }

    /**
     * Set the certReq field requesting the TSA to include its certificate(s) in the response.
     *
     * @param certReq true to ask the TSA to return its certificate(s), false otherwise.
     */
    public void setCertReq(ASN1Boolean certReq)
    {
        this.certReq = certReq;
    }

    /**
     * Set the certReq field requesting the TSA to include its certificate(s) in the response.
     *
     * @param certReq true to ask the TSA to return its certificate(s), false otherwise.
     */
    public void setCertReq(boolean certReq)
    {
        setCertReq(ASN1Boolean.getInstance(certReq));
    }

    /**
     * add a given extension field for the standard extensions tag (tag 3)
     * @throws IOException
     * @deprecated use method taking ASN1ObjectIdentifier
     */
    public void addExtension(String OID, boolean critical, ASN1Encodable value) throws IOException
    {
        addExtension(new ASN1ObjectIdentifier(OID), critical, value);
    }

    /**
     * add a given extension field for the standard extensions tag
     * The value parameter becomes the contents of the octet string associated
     * with the extension.
     * @deprecated use method taking ASN1ObjectIdentifier
     */
    public void addExtension(String OID, boolean critical, byte[] value)
    {
        addExtension(new ASN1ObjectIdentifier(OID), critical, value);
    }

    /**
     * add a given extension field for the standard extensions tag (tag 3)
     * @throws TSPIOException
     */
    public void addExtension(ASN1ObjectIdentifier oid, boolean isCritical, ASN1Encodable value) throws TSPIOException
    {
        TSPUtil.addExtension(extGenerator, oid, isCritical, value);
    }

    /**
     * add a given extension field for the standard extensions tag
     * The value parameter becomes the contents of the octet string associated
     * with the extension.
     */
    public void addExtension(ASN1ObjectIdentifier oid, boolean isCritical, byte[] value)
    {
        extGenerator.addExtension(oid, isCritical, value);
    }

    /**
     * @deprecated use method taking ANS1ObjectIdentifier or AlgorithmIdentifier
     */
    public TimeStampRequest generate(String digestAlgorithm, byte[] digest)
    {
        return generate(digestAlgorithm, digest, null);
    }

    /**
     * @deprecated use method taking ANS1ObjectIdentifier or AlgorithmIdentifier
     */
    public TimeStampRequest generate(String digestAlgorithmOID, byte[] digest, BigInteger nonce)
    {
        if (digestAlgorithmOID == null)
        {
            throw new NullPointerException("'digestAlgorithmOID' cannot be null");
        }

        return generate(new ASN1ObjectIdentifier(digestAlgorithmOID), digest, nonce);
    }

    /**
     * Generate a request for the given digest and algorithm OID.
     *
     * @param digestAlgorithm the OID of the algorithm used to produce the digest.
     * @param digest the message imprint digest to be stamped.
     * @return a TimeStampRequest.
     */
    public TimeStampRequest generate(ASN1ObjectIdentifier digestAlgorithm, byte[] digest)
    {
        return generate(digestAlgorithm, digest, null);
    }

    /**
     * Generate a request for the given digest and algorithm OID, including a nonce.
     *
     * @param digestAlgorithm the OID of the algorithm used to produce the digest.
     * @param digest the message imprint digest to be stamped.
     * @param nonce a nonce to include in the request, allowing the response to be matched to it.
     * @return a TimeStampRequest.
     */
    public TimeStampRequest generate(ASN1ObjectIdentifier digestAlgorithm, byte[] digest, BigInteger nonce)
    {
        return generate(digestAlgFinder.find(digestAlgorithm), digest, nonce);
    }

    /**
     * Generate a request for the given digest and algorithm identifier.
     *
     * @param digestAlgorithmID the identifier of the algorithm used to produce the digest.
     * @param digest the message imprint digest to be stamped.
     * @return a TimeStampRequest.
     */
    public TimeStampRequest generate(AlgorithmIdentifier digestAlgorithmID, byte[] digest)
    {
        return generate(digestAlgorithmID, digest, null);
    }

    /**
     * Generate a request for the given digest and algorithm identifier, including a nonce.
     *
     * @param digestAlgorithmID the identifier of the algorithm used to produce the digest.
     * @param digest the message imprint digest to be stamped.
     * @param nonce a nonce to include in the request, allowing the response to be matched to it.
     * @return a TimeStampRequest.
     */
    public TimeStampRequest generate(AlgorithmIdentifier digestAlgorithmID, byte[] digest, BigInteger nonce)
    {
        if (digestAlgorithmID == null)
        {
            throw new NullPointerException("'digestAlgorithmID' cannot be null");
        }

        MessageImprint messageImprint = new MessageImprint(digestAlgorithmID, digest);
        ASN1Integer reqNonce = nonce == null ? null : new ASN1Integer(nonce);
        Extensions ext = extGenerator.isEmpty() ? null : extGenerator.generate();

        return new TimeStampRequest(new TimeStampReq(messageImprint, reqPolicy, reqNonce, certReq, ext));
    }
}
