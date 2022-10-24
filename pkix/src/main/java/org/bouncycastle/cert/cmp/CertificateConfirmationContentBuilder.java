package org.bouncycastle.cert.cmp;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertConfirmContent;
import org.bouncycastle.asn1.cmp.CertStatus;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;

/**
 * Builder class for a {@link CertConfirmContent} message.
 */
public class CertificateConfirmationContentBuilder
{
    private DigestAlgorithmIdentifierFinder digestAlgFinder;
    private List<CMPCertificate> acceptedCerts = new ArrayList<CMPCertificate>();
    private List<AlgorithmIdentifier> acceptedSignatureAlgorithms = new ArrayList<AlgorithmIdentifier>();
    private List<ASN1Integer> acceptedReqIds = new ArrayList<ASN1Integer>();

    public CertificateConfirmationContentBuilder()
    {
        this(new DefaultDigestAlgorithmIdentifierFinder());
    }

    public CertificateConfirmationContentBuilder(DigestAlgorithmIdentifierFinder digestAlgFinder)
    {
        this.digestAlgFinder = digestAlgFinder;
    }
    
    public CertificateConfirmationContentBuilder addAcceptedCertificate(X509CertificateHolder certHolder, BigInteger certReqID)
    {
        return addAcceptedCertificate(certHolder, new ASN1Integer(certReqID));
    }

    public CertificateConfirmationContentBuilder addAcceptedCertificate(X509CertificateHolder certHolder, ASN1Integer certReqID)
    {
        return addAcceptedCertificate(new CMPCertificate(certHolder.toASN1Structure()), certHolder.getSignatureAlgorithm(), certReqID);
    }

    public CertificateConfirmationContentBuilder addAcceptedCertificate(CMPCertificate cmpCertificate, AlgorithmIdentifier sigAlg, ASN1Integer certReqID)
    {
        acceptedCerts.add(cmpCertificate);
        acceptedSignatureAlgorithms.add(sigAlg);
        acceptedReqIds.add(certReqID);

        return this;
    }

    public CertificateConfirmationContent build(DigestCalculatorProvider digesterProvider)
        throws CMPException
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (int i = 0; i != acceptedCerts.size(); i++)
        {
            CMPCertificate certHolder = (CMPCertificate)acceptedCerts.get(i);
            ASN1Integer reqID = (ASN1Integer)acceptedReqIds.get(i);

            AlgorithmIdentifier digAlg = digestAlgFinder.find((AlgorithmIdentifier)acceptedSignatureAlgorithms.get(i));
            if (digAlg == null)
            {
                throw new CMPException("cannot find algorithm for digest from signature");
            }

            DigestCalculator digester;

            try
            {
                digester = digesterProvider.get(digAlg);
            }
            catch (OperatorCreationException e)
            {
                throw new CMPException("unable to create digest: " + e.getMessage(), e);
            }

            CMPUtil.derEncodeToStream(certHolder, digester.getOutputStream());

            v.add(new CertStatus(digester.getDigest(), reqID));
        }

        return new CertificateConfirmationContent(CertConfirmContent.getInstance(new DERSequence(v)), digestAlgFinder);
    }

}
