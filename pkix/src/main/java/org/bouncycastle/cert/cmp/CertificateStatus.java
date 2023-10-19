package org.bouncycastle.cert.cmp;

import java.math.BigInteger;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Arrays;

public class CertificateStatus
{
    private DigestAlgorithmIdentifierFinder digestAlgFinder;    
    private CertStatus certStatus;

    CertificateStatus(DigestAlgorithmIdentifierFinder digestAlgFinder, CertStatus certStatus)
    {
        this.digestAlgFinder = digestAlgFinder;
        this.certStatus = certStatus;
    }

    public PKIStatusInfo getStatusInfo()
    {
        return certStatus.getStatusInfo();
    }

    public BigInteger getCertRequestID()
    {
        return certStatus.getCertReqId().getValue();
    }

    public boolean isVerified(X509CertificateHolder certHolder, DigestCalculatorProvider digesterProvider)
        throws CMPException
    {
        return isVerified(new CMPCertificate(certHolder.toASN1Structure()), certHolder.getSignatureAlgorithm(),
            digesterProvider);
    }

    public boolean isVerified(CMPCertificate cmpCert, AlgorithmIdentifier signatureAlgorithm,
        DigestCalculatorProvider digesterProvider)
        throws CMPException
    {
        byte[] certHash = CMPUtil.calculateCertHash(cmpCert, signatureAlgorithm, digesterProvider, digestAlgFinder);

        return Arrays.constantTimeAreEqual(certStatus.getCertHash().getOctets(), certHash);
    }
}
