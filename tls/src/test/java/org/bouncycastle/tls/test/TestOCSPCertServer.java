package org.bouncycastle.tls.test;

import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkix.PKIXIdentity;
import org.bouncycastle.util.io.Streams;

public class TestOCSPCertServer
{
    private final KeyPair signKP;

    private final X509Certificate rootCert;

    private final KeyPair interKP;
    private final X509Certificate interCert;

    private final DigestCalculatorProvider digCalcProv;
    private final X509CertificateHolder[] chain;

    private final Set revocations = new HashSet();

    public TestOCSPCertServer()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");

        kpGen.initialize(2048);

        KeyPair trustKP = kpGen.generateKeyPair();

        interKP = kpGen.generateKeyPair();
        signKP = kpGen.generateKeyPair();
        digCalcProv = new JcaDigestCalculatorProviderBuilder().build();

        rootCert = CertChainUtil.createMasterCert("CN=Root Certificate", trustKP);

        interCert = CertChainUtil.createIntermediateCert(
            "CN=Intermediate Certificate", interKP.getPublic(), trustKP.getPrivate(), rootCert);
        X509Certificate ocspCert = CertChainUtil.createEndEntityCert(
            "CN=OCSP Signing Certificate", signKP.getPublic(), interKP.getPrivate(), interCert, KeyPurposeId.id_kp_OCSPSigning);

        this.chain = new X509CertificateHolder[] {
            new X509CertificateHolder(ocspCert.getEncoded()),
            new X509CertificateHolder(interCert.getEncoded()) };
    }

    public X509Certificate getRootCert()
    {
        return rootCert;
    }

    public X509Certificate getCACert()
    {
        return interCert;
    }

    public PKIXIdentity issueClientCert(String subjectName, boolean markRevoked)
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");

        kpGen.initialize(2048);

        KeyPair eeKP = kpGen.generateKeyPair();

        X509Certificate endEntityCert = CertChainUtil.createEndEntityCert(
            subjectName, eeKP.getPublic(),
            interKP.getPrivate(), interCert);

        if (markRevoked)
        {
            revocations.add(endEntityCert.getSerialNumber());
        }

        return new PKIXIdentity(PrivateKeyInfo.getInstance(eeKP.getPrivate().getEncoded()),
            new X509CertificateHolder[] {
                new X509CertificateHolder(endEntityCert.getEncoded()),
                new X509CertificateHolder(interCert.getEncoded())});
    }

    public OCSPResp respond(OCSPReq request)
        throws Exception
    {
        BasicOCSPRespBuilder respGen = new JcaBasicOCSPRespBuilder(signKP.getPublic(), digCalcProv.get(RespID.HASH_SHA1));

        Req[] requests = request.getRequestList();

        for (int i = 0; i != requests.length; i++)
        {
            CertificateID id = requests[i].getCertID();

            if (revocations.contains(id.getSerialNumber()))
            {
                respGen.addResponse(id, new RevokedStatus(
                    new RevokedInfo(
                        new ASN1GeneralizedTime(new Date(System.currentTimeMillis() - 1000L * 60)), CRLReason.lookup(CRLReason.superseded))));
            }
            else
            {
                respGen.addResponse(id, CertificateStatus.GOOD);
            }
        }

        BasicOCSPResp resp = respGen.build(new JcaContentSignerBuilder("SHA1withRSA").build(signKP.getPrivate()), chain, new Date());
        OCSPRespBuilder rGen = new OCSPRespBuilder();

        return rGen.build(OCSPRespBuilder.SUCCESSFUL, resp);
    }

    public static class ServerTask
        implements Runnable
    {
        private final int portNo;
        private final TestOCSPCertServer server;

        public ServerTask(int portNo, TestOCSPCertServer server)
        {
            this.portNo = portNo;
            this.server = server;
        }

        public void run()
        {
            try
            {
                ServerSocket ss = new ServerSocket(portNo);

                Socket s = ss.accept();

                OCSPReq request = new OCSPReq(Streams.readAll(s.getInputStream()));

                s.getOutputStream().write(server.respond(request).getEncoded());

                s.close();
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }
    }
}
