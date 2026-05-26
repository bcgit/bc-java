package org.bouncycastle.cades.examples;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

/**
 * Tiny in-process RFC 3161 timestamp authority for the CAdES examples — lets
 * the examples drive a B-T / B-LT upgrade without depending on a live TSA
 * over HTTP. The caller supplies the TSA's keypair + cert (so the example's
 * cert hierarchy stays explicit) and an imprint; the helper returns a
 * {@link TimeStampToken} signed by that keypair under a fixed policy OID.
 *
 * <p>Production callers should substitute an HTTP client around
 * {@link TimeStampRequestGenerator} / {@link TimeStampResponse}.</p>
 */
final class LocalTsa
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final ASN1ObjectIdentifier TSA_POLICY = new ASN1ObjectIdentifier("1.2.3.4.5");

    private LocalTsa()
    {
    }

    /**
     * Mint a token over {@code imprint} (a SHA-256 hash) signed by the
     * supplied TSA key. The TSA cert is bundled into the token's certificates
     * field so the relying party can verify the token without out-of-band
     * material.
     */
    static TimeStampToken mint(byte[] imprint, X509Certificate tsaCert, KeyPair tsaKp)
        throws Exception
    {
        DigestCalculator sha1 = new BcDigestCalculatorProvider().get(
            new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
        ContentSigner tsaSigner =
            new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(tsaKp.getPrivate());

        TimeStampTokenGenerator tsGen = new TimeStampTokenGenerator(
            new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider(BC).build())
                .build(tsaSigner, tsaCert),
            sha1, TSA_POLICY);
        tsGen.addCertificates(new JcaCertStore(Collections.singletonList(tsaCert)));

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest req = reqGen.generate(TSPAlgorithms.SHA256, imprint, BigInteger.valueOf(100));

        TimeStampResponseGenerator respGen =
            new TimeStampResponseGenerator(tsGen, TSPAlgorithms.ALLOWED);
        TimeStampResponse resp = respGen.generate(req, BigInteger.valueOf(23), new Date());
        return resp.getTimeStampToken();
    }
}
