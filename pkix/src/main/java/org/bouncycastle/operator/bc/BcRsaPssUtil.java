package org.bouncycastle.operator.bc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.operator.OperatorCreationException;

/**
 * Build a {@link PSSSigner} from an id-RSASSA-PSS {@link AlgorithmIdentifier}
 * using BC's lightweight RSA engine, so the {@code Bc*} operator builders
 * (which historically used {@code RSADigestSigner}, i.e. PKCS#1 v1.5)
 * produce and verify RFC 8017 PSS signatures wire-compatible with the JCE
 * {@code RSASSA-PSS} path. Used by both
 * {@link BcRSAContentSignerBuilder#createSigner(AlgorithmIdentifier, AlgorithmIdentifier)}
 * and {@link BcRSAContentVerifierProviderBuilder#createSigner(AlgorithmIdentifier)}
 * (github #721).
 */
class BcRsaPssUtil
{
    private BcRsaPssUtil()
    {
    }

    /**
     * @param sigAlgId         an {@code id-RSASSA-PSS} signature algorithm identifier whose
     *                         {@code parameters} field is an RSASSA-PSS-params SEQUENCE.
     * @param digestProvider   resolves digest OIDs to BC lightweight {@link Digest} instances.
     */
    static Signer createSigner(AlgorithmIdentifier sigAlgId, BcDigestProvider digestProvider)
        throws OperatorCreationException
    {
        RSASSAPSSparams pssParams = (sigAlgId.getParameters() == null)
            ? new RSASSAPSSparams()
            : RSASSAPSSparams.getInstance(sigAlgId.getParameters());

        AlgorithmIdentifier mgfAlg = pssParams.getMaskGenAlgorithm();
        ASN1ObjectIdentifier mgfOid = mgfAlg.getAlgorithm();

        AlgorithmIdentifier hashAlgId = pssParams.getHashAlgorithm();
        AlgorithmIdentifier mgfHashAlgId;
        if (PKCSObjectIdentifiers.id_mgf1.equals(mgfOid))
        {
            // MGF1: the inner hash AlgorithmIdentifier is carried in
            // mgfAlg.parameters (RFC 8017 sec. A.2.1).
            mgfHashAlgId = AlgorithmIdentifier.getInstance(mgfAlg.getParameters());
        }
        else if (NISTObjectIdentifiers.id_shake128.equals(mgfOid)
              || NISTObjectIdentifiers.id_shake256.equals(mgfOid))
        {
            // RFC 8702: SHAKE used directly as the mask generation
            // function — the MGF AlgorithmIdentifier is the SHAKE OID
            // itself, not id-mgf1 with SHAKE inside. PSSSigner's
            // maskGenerator detects mgfDigest instanceof Xof and emits
            // the variable-length output natively.
            mgfHashAlgId = mgfAlg;
        }
        else
        {
            throw new OperatorCreationException(
                "unsupported mask generation function for RSASSA-PSS: " + mgfOid);
        }

        // RSASSA-PSS-params.trailerField INTEGER DEFAULT 1, where the
        // single defined value 1 means trailerField byte 0xBC (RFC 8017
        // sec. 9.1.1). PSSSigner's TRAILER_IMPLICIT carries that byte.
        if (pssParams.getTrailerField().intValue() != 1)
        {
            throw new OperatorCreationException(
                "unsupported trailerField for RSASSA-PSS: " + pssParams.getTrailerField());
        }

        Digest contentDigest = digestProvider.get(hashAlgId);
        Digest mgfDigest = digestProvider.get(mgfHashAlgId);
        int saltLength = pssParams.getSaltLength().intValue();

        return new PSSSigner(new RSABlindedEngine(),
            contentDigest, mgfDigest, saltLength, PSSSigner.TRAILER_IMPLICIT);
    }
}
