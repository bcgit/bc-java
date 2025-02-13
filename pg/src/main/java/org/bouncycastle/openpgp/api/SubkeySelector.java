package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPKeyRing;

import java.util.List;

/**
 * Interface for selecting a subset of keys from a {@link PGPKeyRing}.
 * This is useful e.g. for selecting a signing key from an OpenPGP key, or a for selecting all
 * encryption capable subkeys of a certificate.
 */
public interface SubkeySelector
{
    /**
     * Given a {@link PGPKeyRing}, select a subset of the key rings (sub-)keys and return their
     * {@link KeyIdentifier KeyIdentifiers}.
     *
     * @param certificate OpenPGP key or certificate
     * @param policy      OpenPGP algorithm policy
     * @return non-null list of identifiers
     */
    List<OpenPGPCertificate.OpenPGPComponentKey> select(OpenPGPCertificate certificate, OpenPGPPolicy policy);
}
