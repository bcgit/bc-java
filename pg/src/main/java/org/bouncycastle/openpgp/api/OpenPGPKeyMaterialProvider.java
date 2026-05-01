package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.KeyIdentifier;

/**
 * Interface for providing OpenPGP keys or certificates.
 *
 * @param <M> either {@link OpenPGPCertificate} or {@link OpenPGPKey}
 */
public interface OpenPGPKeyMaterialProvider<M extends OpenPGPCertificate>
{
    /**
     * Provide the requested {@link OpenPGPCertificate} or {@link OpenPGPKey} containing the component key identified
     * by the passed in {@link KeyIdentifier}.
     *
     * @param componentKeyIdentifier identifier of a component key (primary key or subkey)
     * @return the OpenPGP certificate or key containing the identified component key
     */
    M provide(KeyIdentifier componentKeyIdentifier);

    /**
     * Interface for requesting {@link OpenPGPCertificate OpenPGPCertificates} by providing a {@link KeyIdentifier}.
     * The {@link KeyIdentifier} can either be that of the certificates primary key, or of a subkey.
     */
    interface OpenPGPCertificateProvider
            extends OpenPGPKeyMaterialProvider<OpenPGPCertificate>
    {

    }

    /**
     * Interface for requesting {@link OpenPGPKey OpenPGPKeys} by providing a {@link KeyIdentifier}.
     * The {@link KeyIdentifier} can either be that of the keys primary key, or of a subkey.
     */
    interface OpenPGPKeyProvider
            extends OpenPGPKeyMaterialProvider<OpenPGPKey>
    {

    }
}
