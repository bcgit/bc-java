package org.bouncycastle.openpgp;

/**
 * There are two different flavours of AEAD defined for OpenPGP:
 * <b>
 * <ul>
 *     <li>
 *         OpenPGP V5:
 *         RFC4880bis10 defines the AEAD/OCB Encrypted Data packet.
 *         The session key is retrieved from symmetrically encrypted session key (SKESK) packets of
 *         {@link org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket#VERSION_5 version 5}, or
 *         public-key encrypted session key (PKESK) packets of
 *         {@link org.bouncycastle.bcpg.PublicKeyEncSessionPacket#VERSION_3 version 3}.
 *         This method of using AEAD in OpenPGP does not follow consensus of the OpenPGP working group.
 *         To encrypt a message using this flavour of AEAD, use {@link #OPENPGP_V5}.
 *     </li>
 *     <li>
 *         OpenPGP V6:
 *         The OpenPGP working group defines AEAD throughout the crypto-refresh document using a symmetrically
 *         encrypted integrity-protected data (SEIPD) packet of
 *         {@link org.bouncycastle.bcpg.SymmetricEncIntegrityPacket#VERSION_2 version 2}.
 *         The session key is retrieved from symmetrically encrypted session key (SKESK) packets of
 *         {@link org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket#VERSION_6 version 6}, or
 *         public-key encrypted session key (PKESK) packets of
 *         {@link org.bouncycastle.bcpg.PublicKeyEncSessionPacket#VERSION_6 version 6}.
 *         To encrypt a message using this flavour of AEAD, use {@link #OPENPGP_V6}.
 *     </li>
 * </ul>
 */
public enum PGPAEADFlavour {
    /**
     * AEAD in OpenPGP as defined in draft-ietf-openpgp-rfc4880bis-10.
     * Used with OpenPGP v5 keys.
     * <br>
     * Further development of this protocol branch is likely to be found in draft-koch-openpgp-2015-rfc4880bis-01.
     *
     * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-openpgp-rfc4880bis/10/">
     *     draft-ietf-openpgp-rfc4880bis-10</a>
     * @see <a href="https://www.ietf.org/archive/id/draft-koch-openpgp-2015-rfc4880bis-01.html">
     *     draft-koch-openpgp-2015-rfc4880bis-01</a>
     */
    OPENPGP_V5,

    /**
     * AEAD in OpenPGP as defined in draft-ietf-openpgp-crypto-refresh-07 /
     * <a href="https://openpgp-wg.gitlab.io/rfc4880bis">Living Crypto Refresh Document</a>.
     * Used with OpenPGP v6 keys.
     * TODO: Update URL and rename flavour once final RFC is released.
     * @see <a href="https://openpgp-wg.gitlab.io/rfc4880bis/</a>
     */
    OPENPGP_V6,
    ;
}
