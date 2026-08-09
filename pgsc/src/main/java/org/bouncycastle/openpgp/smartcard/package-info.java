/**
 * API for using OpenPGP keys whose private key material lives on a smart card or hardware token.
 * <p>
 * A {@link org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardBackend} enumerates the cards of one card
 * technology; {@link org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager} aggregates several backends and
 * implements {@link org.bouncycastle.openpgp.api.PublicKeyDataDecryptorFactoryProvider}, so registering it
 * with {@link org.bouncycastle.openpgp.api.OpenPGPMessageProcessor} lets the high-level OpenPGP API
 * decrypt messages addressed to a card-held key. Such keys are marked
 * {@link org.bouncycastle.bcpg.SecretKeyPacket#USAGE_EXTERNAL} per
 * <a href="https://datatracker.ietf.org/doc/draft-dkg-openpgp-external-secrets/">OpenPGP External Secret
 * Keys</a>.
 *
 * @see org.bouncycastle.openpgp.smartcard.simulator
 * @see org.bouncycastle.openpgp.smartcard.yubikey
 */
package org.bouncycastle.openpgp.smartcard;
