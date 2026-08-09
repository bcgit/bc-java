/**
 * {@link org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardBackend} implementation for YubiKey devices, built on
 * the YubiKit libraries.
 * <p>
 * YubiKit is a <em>compile-only</em> dependency of bcpgsc: the published artifact declares no third-party
 * runtime dependency, so an application using this package must put
 * <code>com.yubico.yubikit:openpgp</code> and <code>com.yubico.yubikit:desktop</code> on its own
 * classpath. The rest of the {@link org.bouncycastle.openpgp.smartcard} API has no such requirement.
 */
package org.bouncycastle.openpgp.smartcard.yubikey;
