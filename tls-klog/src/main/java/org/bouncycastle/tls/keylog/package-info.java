/**
 * Reporting of TLS connection secrets in the terms of RFC 9850, the SSLKEYLOGFILE format, so that a
 * capture of a test connection can be decrypted by an analyser such as Wireshark.
 * <p>
 * This package exists only in the <code>bctls-klog</code> build of the Bouncy Castle TLS API and
 * consists of a sink, {@link org.bouncycastle.tls.keylog.TlsKeyLog}, which the application
 * implements and names in its <code>java.security</code> file, plus the RFC's labels in
 * {@link org.bouncycastle.tls.keylog.TlsKeyLogLabel}. Storage, encoding and access control are the
 * implementation's to decide; see {@link org.bouncycastle.tls.keylog.TlsKeyLog} for the contract
 * and for why RFC 9850 sec. 1.1 forbids any of this in production.
 */
package org.bouncycastle.tls.keylog;
