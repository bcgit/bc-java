/**
 * Higher-level S/MIME signed-message validator that runs structural, signer, and
 * certificate-path checks against a {@code SignedMailValidator.ValidationResult} and
 * reports failures as localised messages through {@link org.bouncycastle.pkix.util}.
 */
package org.bouncycastle.mail.smime.validator;
