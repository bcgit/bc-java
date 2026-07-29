/**
 * A reader and writer for Deterministically Encoded CBOR (RFC 8949, Sections 4.2.1 and 4.2.2),
 * scoped to the profile required by CBOR-based PKI formats such as C509 certificates
 * (draft-ietf-cose-cbor-encoded-cert-20). Indefinite-length items, non-shortest-form integers
 * and floating-point values are deliberately not supported.
 * <p>
 * This package is a self-contained CBOR layer: it depends only on the JDK and the basic
 * org.bouncycastle.util helpers, and no ASN.1 library type appears in it. The bridge between
 * CBOR and the ASN.1 object model lives in the format-specific sub-packages
 * (org.bouncycastle.cbor.c509), not here.
 */
package org.bouncycastle.cbor;
