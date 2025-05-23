/**
 * High level classes for dealing with S/MIME objects (RFC 3851).
 * <p>
 * There is one thing that is worth commenting about with these. If you're using
 * AS2 on some other standard which specifies a different default content transfer encoding from RFC 2405, make
 * sure you use the constructors on SMIMESigned and SMIMESignedGenerator that allow you to
 * set the default ("binary" in the case of AS2 as opposed to "bit7" which is the default).
 * </p>
 */
package org.bouncycastle.mail.smime;
