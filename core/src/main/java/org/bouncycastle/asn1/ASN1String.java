package org.bouncycastle.asn1;

/**
 * Marker class for extracting String from ASN.1 STRING objects.
 * <p>
 * This contains also the STRING ENCODING RULES of X.690.
 * <p>
 * This supports BER, and DER forms of the data.
 * <p>
 * DER form is always primitive single "STRING", while
 * BER support uses constructed forms.
 * <p>
 * The CER form support does not exist.
 * <hr>
 * <h2>X.690</h2>
 * <h3>8: Basic encoding rules</h3>
 * <h4>8.21 Encoding for values of the restricted character string types </h4>
 * <b>8.21.1</b> The data value consists of a string of characters from
 * the character set specified in the ASN.1 type definition
 * <p>
 * <b>8.21.2</b> Each data value shall be encoded independently
 * of other data values of the same type. 
 * <p>
 * <b>8.21.3</b> Each character string type shall be encoded
 * as if it had been declared: 
 * <blockquote>
 * <b>[UNIVERSAL x] IMPLICIT OCTET STRING </b>
 * </blockquote>
 * where x is the number of the universal class tag
 * assigned to the character string type in ITU-T Rec. X.680 | ISO/IEC 8824-1.
 * The value of the octet string is specified in 8.21.4 and 8.21.5.
 * <p>
 * <b>8.21.4</b> Where a character string type is specified
 * in ITU-T Rec. X.680 | ISO/IEC 8824-1 by direct reference to
 * an enumerating table (NumericString and PrintableString),
 * the value of the octet string shall be that specified in 
 * 8.21.5 for a VisibleString type with the same character string value. 
 * <p>
 * <b>8.21.5</b> For restricted character strings apart from
 * UniversalString and BMPString, the octet string shall contain 
 * the octets specified in ISO/IEC 2022 for encodings in
 * an 8-bit environment, using the escape sequence and character
 * codings registered in accordance with ISO 2375.
 * <p>
 * <b>8.21.5.1</b> An escape sequence shall not be used
 * unless it is one of those specified by one of
 * the registration numbers used to define the character
 * string type in ITU-T Rec. X.680 | ISO/IEC 8824-1.
 * <p>
 * <b>8.21.5.2</b> At the start of each string, certain
 * registration numbers shall be assumed to be designated
 * as G0 and/or C0 and/or C1, and invoked (using
 * the terminology of ISO/IEC 2022). These are specified
 * for each type in Table 3, together with the assumed escape sequence they imply.
 * <p>
 *
 * [ESCAPE CODE TABLE 3]
 * <p>
 * <b>8.21.5.3</b> Certain character string types shall not
 * contain explicit escape sequences in their encodings;
 * in all other cases, any escape sequence allowed by 8.21.5.1
 * can appear at any time, including at the start of the encoding.
 * Table 3 lists the types for which explicit escape sequences are allowed.
 * <p>
 * <b>8.21.5.4</b> Announcers shall not be used unless explicitly permitted
 * by the user of ASN.1.
 * <blockquote>
 * NOTE &mdash; The choice of ASN.1 type provides a limited form of
 * announcer functionality. Specific application protocols may choose 
 * to carry announcers in other protocol elements, or to specify
 * in detail the manner of use of announcers. 
 * </blockquote>
 * <p>
 * <b>8.21.6</b> The above example illustrates three of
 * the (many) possible forms available as a sender's option.
 * Receivers are required to handle all permitted forms (see 7.3). 
 * <p>
 * <b>8.21.7</b> For the UniversalString type, the octet string shall contain
 * the octets specified in ISO/IEC 10646-1, using the 4-octet canonical form
 * (see 13.2 of ISO/IEC 10646-1). Signatures shall not be used.
 * Control functions may be used provided they satisfy the restrictions imposed
 * by 8.21.9
 * <p>
 * <b>8.21.8</b> For the BMPString type, the octet string
 * shall contain the octets specified in ISO/IEC 10646-1,
 * using the 2-octet BMP form (see 13.1 of ISO/IEC 10646-1).
 * Signatures shall not be used. Control functions may be used provided 
 * they satisfy the restrictions imposed by 8.21.9.
 * <p>
 * <b>8.21.9</b> The C0 and C1 control functions of ISO/IEC 6429
 * may be used with the following exceptions.
 * <blockquote>
 * NOTE 1 &mdash; The effect of this subclause is to allow
 * the useful control functions such as LF, CR, TAB, etc.,
 * while forbidding the use of escapes to other character sets.
 * <p>
 * NOTE 2 &mdash; The C0 and C1 control functions are each
 * encoded in two octets for BMPString and four for UniversalString.
 * <ol type="a">
 * <li>Announcer escape sequences defined in ISO/IEC 2022 shall not be used.
 * <blockquote>
 * NOTE 3 &mdash; The assumed character coding environment is ISO/IEC 10646-1.
 * </blockquote></li>
 * <li>Designating or identifying escape sequences defined
 * in ISO/IEC 2022 shall not be used, including the identifying 
 * escape sequences permitted by ISO/IEC 10646-1, 17.2 and 17.4.
 * <blockquote>
 * NOTE 4 &mdash; ASN.1 allows the use of the PermittedAlphabet
 * subtype notation to select the set of allowed characters.
 * PermittedAlphabet is also used to select the level of
 * implementation of ISO/IEC 10646-1. BMPString is always used
 * for the two-octet form and UniversalString for the four-octet form.
 * </blockquote></li>
 * <li>Invoking escape sequence or control sequences of
 * ISO/IEC 2022 shall not be used, such as SHIFT IN (SI),
 * SHIFT OUT (SO), or LOCKING SHIFT FOR G3 (SS3) </li>
 * <li>The coding shall conform to ISO/IEC 10646-1 and
 * remain in that code set. </li>
 * <li>Control sequences for identifying subsets of graphic
 * characters according to ISO/IEC 10646-1, 16.3, shall not be used.
 * <blockquote>
 * NOTE 5 &mdash; ASN.1 applications use subtyping to indicate
 * subsets of the graphic characters of ISO/IEC 10646-1 
 * and to select the ISO/IEC 10646-1 cells that correspond
 * to the control characters of ISO/IEC 6429.
 * </blockquote></li>
 * <li>The escape sequences of ISO/IEC 10646-1, 16.5,
 * shall not be used to switch to ISO/IEC 2022 codes.</li>
 * </ol>
 * </blockquote>
 *
 * <h3>9: Canonical encoding rules</h3>
 * <h4>9.1 Length forms</h4>
 * If the encoding is constructed, it shall employ the indefinite length form.
 * If the encoding is primitive, it shall include the fewest length octets necessary.
 * [Contrast with 8.1.3.2 b).]
 * <h4>9.2 String encoding forms</h4>
 * Bitstring, octetstring, and restricted character string
 * values shall be encoded with a primitive encoding if they would 
 * require no more than 1000 contents octets, and as a constructed
 * encoding otherwise. The string fragments contained in 
 * the constructed encoding shall be encoded with a primitive encoding.
 * The encoding of each fragment, except possibly 
 * the last, shall have 1000 contents octets. (Contrast with 8.21.6.)
 *
 * <h3>10: Distinguished encoding rules</h3>
 * <h4>10.1 Length forms</h4>
 * The definite form of length encoding shall be used,
 * encoded in the minimum number of octets.
 * [Contrast with 8.1.3.2 b).] 
 * <h4>10.2 String encoding forms</h4>
 * For bitstring, octetstring and restricted character string types,
 * the constructed form of encoding shall not be used. (Contrast with 8.21.6.) 
 * <p>
 * <h3>11: Restrictions on BER employed by both CER and DER</h3>
 * <h4>11.4 GeneralString values </h4>
 * The encoding of values of the GeneralString type
 * (and all other restricted character string types defined by reference 
 * to the International Register of Coded Character Sets) shall generate
 * escape sequences to designate and invoke a new register entry only
 * when the register entry for the character is not currently designated
 * as the G0, G1, G2, G3, C0, or C1 set.
 * All designations and invocations shall be into the smallest numbered
 * G or C set for which there is an escape sequence defined in the entry
 * of the International Register of Coded Character Sets to be used with
 * Escape Sequences.
 * <blockquote>
 * NOTE 1 &mdash; For the purposes of the above clause,
 * G0 is the smallest numbered G set, followed by G1, G2, and G3 in order.
 * C0 is the smallest numbered C set, followed by C1.
 * <p>
 * NOTE 2 &mdash; Each character in a character string value is associated
 * with a particular entry in the International Register of Coded Character Sets.
 * </blockquote>
 */

public interface ASN1String
{
    /**
     * Get String value of the ASN.1 STRING object.
     */
    public String getString();
}
