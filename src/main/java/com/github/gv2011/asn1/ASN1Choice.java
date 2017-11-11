package com.github.gv2011.asn1;
/*-
 * #%L
 * Vinz ASN.1
 * %%
 * Copyright (C) 2016 - 2017 Vinz (https://github.com/gv2011)
 * %%
 * Please note this should be read in the same way as the MIT license. (https://www.bouncycastle.org/licence.html)
 *
 * Copyright (c) 2000-2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 * #L%
 */
/**
 * Marker interface for CHOICE objects - if you implement this in a role your
 * own object any attempt to tag the object implicitly will convert the tag to
 * an explicit one as the encoding rules require.
 * <p>
 * If you use this interface your class should also implement the getInstance()
 * pattern which takes a tag object and the tagging mode used.
 * </p>
 * <hr>
 * <p><b>X.690</b></p>
 * <p><b>8: Basic encoding rules</b></p>
 * <p><b>8.13 Encoding of a choice value </b></p>
 * <p>
 * The encoding of a choice value shall be the same as the encoding of a value of the chosen type.
 * <blockquote>
 * NOTE 1 &mdash; The encoding may be primitive or constructed depending on the chosen type.
 * <br />
 * NOTE 2 &mdash; The tag used in the identifier octets is the tag of the chosen type,
 * as specified in the ASN.1 definition of the choice type.
 * </blockquote>
 * </p>
 */
public interface ASN1Choice
{
    // marker interface
}
