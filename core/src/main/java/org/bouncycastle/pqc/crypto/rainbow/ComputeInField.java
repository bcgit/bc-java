package org.bouncycastle.pqc.crypto.rainbow;

/**
 * This class offers different operations on matrices in field GF2^8.
 * <p>
 * Implemented are functions:
 * - finding inverse of a matrix
 * - solving linear equation systems using the Gauss-Elimination method
 * - basic operations like matrix multiplication, addition and so on.
 */

class ComputeInField
{
    /**
     * Constructor with no parameters
     */
    public ComputeInField()
    {
    }


    /**
     * This function finds a solution of the equation Bx = b.
     * Exception is thrown if the linear equation system has no solution
     *
     * @param B this matrix is the left part of the
     *          equation (B in the equation above)
     * @param b the right part of the equation
     *          (b in the equation above)
     * @return x  the solution of the equation if it is solvable
     * null otherwise
     * @throws RuntimeException if LES is not solvable
     */
    public short[] solveEquation(short[][] B, short[] b)
    {
        if (B.length != b.length)
        {
            return null;   // not solvable in this form
        }

        try
        {
            // stores B|b from the equation B*x = b
            short[][] A = new short[B.length][B.length + 1];
            // stores the solution of the LES
            short[] x = new short[B.length];

            // copy B and b into the global matrix A
            // free coefficients in last column are subtracted from b
            for (int i = 0; i < B.length; i++)
            {
                System.arraycopy(B[i], 0, A[i], 0, B[0].length);
                A[i][b.length] = GF2Field.addElem(b[i], A[i][b.length]);
            }

            gaussElim(A);

            // copy solution into x
            for (int i = 0; i < A.length; i++)
            {
                x[i] = A[i][b.length];
            }

            return x;
        }
        catch (RuntimeException rte)
        {
            return null; // the LES is not solvable!
        }
    }

    /**
     * This function computes the inverse of a given matrix using the Gauss-
     * Elimination method.
     * <p>
     * An exception is thrown if the matrix has no inverse
     *
     * @param coef the matrix which inverse matrix is needed
     * @return inverse matrix of the input matrix.
     * If the matrix is singular, null is returned.
     * @throws RuntimeException if the given matrix is not invertible
     */
    public short[][] inverse(short[][] coef)
    {
        if (coef.length != coef[0].length)
        {
            throw new RuntimeException(
                "The matrix is not invertible. Please choose another one!");
        }
        try
        {
            short[][] inverse;
            short[][] A = new short[coef.length][2 * coef.length];

            for (int i = 0; i < coef.length; i++)
            {
                //copy the input matrix coef into A
                System.arraycopy(coef[i], 0, A[i], 0, coef.length);
                // copy the identity matrix into A.
                for (int j = coef.length; j < 2 * coef.length; j++)
                {
                    A[i][j] = 0;
                }
                A[i][i + A.length] = 1;
            }

            gaussElim(A);

            // copy the result (the second half of A) in the matrix inverse.
            inverse = new short[A.length][A.length];
            for (int i = 0; i < A.length; i++)
            {
                for (int j = A.length; j < 2 * A.length; j++)
                {
                    inverse[i][j - A.length] = A[i][j];
                }
            }
            return inverse;
        }
        catch (RuntimeException rte)
        {
            // The matrix is not invertible! A new one should be generated!
            return null;
        }
    }

    private void gaussElim(short[][] A)
    {
        short tmp;
        short factor;
        short factor2;
        for (int i = 0; i < A.length; i++)
        {
            for (int j = i + 1; j < A.length; j++)
            {
                if (A[i][i] == 0)
                {
                    for (int k = i; k < A[0].length; k++)
                    {
                        A[i][k] = GF2Field.addElem(A[i][k], A[j][k]);
                    }
                }
            }

            factor = GF2Field.invElem(A[i][i]);
            if (factor == 0)
            {
                // TODO instead of exception make addition conditional with bit mask for time consistency, see reference implementation
                throw new RuntimeException("The matrix is not invertible");
            }

            A[i] = this.multVect(factor, A[i]);
            for (int j = 0; j < A.length; j++)
            {
                if (i == j)
                {
                    continue;
                }
                factor2 = A[j][i];
                for (int k = i; k < A[0].length; k++)
                {
                    tmp = GF2Field.multElem(A[i][k], factor2);
                    A[j][k] = GF2Field.addElem(A[j][k], tmp);
                }
            }
        }
    }

    /**
     * This function multiplies two given matrices.
     * If the given matrices cannot be multiplied due
     * to different sizes, an exception is thrown.
     *
     * @param M1 -the 1st matrix
     * @param M2 -the 2nd matrix
     * @return A = M1*M2
     * @throws RuntimeException in case the given matrices cannot be multiplied
     *                          due to different dimensions.
     */
    public short[][] multiplyMatrix(short[][] M1, short[][] M2)
        throws RuntimeException
    {

        if (M1[0].length != M2.length)
        {
            throw new RuntimeException("Multiplication is not possible!");
        }
        short tmp = 0;
        short[][] A = new short[M1.length][M2[0].length];
        for (int i = 0; i < M1.length; i++)
        {
            for (int j = 0; j < M2.length; j++)
            {
                for (int k = 0; k < M2[0].length; k++)
                {
                    tmp = GF2Field.multElem(M1[i][j], M2[j][k]);
                    A[i][k] = GF2Field.addElem(A[i][k], tmp);
                }
            }
        }
        return A;
    }

    /**
     * This function multiplies a given matrix with a one-dimensional array.
     * <p>
     * An exception is thrown, if the number of columns in the matrix and
     * the number of rows in the one-dim. array differ.
     *
     * @param M1 the matrix to be multiplied
     * @param m  the one-dimensional array to be multiplied
     * @return M1*m
     * @throws RuntimeException in case of dimension inconsistency
     */
    public short[] multiplyMatrix(short[][] M1, short[] m)
        throws RuntimeException
    {
        if (M1[0].length != m.length)
        {
            throw new RuntimeException("Multiplication is not possible!");
        }
        short tmp = 0;
        short[] B = new short[M1.length];
        for (int i = 0; i < M1.length; i++)
        {
            for (int j = 0; j < m.length; j++)
            {
                tmp = GF2Field.multElem(M1[i][j], m[j]);
                B[i] = GF2Field.addElem(B[i], tmp);
            }
        }
        return B;
    }

    /**
     * This function multiplies a given matrix with a one-dimensional array
     * as m_transpose * M1 * m.
     * <p>
     * An exception is thrown, if matrix is ot quadratic and the number of columns
     * in the matrix and the number of rows in the one-dim. array differ.
     *
     * @param M1 the matrix to be multiplied
     * @param m  the one-dimensional array to be multiplied
     * @return m_transpose*M1*m
     * @throws RuntimeException in case of dimension inconsistency
     */
    public short multiplyMatrix_quad(short[][] M1, short[] m)
        throws RuntimeException
    {
        if (M1.length != M1[0].length || M1[0].length != m.length)
        {
            throw new RuntimeException("Multiplication is not possible!");
        }
        short tmp = 0;
        short[] B = new short[M1.length];
        short ret = 0;
        for (int i = 0; i < M1.length; i++)
        {
            for (int j = 0; j < m.length; j++)
            {
                tmp = GF2Field.multElem(M1[i][j], m[j]);
                B[i] = GF2Field.addElem(B[i], tmp);
            }
            tmp = GF2Field.multElem(B[i], m[i]);
            ret = GF2Field.addElem(ret, tmp);
        }
        return ret;
    }

    /**
     * Addition of two vectors
     *
     * @param vector1 first summand, always of dim n
     * @param vector2 second summand, always of dim n
     * @return addition of vector1 and vector2
     * @throws RuntimeException in case the addition is impossible
     *                          due to inconsistency in the dimensions
     */
    public short[] addVect(short[] vector1, short[] vector2)
    {
        if (vector1.length != vector2.length)
        {
            throw new RuntimeException("Addition is not possible! vector1.length: " + vector1.length + " vector2.length: " + vector2.length);
        }
        short[] rslt = new short[vector1.length];
        for (int n = 0; n < rslt.length; n++)
        {
            rslt[n] = GF2Field.addElem(vector1[n], vector2[n]);
        }
        return rslt;
    }

    /**
     * Multiplication of column vector with row vector
     *
     * @param vector1 column vector, always n x 1
     * @param vector2 row vector, always 1 x n
     * @return resulting n x n matrix of multiplication
     * @throws RuntimeException in case the multiplication is impossible due to
     *                          inconsistency in the dimensions
     */
    public short[][] multVects(short[] vector1, short[] vector2)
    {
        if (vector1.length != vector2.length)
        {
            throw new RuntimeException("Multiplication is not possible!");
        }
        short rslt[][] = new short[vector1.length][vector2.length];
        for (int i = 0; i < vector1.length; i++)
        {
            for (int j = 0; j < vector2.length; j++)
            {
                rslt[i][j] = GF2Field.multElem(vector1[i], vector2[j]);
            }
        }
        return rslt;
    }

    /**
     * Multiplies vector with scalar
     *
     * @param scalar galois element to multiply vector with
     * @param vector vector to be multiplied
     * @return vector multiplied with scalar
     */
    public short[] multVect(short scalar, short[] vector)
    {
        short[] rslt = new short[vector.length];
        for (int n = 0; n < rslt.length; n++)
        {
            rslt[n] = GF2Field.multElem(scalar, vector[n]);
        }
        return rslt;
    }

    /**
     * Multiplies matrix with scalar
     *
     * @param scalar galois element to multiply matrix with
     * @param matrix 2-dim n x n matrix to be multiplied
     * @return matrix multiplied with scalar
     */
    public short[][] multMatrix(short scalar, short[][] matrix)
    {
        short[][] rslt = new short[matrix.length][matrix[0].length];
        for (int i = 0; i < matrix.length; i++)
        {
            for (int j = 0; j < matrix[0].length; j++)
            {
                rslt[i][j] = GF2Field.multElem(scalar, matrix[i][j]);
            }
        }
        return rslt;
    }

    /**
     * Adds the matrices matrix1 and matrix2
     *
     * @param matrix1 first summand
     * @param matrix2 second summand
     * @return addition of matrix1 and matrix2
     * @throws RuntimeException in case the addition is not possible because of
     *                          different dimensions of the matrices
     */
    public short[][] addMatrix(short[][] matrix1, short[][] matrix2)
    {
        if (matrix1.length != matrix2.length || matrix1[0].length != matrix2[0].length)
        {
            throw new RuntimeException("Addition is not possible!");
        }

        short[][] rslt = new short[matrix1.length][matrix1[0].length];//
        for (int i = 0; i < matrix1.length; i++)
        {
            for (int j = 0; j < matrix1[0].length; j++)
            {
                rslt[i][j] = GF2Field.addElem(matrix1[i][j], matrix2[i][j]);
            }
        }
        return rslt;
    }

    /**
     * Adds the transpose of a n x n matrix to itself
     *
     * @param matrix first summand
     * @return addition of matrix and matrix_transpose
     * @throws RuntimeException in case the addition is not possible because of
     *                          different dimensions of the matrices
     */
    public short[][] addMatrixTranspose(short[][] matrix)
    {
        if (matrix.length != matrix[0].length)
        {
            throw new RuntimeException("Addition is not possible!");
        }

        return addMatrix(matrix, transpose(matrix));
    }

    /**
     * Returns the transpose of matrix
     *
     * @param matrix matrix to transpose
     * @return transpose of matrix
     */
    public short[][] transpose(short[][] matrix)
    {
        short[][] rslt = new short[matrix[0].length][matrix.length];//
        for (int i = 0; i < matrix.length; i++)
        {
            for (int j = 0; j < matrix[0].length; j++)
            {
                rslt[j][i] = matrix[i][j];
            }
        }
        return rslt;
    }

    /**
     * Compute upper triangular matrix for given n x n matrix
     *
     * @param matrix matrix to turn into UT
     * @return UT of matrix
     * @throws RuntimeException in case the matrix is not square
     */
    public short[][] to_UT(short[][] matrix)
    {
        if (matrix.length != matrix[0].length)
        {
            throw new RuntimeException("Computation to upper triangular matrix is not possible!");
        }

        short[][] rslt = new short[matrix.length][matrix.length];//
        for (int i = 0; i < matrix.length; i++)
        {
            rslt[i][i] = matrix[i][i];
            for (int j = i + 1; j < matrix[0].length; j++)
            {
                rslt[i][j] = GF2Field.addElem(matrix[i][j], matrix[j][i]);
            }
        }
        return rslt;
    }

    /**
     * Computes a * b + c for batched matrices b and c
     *
     * @param a matrix
     * @param b batched matrix
     * @param c batched matrix
     * @return batch matrix a * b + c
     * @throws RuntimeException in case the matrices dimensions don't permit these operations
     */
    public short[][][] obfuscate_l1_polys(short[][] a, short[][][] b, short[][][] c)
    {
        if (b[0].length != c[0].length
            || b[0][0].length != c[0][0].length
            || b.length != a[0].length
            || c.length != a.length)
        {
            throw new RuntimeException("Multiplication not possible!");
        }
        short temp;
        short[][][] ret = new short[c.length][c[0].length][c[0][0].length];

        for (int i = 0; i < b[0].length; i++)
        {
            for (int j = 0; j < b[0][0].length; j++)
            {
                for (int l = 0; l < a.length; l++)
                {
                    for (int k = 0; k < a[0].length; k++)
                    {
                        temp = GF2Field.multElem(a[l][k], b[k][i][j]);
                        ret[l][i][j] = GF2Field.addElem(ret[l][i][j], temp);
                    }
                    ret[l][i][j] = GF2Field.addElem(c[l][i][j], ret[l][i][j]);
                }
            }
        }
        return ret;
    }

}
