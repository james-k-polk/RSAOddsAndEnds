/*
 * MIT License
 *
 * Copyright (c) 2020. James K Polk
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

package com.github.jameskpolk;

import java.math.BigInteger;

/**
 * This is based on a comment,
 * https://stackoverflow.com/questions/4078902/cracking-short-rsa-keys/4083501#comment84706047_4083501
 */
public class RSACrtFromDMethod2 {

    /**
     * Compute the integer square root of n, which is defined as the greatest integer
     * less than or equal to the real-valued square root of n. If n is an integer
     * perfect square, n = y*y for integer y, then y is returned, else null is.
     *
     * @param n
     * @return the integer square root of n is an integer perfect square,
     * null otherwise
     */
    public static BigInteger perfectSqrt(BigInteger n) {
        BigInteger prev = BigInteger.ZERO;
        BigInteger current = BigInteger.ONE.shiftLeft(n.bitLength() / 2);
        while (prev.subtract(current).abs().compareTo(BigInteger.ONE) > 0) {
            prev = current;
            current = current.add(n.divide(current)).shiftRight(1);
        }
        BigInteger isqrt = prev.min(current);
        if (n.equals(isqrt.multiply(isqrt))) {
            return isqrt;
        } else {
            return null;
        }
    }

    /**
     * Solve for the unknown in a quadratic polynominal using the quadratic formula,
     * x = (-b +/- sqrt(b*b - 4ac)) / 2a. We are only interest in integer solutions,
     * therefore the discriminant must be an integer perfect square and 2a must be a
     * divisor of the numerator.
     *
     * @param a
     * @param b
     * @param c
     * @return one of the two solutions if they exist, null otherwise
     */
    public static BigInteger solveQuadratic(BigInteger a, BigInteger b, BigInteger c) {
        BigInteger discriminant = b.multiply(b).subtract(a.multiply(c).shiftLeft(2));
        BigInteger isqrt = perfectSqrt(discriminant);
        if (isqrt == null) {
            return null;
        }
        BigInteger numerator = isqrt.subtract(b);
        BigInteger[] result = numerator.divideAndRemainder(a.shiftLeft(1));
        if (result[1].equals(BigInteger.ZERO)) {
            return result[0];
        } else {
            return null;
        }
    }

    /**
     * Given e, d, and n, and a guess k for ed-1==k*(p-1)*(q-1), attempt to solve for
     * p.
     *
     * @param n
     * @param e
     * @param d
     * @param k
     * @return p if it exists, null otherwise
     */
    public static BigInteger solveForP(BigInteger n, BigInteger e, BigInteger d, BigInteger k) {
        /**
         * Starting with ed - 1 == k(x-1)(n/x-1),
         * sagemath gives the coefficients of the quadratic ax*x + bx + c in x as:
         * a == k*k, b == d*e - k*n - k - 1, c == k*n
         */

        BigInteger a = k;
        BigInteger temp = k.multiply(n);
        BigInteger b = d.multiply(e).subtract(temp).subtract(k).subtract(BigInteger.ONE);
        BigInteger c = temp;
        BigInteger p = solveQuadratic(a, b, c);
        return p;
    }

    /**
     * Try different values of k in the equation ed - 1 == k(x-1)(n/x-1), hoping
     * to find one that results in a solution for x.
     *
     * @param n
     * @param e
     * @param d
     * @return x (==p) if found, null for failure.
     */
    public static BigInteger solveForPandK(BigInteger n, BigInteger e, BigInteger d) {
        /**
         * d is typically about the size of n, therefore e*d is typically about the size of
         * e*n. Therefore we try multiples of k that are around e.
         */
        for (BigInteger k = BigInteger.ONE; true; k = k.add(BigInteger.ONE)) {
//            if (k.mod(BigInteger.valueOf(500L)).equals(BigInteger.ZERO)) {
//                System.out.printf("%d,", k);
//            }
            BigInteger p = solveForP(n, e, d, k);
            if (p != null) {
                return p;
            }
        }
    }

    public static void main(String[] args) {
        BigInteger n = new BigInteger("1b666dbb10d5f9e6847e7ae23810f096cb873b48338e7b3ffbac1651307b6c997202182e29661f018065851a6f15105aea5d7538eaa2c49a72177c3a88dd8abb826ee863e7495256947ac16d3c4e676a031dc7da0b0937c20aa4672b01ad4a0bb139a149e3dc7b386fa5901e93a860e2ff9d82f86a7fd624d7077e8c6f34396fb723bdf5f41bc1aa32c590014c2e9777c2115ba1cc244e73c415d56be303222f893ed540e833b22e162943d1fe75bc333b5d0b6aaaf30854bdc54b0da40b8e073017c5411515f77d05113739264915adace35ae14879f98f55aad4998b76b5b6394c3a3f8bb6417696b8b151e2ba4a265e88ada2cfae2bfc5f78b3f14eff0733", 16);
        BigInteger e = BigInteger.valueOf(65537L);
//        BigInteger d = new BigInteger("85b19cf35076430745da70b4c2bec730bcf5fe4e4dbf885a2d440587dbe16b35c93206322c95d6487c205f6ac2e39d45bce6d318886e6bb6b4c36c7b38d85db529e9b6a8ebaf10fbf22e6c6b2cc7ae5fa5341ba9bd170f287f69323082118e57203a4e4d9db6d276d5782665be4296d3c8b1e60b43a405b5ab149928b00868b9a7da718a679335d49908bd9ea11bda770863c7a9b07647c6a0674c463c934ebaa88a32c659914f52a943a514322e4c926299ac45d55c58d69d2bb70076d27cb77db374b5a8a61a2c98d2fdfc06f7ac782f1f25e46ba48cdfb90fe58982730ba4de8a658d532d3acc7686443c2195d3f77f5e164790da2a3ee21ddb8a12e2aeb1", 16);
        BigInteger d = new BigInteger("128ebe351b83011d6a914b6319fc0726eab42da78a1baf48378967181811100da154dfd1ac02596fa7e99a4bbbfe75344e557c064f8c6c41fa92037695aa0ec34ee5150a4ce4b11aa8b7b777e78766ad3b6d192589a1f59cbb9e7bad7a1646f7425238f6159907efc2564d151886cb10137637f54e144512707cc7ee0f873c7b067ed24f2bb3a1671d1f29620babf6d79aa23c1171a55b98d4cbb67606441109d2020d41317ac115a51e67f185ccb6aa31a49c1e94d66b36c1d8e3d4e42da6a1c8e733c6330d722d3c55cb75172db93a52f3dc82d25ba49b3fed97801478ba705ec92d849d295368f126a860c5a91c19e487535c64c76bf1492bb23de699d639", 16);
        BigInteger p = solveForPandK(n, e, d);
        // sanity check
        BigInteger q = n.divide(p);
        if (!p.multiply(q).equals(n)) {
            System.out.println("Sanity check failure");
        } else {
            System.out.println(p);
        }
    }
}
