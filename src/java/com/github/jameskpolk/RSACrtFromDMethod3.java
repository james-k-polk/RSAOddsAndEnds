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
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPrivateCrtKeySpec;

import static com.github.jameskpolk.RSACrtFromDMethod2.perfectSqrt;


public class RSACrtFromDMethod3 {

    private static RSAPrivateCrtKey solveForPrivateKey(BigInteger n, BigInteger e, BigInteger d) throws Exception {
        BigInteger edMinus1 = e.multiply(d).subtract(BigInteger.ONE);
        BigInteger k = edMinus1.divide(n).add(BigInteger.ONE);
        BigInteger phi = edMinus1.divide(k);
        BigInteger t1 = n.subtract(phi).add(BigInteger.ONE).shiftRight(1); // (p+q) / 2
        BigInteger t2 = perfectSqrt(t1.multiply(t1).subtract(n));// (p-q) / 2
        BigInteger p = t1.add(t2);
        BigInteger q = t1.subtract(t2);
        // Sanity check
        if (! p.multiply(q).equals(n)) {
            throw new Exception("Failure. Perhaps d= inv(e) mod lambda(n)");
        }

        // Now compute the other parameters.

        BigInteger dp = d.mod(p.subtract(BigInteger.ONE));
        BigInteger dq = d.mod(q.subtract(BigInteger.ONE));
        BigInteger qInvModp = q.modInverse(p);
        RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, qInvModp);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPrivateCrtKey) kf.generatePrivate(keySpec);
    }

    public static void main(String[] args) throws Exception {
        BigInteger n = new BigInteger("1b666dbb10d5f9e6847e7ae23810f096cb873b48338e7b3ffbac1651307b6c997202182e29661f018065851a6f15105aea5d7538eaa2c49a72177c3a88dd8abb826ee863e7495256947ac16d3c4e676a031dc7da0b0937c20aa4672b01ad4a0bb139a149e3dc7b386fa5901e93a860e2ff9d82f86a7fd624d7077e8c6f34396fb723bdf5f41bc1aa32c590014c2e9777c2115ba1cc244e73c415d56be303222f893ed540e833b22e162943d1fe75bc333b5d0b6aaaf30854bdc54b0da40b8e073017c5411515f77d05113739264915adace35ae14879f98f55aad4998b76b5b6394c3a3f8bb6417696b8b151e2ba4a265e88ada2cfae2bfc5f78b3f14eff0733", 16);
        BigInteger e = BigInteger.valueOf(65537L);
        BigInteger d = new BigInteger("128ebe351b83011d6a914b6319fc0726eab42da78a1baf48378967181811100da154dfd1ac02596fa7e99a4bbbfe75344e557c064f8c6c41fa92037695aa0ec34ee5150a4ce4b11aa8b7b777e78766ad3b6d192589a1f59cbb9e7bad7a1646f7425238f6159907efc2564d151886cb10137637f54e144512707cc7ee0f873c7b067ed24f2bb3a1671d1f29620babf6d79aa23c1171a55b98d4cbb67606441109d2020d41317ac115a51e67f185ccb6aa31a49c1e94d66b36c1d8e3d4e42da6a1c8e733c6330d722d3c55cb75172db93a52f3dc82d25ba49b3fed97801478ba705ec92d849d295368f126a860c5a91c19e487535c64c76bf1492bb23de699d639", 16);
        RSAPrivateCrtKey privKey = solveForPrivateKey(n, e, d);
    }


}
