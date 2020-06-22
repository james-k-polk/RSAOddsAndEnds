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

public class Examples {
    public static void main(String[] args) {
//        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("RSA");
//        kpg.initialize(512);
//        java.security.KeyPair keyPair = kpg.generateKeyPair();
//        RSAPublicKey rsaPub = (RSAPublicKey) keyPair.getPublic();
//        RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) keyPair.getPrivate();
//        System.out.printf("BigInteger n = new BigInteger(\"%x\", 16);%n", rsaPub.getModulus());
//        System.out.printf("BigInteger e = new BigInteger(\"%x\", 16);%n", rsaPub.getPublicExponent());
//        System.out.printf("BigInteger d = new BigInteger(\"%x\", 16);%n", rsaPrivateCrtKey.getPrivateExponent());
        BigInteger n = new BigInteger("e000216ac013b89c70079f237899daf2e81875d68d6bcfb0ee1d19452915b57f60ded5830d608fa9b9ffa34796a043ea024b3e8388c5f20cdb4de80ebd7779f9", 16);
        BigInteger e = new BigInteger("10001", 16);
        BigInteger d = new BigInteger("c6f196bc56c7ad28d39f1149d1ace3f6e50804707fbe07021f191cfe7dd4d8121623df40d9e102f009cc6b0ba2c9b3c81caa11688f4d86ba25cd7aad0e044301", 16);
        BigInteger p = RSACrtFromD.findFactor(e, d, n);
        BigInteger q = n.divide(p);
        System.out.println(p);
    }
}
