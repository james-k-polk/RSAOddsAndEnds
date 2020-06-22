/*
MIT License

Copyright (c) 2017 President James K. Polk

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

package com.github.jameskpolk;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Random;

public class RSACrtFromD {

    private static final Random RAND = new Random();

    /**
     * Find a factor of n by following the algorithm outlined in Handbook of Applied Cryptography, section
     * 8.2.2(i). See http://cacr.uwaterloo.ca/hac/about/chap8.pdf.
     *
     * @param e the RSA public exponent.
     * @param d the RSA private exponent.
     * @param n the RSA modulus.
     * @return a BigInteger non-trivial proper factor of n
     */
    public static BigInteger findFactor(BigInteger e, BigInteger d, BigInteger n) {
        BigInteger edMinus1 = e.multiply(d).subtract(BigInteger.ONE);
        int s = edMinus1.getLowestSetBit();
        BigInteger t = edMinus1.shiftRight(s);

        for (int aInt = 2; true; aInt++) { // this sequence of a's should do just as well as random
            BigInteger aPow = BigInteger.valueOf(aInt).modPow(t, n);
            for (int i = 1; i <= s; i++) {
                if (aPow.equals(BigInteger.ONE)) {
                    break;
                }
                if (aPow.equals(n.subtract(BigInteger.ONE))) {
                    break;
                }
                BigInteger aPowSquared = aPow.multiply(aPow).mod(n);
                if (aPowSquared.equals(BigInteger.ONE)) {
                    return aPow.subtract(BigInteger.ONE).gcd(n);
                }
                aPow = aPowSquared;
            }
        }

    }

    /**
     * Same method as <code>findFactor()</code>, but designed for fidelity to the HAC text
     * rather than speed.
     *
     * @param e the RSA public exponent.
     * @param d the RSA private exponent.
     * @param n the RSA modulus.
     * @return a BigInteger non-trivial proper factor of n.
     */
    public static BigInteger findFactorSlow(BigInteger e, BigInteger d, BigInteger n) {
        // Let ed − 1 = t * (2**s), where t is an odd integer.
        BigInteger edMinus1 = e.multiply(d).subtract(BigInteger.ONE);
        int s = edMinus1.getLowestSetBit();
        BigInteger t = edMinus1.shiftRight(s);
        while (true) {
            BigInteger a = randomZnStar(n);
            // a is now a member of [1, n-1]
            for (int i = 1; i <= s; i++) {
                BigInteger temp_iMinus1 = a.modPow(t.shiftLeft(i - 1), n);
                BigInteger temp_i = a.modPow(t.shiftLeft(i), n);
                if (temp_i.equals(BigInteger.ONE)) {
                    if (temp_iMinus1.equals(BigInteger.ONE) || temp_iMinus1.equals(n.subtract(BigInteger.ONE))) {
                        // No solutions for this value of a.
                        break;
                    } else {
                        // found factor.
                        return temp_iMinus1.subtract(BigInteger.ONE).gcd(n);
                    }
                }
            }
        }
    }

    /**
     * Returns a random integer in the closed interval [1, n-1].
     *
     * @param n the upper bound
     * @return a random integer in [1, n-1].
     */
    private static BigInteger randomZnStar(BigInteger n) {
        while (true) {
            BigInteger a = new BigInteger(n.bitLength(), RAND);
            if ((a.compareTo(n) != 0) && (a.compareTo(n) < 0)) {
                return a;
            }
        }
    }

    /**
     * Create a complete RSA CRT private key from a non-CRT RSA private key by using
     * an algorithm to factor the modulus and then computing each of the remaining
     * CRT parameters.
     *
     * @param rsaPub  RSA public key,includes public exponent e and modulus n.
     * @param rsaPriv RSA private key, include private exponent d and modulus n.
     * @return an RSAPrivateCrtKey containing all the CRT parameters.
     */

    public static RSAPrivateCrtKey createCrtKey(RSAPublicKey rsaPub, RSAPrivateKey rsaPriv) throws
            NoSuchAlgorithmException, InvalidKeySpecException {

        BigInteger e = rsaPub.getPublicExponent();
        BigInteger d = rsaPriv.getPrivateExponent();
        BigInteger n = rsaPub.getModulus();
        BigInteger p = findFactor(e, d, n);
        BigInteger q = n.divide(p);
        if (p.compareTo(q) < 0) {
            BigInteger t = p;
            p = q;
            q = t;
        }
        assert p.multiply(q).equals(n);
        BigInteger exp1 = d.mod(p.subtract(BigInteger.ONE));
        BigInteger exp2 = d.mod(q.subtract(BigInteger.ONE));
        BigInteger coeff = q.modInverse(p);
        RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(n, e, d, p, q, exp1, exp2, coeff);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPrivateCrtKey) kf.generatePrivate(keySpec);

    }

    private static boolean keyEquals(RSAPrivateCrtKey k1, RSAPrivateCrtKey k2) {
        boolean result = true;
        result = result && k1.getModulus().equals(k2.getModulus());
        result = result && k1.getPublicExponent().equals(k2.getPublicExponent());
        result = result && k1.getPrivateExponent().equals(k2.getPrivateExponent());
        result = result && k1.getPrimeP().equals(k2.getPrimeP());
        result = result && k1.getPrimeQ().equals(k2.getPrimeQ());
        result = result && k1.getPrimeExponentP().equals(k2.getPrimeExponentP());
        result = result && k1.getPrimeExponentQ().equals(k2.getPrimeExponentQ());
        result = result && k1.getCrtCoefficient().equals(k2.getCrtCoefficient());

        return result;
    }

    /**
     * This main method simply enters an infinite loop, generating RSA keypairs
     * and attempting to regenerate the private key from the e, d, and n components
     * only.
     *
     * @param args these are ignored.
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        while (true) {
            KeyPair keyPair = kpg.generateKeyPair();
            RSAPublicKey rsaPub = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) keyPair.getPrivate();
            RSAPrivateCrtKey rsaPrivateCrtKey1 = createCrtKey(rsaPub, rsaPrivateCrtKey);
            assert keyEquals(rsaPrivateCrtKey, rsaPrivateCrtKey1);
        }
    }
}
