<?php

/**
 * Created By Muneeb Ahmad.
 * Created In NetBeans IDE 8.1 (http://netbeans.org/)
 * JDK version JDK8u65+
 * JRE Java Hotspot Server 8
 * 
 * WAMP Server
 * php version 5.6.25
 * Apache httpd version 2.4.23
 * 
 * PHP Scrypt for AES encryption and decryption
 * This is template and should be followed strictly.
 * Covers CBC and ECB Transformations which is more than sufficient for our purpose.
 * it can be encrypted with 256 bit key, but many low end mobile devices running both Android and iOS may
 * not support that, so stick with 128 bit key, similarly don't use hex key, it creates mess on low end mobile decives.
 * 
 * With Regards
 * Muneeb Ahmad
 * http://1-dot-muneeb-ahmad.appspot.com
 */
echo "Muneeb Ahmad AES (ECB and CBC) Encryption and Decryption template script <br />"
. "Should be used literally without modifying the algo for cross compatibility.<br /><br />";

class AES {

    /**
     * Use this mehtod to encrypt a string using ecb trnasformation with AES algorithm.
     * 
     * @param type $key -- this should be plain string
     * @param type $value -- the string to be encrypted
     * @return type -- encrypted string
     * @throws Exception
     */
    public function encryptECB($key, $value) {
        if ($key != null && $value != null) {
            $cipher = MCRYPT_RIJNDAEL_128;
            $data = $this->pkcs5pad($value);
            return trim(base64_encode(mcrypt_encrypt($cipher, $key, $data, MCRYPT_MODE_ECB)));
        } else {
            throw new Exception('Null params!');
        }
    }
    
    /**
     * Use this method to encrypt a string using cbc transformation using AES algorithm.
     * 
     * @param type $key -- key in plain string fromat
     * @param type $value -- string to be encrypted
     * @param type $iv -- init vector, should be 16 bytes
     * @return type -- encrypted string.
     * @throws Exception
     */
    public function encryptCBC($key, $value, $iv) {
        if ($key != null && $value != null && $iv != null) {
            $cipher = MCRYPT_RIJNDAEL_128;
            $data = $this->pkcs5pad($value);
            return trim(base64_encode(mcrypt_encrypt($cipher, $key, $data, MCRYPT_MODE_CBC, $iv)));
        } else {
            throw new Exception('NULL params!');
        }
    }

    /**
     * Use this method to decrpt an encrypted string using ecb transformation using AES algorithm.
     * 
     * @param type $key -- key should be plain string
     * @param type $value -- encrypted string to be decrypted
     * @return type -- decrypted string
     * @throws Exception
     */
    public function decryptECB($key, $value) {
        if ($key != null && $value != null) {
            $cipher = MCRYPT_RIJNDAEL_128;
            return $this->pkcs5unpad(mcrypt_decrypt($cipher, $key, base64_decode($value), MCRYPT_MODE_ECB));
        } else {
            throw new Exception('Null params!');
        }
    }
    
    /**
     * Use this method to decrypt an ecnrypted string using cbc transformation using AES alogrighm.
     * 
     * @param type $key -- key should be in plain string.
     * @param type $value -- encrypted string to be decrypting
     * @param type $iv -- init vector, should be 16 bytes.
     * @throws Exception
     */
    public function decryptCBC($key, $value, $iv) {
        if ($key != null && $value != null && $iv != null) {
            $cipher = MCRYPT_RIJNDAEL_128;
            return $this->pkcs5unpad(mcrypt_decrypt($cipher, $key, base64_decode($value), MCRYPT_MODE_CBC, $iv));
        } else {
            throw new Exception("Null params!");
        }
    }

    /**
     * Use this method to Pad the given string to PKCS5Padding (EQUIV to PKCS5Padding and PKCS7Padding done in Java) padding.
     * NOTE: PKCS5Padding and PKCS7Padding pad to same points.
     * 
     * @param type $text -- string to be padded
     * @return type -- padded string
     */
    protected function pkcs5pad($text) {
        $size = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
        $pad = $size - (strlen($text) % $size);
        return $text . str_repeat(chr($pad), $pad);
    }

    /**
     * Use this mehtod to UN Pad the PKCS5Padding (EQUIV to PKCS5Padding and PKCS7Padding done in Java).
     * NOTE: PKCS5Padding and PKCS7Padding pad to same points.
     * 
     * @param type $text -- padded string to be un-padded
     * @return boolean -- un-padded string if succesful, else false if not.
     */
    protected function pkcs5unpad($text) {
        $pad = ord($text{strlen($text) - 1});
        if ($pad > strlen($text)) {
            return false;
        }
        if (strspn($text, $text{strlen($text) - 1}, strlen($text) - $pad) != $pad) {
            return false;
        }
        return substr($text, 0, -1 * $pad);
    }

}/** end class. */

//How to use above mentioned AES class. I have tried to make it very similar to Java code, 
//but php lacks many advanced features of raw Java crypto, so I have not extended my Java code for compatibility with php and swift.
//So this code is perfectly compatible with ecnryption and decryption with Java, The Java SE and Android projects
//links have also been provided.
//Output is exxactly same on Android (Java), iOS (Swift2) and Desktop (Java SE), i have tested it my self. 
//This is tested on WAMP server, the specs are listed above, i don't know which PHP version Inaam is using.

$aes = new AES();
$key = 'A1zFlux77a99X1be';                  //should be 16 bytes for 128 bit
$str = 'My name is Muneeb Ahmad';       
$javaEncStr = 'XDR5eeofBwX4H+xsxxXbEOH3pxw4yL+VYwaDVPS1Ys8=';
$initVector = 'RandomInitVector';           //should be 16 bytes
echo "String for Encryption: " . $str . "<br />";
echo "Key for Encryption: [" . $key . "] <br />";       //can use different key, but should use one and same key on all plarform(s)
$encECB = $aes->encryptECB($key, $str);
echo "ECB Encryption: " . $encECB . "<br />";
$deEncECB = $aes->decryptECB($key, $encECB);
echo "ECB Decryption: " . $deEncECB . "<br />";
$encCBC = $aes->encryptCBC($key, $str, $initVector);
echo "CBC Encryption: " . $encCBC . "<br />";
$deEncCBC = $aes->decryptCBC($key, $encCBC, $initVector);
echo "CBC Decryption: " . $deEncCBC . "<br />";

?>