import java.time.Instant
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

class HOTP {
    private fun hmacSHA1Encode(secret: ByteArray, counter: ByteArray): ByteArray {
        val secretKeySpec = SecretKeySpec(secret, "HmacSHA1") // Useless GetBytes

        val mac = Mac.getInstance("HmacSHA1")
        mac.init(secretKeySpec)
        return mac.doFinal(counter)
    }

    private fun bytesToHex(bytes: ByteArray): String {
        val hexChars = "0123456789ABCDEF"
        val result = StringBuilder(bytes.size * 2)
        for (byte in bytes) {
            val octet = byte.toInt()
            val firstIndex = octet ushr 4 and 0x0F
            val secondIndex = octet and 0x0F
            result.append(hexChars[firstIndex])
            result.append(hexChars[secondIndex])
        }
        return result.toString()
    }

    private fun hmacSha1ResultToRawString(secretKey: ByteArray, data: ByteArray): String {
        val hmacResult = hmacSHA1Encode(secretKey, data)
        return bytesToHex(hmacResult)
    }

    private fun hexToRawString(hex: String): String {
        val cleanHex = if (hex.length % 2 != 0) "0$hex" else hex // Ensure even-length hex string
        val result = StringBuilder()

        for (i in cleanHex.indices step 2) {
            val byteValue = cleanHex.substring(i, i + 2).toInt(16)
            result.append(byteValue.toChar())
        }

        return result.toString()
    }

    fun getCode(secret: ByteArray, counter: Long, digit: Int): String {
        val counterData: ByteArray = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0)
        var counterChangeable = counter
        for (i in 7 downTo 0){
            counterData[i] = (counterChangeable and 0xFF).toByte()

            counterChangeable = counterChangeable shr 8
        }

        val hsHex = hmacSha1ResultToRawString(secret, counterData)
        val hsString = hexToRawString(hsHex)

        val offset = hsString[hsString.length - 1].code and 0x0F
        val code = (hsString[offset].code and 0x7F shl 24) or
                (hsString[offset + 1].code and 0xFF shl 16) or
                (hsString[offset + 2].code and 0xFF shl 8) or
                (hsString[offset + 3].code and 0xFF)

        val hotp = code % 10.0.pow(digit).toInt()

        return "%0${digit}d".format(hotp)
    }
}


internal object Base32 {
    private val base32Lookup = intArrayOf(
        0xFF, 0xFF, 0x1A, 0x1B, 0x1C,
        0x1D, 0x1E, 0x1F,  // '0', '1', '2', '3', '4', '5', '6', '7'
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // '8', '9', ':',
        // ';', '<', '=',
        // '>', '?'
        0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,  // '@', 'A', 'B',
        // 'C', 'D', 'E',
        // 'F', 'G'
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,  // 'H', 'I', 'J',
        // 'K', 'L', 'M',
        // 'N', 'O'
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,  // 'P', 'Q', 'R',
        // 'S', 'T', 'U',
        // 'V', 'W'
        0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // 'X', 'Y', 'Z',
        // '[', '', ']',
        // '^', '_'
        0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,  // '`', 'a', 'b',
        // 'c', 'd', 'e',
        // 'f', 'g'
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,  // 'h', 'i', 'j',
        // 'k', 'l', 'm',
        // 'n', 'o'
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,  // 'p', 'q', 'r',
        // 's', 't', 'u',
        // 'v', 'w'
        0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF // 'x', 'y', 'z',
        // '{', '|', '}',
        // '~', 'DEL'
    )

    /**
     * Decodes the given Base32 String to a raw byte array.
     *
     * @param base32
     * @return Decoded `base32` String as a raw byte array.
     */
    fun decode(base32: String): ByteArray {
        var index: Int
        var lookup: Int
        var digit: Int
        val bytes = ByteArray(base32.length * 5 / 8)
        var i = 0
        index = 0
        var offset = 0
        while (i < base32.length) {
            lookup = base32[i].code - '0'.code
            /* Skip chars outside the lookup table */if (lookup < 0 || lookup >= base32Lookup.size) {
                i++
                continue
            }
            digit = base32Lookup[lookup]
            /* If this digit is not in the table, ignore it */if (digit == 0xFF) {
                i++
                continue
            }
            if (index <= 3) {
                index = (index + 5) % 8
                if (index == 0) {
                    bytes[offset] = (bytes[offset].toInt() or digit).toByte()
                    offset++
                    if (offset >= bytes.size) break
                } else {
                    bytes[offset] = (bytes[offset].toInt() or (digit shl 8 - index)).toByte()
                }
            } else {
                index = (index + 5) % 8
                bytes[offset] = (bytes[offset].toInt() or (digit ushr index)).toByte()
                offset++
                if (offset >= bytes.size) {
                    break
                }
                bytes[offset] = (bytes[offset].toInt() or (digit shl 8 - index)).toByte()
            }
            i++
        }
        return bytes
    }
}


fun totp(secret: String){
    val t = Instant.now().epochSecond / 30
    val hotp = HOTP()

    println(hotp.getCode(Base32.decode(secret), t, 6))
}

fun main() {
    totp("I65VU7K5ZQL7WB4E")
}