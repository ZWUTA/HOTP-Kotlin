import java.time.Instant
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

class TOTP {
    private fun hmacSHA1Encode(secret: ByteArray, counter: ByteArray): ByteArray {
        val secretKeySpec = SecretKeySpec(secret, "HmacSHA1") // Useless GetBytes

        val mac = Mac.getInstance("HmacSHA1")
        mac.init(secretKeySpec)
        return mac.doFinal(counter)
    }

    private fun getCode(secret: ByteArray, counter: Long): String {
        val counterData: ByteArray = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0)
        var counterChangeable = counter
        for (i in 7 downTo 0){
            counterData[i] = (counterChangeable and 0xFF).toByte()

            counterChangeable = counterChangeable shr 8
        }

        val hs = hmacSHA1Encode(secret, counterData)

        val offset = hs[hs.size - 1].toInt() and 0x0F
        val code = (hs[offset].toInt() and 0x7F shl 24) or
                (hs[offset + 1].toInt() and 0xFF shl 16) or
                (hs[offset + 2].toInt() and 0xFF shl 8) or
                (hs[offset + 3].toInt() and 0xFF)

        val hotp = code % 10.0.pow(6).toInt()

        return "%0${6}d".format(hotp)
    }

    fun generateCode(secret: String){
        val t = Instant.now().epochSecond / 30
        val totp = TOTP()

        println(totp.getCode(Base32.decode(secret), t))
    }
}