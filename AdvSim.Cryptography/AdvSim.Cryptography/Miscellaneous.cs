using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography
{
    public class Miscellaneous
    {
        // Misc Data types
        //============================

        /// <summary>
        /// TOTP object containing properties of the TOTP generator.
        /// </summary>
        public class TOTP
        {
            public UInt32 Seconds;
            public UInt32 Code;
            public UInt32 LastCode;
        }

        // Misc functions
        //============================

        /// <summary>
        /// Generate TOTP object based on manipulating a HMACSHA256 value seeded with UtcNow and a string based seed.
        /// </summary>
        /// <param name="sSeed">String seed used to generate pseudo-random HMACSHA256 value.</param>
        /// <returns>TOTP</returns>
        public static TOTP generateTOTP(String sSeed)
        {
            // Create return object
            TOTP oTOTP = new TOTP();

            // Get DatTime
            DateTime dtNow = DateTime.UtcNow;
            oTOTP.Seconds = (UInt32)(60 - dtNow.Second);

            // Subtract seconds from current time
            dtNow = dtNow.AddSeconds(-dtNow.Second);

            // -= Get Current TOTP Code =-

            // Init HMAC with DateTime key & compute hash with seed value
            HMACSHA256 hmac = new HMACSHA256(Encoding.ASCII.GetBytes(dtNow.ToString(CultureInfo.InvariantCulture)));
            Byte[] bHash = hmac.ComputeHash(Encoding.ASCII.GetBytes(sSeed));

            // Get TOTP
            UInt32 iOffset = (UInt32)bHash[bHash.Length - 1] & 0xF;
            oTOTP.Code = (UInt32)((bHash[iOffset] & 0x7F) << 24 | (bHash[iOffset + 1] & 0xFF) << 16 | (bHash[iOffset + 2] & 0xFF) << 8 | (bHash[iOffset + 3] & 0xFF) % 1000000);

            // -= Get Last TOTP Code =-

            // Subtract 1 minute
            dtNow = dtNow.AddSeconds(-60);

            // Init HMAC with DateTime key & compute hash with seed value
            hmac = new HMACSHA256(Encoding.ASCII.GetBytes(dtNow.ToString(CultureInfo.InvariantCulture)));
            bHash = hmac.ComputeHash(Encoding.ASCII.GetBytes(sSeed));

            // Get TOTP
            iOffset = (UInt32)bHash[bHash.Length - 1] & 0xF;
            oTOTP.LastCode = (UInt32)((bHash[iOffset] & 0x7F) << 24 | (bHash[iOffset + 1] & 0xFF) << 16 | (bHash[iOffset + 2] & 0xFF) << 8 | (bHash[iOffset + 3] & 0xFF) % 1000000);

            // Return TOTP
            return oTOTP;
        }

        /// <summary>
        /// Validate TOTP code by manipulating a HMACSHA256 value seeded with UtcNow and a string based seed.
        /// </summary>
        /// <param name="sSeed">String seed used to generate pseudo-random HMACSHA256 value.</param>
        /// <param name="iCode">TOTP integer to validate.</param>
        /// <param name="bAllowLastCode">Allows the previous TOTP code to also be valid.</param>
        /// <returns>TOTP</returns>
        public static Boolean validateTOTP(String sSeed, UInt32 iCode, Boolean bAllowLastCode = false)
        {
            // Get TOTP
            TOTP oTOTP = generateTOTP(sSeed);

            // Check if code is valid
            if (oTOTP.Code == iCode || (bAllowLastCode && oTOTP.LastCode == iCode))
            {
                return true;
            }

            return false;
        }
    }
}