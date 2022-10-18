using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography.Miscellaneous
{
    /// <summary>
    /// One time passcode generator object.
    /// </summary>
    public class TOTP
    {
        public UInt32 Seconds;
        public UInt32 Code;
        public UInt32 LastCode;

        /// <summary>
        /// Create a TOTP object that derives codes based on the provided seed.
        /// </summary>
        /// <param name="seed">Seed used in code derivation.</param>
        public TOTP(string seed)
        {
            // Get DatTime
            DateTime dtNow = DateTime.UtcNow;
            Seconds = (UInt32)(60 - dtNow.Second);

            // Subtract seconds from current time
            dtNow = dtNow.AddSeconds(-dtNow.Second);

            // -= Get Current TOTP Code =-

            // Init HMAC with DateTime key & compute hash with seed value
            HMACSHA256 hmac = new HMACSHA256(
                Encoding.ASCII.GetBytes(dtNow.ToString(CultureInfo.InvariantCulture)));
            Byte[] bHash = hmac.ComputeHash(Encoding.ASCII.GetBytes(seed));

            // Get TOTP
            UInt32 iOffset = (UInt32)bHash[bHash.Length - 1] & 0xF;
            Code = (UInt32)((bHash[iOffset] & 0x7F) << 24 | (bHash[iOffset + 1] & 0xFF) << 16 | (bHash[iOffset + 2] & 0xFF) << 8 | (bHash[iOffset + 3] & 0xFF) % 1000000);

            // -= Get Last TOTP Code =-

            // Subtract 1 minute
            dtNow = dtNow.AddSeconds(-60);

            // Init HMAC with DateTime key & compute hash with seed value
            hmac = new HMACSHA256(Encoding.ASCII.GetBytes(dtNow.ToString(CultureInfo.InvariantCulture)));
            bHash = hmac.ComputeHash(Encoding.ASCII.GetBytes(seed));

            // Get TOTP
            iOffset = (UInt32)bHash[bHash.Length - 1] & 0xF;
            LastCode = (UInt32)((bHash[iOffset] & 0x7F) << 24 | (bHash[iOffset + 1] & 0xFF) << 16 | (bHash[iOffset + 2] & 0xFF) << 8 | (bHash[iOffset + 3] & 0xFF) % 1000000);
        }

        /// <summary>
        /// Validate that a given code is valid for this instance of TOTP.
        /// </summary>
        /// <param name="code">Code to validate.</param>
        /// <param name="allowLastCode">
        /// If true, allow code to be valid if it matches the current or last code.
        /// Otherwise, match only the current code.</param>
        /// <returns></returns>
        public bool Validate(UInt32 code, bool allowLastCode = false)
        {
            // Check if code is valid
            if (this.Code == code || (allowLastCode && this.LastCode == code))
            {
                return true;
            }

            return false;
        }
    }
}
