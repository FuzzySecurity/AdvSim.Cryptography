using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography.Asymmetric.Extensions
{
    public static class RSAParameterExtensions
    {
        /// <summary>
        /// Return the byte representation of a given RSAParameters object.
        /// </summary>
        /// <param name="key">RSAParameters object to retrieve key bytes from.</param>
        /// <returns>Byte array representation of the RSAParameters object.</returns>
        public static byte[] GetBytes(this RSAParameters key)
        {
            using (StringWriter sw = new StringWriter())
            {
                new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters)).Serialize(sw, key);
                return System.Text.Encoding.UTF8.GetBytes(sw.ToString());
            }
        }
    }
}
