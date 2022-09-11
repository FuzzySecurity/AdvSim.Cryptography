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
