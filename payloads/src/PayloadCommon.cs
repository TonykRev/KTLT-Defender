// PayloadCommon.cs — shared helper for v0..v3 (Owner: Opus).
// EICAR is stored ENCODED (XOR 0x5A + Base64). The repo & binaries do NOT contain the raw EICAR string
// => cloning the repo does not trigger AV alerts; compiling the .exe is safe on the dev machine.
// Only RUNNING v0/v2 writes the raw EICAR to disk -> that is the measurement.
using System;
using System.IO;
using System.Reflection;

namespace Payload
{
    static class Common
    {
        // XOR(0x5A)+Base64 of the standard EICAR test string (harmless). Generated in Python, round-trip verified.
        public const string ENC = "Am8Vewp/GhsKAW4GCgACb25yCgRzbRkZc20nfh8TGRsIdwkOGxQeGwgedxsUDhMMEwgPCXcOHwkOdxwTFh97fhJxEnA=";
        public const byte KEY = 0x5A;

        public static byte[] Encoded()
        {
            return Convert.FromBase64String(ENC);
        }

        public static byte[] Decoded()
        {
            byte[] e = Encoded();
            byte[] d = new byte[e.Length];
            for (int i = 0; i < e.Length; i++) d[i] = (byte)(e[i] ^ KEY);
            return d;   // = raw EICAR string, exists only at runtime
        }

        public static string ExeDir()
        {
            return Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        }

        public static void Marker(string variant, string note)
        {
            Console.WriteLine("VARIANT=" + variant + " " + note);
        }
    }
}
