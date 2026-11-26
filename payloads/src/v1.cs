// v1 — v0 + STRING ENCODING: writes the sample still encoded (XOR+Base64) to disk.
// Measures: does string encoding get past the static scan? (differs from v0 only by the encoding)
using System.IO;

namespace Payload
{
    class V1
    {
        static void Main()
        {
            string path = Path.Combine(Common.ExeDir(), "sample_v1.bin");
            File.WriteAllBytes(path, Common.Encoded());   // keep ENCODED
            Common.Marker("v1", "wrote ENCODED sample -> " + path);
        }
    }
}
