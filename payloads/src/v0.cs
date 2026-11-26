// v0 — BARE SAMPLE: writes the RAW sample (not obfuscated) to disk.
// Measures the STATIC/signature layer: does Defender catch an exposed sample immediately?
// NOTE: running v0 drops the raw EICAR file -> Defender RTP quarantines it (that is the measurement).
using System.IO;

namespace Payload
{
    class V0
    {
        static void Main()
        {
            string path = Path.Combine(Common.ExeDir(), "sample_v0.bin");
            File.WriteAllBytes(path, Common.Decoded());   // RAW, exposed
            Common.Marker("v0", "wrote RAW sample -> " + path);
        }
    }
}
