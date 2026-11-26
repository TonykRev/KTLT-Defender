// v2 — v1 + DISK EXECUTION: decode in RAM -> write RAW to disk -> read it back (disk execution).
// Measures: does decoding then writing to disk trigger the static scan/RTP?
// NOTE: drops the raw EICAR file -> Defender RTP quarantines it (that is the measurement).
using System.IO;

namespace Payload
{
    class V2
    {
        static void Main()
        {
            string path = Path.Combine(Common.ExeDir(), "sample_v2.bin");
            byte[] d = Common.Decoded();              // decode in RAM
            File.WriteAllBytes(path, d);              // write RAW to disk
            byte[] back = File.ReadAllBytes(path);    // "disk execution" (benign: read back)
            Common.Marker("v2", "decoded->disk->read " + back.Length + "B -> " + path);
        }
    }
}
