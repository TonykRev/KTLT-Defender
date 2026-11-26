// v3 — v1 + IN-MEMORY EXECUTION: decode and keep it ONLY in RAM, never touching disk.
// Measures: does running in-memory evade the static scan/RTP? Does AMSI catch it?
using System.IO;

namespace Payload
{
    class V3
    {
        static void Main()
        {
            byte[] d = Common.Decoded();              // decode, only in RAM
            using (MemoryStream ms = new MemoryStream(d))
            {
                int len = (int)ms.Length;             // "in-memory execution" (benign)
                Common.Marker("v3", "decoded in-memory only (" + len + "B), no disk write");
            }
        }
    }
}
