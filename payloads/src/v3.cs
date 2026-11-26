// v3 — v1 + THỰC THI TỪ BỘ NHỚ: giải mã và CHỈ giữ trong RAM, KHÔNG chạm đĩa.
// Đo: chạy in-memory có né được quét tĩnh/RTP không? AMSI có bắt không?
using System.IO;

namespace Payload
{
    class V3
    {
        static void Main()
        {
            byte[] d = Common.Decoded();              // giải mã, chỉ trong RAM
            using (MemoryStream ms = new MemoryStream(d))
            {
                int len = (int)ms.Length;             // "thực thi từ bộ nhớ" (benign)
                Common.Marker("v3", "decoded in-memory only (" + len + "B), no disk write");
            }
        }
    }
}
