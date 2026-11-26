// v1 — v0 + MÃ HOÁ CHUỖI: ghi mẫu vẫn ở dạng mã hoá (XOR+Base64) ra đĩa.
// Đo: mã hoá chuỗi có qua được quét tĩnh không? (so với v0 chỉ khác đúng việc mã hoá)
using System.IO;

namespace Payload
{
    class V1
    {
        static void Main()
        {
            string path = Path.Combine(Common.ExeDir(), "sample_v1.bin");
            File.WriteAllBytes(path, Common.Encoded());   // giữ MÃ HOÁ
            Common.Marker("v1", "wrote ENCODED sample -> " + path);
        }
    }
}
