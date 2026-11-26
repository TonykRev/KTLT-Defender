// v0 — MẪU TRẦN: ghi mẫu RAW (không obfuscate) ra đĩa.
// Đo tầng TĨNH/chữ ký: Defender có bắt mẫu lộ rõ ngay không?
// LƯU Ý: chạy v0 sẽ thả file EICAR thô -> Defender RTP cách ly (đúng là phép đo).
using System.IO;

namespace Payload
{
    class V0
    {
        static void Main()
        {
            string path = Path.Combine(Common.ExeDir(), "sample_v0.bin");
            File.WriteAllBytes(path, Common.Decoded());   // RAW, lộ rõ
            Common.Marker("v0", "wrote RAW sample -> " + path);
        }
    }
}
