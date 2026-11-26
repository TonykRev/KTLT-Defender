// v2 — v1 + THỰC THI TỪ ĐĨA: giải mã trong RAM -> ghi RAW ra đĩa -> đọc lại (thực thi từ đĩa).
// Đo: việc giải mã rồi ghi xuống đĩa có kích hoạt quét tĩnh/RTP không?
// LƯU Ý: thả file EICAR thô -> Defender RTP cách ly (đúng là phép đo).
using System.IO;

namespace Payload
{
    class V2
    {
        static void Main()
        {
            string path = Path.Combine(Common.ExeDir(), "sample_v2.bin");
            byte[] d = Common.Decoded();              // giải mã trong RAM
            File.WriteAllBytes(path, d);              // ghi RAW ra đĩa
            byte[] back = File.ReadAllBytes(path);    // "thực thi từ đĩa" (benign: đọc lại)
            Common.Marker("v2", "decoded->disk->read " + back.Length + "B -> " + path);
        }
    }
}
