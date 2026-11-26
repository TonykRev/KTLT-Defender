// PayloadCommon.cs — helper dùng chung cho v0..v3 (Chủ: Opus).
// EICAR được lưu DẠNG MÃ HOÁ (XOR 0x5A + Base64). Repo & binary KHÔNG chứa chuỗi EICAR thô
// => clone repo không bị AV báo động; biên dịch .exe an toàn trên máy dev.
// Chỉ khi CHẠY v0/v2 mới ghi EICAR thô ra đĩa -> đó chính là phép đo.
using System;
using System.IO;
using System.Reflection;

namespace Payload
{
    static class Common
    {
        // XOR(0x5A)+Base64 của chuỗi test chuẩn EICAR (vô hại). Sinh bằng Python, round-trip đã kiểm.
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
            return d;   // = chuỗi EICAR thô, chỉ tồn tại lúc chạy
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
