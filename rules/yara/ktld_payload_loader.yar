/*
 * KTLT-Defender supplementary rule (M11) — YARA
 * Closes an Axis-A memory-layer gap: variant v3 (in-memory / fileless) was NOT detected, because the
 * decoded sample never touches disk. The on-disk artifact in that case is the LOADER binary itself —
 * a .NET executable that carries the encoded blob and a XOR+Base64 decode routine. This rule detects
 * that loader on disk, so the fileless variant is still catchable by its dropper.
 *
 * It also matches v0/v1/v2 loaders (same family). Uses only the already-obfuscated Base64 constant and
 * ordinary .NET API/type strings, so the rule file stays AV-clean.
 *
 * MITRE ATT&CK: T1027 (Obfuscated Files or Information), T1620 (Reflective/in-memory loading)
 */

rule KTLD_Payload_Loader_Binary
{
    meta:
        author          = "KTLT Defender (Academy of Cryptography Techniques)"
        description     = "KTLT-Defender C# payload loader (v0-v3): embedded encoded blob + XOR/Base64 decode; catches the fileless v3 variant by its dropper"
        reference       = "KTLT-Defender; MITRE ATT&CK T1027, T1620"
        technique_id    = "T1027,T1620"
        gap             = "v3 in-memory loader -> not_detected by Defender static/RTP"
        version         = "1.0"
        date            = "2026-11-27"

    strings:
        // The encoded EICAR blob is stored as a .NET string literal (UTF-16 in the PE), hence 'wide'.
        $enc_b64   = "Am8Vewp/GhsKAW4GCgACb25yCgRzbRkZc20nfh8TGRsIdwkOGxQeGwgedxsUDhMMEwgPCXcOHwkOdxwTFh97fhJxEnA=" ascii wide
        $api_b64   = "FromBase64String" ascii wide
        $marker    = "VARIANT=v" ascii wide
        $ns        = "Payload" ascii wide

    condition:
        // Windows PE (MZ) that embeds the encoded blob and the decode API; markers raise confidence.
        uint16(0) == 0x5A4D and $enc_b64 and $api_b64 and ($marker or $ns)
}
