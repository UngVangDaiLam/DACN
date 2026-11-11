// Indicators of techniques, not malware signatures or family attribution.
rule DEX_Dynamic_Load_Reflection {
    meta:
        title = "DEX chứa chỉ báo nạp mã động và reflection"
        severity = "low"
        technique = "dynamic_dex"
    strings:
        $loader1 = "Ldalvik/system/DexClassLoader;" ascii
        $loader2 = "Ldalvik/system/InMemoryDexClassLoader;" ascii
        $reflection = "Ljava/lang/reflect/Method;" ascii
    condition:
        uint32(0) == 0x0a786564 and 1 of ($loader*) and $reflection
}

rule DEX_Cipher_Base64 {
    meta:
        title = "DEX chứa API mã hóa và Base64"
        severity = "info"
        technique = "encoded_string"
    strings:
        $cipher = "Ljavax/crypto/Cipher;" ascii
        $base64a = "Landroid/util/Base64;" ascii
        $base64b = "Ljava/util/Base64" ascii
    condition:
        uint32(0) == 0x0a786564 and $cipher and 1 of ($base64*)
}

rule Native_Dynamic_Linker {
    meta:
        title = "Thư viện native có chỉ báo liên kết động"
        severity = "info"
        technique = "native_loading"
    strings:
        $open = "dlopen" ascii
        $symbol = "dlsym" ascii
    condition:
        uint32(0) == 0x464c457f and $open and $symbol
}

rule Native_DEX_Loader {
    meta:
        title = "Thư viện native chứa chỉ báo nạp DEX"
        severity = "low"
        technique = "dynamic_dex"
    strings:
        $dex1 = "DexClassLoader" ascii
        $dex2 = "InMemoryDexClassLoader" ascii
        $dex3 = "DexFile" ascii
        $jni = "JNI_OnLoad" ascii
    condition:
        uint32(0) == 0x464c457f and $jni and 1 of ($dex*)
}
