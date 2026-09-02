rule eicar_test_file {
    meta:
        description = "EICAR antivirus test file"
        author = "lab"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

rule php_webshell_generic {
    meta:
        description = "Generic PHP webshell indicators"
        author = "lab"
        mitre = "T1505.003"
    strings:
        $php = "<?php"
        $s1  = "system($_GET"
        $s2  = "system($_POST"
        $s3  = "eval($_POST"
        $s4  = "eval($_REQUEST"
        $s5  = "shell_exec($_"
        $s6  = "passthru($_"
        $s7  = "base64_decode($_"
        $s8  = "assert($_"
    condition:
        $php and any of ($s*)
}
