rule granite_coroner_dropper {
    meta:
        description = "Payload dropper for password theft or keylogging"

    strings:
        $mz = "MZ"

        // 5222D4EE744464B154505E68579EB896 - Resource names
        $granitea = "GRANITE" nocase
        $granitew = "GRANITE" nocase wide
        $jocastaeluviuma = "JOCASTAELUVIUM" nocase
        $jocastaeluviumw = "JOCASTAELUVIUM" nocase wide

        // FA620D788F4E9B22B603276EB020AA8C - Resource names
        $coronera = "CORONER" nocase
        $coronerw = "CORONER" nocase wide
        $bolshiecharitya = "BOLSHIECHARITY" nocase
        $bolshiecharityw = "BOLSHIECHARITY" nocase wide

        // Both
        $cypher_cryptor = "Cypher Cryptor" wide

    condition:
        $mz at 0 and 
            ($granitea and $jocastaeluviuma) or
            ($granitew and $jocastaeluviumw) or
            ($coronera and $bolshiecharitya) or
            ($coronerw and $bolshiecharityw) or
        $cypher_cryptor
}