rule SquirrelWaffle {
  meta:
    author = "@jxd_io"
    description = "Detects SquirrelWaffle Loader"
    date = "2021-09-23"

  strings:
    $config_decryption = {F77530837D1C108D4D088D4520C645CC000F434D08837D34100F4345208A04103204398D4DCC0FB6C0}

  condition:
    uint16(0) == 0x5a4d and filesize < 1MB and all of them
}
