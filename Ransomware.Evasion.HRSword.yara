import "pe"

rule HRSword {

	meta:
		author = "@jxd_io"
		date = "2021-08-15"
		description = "Detects HRSword used in recent Ransomware Campaigns, e.g. Ragnarok or LockBit to deactivate AV and system logging"

	strings:
		$LogFile = "hrlog.txt" nocase ascii
		$Mutex = "hr_sysdiag_gui" nocase ascii
		$LoadReplaceDestroyIcon = {68EA000000FF35??????00C745FC00000000FF15????54008BD8536AFFFFB7E4090000FF1564??540053FF15????5400}
		
	condition:
		uint16(0) == 0x5a4d and filesize < 4MB and pe.imports("uactmon.dll") and
		
		for any i in (0 .. pe.number_of_signatures): (
			pe.signatures[i].subject contains "HuoRongBoRui (Beijing) Technology" or
			pe.signatures[i].subject contains "Beijing Huorong Network Technology" or
			pe.signatures[i].subject contains "BaseTruck Security"
		)
		
		and all of them
}
