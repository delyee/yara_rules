import "elf"

private rule IsELF
{
     condition:
         elf.entry_point
}

private rule IsPHP
 {
     strings:
         $ = "<?" nocase fullword
     condition:
         all of them
 }

