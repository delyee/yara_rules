import "elf"

private rule IsELF
{
     condition:
         elf.entry_point
}

private rule IsPHP
 {
     strings:
         $ = "<?" nocase
     condition:
         all of them
 }

