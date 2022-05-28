import "elf"

private rule IsELF
{
     condition:
         elf.entry_point
}

private rule IsPHP
 {
     strings:
         $ = "<?" fullword
     condition:
         all of them
 }

