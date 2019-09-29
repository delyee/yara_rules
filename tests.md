### directories
```
>> for i in `find . -type d`; do du -sh $i; done
13G	.
6.6G	./uploads.18.09.2019
5.4G	./uploads
4.6M	./token_uploads
```

### files:
```
>> find . -type f -name '*.php' | wc -l
1625131
```

### clamav (total: 72)
```
----------- SCAN SUMMARY -----------
Known viruses: 6339198
Engine version: 0.100.3
Scanned directories: 4
Scanned files: 1620532
Infected files: 72
Data scanned: 7642.56 MB
Data read: 6687.89 MB (ratio 1.14:1)
Time: 11257.514 sec (187 m 37 s)
```

### yara (total: 94)
```
real    25m21.543s
user    2m44.678s
sys     3m16.950s

rules stats:
  [61] Generic_Eval
  [16] ZeroArray_Obfuscated
  [8]  i0_php_backdoor
  [7]  other_wso_php_shell
  [1]  Generic_v2
  [1]  FOPO_Obfuscated
```

### result: for a successful detection, it is not even necessary to use a bulky clamav/etc. A few self-written and public rules will suffice.
