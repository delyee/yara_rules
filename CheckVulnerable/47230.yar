// webmin-1.920/proc/module.info
// webmin-1.920/init/module.info
// webmin-1.920/acl/module.info

private rule proc_module_info: CheckVulnerable
{
    strings:
        $ = { 6c 6f 6e 67 64 65 73 63 3d 4c 69 73 74 2c 20 6b 69 6c 6c 20 61 6e 64 20 72 65 6e 69 63 65 20 72 75 6e 6e 69 6e 67 20 70 72 6f 63 65 73 73 65 73 20 6f 6e 20 79 6f 75 72 20 73 79 73 74 65 6d 2e } // "longdesc=List, kill and renice running processes on your system."
        $ = { 64 65 70 65 6e 64 73 3d 6d 6f 75 6e 74 20 31 2e 39 32 30 } // "depends=mount 1.920"
    condition:
        all of them
}

private rule init_module_info: CheckVulnerable
{
    strings:
        $ = { 6c 6f 6e 67 64 65 73 63 3d 53 65 74 75 70 20 73 63 72 69 70 74 73 20 74 6f 20 62 65 20 72 75 6e 20 61 74 20 62 6f 6f 74 20 74 69 6d 65 20 66 72 6f 6d 20 2f 65 74 63 2f 69 6e 69 74 2e 64 20 6f 72 20 2f 65 74 63 2f 72 63 2e 6c 6f 63 61 6c 2e } // "longdesc=Setup scripts to be run at boot time from /etc/init.d or /etc/rc.local."
        $ = { 64 65 70 65 6e 64 73 3d 70 72 6f 63 20 69 6e 69 74 74 61 62 20 31 2e 39 32 30 } // "depends=proc inittab 1.920"
    condition:
        all of them
}

private rule acl_module_info: CheckVulnerable
{
    strings:
        $ = { 6c 6f 6e 67 64 65 73 63 3d 43 72 65 61 74 65 20 57 65 62 6d 69 6e 20 75 73 65 72 73 20 61 6e 64 20 63 6f 6e 66 69 67 75 72 65 20 77 68 69 63 68 20 6d 6f 64 75 6c 65 73 20 61 6e 64 20 66 65 61 74 75 72 65 73 20 74 68 65 79 20 61 72 65 20 61 6c 6c 6f 77 65 64 20 74 6f 20 61 63 63 65 73 73 2e } // "longdesc=Create Webmin users and configure which modules and features they are allowed to access."
        $ = { 64 65 70 65 6e 64 73 3d 31 2e 39 32 30 } // "depends=1.920"
    condition:
        all of them
}


rule CheckVulnerable_Webmin_EDB47230: CheckVulnerable Webmin EDB47230
{
    meta:
        description = "Unauthenticated RCE CVE-2019-15107"
        author = "delyee"
        date = "01-12-2020"
    strings:
    	$version = { 76 65 72 73 69 6f 6e 3d 31 2e 39 32 30 } // "version=1.920"
    condition:
        $version and (proc_module_info or init_module_info or acl_module_info)
}


