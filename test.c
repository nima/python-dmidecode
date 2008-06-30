#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "version.h"
#include "config.h"
#include "types.h"
#include "util.h"
#include "dmidecode.h"
#include "dmiopt.h"
#include "dmioem.h"

#define EFI_NOT_FOUND   (-1)
#define EFI_NO_SMBIOS   (-2)

#include <Python.h>
#include "catsprintf.h"
#include "global.h"

extern void dmi_dump(struct dmi_header *h, const char *prefix);
extern void dmi_decode(struct dmi_header *h, u16 ver);
extern int address_from_efi(size_t *address);
extern void to_dmi_header(struct dmi_header *h, u8 *data);
extern void dmi_table(u32 base, u16 len, u16 num, u16 ver, const char *devmem);
extern int smbios_decode(u8 *buf, const char *devmem);
extern int legacy_decode(u8 *buf, const char *devmem);



int main(int argc, char * const argv[])
{
        bzero(buffer, 50000);

	int ret=0;                  /* Returned value */
	int found=0;
	size_t fp;
	int efi;
	u8 *buf;

	if(sizeof(u8)!=1 || sizeof(u16)!=2 || sizeof(u32)!=4 || '\0'!=0)
	{
		fprintf(stderr, "%s: compiler incompatibility\n", argv[0]);
		exit(255);
	}

	/* Set default option values */
	opt.devmem=DEFAULT_MEM_DEV;
	opt.flags=0;

	if(parse_command_line(argc, argv)<0)
	{
		ret=2;
		goto exit_free;
	}

	if(opt.flags & FLAG_HELP)
	{
		print_help();
		goto exit_free;
	}

	if(opt.flags & FLAG_VERSION)
	{
		printf("%s\n", VERSION);
		goto exit_free;
	}

	if(!(opt.flags & FLAG_QUIET))
		printf("# dmidecode %s\n", VERSION);

	/* First try EFI (ia64, Intel-based Mac) */
	efi=address_from_efi(&fp);
	switch(efi)
	{
		case EFI_NOT_FOUND:
			goto memory_scan;
		case EFI_NO_SMBIOS:
			ret=1;
			goto exit_free;
	}

	if((buf=mem_chunk(fp, 0x20, opt.devmem))==NULL)
	{
		ret=1;
		goto exit_free;
	}

	if(smbios_decode(buf, opt.devmem))
		found++;
	goto done;

memory_scan:
	/* Fallback to memory scan (x86, x86_64) */
	if((buf=mem_chunk(0xF0000, 0x10000, opt.devmem))==NULL)
	{
		ret=1;
		goto exit_free;
	}

	for(fp=0; fp<=0xFFF0; fp+=16)
	{
		if(memcmp(buf+fp, "_SM_", 4)==0 && fp<=0xFFE0)
		{
			if(smbios_decode(buf+fp, opt.devmem))
				found++;
			fp+=16;
		}
		else if(memcmp(buf+fp, "_DMI_", 5)==0)
		{
			if (legacy_decode(buf+fp, opt.devmem))
				found++;
		}
	}

done:
	free(buf);

	if(!found && !(opt.flags & FLAG_QUIET))
		printf("# No SMBIOS nor DMI entry point found, sorry.\n");

exit_free:
	free(opt.type);

        printf("%s\n", buffer);
	return ret;
}
