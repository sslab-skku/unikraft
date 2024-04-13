SECTIONS
{
	.isr_text :
	{
		*.isr.o (.text .text*)
	}
}
INSERT AFTER .text;

SECTIONS
{
	.isr_rodata :
	{
		*.isr.o (.rodata .rodata*)
	}
}
INSERT AFTER .rodata;

SECTIONS
{
	.isr_data :
	{
		*.isr.o (.data .data*)
	}
}
INSERT AFTER .data;

SECTIONS
{
	.isr_bss :
	{
		*.isr.o (.bss .bss*)
	}
}
INSERT BEFORE .bss;
