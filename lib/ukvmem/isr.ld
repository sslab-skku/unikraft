SECTIONS
{
	.isr_text :
	{
		*.isr.o (.text .text*)
	}
}
INSERT AFTER .text;
