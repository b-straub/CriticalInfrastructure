SECTIONS {
  .rodata_desc : ALIGN(4)
  {
    KEEP(*(.rodata.desc))
  } > RODATA
}
INSERT BEFORE .rodata;
