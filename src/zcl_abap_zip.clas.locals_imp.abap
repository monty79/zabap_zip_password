*"* use this source file for the definition and implementation of
*"* local helper classes, interface definitions and type
*"* declarations
CLASS lcl_msdos DEFINITION FINAL.
  PUBLIC SECTION.
    CLASS-METHODS: to_date IMPORTING  iv_date TYPE d RETURNING VALUE(rv_msdos_date) TYPE i.
    CLASS-METHODS: to_time IMPORTING  iv_time TYPE t RETURNING VALUE(rv_msdos_time) TYPE i.
    CLASS-METHODS: from_date IMPORTING iv_msdos_date TYPE i RETURNING VALUE(rv_date)       TYPE d.
    CLASS-METHODS: from_time IMPORTING iv_msdos_time TYPE i RETURNING VALUE(rv_time)       TYPE t.
ENDCLASS.

CLASS lcl_msdos IMPLEMENTATION.


METHOD from_date. " IMPORTING msdos_date TYPE i RETURNING value(date) TYPE d

*   MS-DOS format for date:
*     Bits 15:9 = year - 1980
*     Bits 8:5 = month of year
*     Bits 4:0 = day of month

  CONSTANTS: lc_mFE00(2) TYPE x VALUE 'FE00',
             lc_m01E0(2) TYPE x VALUE '01E0',
             lc_m007F(2) TYPE x VALUE '007F',
             lc_m001F(2) TYPE x VALUE '001F',
             lc_m000F(2) TYPE x VALUE '000F'.

  DATA: lv_x(2)  TYPE x,
        lv_year  TYPE i,
        lv_month TYPE i,
        lv_day   TYPE i,
        lv_c4(4) TYPE c,
        lv_str   TYPE string.

*   Bits 15:9 = year - 1980
  lv_x     = iv_msdos_date.
  lv_x     = lv_x BIT-AND lc_mFE00.
  lv_x     = lv_x DIV 512. " >> 9
  lv_x     = lv_x BIT-AND lc_m007F.
  lv_year  = lv_x.
  lv_year  = lv_year + 1980.
  WRITE lv_year TO lv_c4 USING EDIT MASK 'RR____'.
  CONCATENATE lv_str lv_c4 INTO lv_str.

*     Bits 8:5 = month of year
  lv_x     = iv_msdos_date.
  lv_x     = lv_x BIT-AND lc_m01E0.
  lv_x     = lv_x DIV 32. " >> 5
  lv_x     = lv_x BIT-AND lc_m000F.
  lv_month = lv_x.
  WRITE lv_month TO lv_c4 USING EDIT MASK 'RR__'.
  CONCATENATE lv_str lv_c4 INTO lv_str.

*     Bits 4:0 = day of month
  lv_x     = iv_msdos_date.
  lv_x     = lv_x BIT-AND lc_m001F.
  lv_day   = lv_x.
  WRITE lv_day TO lv_c4 USING EDIT MASK 'RR__'.
  CONCATENATE lv_str lv_c4 INTO lv_str.

*   Build date
  TRANSLATE lv_str USING ' 0'.
  rv_date = lv_str.

ENDMETHOD.


METHOD from_time. " IMPORTING msdos_time TYPE i RETURNING value(time) TYPE t.

*   MS-DOS format for time:
*     Bits 15:11 = hour   (24-hour clock)
*     Bits 10:5 = minute
*     Bits 4:0 = second/2

  CONSTANTS: lc_mF100(2) TYPE x VALUE 'F100',
             lc_m07E0(2) TYPE x VALUE '07E0',
             lc_m003F(2) TYPE x VALUE '003F',
             lc_m001F(2) TYPE x VALUE '001F'.

  DATA: lv_x(2)  TYPE x,
        lv_hour  TYPE i,
        lv_min   TYPE i,
        lv_c4(4) TYPE c,
        lv_str   TYPE string.

*   Bits 15:11 = hour (24-hour clock)
  lv_x     = iv_msdos_time.
  lv_x     = lv_x BIT-AND lc_mF100.
  lv_x     = lv_x DIV 2048. " >> 11
  lv_x     = lv_x BIT-AND lc_m001F.
  lv_hour  = lv_x.
  WRITE lv_hour TO lv_c4 USING EDIT MASK 'RR__'.
  CONCATENATE lv_str lv_c4 INTO lv_str.

*   Bits 10:5 = minute
  lv_x     = iv_msdos_time.
  lv_x     = lv_x BIT-AND lc_m07E0.
  lv_x     = lv_x DIV 32. " >> 5
  lv_x     = lv_x BIT-AND lc_m003F.
  lv_min   = lv_x.
  WRITE lv_min TO lv_c4 USING EDIT MASK 'RR__'.
  CONCATENATE lv_str lv_c4 INTO lv_str.

*   Bits 4:0 = second/2
  CONCATENATE lv_str '00' INTO lv_str.

*   Build time
  TRANSLATE lv_str USING ' 0'.
  rv_time = lv_str.

ENDMETHOD.


METHOD to_date. " IMPORTING date TYPE d RETURNING value(msdos_date) TYPE i.

*   MS-DOS format for date:
*     Bits 15:9 = year - 1980
*     Bits 8:5 = month of year
*     Bits 4:0 = day of month

  DATA: lv_xdate(2) TYPE x,
        lv_x(2)     TYPE x,
        lv_year     TYPE i,
        lv_month    TYPE i,
        lv_day      TYPE i.

*   Bits 15:9 = year - 1980
  lv_year  = iv_date+0(4).
  lv_x     = lv_year - 1980.
  lv_x     = lv_x * 512. " << 9
  lv_xdate = lv_xdate BIT-OR lv_x.

*   Bits 8:5 = month of year
  lv_month = iv_date+4(2).
  lv_x     = lv_month.
  lv_x     = lv_x * 32. " << 5
  lv_xdate = lv_xdate BIT-OR lv_x.

*   Bits 4:0 = day of month
  lv_day   = iv_date+6(2).
  lv_x     = lv_day.
  lv_xdate = lv_xdate BIT-OR lv_x.

  rv_msdos_date = lv_xdate.

ENDMETHOD.


METHOD to_time. " IMPORTING time TYPE t RETURNING value(msdos_time) TYPE i.

*   MS-DOS format for time:
*     Bits 15:11 = hour   (24-hour clock)
*     Bits 10:5 = minute
*     Bits 4:0 = second/2

  DATA: lv_xtime(2) TYPE x,
        lv_x(2)     TYPE x,
        lv_hour     TYPE i,
        lv_min      TYPE i,
        lv_sec      TYPE i.

*   Bits 15:11 = hour (24-hour clock)
  lv_hour  = iv_time+0(2).
  lv_x     = lv_hour.
  lv_x     = lv_x * 2048. " << 11
  lv_xtime = lv_xtime BIT-OR lv_x.

*   Bits 10:5 = minute
  lv_min   = iv_time+2(2).
  lv_x     = lv_min.
  lv_x     = lv_x * 32. " << 5
  lv_xtime = lv_xtime BIT-OR lv_x.

*   Bits 4:0 = seconds
  lv_sec   = iv_time+4(2).
  lv_x     = lv_sec / 2.
  lv_xtime = lv_xtime BIT-OR lv_x.

  rv_msdos_time = lv_xtime.

ENDMETHOD.


ENDCLASS.
