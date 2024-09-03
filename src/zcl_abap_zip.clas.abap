class ZCL_ABAP_ZIP definition
  public
  final
  create public .

public section.
  type-pools ABAP .
*"* public components of class ZCL_ABAP_ZIP_CRYPT
*"* do not include other source files here!!
  type-pools IHTTP .

  types:
    BEGIN OF TS_FILE,
           name TYPE string,
           date TYPE d,
           time TYPE t,
           size TYPE i,
         END OF TS_FILE .
  types:
    TT_FILES TYPE STANDARD TABLE OF TS_FILE .
  types:
    BEGIN OF TS_SPLICE_ENTRY,
           name       TYPE string,
           offset     TYPE i,
           length     TYPE i,
           compressed TYPE i,
         END OF TS_SPLICE_ENTRY .
  types:
    TT_SPLICE_ENTRIES TYPE STANDARD TABLE OF TS_SPLICE_ENTRY WITH DEFAULT KEY .

  data MT_FILES type TT_FILES read-only .
  data MV_SUPPORT_UNICODE_NAMES type ABAP_BOOL value ABAP_FALSE ##NO_TEXT.
  data MV_CRYPTED type FLAG value 'X' ##NO_TEXT.

  methods LOAD
    importing
      !IV_ZIP type XSTRING
    exceptions
      ZIP_PARSE_ERROR .
  methods SAVE
    returning
      value(RV_ZIP) type XSTRING .
  methods GET
    importing
      !IV_NAME type STRING optional
      value(IV_INDEX) type I default 0
    exporting
      !EV_CONTENT type XSTRING
    exceptions
      ZIP_INDEX_ERROR
      ZIP_DECOMPRESSION_ERROR .
  methods ADD
    importing
      !IV_NAME type STRING
      !IV_CONTENT type XSEQUENCE .
  methods DELETE
    importing
      !IV_NAME type STRING optional
      value(IV_INDEX) type I default 0
    exceptions
      ZIP_INDEX_ERROR .
  class-methods CRC32
    importing
      !IV_CONTENT type XSTRING
    returning
      value(RV_CRC32) type I .
  class-methods SPLICE
    importing
      !IV_ZIP type XSTRING
      !IV_SUPPORT_UNICODE type ABAP_BOOL default ABAP_FALSE
    returning
      value(RT_ENTRIES) type TT_SPLICE_ENTRIES .
  class-methods PBKDF2_SHA1_SALT_1000
    importing
      !IV_SALT type XSTRING
      !IV_PASSWORD type STRING
    exporting
      !EV_HASH type XSTRING .
  class-methods GET_KEYS
    importing
      !IV_PASS type STRING
      !IV_SALT type XSTRING
      !IV_KEY_LEN type I
    exporting
      !EV_KEY_CRYPT type XSTRING
      !EV_PV type XSTRING
      !EV_KEY_AUTH_CODE type XSTRING .
  methods SET_PASS
    importing
      !IV_IPASS type STRING .
  methods SET_KEY_LEN
    importing
      !IV_KEY_LEN type I .
*  private section.
*  types:
*    BEGIN OF T_EXT,
*           min_extract_version TYPE i,
*           gen_flags           TYPE i,
*           compressed          TYPE i,
*           compsize            TYPE i,
*           cryptcompsize       TYPE i,
*           crc32(4)            TYPE x,
*           filename_len        TYPE i,
*           filename            TYPE xstring,
*           extra_len           TYPE i,
*           extra               TYPE xstring,
*           content             TYPE xstring,
*           cryptcontent        type xstring,
*           salt                type xstring,
*           pv                  type xstring,
*           auth_codes          type xstring,
*         END OF T_EXT .
*  types:
*    T_EXTS TYPE STANDARD TABLE OF T_EXT .
*
*  data EXTS type T_EXTS .
*  class-data CRC32_MAP type XSTRING .
*  data PASSWORD type STRING .
*  data CRYPTO_KEY_LEN type I value 256 ##NO_TEXT.
  methods GEN_SALT
    returning
      value(RV_SALT) type XSTRING .
  methods ENCRYPT
    importing
      !IV_KEY type XSTRING
      !IV_V type XSTRING
      !IV_PLAINTEXT type XSTRING
      !IV_KEY_LEN type I default 256
    returning
      value(RV_CIPHERTEXT) type XSTRING .
private section.

  types:
    BEGIN OF TS_EXT,
           min_extract_version TYPE i,
           gen_flags           TYPE i,
           compressed          TYPE i,
           compsize            TYPE i,
           cryptcompsize       TYPE i,
           crc32(4)            TYPE x,
           filename_len        TYPE i,
           filename            TYPE xstring,
           extra_len           TYPE i,
           extra               TYPE xstring,
           content             TYPE xstring,
           cryptcontent        type xstring,
           salt                type xstring,
           pv                  type xstring,
           auth_codes          type xstring,
         END OF TS_EXT .
  types:
    TT_EXTS TYPE STANDARD TABLE OF TS_EXT .
  types:
    tv_raw16 type x length 16 .
  types:
    tt_raw16 type table of  tv_raw16 .

  data MT_EXTS type TT_EXTS .
  class-data MCV_CRC32_MAP type XSTRING .
  data MV_PASSWORD type STRING .
  data MV_CRYPTO_KEY_LEN type I value 256 ##NO_TEXT.

  methods CONVERT_XSTRING_TO_RAW16_TABLE
    importing
      !IV_DATA type XSTRING
    exporting
      !ET_RAW16_TABLE type TT_RAW16 .
  methods GET_COUNTER_INCREMENT
    importing
      !IV_DATA type XSTRING
    returning
      value(RV_DATA) type XSTRING .
  methods PROGRESS_BAR
    importing
      !IV_PERCENTAGE type P .
ENDCLASS.



CLASS ZCL_ABAP_ZIP IMPLEMENTATION.


  METHOD ADD.
    DATA lv_key_crypt TYPE xstring.
    DATA lv_key_auth_code TYPE xstring.
    DATA lv_hmac TYPE xstring.

    FIELD-SYMBOLS: <ls_file> TYPE ts_file,
                   <ls_ext>  TYPE ts_ext.

    APPEND INITIAL LINE TO mt_files ASSIGNING <ls_file>.
    APPEND INITIAL LINE TO mt_exts  ASSIGNING <ls_ext>.

    <ls_file>-name = iv_name.
    <ls_file>-date = sy-datum.
    <ls_file>-time = sy-uzeit.
    <ls_file>-size = xstrlen( iv_content ).

* general purpose flag bit 11 (Language encoding flag (EFS)
    CONSTANTS: lc_gen_flags_unicode(2) TYPE x VALUE '0800'.
    CONSTANTS: lc_gen_flags_encode(2) TYPE x VALUE '0001'.

    CONSTANTS: lc_gen_flags_extra_aes(11) TYPE x VALUE '0199070002004145030800'. "'0199070002004145030000'.
    CONSTANTS: lc_gen_flags_extra_aes_rd(8) TYPE x VALUE '0199070002004145'.

    CONSTANTS: lc_gen_flags_aes_128 TYPE x VALUE '01'.
    CONSTANTS: lc_gen_flags_aes_192 TYPE x VALUE '02'.
    CONSTANTS: lc_gen_flags_aes_256 TYPE x VALUE '03'.
    CONSTANTS: lc_gen_flags_compress(2)   TYPE x VALUE '0800'.
    CONSTANTS: lc_gen_flags_uncompress(2) TYPE x VALUE '0000'.

* see: http://www.pkware.com/documents/casestudies/APPNOTE.TXT, APPENDIX D
* zip normaly used IBM Code Page 437 mapped to SAP Printer EPESCP IBM 437

    DATA: lo_conv       TYPE ref TO cl_abap_conv_out_ce,
          lo_conv_cp437 TYPE REF TO cl_abap_conv_out_ce,
          lo_conv_utf8  TYPE REF TO cl_abap_conv_out_ce,
          lv_cp437      TYPE abap_encoding VALUE '1107', " IBM 437
          lv_utf8       TYPE abap_encoding VALUE '4110'. " UTF-8
    IF mv_support_unicode_names = abap_true.
      lo_conv = cl_abap_conv_out_ce=>create( encoding = lv_utf8
                                       ignore_cerr = abap_true
                                       replacement = '#' ).
    ELSE.
      lo_conv = cl_abap_conv_out_ce=>create( encoding = lv_cp437
                                       ignore_cerr = abap_true
                                       replacement = '#' ).
    ENDIF.
    lo_conv->convert( EXPORTING data = <ls_file>-name IMPORTING buffer = <ls_ext>-filename ).
    <ls_ext>-filename_len = xstrlen( <ls_ext>-filename ).
    IF mv_crypted = 'X'.
      <ls_ext>-extra_len = 11.
      <ls_ext>-extra     = lc_gen_flags_extra_aes_rd.
      CASE mv_crypto_key_len.
        WHEN 128.
          <ls_ext>-extra = <ls_ext>-extra && lc_gen_flags_aes_128.
        WHEN 192.
          <ls_ext>-extra = <ls_ext>-extra && lc_gen_flags_aes_192.
        WHEN 256.
          <ls_ext>-extra = <ls_ext>-extra && lc_gen_flags_aes_256.
        WHEN OTHERS.
          <ls_ext>-extra = <ls_ext>-extra && lc_gen_flags_aes_256.
      ENDCASE.
      <ls_ext>-extra = <ls_ext>-extra && lc_gen_flags_compress .
    ELSE.
      <ls_ext>-extra_len = 0.
      <ls_ext>-extra     = ''.
    ENDIF.
    <ls_ext>-min_extract_version = 51.
    IF mv_support_unicode_names  = abap_true.
      <ls_ext>-gen_flags        = lc_gen_flags_unicode.
    ELSE.
      <ls_ext>-gen_flags        = 0.
    ENDIF.

    IF mv_crypted = 'X'.
      <ls_ext>-gen_flags =  <ls_ext>-gen_flags + lc_gen_flags_encode.
    ENDIF.

    IF <ls_file>-size > 0.
      IF mv_crypted = 'X'.
        <ls_ext>-compressed = 99.
        <ls_ext>-crc32  = 0.
      ELSE.
        <ls_ext>-compressed = 8. " 8 gzip Deflate
        <ls_ext>-crc32  = crc32( iv_content ).
      ENDIF.
      cl_abap_gzip=>compress_binary(
        EXPORTING raw_in       = iv_content
                  raw_in_len   = <ls_file>-size
        IMPORTING gzip_out     = <ls_ext>-content
                  gzip_out_len = <ls_ext>-compsize ).
      IF mv_crypted = 'X'.
        <ls_ext>-salt = gen_salt( ).
        get_keys( EXPORTING iv_pass = mv_password   iv_salt = <ls_ext>-salt  iv_key_len = mv_crypto_key_len
                  IMPORTING ev_key_crypt = lv_key_crypt   ev_pv = <ls_ext>-pv   ev_key_auth_code = lv_key_auth_code ).

        <ls_ext>-cryptcontent = encrypt( iv_key = lv_key_crypt
                                         iv_v = '01000000000000000000000000000000'
                                         iv_plaintext = <ls_ext>-content
                                         iv_key_len = mv_crypto_key_len ) .

        TRY.
            cl_abap_hmac=>calculate_hmac_for_raw(
                EXPORTING if_algorithm  = 'SHA1'   if_key = lv_key_auth_code  if_data = <ls_ext>-cryptcontent
                IMPORTING ef_hmacxstring = lv_hmac ).
          CATCH cx_abap_message_digest.
        ENDTRY.
        <ls_ext>-auth_codes = lv_hmac(10).
        <ls_ext>-cryptcompsize = <ls_ext>-compsize + xstrlen( <ls_ext>-salt ) + xstrlen( <ls_ext>-pv ) +  xstrlen( <ls_ext>-auth_codes ).
      ENDIF.
    ELSE. " folder
      <ls_ext>-compressed        = 0. " gzip Stored
      <ls_ext>-crc32             = 0.
      <ls_ext>-compsize          = 0.
    ENDIF.
  ENDMETHOD.


  METHOD CONVERT_XSTRING_TO_RAW16_TABLE.
    DATA: lv_input_length     TYPE int4,
          lv_number_of_blocks TYPE int4,
          lv_block_cursor     TYPE int4,
          lv_offset           TYPE int4.

    FIELD-SYMBOLS <lv_raw16>  TYPE tv_raw16.

    REFRESH et_raw16_table.

    lv_input_length = xstrlen( iv_data ).
    lv_number_of_blocks = ceil( '1.0' * lv_input_length / 16 ).

    lv_block_cursor = 1.
    lv_offset = 0.

    WHILE lv_block_cursor <= lv_number_of_blocks.
      APPEND INITIAL LINE TO et_raw16_table ASSIGNING <lv_raw16>.

      IF lv_block_cursor < lv_number_of_blocks.
        <lv_raw16> = iv_data+lv_offset(16).
      ELSE.
        <lv_raw16> = iv_data+lv_offset.
      ENDIF.

      lv_block_cursor = lv_block_cursor + 1.
      lv_offset = lv_offset + 16.
    ENDWHILE.
  ENDMETHOD.


  method CRC32.
* Let us ask our friendly neighbour whether there is a CRC32 in the kernel (thanks guys!)
  IF cl_http_utility=>is_ict_system_call_implemented( ihttp_scid_crc32_checksum ) IS INITIAL.
    SYSTEM-CALL ict                        "#EC CI_SYSTEMCALL
      DID
        ihttp_scid_crc32_checksum
      PARAMETERS
        iv_content                            " > xstr
        rv_crc32.                             " < unsigned int
    RETURN.
  ENDIF.

* Do the calculations by hand. This is going to be slow. This is going to be a pain.
* What is a man to do?

  CONSTANTS: lc_magic_nr(4)  TYPE x VALUE 'EDB88320',
             lc_mFFFFFFFF(4) TYPE x VALUE 'FFFFFFFF',
             lc_m7FFFFFFF(4) TYPE x VALUE '7FFFFFFF',
             lc_m00FFFFFF(4) TYPE x VALUE '00FFFFFF',
             lc_m000000FF(4) TYPE x VALUE '000000FF',
             lc_m000000(3)   TYPE x VALUE '000000'.

  IF XSTRLEN( mcv_crc32_map ) = 0.
    DO 256 TIMES.
      DATA: lv_c(4) TYPE x, lv_low_bit(4) TYPE x.
      lv_c = sy-index - 1.
      DO 8 TIMES.
        lv_low_bit = '00000001'.
        lv_low_bit = lv_c BIT-AND lv_low_bit.   " c  & 1
        lv_c = lv_c DIV 2.
        lv_c = lv_c BIT-AND lc_m7FFFFFFF. " c >> 1 (top is zero, but in ABAP signed!)
        IF lv_low_bit IS NOT INITIAL.
          lv_c = lv_c BIT-XOR lc_magic_nr.
        ENDIF.
      ENDDO.
      CONCATENATE mcv_crc32_map lv_c INTO mcv_crc32_map IN BYTE MODE.
    ENDDO.
  ENDIF.

  DATA: lv_len TYPE i, lv_n TYPE i. "#EC *
  DATA: lv_crc(4) TYPE x VALUE lc_mFFFFFFFF, lv_x4(4) TYPE x, lv_idx(4) TYPE x.

  lv_len = XSTRLEN( iv_content ).
  DO lv_len TIMES.
    lv_n = sy-index - 1.
    CONCATENATE lc_m000000 iv_content+lv_n(1) INTO lv_idx IN BYTE MODE.
    lv_idx = ( lv_crc BIT-XOR lv_idx ) BIT-AND lc_m000000FF.
    lv_idx = lv_idx * 4.
    lv_x4  = mcv_crc32_map+lv_idx(4).
    lv_crc = lv_crc DIV 256.
    lv_crc = lv_crc BIT-AND lc_m00FFFFFF. " c >> 8
    lv_crc = lv_x4 BIT-XOR lv_crc.
  ENDDO.
  lv_crc = lv_crc BIT-XOR lc_mFFFFFFFF.

  rv_crc32 = lv_crc.

  endmethod.


  METHOD DELETE.
    DATA: lv_index TYPE i.

    IF iv_index = 0.
      READ TABLE mt_files TRANSPORTING NO FIELDS WITH KEY name = iv_name.
      IF sy-subrc IS NOT INITIAL.
        RAISE zip_index_error.                            "#EC RAISE_OK
      ENDIF.
      lv_index = sy-tabix.
    ELSE.
      lv_index = iv_index .
    ENDIF.

    IF lv_index < 1 OR lv_index > lines( mt_files ).
      RAISE zip_index_error.                              "#EC RAISE_OK
    ENDIF.

    DELETE mt_files INDEX lv_index.
    DELETE mt_exts  INDEX lv_index.
  ENDMETHOD.


  METHOD ENCRYPT.
    DATA lt_i_data TYPE tt_raw16.
    DATA lv_length TYPE i.
    DATA lv_crypt_stream TYPE xstring.
    DATA lv_ciphertextblock TYPE xstring.
    DATA lv_iv TYPE xstring.
    DATA lv_algorithm TYPE string.

    lv_length =  xstrlen( iv_plaintext ).
    REFRESH lt_i_data[].

    convert_xstring_to_raw16_table( EXPORTING iv_data = iv_plaintext
                                    IMPORTING et_raw16_table = lt_i_data ).
    lv_iv = iv_v.

    CASE iv_key_len.
      WHEN 128.
        lv_algorithm = cl_sec_sxml_writer=>co_aes128_algorithm.
      WHEN 192.
        lv_algorithm = cl_sec_sxml_writer=>co_aes192_algorithm.
      WHEN 256.
        lv_algorithm = cl_sec_sxml_writer=>co_aes256_algorithm.
      WHEN OTHERS.
        lv_algorithm = cl_sec_sxml_writer=>co_aes256_algorithm.
    ENDCASE.

    DATA(lv_len_i_data) = lines( lt_i_data ).
    LOOP AT lt_i_data ASSIGNING FIELD-SYMBOL(<lv_iraw16>).

      cl_sec_sxml_writer=>encrypt_iv( EXPORTING
                                          key = iv_key
                                          plaintext = lv_iv
                                          iv = '00000000000000000000000000000000'
                                          algorithm = lv_algorithm
                                      IMPORTING ciphertext = lv_crypt_stream ).

      lv_crypt_stream = lv_crypt_stream+16(16).
      lv_ciphertextblock =  <lv_iraw16> BIT-XOR lv_crypt_stream .
      rv_ciphertext =  rv_ciphertext && lv_ciphertextblock.
      lv_iv = get_counter_increment( lv_iv ).

      IF ( sy-tabix MOD 500 ) = 0.
        progress_bar( sy-tabix * 100 / lv_len_i_data ).
      ENDIF.
    ENDLOOP.

    rv_ciphertext = rv_ciphertext(lv_length).
  ENDMETHOD.


  METHOD GEN_SALT.
    DATA lv_len  TYPE i.

    CASE mv_crypto_key_len.
      WHEN 128.
        lv_len = 8.
      WHEN 192.
        lv_len = 12.
      WHEN 256.
        lv_len = 16.
      WHEN OTHERS.
        lv_len = 16.
    ENDCASE.

    CALL FUNCTION 'GENERATE_SEC_RANDOM'
      EXPORTING
        length = lv_len
      IMPORTING
        random = rv_salt
      EXCEPTIONS
        OTHERS = 1.


  ENDMETHOD.


  METHOD GET.
    FIELD-SYMBOLS: <ls_ext> TYPE ts_ext.
    DATA: lv_index TYPE i.

    IF iv_index IS INITIAL.
      READ TABLE MT_FILES TRANSPORTING NO FIELDS WITH KEY name = iv_name.
      IF sy-subrc IS NOT INITIAL.
        RAISE zip_index_error.
      ENDIF.
      lv_index = sy-tabix.
    ELSE.
      lv_index = iv_index.
    ENDIF.

    IF lv_index < 1 OR lv_index > lines( MT_FILES ).
      RAISE zip_index_error.
    ENDIF.

    READ TABLE mt_exts INDEX lv_index ASSIGNING <ls_ext>.

    IF <ls_ext>-compressed IS INITIAL.
      ev_content = <ls_ext>-content.
    ELSE.
      cl_abap_gzip=>decompress_binary(
        EXPORTING gzip_in     = <ls_ext>-content
                  gzip_in_len = <ls_ext>-compsize
        IMPORTING raw_out     = ev_content ).
    ENDIF.

    IF crc32( ev_content ) <> <ls_ext>-crc32.
      RAISE zip_decompression_error.
    ENDIF.
  ENDMETHOD.


  METHOD GET_COUNTER_INCREMENT.
    CONSTANTS lc_one  TYPE x LENGTH 1 VALUE '01'.
    DATA lv_len TYPE i.
    DATA lv_offset TYPE i.
    DATA lv_ind TYPE i.
    DATA lv_reverse TYPE xstring.
    DATA lv_reverse16 TYPE x LENGTH 16.

   lv_len = xstrlen( iv_data ).

    lv_ind = 0.
    DO lv_len TIMES.
      lv_ind = lv_ind + 1.
      lv_offset = lv_len - lv_ind.
      lv_reverse = lv_reverse && iv_data+lv_offset(1).
    ENDDO.

    lv_reverse16 = lv_reverse + lc_one.
    lv_reverse = lv_reverse16.

    lv_ind = 0.
    DO lv_len TIMES.
      lv_ind = lv_ind + 1.
      lv_offset = lv_len - lv_ind.
      rv_data = rv_data && lv_reverse+lv_offset(1).
    ENDDO.
  ENDMETHOD.


  METHOD GET_KEYS.
    DATA lv_keys TYPE xstring.
    DATA lv_salt TYPE xstring.
    DATA lv_key_len_in_bytes TYPE i.

    lv_salt = iv_salt.
    lv_key_len_in_bytes = iv_key_len / 8.
    DATA(lv_key_len_in_bytes_doub) = lv_key_len_in_bytes * 2.

    pbkdf2_sha1_salt_1000( EXPORTING iv_salt = lv_salt
                                     iv_password = iv_pass
                           IMPORTING ev_hash = lv_keys ).
    ev_key_crypt = lv_keys(lv_key_len_in_bytes) .
    ev_key_auth_code = lv_keys+lv_key_len_in_bytes(lv_key_len_in_bytes) .
    ev_pv = lv_keys+lv_key_len_in_bytes_doub(2) .

  ENDMETHOD.


  METHOD LOAD.
* Documentation from: http://www.pkware.com/company/standards/appnote/appnote.txt

* Start to decode new ZIP file
    CLEAR:   mt_files, mt_exts.
    REFRESH: mt_files, mt_exts.

* Global offset for moving through file
    DATA: lv_offset  TYPE i.

    DEFINE next.   " move offset
      lv_offset = lv_offset + &1.
    END-OF-DEFINITION.

    DATA: lv_w2(2) TYPE x, lv_w4(4) TYPE x, lv_xstr TYPE xstring.
    DEFINE read2.  " read two bytes as integer and move offset
      lv_w2     = iv_zip+lv_offset(2).
      lv_offset = lv_offset + 2.
      CONCATENATE lv_w2+1(1) lv_w2+0(1) INTO lv_xstr IN BYTE MODE.
      &1     = lv_xstr.
    END-OF-DEFINITION.

    DEFINE read4.  " read four bytes as integer and move offset
      lv_w4     = iv_zip+lv_offset(4).
      lv_offset = lv_offset + 4.
      CONCATENATE lv_w4+3(1) lv_w4+2(1) lv_w4+1(1) lv_w4+0(1) INTO lv_xstr IN BYTE MODE.
      &1     = lv_xstr.
    END-OF-DEFINITION.

    CONSTANTS: lc_gen_flags_encrypted(2)       TYPE x VALUE '0001',
               lc_gen_flags_data_descriptor(2) TYPE x VALUE '0008', " general purpose flag bit 3
               lc_gen_flags_unicode(2)         TYPE x VALUE '0800'. " general purpose flag bit 11
    DATA:      lv_gen_flags(2) TYPE x.

* We convert all names from xstring into string
* see: http://www.pkware.com/documents/casestudies/APPNOTE.TXT, APPENDIX D
* zip normaly used IBM Code Page 437 mapped to SAP Printer EPESCP IBM 437
    DATA: lo_conv       TYPE ref TO cl_abap_conv_in_ce,
          lo_conv_cp437 TYPE REF TO cl_abap_conv_in_ce,
          lo_conv_utf8  TYPE REF TO cl_abap_conv_in_ce,
          lv_cp437      TYPE abap_encoding VALUE '1107', " IBM 437
          lv_utf8       TYPE abap_encoding VALUE '4110'. " UTF-8

    lo_conv_cp437 = cl_abap_conv_in_ce=>create( encoding = lv_cp437
                                          ignore_cerr = abap_true
                                          replacement = '#' ).
    lo_conv_utf8  = cl_abap_conv_in_ce=>create( encoding = lv_utf8
                                          ignore_cerr = abap_true
                                          replacement = '#' ).

* The maximum length of the ZIP file for scanning.
    DATA: lv_max_length TYPE i.
    lv_max_length = xstrlen( iv_zip ) - 4.

* Extract information about all files.
    DATA: lv_msdos_date TYPE i, lv_msdos_time TYPE i, lv_file_no TYPE i VALUE 0.
    FIELD-SYMBOLS: <ls_file> TYPE ts_file,
                   <ls_ext>  TYPE ts_ext.

* strip 0000 buffer from some zips
    WHILE lv_offset < lv_max_length AND iv_zip+lv_offset(1) = '00'.
      next 1.
    ENDWHILE.

    WHILE lv_offset < lv_max_length AND iv_zip+lv_offset(4) = '504B0304'.  " local file header signature

      lv_file_no = lv_file_no + 1.
      APPEND INITIAL LINE TO mt_files ASSIGNING <ls_file>.
      APPEND INITIAL LINE TO mt_exts  ASSIGNING <ls_ext>.

      next  4.                          " local file header signature
      read2 <ls_ext>-min_extract_version.  " version needed to extract = 2.0 - File is compressed using Deflate
      read2 <ls_ext>-gen_flags.            " general purpose bit flag
      read2 <ls_ext>-compressed.           " compression method: deflated
      read2 lv_msdos_time.                 " last mod file time
      read2 lv_msdos_date.                 " last mod file date
      read4 <ls_ext>-crc32.                " crc-32
      read4 <ls_ext>-compsize.             " compressed size
      read4 <ls_file>-size.                " uncompressed size
      read2 <ls_ext>-filename_len.         " file name length
      read2 <ls_ext>-extra_len.            " extra field length

      lv_gen_flags = <ls_ext>-gen_flags.
      lv_gen_flags = lv_gen_flags BIT-AND lc_gen_flags_unicode. " bit 11: Language encoding flag
      IF lv_gen_flags <> 0 AND mv_support_unicode_names = abap_true.
        lo_conv = lo_conv_utf8.  " utf-8 filename extension
      ELSE.
        lo_conv = lo_conv_cp437. " IBM CP437
      ENDIF.

      <ls_ext>-filename = iv_zip+lv_offset(<ls_ext>-filename_len).
      lo_conv->convert( EXPORTING input = <ls_ext>-filename IMPORTING data = <ls_file>-name ).
      next <ls_ext>-filename_len.

      <ls_ext>-extra = iv_zip+lv_offset(<ls_ext>-extra_len).
      next <ls_ext>-extra_len.

      lv_gen_flags = <ls_ext>-gen_flags.
      lv_gen_flags = lv_gen_flags BIT-AND lc_gen_flags_data_descriptor. " bit 3: Data Descriptor
      IF lv_gen_flags = 0.

        <ls_ext>-content = iv_zip+lv_offset(<ls_ext>-compsize).
        next <ls_ext>-compsize.

      ELSE.

        DATA   lt_result_tab TYPE match_result_tab.
        FIELD-SYMBOLS <ls_match> LIKE LINE OF lt_result_tab.
        FIND ALL OCCURRENCES OF <ls_ext>-filename IN iv_zip RESULTS lt_result_tab IN BYTE MODE.
* --- start of modification:
* The following modification was necessary to handle zip-archives containing files
* where the name of one file is a sub-string of the name of another file

        DATA: lv_cached_offset TYPE i.
        lv_cached_offset = lv_offset.
        DATA: lv_filename_length TYPE i.
        SORT lt_result_tab BY offset DESCENDING. "#EC CI_SORTLOOP
        LOOP AT lt_result_tab ASSIGNING <ls_match>.
          lv_offset = <ls_match>-offset - 46.
          IF iv_zip+lv_offset(4) <> '504B0102'. " central directory header record's signature
            CONTINUE.
          ENDIF.
          ADD 28 TO lv_offset.
          read2 lv_filename_length.
          IF lv_filename_length = xstrlen( <ls_ext>-filename ).
            EXIT.
          ENDIF.
        ENDLOOP .

        lv_offset = <ls_match>-offset - 30.

        read4 <ls_ext>-crc32.
        read4 <ls_ext>-compsize.
        read4 <ls_file>-size.
        next 18.
        lv_offset = lv_cached_offset.
        <ls_ext>-content = iv_zip+lv_offset(<ls_ext>-compsize).
        next <ls_ext>-compsize.
        next 16.                                            " I032850

      ENDIF.

      <ls_file>-time = lcl_msdos=>from_time( lv_msdos_time ).
      <ls_file>-date = lcl_msdos=>from_date( lv_msdos_date ).

      lv_gen_flags = <ls_ext>-gen_flags.
      lv_gen_flags = lv_gen_flags BIT-AND lc_gen_flags_encrypted.

      IF NOT ( <ls_ext>-min_extract_version <= 20 )
          OR ( lv_gen_flags = lc_gen_flags_encrypted )
          OR NOT ( <ls_ext>-compressed = 0 OR <ls_ext>-compressed = 8 ).
        RAISE zip_parse_error.
      ENDIF.

*   strip 0000 buffer from some zips
      WHILE lv_offset < lv_max_length AND iv_zip+lv_offset(1) = '00'.
        next 1.
      ENDWHILE.

    ENDWHILE.
  ENDMETHOD.


  METHOD PBKDF2_SHA1_SALT_1000.
    CONSTANTS:
      lc_con_01(4) TYPE x VALUE '00000001',
      lc_con_02(4) TYPE x VALUE '00000002',
      lc_con_03(4) TYPE x VALUE '00000003',
      lc_con_04(4) TYPE x VALUE '00000004'.

    FIELD-SYMBOLS <lv_con> LIKE lc_con_01.

    DATA:
      lv_lf_single_round_input  TYPE xstring,
      lv_lf_single_round_result TYPE xstring,
      lv_lf_pbkdf2_result       TYPE xstring,
      lv_lf_password            TYPE xstring.

    DATA lv_index TYPE numc2.

    DATA: lo_conv   TYPE ref to cl_abap_conv_out_ce,
          lv_cp437 TYPE abap_encoding VALUE '1107'.

    lo_conv = cl_abap_conv_out_ce=>create( encoding = lv_cp437  ignore_cerr = abap_true replacement = '#' ).
    lo_conv->convert( EXPORTING data = iv_password
                      IMPORTING buffer = lv_lf_password ).

    lv_index = 0.
    DO 4 TIMES.
      lv_index = lv_index + 1.

      CLEAR : lv_lf_single_round_input, lv_lf_single_round_result, lv_lf_pbkdf2_result.

      DATA(lv_con) = |LC_CON_{ lv_index }|.
      ASSIGN (lv_con) TO <lv_con>.
      CHECK sy-subrc = 0.
      CONCATENATE iv_salt <lv_con> INTO lv_lf_single_round_input IN BYTE MODE.

      TRY.
          cl_abap_hmac=>calculate_hmac_for_raw(
            EXPORTING
              if_algorithm   = 'SHA1'
              if_key         = lv_lf_password
              if_data        = lv_lf_single_round_input
            IMPORTING
              ef_hmacxstring = lv_lf_single_round_result ).
        CATCH cx_abap_message_digest.
          ASSERT 1 = 0.
      ENDTRY.

      lv_lf_pbkdf2_result = lv_lf_single_round_result.

      DO 999 TIMES.
        lv_lf_single_round_input = lv_lf_single_round_result.
        TRY.
            cl_abap_hmac=>calculate_hmac_for_raw(
              EXPORTING
                if_algorithm   = 'SHA1'
                if_key         = lv_lf_password
                if_data        = lv_lf_single_round_input
              IMPORTING
                ef_hmacxstring = lv_lf_single_round_result ).
          CATCH cx_abap_message_digest.
            ASSERT 1 = 0.
        ENDTRY.
        lv_lf_pbkdf2_result = lv_lf_pbkdf2_result BIT-XOR lv_lf_single_round_result.
      ENDDO.

      ev_hash = ev_hash && lv_lf_pbkdf2_result .

    ENDDO.
  ENDMETHOD.


  method PROGRESS_BAR.
     CALL FUNCTION 'SAPGUI_PROGRESS_INDICATOR'
      EXPORTING
        percentage = iv_percentage.
  endmethod.


  METHOD SAVE.
* Documentation from: http://www.pkware.com/company/standards/appnote/appnote.txt

    CONSTANTS: lc_her(36) TYPE x VALUE '0A0020000000000001001800E8771643ED26D30174CE0F1E2F26D30174CE0F1E2F26D301'. " хз что это

    DATA: lv_x2(2) TYPE x, lv_x4(4) TYPE x.

    DEFINE writeX4.    " write xstring
      lv_x4 = &2.
      CONCATENATE &1 lv_x4 INTO &1 IN BYTE MODE.
    END-OF-DEFINITION.

    DEFINE write2.  " write two bytes from integer
      lv_x2 = &2.
      CONCATENATE &1 lv_x2+1(1) lv_x2+0(1) INTO &1 IN BYTE MODE.
    END-OF-DEFINITION.

    DEFINE write4.  " write four bytes from integer
      lv_x4 = &2.
      CONCATENATE &1 lv_x4+3(1) lv_x4+2(1) lv_x4+1(1) lv_x4+0(1) INTO &1 IN BYTE MODE.
    END-OF-DEFINITION.

* Process all files. We write in parallel the zip and the central directory to use later
    DATA: lv_msdos_date TYPE i, lv_msdos_time TYPE i.
    FIELD-SYMBOLS: <ls_file> TYPE ts_file,
                   <ls_ext>  TYPE ts_ext.
    DATA: lv_dir             TYPE xstring, lv_start_offset(4) TYPE x.

    LOOP AT mt_files ASSIGNING <ls_file>.
      READ TABLE mt_exts INDEX sy-tabix ASSIGNING <ls_ext>.
      lv_start_offset = xstrlen( rv_zip ).

      lv_msdos_time = lcl_msdos=>to_time( <ls_file>-time ).
      lv_msdos_date = lcl_msdos=>to_date( <ls_file>-date ).

*   zip data stream
      writeX4  rv_zip '504B0304'.                  " local file header signature
      write2   rv_zip <ls_ext>-min_extract_version.   " version needed to extract = 2.0 - File is compressed using Deflate
      write2   rv_zip <ls_ext>-gen_flags.             " general purpose bit flag
      write2   rv_zip <ls_ext>-compressed.            " compression method: deflated
      write2   rv_zip lv_msdos_time.                  " last mod file time
      write2   rv_zip lv_msdos_date.                  " last mod file date
      write4   rv_zip <ls_ext>-crc32.                 " crc-32
      IF mv_crypted = 'X'.
        write4   rv_zip <ls_ext>-cryptcompsize.       " crypto compressed size
      ELSE.
        write4   rv_zip <ls_ext>-compsize.            " compressed size
      ENDIF.
      write4   rv_zip <ls_file>-size.                 " uncompressed size
      write2   rv_zip <ls_ext>-filename_len.          " file name length
      write2   rv_zip <ls_ext>-extra_len.             " extra field length

      CONCATENATE rv_zip <ls_ext>-filename <ls_ext>-extra INTO rv_zip IN BYTE MODE.
      IF mv_crypted = 'X'.
        CONCATENATE rv_zip <ls_ext>-salt <ls_ext>-pv <ls_ext>-cryptcontent <ls_ext>-auth_codes INTO rv_zip IN BYTE MODE.
      ELSE.
        CONCATENATE rv_zip <ls_ext>-content INTO rv_zip IN BYTE MODE.
      ENDIF.

*   central directory stream (which has a lare duplicate sequence of zip header)
      DATA: lv_dup_offset TYPE i.
      lv_dup_offset = lv_start_offset + 4.
      writeX4  lv_dir '504B0102'.                  " central file header signature
      " version made by (== pkzip 2.04g)
      IF mv_crypted = 'X'.
        write2   lv_dir 63.
        CONCATENATE lv_dir rv_zip+lv_dup_offset(24) INTO lv_dir IN BYTE MODE.  " part which matches exactly zip header
        write2   lv_dir 47.
      ELSE.
        write2   lv_dir 19.
        CONCATENATE lv_dir rv_zip+lv_dup_offset(26) INTO lv_dir IN BYTE MODE.  " part which matches exactly zip header
      ENDIF.
      write2   lv_dir  0.                          " file comment length
      write2   lv_dir  0.                          " disk number start
      write2   lv_dir  0.                          " internal file attributes
      IF mv_crypted = 'X'.
        write4   lv_dir  32.
      ELSE.
        write4   lv_dir  0.                        " external file attributes
      ENDIF.
      write4   lv_dir  lv_start_offset.               " relative offset of local header

      IF mv_crypted = 'X'.
        CONCATENATE lv_dir <ls_ext>-filename INTO lv_dir IN BYTE MODE. "  + file name
        CONCATENATE lv_dir lc_her INTO lv_dir IN BYTE MODE.         "  не знаю, что это. скопировано с архивов от 7-zip
        CONCATENATE lv_dir <ls_ext>-extra INTO lv_dir IN BYTE MODE.    "  + extra info
      ELSE.
        CONCATENATE lv_dir <ls_ext>-filename  <ls_ext>-extra INTO lv_dir IN BYTE MODE.  " file name + extra info
      ENDIF.

    ENDLOOP.

* Write Central Directory
    DATA: lv_lines_files TYPE i.
    lv_lines_files = lines( mt_files ).
    DATA: lv_xstrlen_dir TYPE i.
    lv_xstrlen_dir = xstrlen( lv_dir ).
    DATA: lv_offset_dir  TYPE i.
    lv_offset_dir  = xstrlen( rv_zip ).

    CONCATENATE rv_zip lv_dir INTO rv_zip IN BYTE MODE.
    writeX4  rv_zip '504B0506'.                    " End of central directory
    write2   rv_zip  0.                            " number of this disk
    write2   rv_zip  0.                            " number of the disk with the start of the central directory
    write2   rv_zip  lv_lines_files.               " total number of entries in the central directory on this disk
    write2   rv_zip  lv_lines_files.               " total number of entries in the central directory
    write4   rv_zip  lv_xstrlen_dir.               " size of the central directory
    write4   rv_zip  lv_offset_dir.                " offset of start of central directory
    write2   rv_zip  0.                            " ZIP file comment length
  ENDMETHOD.


  method SET_KEY_LEN.
       mv_crypto_key_len = iv_key_len.
  endmethod.


  method SET_PASS.
     mv_password = iv_ipass.
    if mv_password is not initial.
       mv_crypted = 'X'.
     else.
       clear mv_crypted.
     endif.
  endmethod.


  METHOD SPLICE.
* ZIP format: http://www.pkware.com/company/standards/appnote/appnote.txt

    DATA: lv_w2(2) TYPE x, lv_w4(4) TYPE x, lv_xstr TYPE xstring.
    DEFINE read2. "#EC NEEDED read two bytes as integer and move offset
      lv_w2     = iv_zip+lv_offset(2).
      lv_offset = lv_offset + 2.
      CONCATENATE lv_w2+1(1) lv_w2+0(1) INTO lv_xstr IN BYTE MODE.
      &1     = lv_xstr.
    END-OF-DEFINITION.

    DEFINE read4. "#EC NEEDED read four bytes as integer and move offset
      lv_w4     = iv_zip+lv_offset(4).
      lv_offset = lv_offset + 4.
      CONCATENATE lv_w4+3(1) lv_w4+2(1) lv_w4+1(1) lv_w4+0(1) INTO lv_xstr IN BYTE MODE.
      &1     = lv_xstr.
    END-OF-DEFINITION.

* Global offset for moving through file
    DATA: lv_offset  TYPE i.
* The maximum length of the ZIP file for scanning.
    DATA: lv_max_length TYPE i.

    FIELD-SYMBOLS:
          <ls_entry>      LIKE LINE OF rt_entries.
    DATA: lv_filename_len TYPE i,
          lv_extra_len    TYPE i,
          lv_filename     TYPE xstring.

    CONSTANTS: lc_gen_flags_data_descriptor(2) TYPE x VALUE '0008', " general purpose flag bit 3
               lc_gen_flags_unicode(2)         TYPE x VALUE '0800', " general purpose flag bit 11
               lc_gen_flags_null(2)            TYPE x VALUE '0000'.

    DATA:      lv_gen_flags(2) TYPE x.

    DATA   lt_result_tab TYPE match_result_tab.
    FIELD-SYMBOLS <ls_match> LIKE LINE OF lt_result_tab.
    DATA: lv_cached_offset TYPE i.
    DATA: lv_filename_length TYPE i.

* We convert all filenames from xstring into string
* zip normally uses IBM Code Page 437 mapped to SAP Printer EPESCP IBM 437
* utf-8 is supported and detected automatically
    DATA: lo_conv  TYPE ref to cl_abap_conv_in_ce,
          lo_conv_cp437 TYPE REF TO cl_abap_conv_in_ce,
          lo_conv_utf8  TYPE REF TO cl_abap_conv_in_ce,
          lv_cp437      TYPE abap_encoding VALUE '1107', " IBM 437
          lv_utf8       TYPE abap_encoding VALUE '4110'. " UTF-8

    lo_conv_cp437 = cl_abap_conv_in_ce=>create( encoding = lv_cp437
                                          ignore_cerr = abap_true
                                          replacement = '#' ).
    lo_conv_utf8  = cl_abap_conv_in_ce=>create( encoding = lv_utf8
                                       ignore_cerr = abap_true
                                       replacement = '#' ).

* Start to decode new ZIP file
    CLEAR:   rt_entries.
    REFRESH: rt_entries.

    lv_max_length = xstrlen( iv_zip ) - 4.

* strip 0000 buffer from some zips
    WHILE lv_offset < lv_max_length AND iv_zip+lv_offset(1) = '00'.
      next 1.
    ENDWHILE.

* Extract information about all files.
    WHILE iv_zip+lv_offset(4) = '504B0304'.  " local file header signature

      APPEND INITIAL LINE TO rt_entries ASSIGNING <ls_entry>.

      lv_offset = lv_offset + 6.       " next 4=(header). read2 <ext>-min_extract_version.
      read2 lv_gen_flags.
      read2 <ls_entry>-compressed.  " compression method: deflated
      lv_offset = lv_offset + 8.       " read2 msdos_time. read2 msdos_date. read4 <ext>-crc32.
      read4 <ls_entry>-length.      " compressed size
      lv_offset = lv_offset + 4.       " uncompressed size
      read2 lv_filename_len.        " file name length
      read2 lv_extra_len.           " extra field length

*   check encoding of filename
      IF ( lv_gen_flags BIT-AND lc_gen_flags_unicode ) <> lc_gen_flags_null AND iv_support_unicode = abap_true.
        lo_conv = lo_conv_utf8.  " utf-8 filename extension
      ELSE.
        lo_conv = lo_conv_cp437. " IBM CP437
      ENDIF.

      lv_filename = iv_zip+lv_offset(lv_filename_len).
      lo_conv->convert( EXPORTING input = lv_filename IMPORTING data = <ls_entry>-name ).
      next: lv_filename_len, lv_extra_len.
      <ls_entry>-offset = lv_offset.

*   check data descriptor flag
      IF ( lv_gen_flags BIT-AND lc_gen_flags_data_descriptor ) <> lc_gen_flags_null.
*     correct size must be read from central directory entry
        lv_cached_offset = lv_offset.
        FIND ALL OCCURRENCES OF lv_filename IN iv_zip RESULTS lt_result_tab IN BYTE MODE.
        SORT lt_result_tab BY offset DESCENDING. "#EC CI_SORTLOOP
        LOOP AT lt_result_tab ASSIGNING <ls_match>.
          lv_offset = <ls_match>-offset - 18.
          read2 lv_filename_length.
          IF lv_filename_length = xstrlen( lv_filename ).
            EXIT.
          ENDIF.
        ENDLOOP .

        lv_offset = <ls_match>-offset - 26.
        read4 <ls_entry>-length.

*     reset position to local file header and data area
        lv_offset = lv_cached_offset.
        next <ls_entry>-length.

*     skip data descriptor
        IF iv_zip+lv_offset(4) = '504B0708'. "optional signature field
          next 16.
        ELSE.
          next 12.
        ENDIF.

      ELSE.
        next <ls_entry>-length.
      ENDIF.

*   strip 0000 buffer from some zips
      WHILE lv_offset < lv_max_length AND iv_zip+lv_offset(1) = '00'.
        next 1.
      ENDWHILE.

    ENDWHILE.

    DELETE rt_entries WHERE length = 0.
  ENDMETHOD.
ENDCLASS.
