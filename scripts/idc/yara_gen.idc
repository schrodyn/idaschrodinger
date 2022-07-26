/*
 * Ida IDC Script to generate Yara rules for functions.
 * Mostly a learning experience to see what I could do with **JUST**
 * IDC.
 * Conor Quigley <schrodinger@konundrum.org>
 */
#include <idc.idc>
#define DEBUG 0

// https://gist.github.com/nosoop/7ddfad3f49f40ccd5a310608c091b134
static wildcards(count) {
    auto i = 0;
    auto wildcard = "";

    for (i=0; i<count; i++) {
        wildcard = wildcard + "?? ";
    }

    return wildcard;
}

// https://gist.github.com/nosoop/7ddfad3f49f40ccd5a310608c091b134
static GetDTSize(dtype) {
    if (dtype == dt_byte) {
        return 1;
    } else if (dtype == dt_word) {
        return 2;
    } else if (dtype == dt_dword) {
        return 4;
    } else if (dtype == dt_float) {
        return 4;
    } else if (dtype == dt_double) {
        return 8;
    } else {
        warning("Unsupported dtype size: %d", dtype);
        return -1;
    }
}

/*
 * This function generates a Yara hex string for static bytes within a
 * range.
 */
static yara_static(start, end) {

    msg("{ ");

    while( start < end ) {
        msg("%02lx ", Byte(start));
        start = next_addr(start);
    }

    msg("}\n");

    return;
}

/*
 * Function to check if an address is a fixup address.
 */
static is_fixup(va, n) {
    auto x_fixups = GetArrayId("x_fixups");
    auto i;
    auto x;

    for( i = 0; i < n; i++ ) {
        x = GetArrayElement(AR_LONG, x_fixups, i);

        if ( va == x ) {

#if ( DEBUG > 0 )
            msg("Fixup found @ 0x%lx\n", x);

            auto head = get_item_head(x);
            auto ins = generate_disasm_line(head, 1);

            msg("0x%lx: %s\n", head, ins);
#endif

            return 1;
        }
    }

    return 0;
}

/*
 * This function generates a Yara hex string with wildcards for fixup
 * addresses.
 */
static yara_wildcard(start, end, num_fixups) {

    /*
     * Loop through range.
     * For each instruction:
     *  - Get number of operands
     *  - Get address of each operand
     *  - Check if operand is a fixup address
     *  - If it's a fixup: check size of operand?
     *  - Generate appropriate wildcard mask or range of bytes.
     */

    auto cur_ea = 0;
    auto pos    = 0;
    auto i      = 0;
    auto head   = 0;
    auto rule   = "{ ";
    auto tmp    = "";

    auto x_fixups = GetArrayId("x_fixups");

    for( cur_ea = start; cur_ea < end;
            cur_ea = find_code(cur_ea, SEARCH_DOWN | SEARCH_NEXT) ) {

        head = get_item_head(cur_ea);

#if ( DEBUG > 2 )
        auto ins = generate_disasm_line(head, 1);
        msg("0x%lx: %s\n", head, ins);
#endif

        // Decode an instruction and returns an insn_t object
        // https://hex-rays.com/products/ida/support/idadoc/1218.shtml
        auto insn_t = decode_insn(head);

#if ( DEBUG > 2 )
        // Print number of operands at instruction line.
        msg("#%d operands @ 0x%lx\n", insn_t.n, head);
#endif

        // LOOP THROUGH BYTES
        auto size = get_item_size(head);

        // Starting position
        pos = head;

        // Loop through instruction bytes.
        while( pos < head+size ) {
            rule = rule + sprintf("%02x ", Byte(pos));

            pos = next_addr(pos);

            // No operands = just dump the rest of the bytes.
            if ( insn_t.n == 0 ) {
                continue;
            }
            else {
                auto dtype = 0;

                if ( insn_t.n > 2 ) {
                    warning("Unhandled number of operands: %d @ 0x%lx", head, insn_t.n);
                }

                if ( is_fixup(pos, num_fixups) ) {
                    // What's the size of the type?
                    dtype = GetDTSize(insn_t.Op0.dtype);

#if ( DEBUG > 1 )
                    msg("Fixup here 0x%lx\n", pos);
                    msg("Op0 dtype: %d\n", dtype);
#endif
                    tmp = wildcards(dtype);
                    rule = rule + tmp;

                    if (insn_t.n == 1 ) {break;}
                    else {
                        pos = pos + dtype;
                    }
                }

                if ( insn_t.n > 1 ) {

                    if ( is_fixup(pos, num_fixups) ) {
                        // What's the size of the type?
                        dtype = GetDTSize(insn_t.Op1.dtype);

#if ( DEBUG > 1 )
                        msg("Fixup here 0x%lx\n", pos);
                        msg("Op1 dtype: %d\n", dtype);
#endif

                        tmp = wildcards(dtype);
                        rule = rule + tmp;

                        break;
                    }
                }
            }
        }
    }

    rule = rule + "}";
    msg(rule);
    return;
}

static main(void) {

    auto current_ea = get_screen_ea();
    auto i;
    auto num_fixups = 0;

    auto arr_fixups = CreateArray("x_fixups");

    if ( arr_fixups == -1 ) {
        warning("Deleting existing fixups array!");
        DeleteArray("x_fixups");
        arr_fixups = CreateArray("x_fixups");
    }

    auto x_fixups = GetArrayId("x_fixups");
    auto fn_name = get_func_name(current_ea);
    auto fn_start = get_func_attr(current_ea, FUNCATTR_START);
    auto fn_end = get_func_attr(current_ea, FUNCATTR_END);
    auto fn_size = fn_end - fn_start;

#if (DEBUG > 0)
    msg("Function @ 0x%lx (%s) start: 0x%lx end: 0x%lx\n",
            current_ea, fn_name, fn_start, fn_end);

    msg("Function size: %d\n", fn_size);
#endif

    // Store a list of fixup addresses.
    for( i = get_next_fixup_ea(fn_start); i < fn_end;
            i = get_next_fixup_ea(i) )
    {

#if (DEBUG > 1)
        msg("Fixup @ 0x%lx\n", i);
        auto head = get_item_head(i);
        auto ins = generate_disasm_line(head, 1);
        msg("0x%lx: %s\n", head, ins);
#endif

        SetArrayLong(x_fixups, num_fixups, i);
        num_fixups++;
    }

    msg("\n-----> Yarrrrrrrrrrrrrrra\n");

    yara_static(fn_start, fn_end);
    yara_wildcard(fn_start, fn_end, num_fixups);

    DeleteArray(x_fixups);
}
