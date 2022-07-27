//
//      This file is automatically executed when IDA is started.
//      You can define your own IDC functions and assign hotkeys to them.
//
//      You may add your frequently used functions here and they will
//      be always available.
//
//
//


//
//      This file is automatically executed when IDA is started.
//      You can define your own IDC functions and assign hotkeys to them.
//
//      You may add your frequently used functions here and they will
//      be always available.
//
//
//

#include "scripts/idc/ColourIda.idc"

static hello_world(void)
{
    msg("Hello world!\n");
}

static user_main(void)
{
    auto_wait();

    Message("+=========================+\n");
    Message("schrodinger IDC user_main()\n");
    Message("+=========================+\n");

    add_idc_hotkey("Ctrl-Shift-H", "hello_world");
    add_idc_hotkey("Alt-Shift-C", "ColourIda");
}
