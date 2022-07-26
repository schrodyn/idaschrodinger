//
//      This file is automatically executed when IDA is started.
//      You can define your own IDC functions and assign hotkeys to them.
//
//      You may add your frequently used functions here and they will
//      be always available.
//
//
//

//#include "scripts/idc/ColourIda.idc"

static user_main(void)
{
    auto_wait();

    Message("+=========================+\n");
    Message("schrodinger IDC user_main()\n");
    Message("+=========================+\n");

    auto compile_err = compile_idc_file("/Users/lmulligan/.idapro/scripts/idc/ColourIda.idc");
    if (compile_err != 0) {
        Message("E Could not compile file:\n");
        Message("  " + compile_err + "\n");
    }
    //add_idc_hotkey("Ctrl-Shift-C", ColourIda());
}
