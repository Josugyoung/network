#include <idc.idc>

static main(){

    auto max_eax, max_ebx, second_eax, second_ebx, third_eax, third_ebx;
    auto eax, ebx;

    max_eax = 0;
    second_eax = 0;
    third_eax = 0;
    max_ebx = 0;
    second_ebx = 0;
    third_ebx = 0;

    AddBpt(0x403E65);
    StartDebugger("","","");
    auto count;
    for(count = 0; count < 999; count ++){
        auto code = GetDebuggerEvent(WFNE_SUSP|WFNE_CONT, -1);
        eax = GetRegValue("EAX");
        ebx = GetRegValue("EBX");
    
        if(max_eax < eax){
            third_eax = second_eax;
            third_ebx = second_ebx;
            second_eax = max_eax;
            second_ebx = max_ebx;
            max_eax = eax;
            max_ebx = ebx;
        }else if(second_eax < eax){
            third_eax = second_eax;
            third_ebx = second_ebx;
            second_eax = eax;
            second_ebx = ebx;
        }else if(third_eax < eax){
            third_eax = eax;
            third_ebx = ebx;
        }
    }
    Message("max eax: %d, ebx: %x, second eax: %d, ebx: %x, third eax: %d, ebx: %x\n", max_eax, max_ebx, second_eax, second_ebx, third_eax, third_ebx);
}