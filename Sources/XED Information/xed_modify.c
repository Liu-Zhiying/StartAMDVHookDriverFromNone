//这是为了在驱动中集成XED中修改的代码
//XED中有两处相同代码，都是这样修改

void xed_internal_assert(const char* msg, const char* file, int line) {
    if (xed_user_abort_function) {
        (*xed_user_abort_function)(msg, file, line, xed_user_abort_other);
    }
    else {
        DbgPrint("ASSERTION FAILURE %s at %s:%d\n", msg, file, line);
    }
    __debugbreak();
}