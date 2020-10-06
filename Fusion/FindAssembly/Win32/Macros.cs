
namespace FindAssembly.Win32 {
    public static class Macros {

        public static bool SUCCEEDED(uint hr) => hr >= S_OK;

        public static uint S_OK = 0x00000000;
        public static uint E_FAIL = 0x80004005;

    }
}
