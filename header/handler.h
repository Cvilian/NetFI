/* handler.h
 *
 * routines to catch several errors, sudden cessations
 *  
 * NetFI - a fast and simple tool to analyze the network flow (Internet Protocol family) 
 */

#ifndef PUMP_HANDLER
#define PUMP_HANDLER

#include <string>

#define EXIT_WITH_RUNERROR(reason, ...) do { \
	printf("\n " reason "\n", ##__VA_ARGS__); \
    WRITE_LOG(reason, ##__VA_ARGS__); \
    pump::clearNetFI(); \
	exit(1); \
} while(0)

#define EXIT_WITH_CONFERROR(reason, ...) do { \
	printf("\n " reason "\n", ##__VA_ARGS__); \
    WRITE_LOG(reason, ##__VA_ARGS__); \
	exit(1); \
} while(0)

#define WRITE_LOG(fmt, ...){ \
    FILE* lfile = fopen((log_dir + pump::currTime()).c_str(), "a"); \
    if (lfile != NULL){ fprintf(lfile, fmt "\n", ##__VA_ARGS__); fclose(lfile); }\
}

static const std::string log_dir = "/usr/local/etc/NetFI/logDIR/";
static const std::string save_dir = "/usr/local/etc/NetFI/streamDIR/";

namespace pump
{

    std::string currTime();

    void clearNetFI();

    class EventHandler
    {

        public:

            typedef void (*EventHandlerCallback)(void* cookie);

            static EventHandler& getInstance()
            {
                static EventHandler instance;
                return instance;
            }

            void onInterrupted(EventHandlerCallback handler, void* cookie);

        private:

            EventHandlerCallback h_InterruptedHandler;
            void* h_InterruptedCookie;

            static void handlerRoutine(int signum);

    };

}

#endif