#ifdef LOG_E
#undef LOG_E
#endif
#define LOG_TAG_E "error"
#define LOG_E(fmt, ...) \
    fprintf(stderr, "%s: %d: " fmt, LOG_TAG_E, __LINE__, ##__VA_ARGS__)
#ifdef LOG_D
#undef LOG_D
#endif
#define LOG_TAG_D "debug"
#define LOG_D(fmt, ...) \
    fprintf(stderr, "%s: %d: " fmt, LOG_TAG_D, __LINE__, ##__VA_ARGS__)