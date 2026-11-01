#define ARGPARSE_BEGIN(ARGV) \
    int argparse_pos = 1; \
    char argparse_opt = '\0'; \
    const char *argparse_long_opt = NULL; \
    for (;; ++argparse_pos) { \
        const char *argparse_arg = (ARGV)[argparse_pos]; \
        if (argparse_arg == NULL) { \
            if (argparse_opt != '\0') --argparse_pos; \
            goto argparse_done; \
        } \
        switch (argparse_opt) { \
            default: --argparse_pos; goto argparse_done; \
            case '\0': { \
                argparse_long_opt = NULL; \
                if (argparse_arg++[0] != '-') goto argparse_done; \
                switch (argparse_arg[0]) { \
                    default: break; \
                    case '\0': goto argparse_done; \
                    case '-': { \
                        if (argparse_arg[1] == '\0') { \
                            ++argparse_pos; \
                            goto argparse_done; \
                        } \
                        argparse_long_opt = argparse_arg + 1; \

#define ARGPARSE_LONG_OPTS_TO_FLAGS_DELIMITER \
                        argparse_arg = "\n"; \
                        break; \
                    } \
                } \
                do { \
                    switch (argparse_arg[0]) { \
                        default: { \
                            argparse_opt = argparse_arg[0]; \
                            if (argparse_arg[1] != '\0') goto argparse_done; \
                            break; \
                        } \

#define ARGPARSE_FLAGS_TO_ARGS_DELIMITER \
                    } \
                } while ((++argparse_arg)[0] != '\0'); \
                continue; \
            }

#define ARGPARSE_END \
        } \
        argparse_opt = '\0'; \
    } \
    argparse_done:
