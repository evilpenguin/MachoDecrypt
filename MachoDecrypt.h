//
//
//
//
//
//
//

#import <Foundation/Foundation.h>
#import <syslog.h>

#ifdef DEBUG
    #define DLog(FORMAT, ...) syslog(LOG_ERR, "+[MachoDecrypt] %s\n", [[NSString stringWithFormat:FORMAT, ##__VA_ARGS__] UTF8String]);
#else 
    #define DLog(...) (void)0
#endif

typedef void (^completion_block_t)(int);
void macho_decrypt_binary(const char *binary_Name, const char *sandbox_path, completion_block_t completion);