//
//
//
//
//
//

#import "MachoDecrypt.h"

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

@interface UIApplication()
- (NSString *) userHomeDirectory;
@end

%ctor {
    NSString *processName = NSProcessInfo.processInfo.processName;
    if (![processName isEqualToString:@"SpringBoard"]) {
        [NSNotificationCenter.defaultCenter addObserverForName:UIApplicationDidBecomeActiveNotification object:nil queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *notification) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                UIApplication *application = notification.object;

                __weak UIViewController *rootViewController = application.keyWindow.rootViewController;
                if ([rootViewController isKindOfClass:UINavigationController.class]) {
                    rootViewController = ((UINavigationController *)rootViewController).viewControllers.firstObject;
                }
                else if ([rootViewController isKindOfClass:UITabBarController.class]) {
                    rootViewController = ((UITabBarController *)rootViewController).selectedViewController;
                }
                else if (rootViewController.presentedViewController) {
                    rootViewController = rootViewController.presentedViewController;
                }

                NSString *alertMessage = [NSString stringWithFormat:@"Would you like to decrypt %@?", processName];
                UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"MachoDecrypt" message:alertMessage preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:@"Decryt" style:UIAlertActionStyleDefault handler:^(UIAlertAction * action) {
                    macho_decrypt_binary(processName.UTF8String, application.userHomeDirectory.UTF8String, ^(int code) {
                        NSString *message = code == 0 ? [NSString stringWithFormat:@"Compelte!\n\n Please check %@", application.userHomeDirectory] : @"Failed";

                        UIAlertController *completeAlert = [UIAlertController alertControllerWithTitle:@"MachoDecrypt" message:message preferredStyle:UIAlertControllerStyleAlert];
                        [completeAlert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleCancel handler:nil]];
                        [rootViewController presentViewController:completeAlert animated:YES completion:nil];
                    });
                }]];
                [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
                
                [rootViewController dismissViewControllerAnimated:NO completion:^{
                    [rootViewController presentViewController:alert animated:YES completion:nil];
                }];
            });
        }];
    }
}
