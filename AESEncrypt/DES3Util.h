//
//  DES3Util.h
//  AES加解密
//
//  Created by ZhangLiang on 15/10/28.
//  Copyright © 2015年 wja. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface DES3Util : NSObject

/**
*  使用主密钥进行AES加密 128bit
*/
+ (NSString *)AES128Encrypt:(NSString *)plainText;

/**
*  使用主密钥进行AES加密 256bit
*/
+ (NSString *)AES256Encrypt:(NSString *)plainText;

/**
*  使用工作密钥进行AES加密 256bit
*/
+ (NSString *)AES256EncryptWorkKey:(NSString *)plainText;

/**
*  AES解密 256bit/128bit
*/
+ (NSString *)AES128Decrypt:(NSString *)encryptText;

/**
 *  AES工作密钥解密 256bit/128bit
 */
+ (NSString *)AESWorkKey128Decrypt:(NSString *)encryptText;

@end
